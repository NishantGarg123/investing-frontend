"""Investing Reporter frontend request store with Authentication.

The browser authenticates via POST /api/login using hardcoded/env credentials.
Subsequent calls to /api/store, /api/logs, and /api/config require Authorization: Bearer <token>.
"""

import json
import os
from pathlib import Path
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from functools import wraps
try:
    import pyodbc
except ImportError:
    pyodbc = None
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DB_CONNECTION_STRING = os.getenv("DB_CONNECTION_STRING", "").strip()
if not DB_CONNECTION_STRING and os.getenv("DB_SERVER"):
    db_srv = os.getenv("DB_SERVER", "localhost").strip()
    db_prt = os.getenv("DB_PORT", "1433").strip()
    db_name = os.getenv("DB_DATABASE", "InvestingDB").strip()
    db_user = os.getenv("DB_USERNAME", "SA").strip()
    db_pwd = os.getenv("DB_PASSWORD", "ScrapInvest321").strip()
    DB_CONNECTION_STRING = f"Driver={{ODBC Driver 18 for SQL Server}};Server=tcp:{db_srv},{db_prt};Database={db_name};Uid={db_user};Pwd={db_pwd};Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=30;"

LAMBDA_API_URL = os.getenv(
    "LAMBDA_API_URL",
    "https://al4vj8u8yh.execute-api.us-west-2.amazonaws.com/dev/investing-scrapper",
).strip()
SCRAPER_API_URL = os.getenv(
    "SCRAPER_API_URL",
    "http://74.207.229.12:3000/api/run",
).strip()
BILLING_API_URL = os.getenv(
    "BILLING_API_URL",
    "http://74.207.229.12:3000/api/billing/ecs-fargate",
).strip()
BILLING_API_KEY = os.getenv(
    "BILLING_API_KEY",
    "ak_live_7e8b4f1c9a3d5206e1",
).strip()



# ---------------------------------------------------------------------------
# Authentication Configuration (configured via .env or hardcoded fallback)
# ---------------------------------------------------------------------------
AUTH_EMAIL = (
    os.getenv("AUTH_EMAIL")
    or os.getenv("ADMIN_EMAIL")
    or os.getenv("LOGIN_EMAIL")
    or "admin@investing.com"
).strip()

AUTH_ID = (
    os.getenv("AUTH_ID")
    or os.getenv("ADMIN_ID")
    or os.getenv("LOGIN_ID")
    or ""
).strip()

AUTH_PASSWORD = (
    os.getenv("AUTH_PASSWORD")
    or os.getenv("ADMIN_PASSWORD")
    or os.getenv("LOGIN_PASSWORD")
    or os.getenv("AUTH_PASS")
    or os.getenv("LOGIN_PASS")
    or "Admin@Investing2026"
).strip()

# Session Expiration Configuration (24 Hours / 86400 Seconds)
SESSION_EXPIRY_HOURS = int(os.getenv("SESSION_EXPIRY_HOURS", "24"))
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", str(SESSION_EXPIRY_HOURS * 3600)))  # 24 hours validity

_SESSIONS_FILE = BASE_DIR / ".active_sessions.json"


def _load_persisted_tokens() -> dict[str, dict]:
    """Load active session tokens from disk cache."""
    if not _SESSIONS_FILE.exists():
        return {}
    try:
        with open(_SESSIONS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_persisted_tokens():
    """Save active session tokens to disk cache."""
    try:
        with open(_SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(_ACTIVE_TOKENS, f)
    except Exception:
        pass


# Active session tokens: token -> {"email": email, "expires_at": epoch_seconds}
_ACTIVE_TOKENS: dict[str, dict] = _load_persisted_tokens()


def _clean_expired_tokens():
    """Purge expired sessions from memory and disk."""
    now = time.time()
    expired = [tok for tok, data in _ACTIVE_TOKENS.items() if data.get("expires_at", 0) < now]
    if expired:
        for tok in expired:
            _ACTIVE_TOKENS.pop(tok, None)
        _save_persisted_tokens()


def _get_bearer_token() -> str:
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return request.args.get("token", "").strip()


def _is_valid_token(token: str) -> tuple[bool, dict | None]:
    if not token:
        return False, None
    _clean_expired_tokens()
    session = _ACTIVE_TOKENS.get(token)
    if not session:
        return False, None
    if time.time() > session.get("expires_at", 0):
        _ACTIVE_TOKENS.pop(token, None)
        _save_persisted_tokens()
        return False, None
    return True, session


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_bearer_token()
        valid, _ = _is_valid_token(token)
        if not valid:
            return jsonify({
                "success": False,
                "error": "Unauthorized. Please log in.",
                "code": "UNAUTHORIZED"
            }), 401
        return f(*args, **kwargs)
    return decorated


app = Flask(__name__)


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("email") or data.get("username") or data.get("id") or "").strip()
    password = str(data.get("password") or data.get("pass") or "").strip()

    if not identifier or not password:
        return jsonify({
            "success": False,
            "error": "Email/User ID and password are required."
        }), 400

    # Match against configured AUTH_EMAIL or AUTH_ID
    allowed_identifiers = set()
    if AUTH_EMAIL:
        allowed_identifiers.add(AUTH_EMAIL.lower())
    if AUTH_ID:
        allowed_identifiers.add(AUTH_ID.lower())

    # Fallback to AUTH_EMAIL if no identifier configured
    if not allowed_identifiers:
        allowed_identifiers.add("admin@investing.com")

    if identifier.lower() not in allowed_identifiers or password != AUTH_PASSWORD:
        return jsonify({
            "success": False,
            "error": "Invalid email/ID or password. Login failed."
        }), 401

    token = secrets.token_hex(32)
    expires_at = time.time() + TOKEN_TTL_SECONDS
    display_name = AUTH_EMAIL if identifier.lower() == AUTH_EMAIL.lower() else identifier

    _ACTIVE_TOKENS[token] = {
        "email": display_name,
        "expires_at": expires_at,
    }
    _save_persisted_tokens()

    return jsonify({
        "success": True,
        "message": "Login successful",
        "token": token,
        "email": display_name,
        "expires_in": TOKEN_TTL_SECONDS,
    })



@app.get("/api/auth/verify")
def verify_auth():
    token = _get_bearer_token()
    valid, session = _is_valid_token(token)
    if not valid or not session:
        return jsonify({
            "success": False,
            "authenticated": False,
            "error": "Session is invalid or has expired."
        }), 401

    return jsonify({
        "success": True,
        "authenticated": True,
        "email": session["email"],
    })


@app.post("/api/logout")
def logout():
    token = _get_bearer_token()
    if token:
        _ACTIVE_TOKENS.pop(token, None)
        _save_persisted_tokens()
    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })


# ---------------------------------------------------------------------------
# App & Protected API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/config")
@require_auth
def get_config():
    return jsonify({
        "lambda_api_url": LAMBDA_API_URL,
        "scraper_api_url": SCRAPER_API_URL,
        "billing_api_url": BILLING_API_URL,
        "billing_api_key": BILLING_API_KEY,
    })


@app.get("/api/billing/ecs-fargate")
@app.get("/api/billing")
@require_auth
def get_billing_ecs_fargate():
    """Fetch ECS Fargate billing data from external billing API using configured API key from .env."""
    target_url = ""
    try:
        base_url = BILLING_API_URL or "http://74.207.229.12:3000/api/billing/ecs-fargate"
        api_key = BILLING_API_KEY or "ak_live_7e8b4f1c9a3d5206e1"

        def _build_url(source_url):
            url_parts = urllib.parse.urlparse(source_url)
            query_params = urllib.parse.parse_qs(url_parts.query)
            if api_key:
                query_params["api_key"] = [api_key]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            return urllib.parse.urlunparse((
                url_parts.scheme,
                url_parts.netloc,
                url_parts.path,
                url_parts.params,
                new_query,
                url_parts.fragment,
            ))

        target_url = _build_url(base_url)

        req = urllib.request.Request(
            target_url,
            headers={
                "Accept": "application/json",
                "User-Agent": "InvestingReporter/1.0",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_body = resp.read().decode("utf-8")
                data = json.loads(resp_body)
                return jsonify(data), resp.status
        except urllib.error.URLError as url_err:
            # If backend is running inside Docker container and localhost was refused, try host.docker.internal
            if ("74.207.229.12" in target_url or "127.0.0.1" in target_url) and "host.docker.internal" not in target_url:
                docker_host_url = base_url.replace("74.207.229.12", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
                docker_target_url = _build_url(docker_host_url)
                try:
                    req_docker = urllib.request.Request(
                        docker_target_url,
                        headers={
                            "Accept": "application/json",
                            "User-Agent": "InvestingReporter/1.0",
                        },
                        method="GET",
                    )
                    with urllib.request.urlopen(req_docker, timeout=10) as resp2:
                        resp_body2 = resp2.read().decode("utf-8")
                        data2 = json.loads(resp_body2)
                        return jsonify(data2), resp2.status
                except Exception:
                    pass
            raise url_err
    except urllib.error.HTTPError as http_err:
        error_text = ""
        try:
            error_text = http_err.read().decode("utf-8")
        except Exception:
            pass
        app.logger.warning(f"Billing API returned HTTP {http_err.code}: {error_text}")
        return jsonify({
            "status": "error",
            "error": f"Billing API returned error ({http_err.code}): {error_text or http_err.reason}",
            "target_url": target_url,
        }), http_err.code
    except Exception as error:
        app.logger.exception("Could not fetch billing data")
        return jsonify({
            "status": "error",
            "error": f"Could not connect to Billing API ({target_url or BILLING_API_URL}): {str(error)}",
            "target_url": target_url,
        }), 502




def _normalise_ids(value: object, field_name: str) -> list[str]:
    """Validate and normalise an array of non-empty IDs."""
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field_name} must be a non-empty array")

    ids = [str(item).strip() for item in value]
    if any(not item for item in ids):
        raise ValueError(f"{field_name} cannot contain empty values")
    return ids


def _validate_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object")

    comment_ids = _normalise_ids(payload.get("comment_ids"), "comment_ids")
    user_ids = _normalise_ids(payload.get("user_ids"), "user_ids")
    number_of_accounts = payload.get("number_of_accounts")

    if len(comment_ids) != len(user_ids):
        raise ValueError("comment_ids and user_ids must contain the same number of values")
    if isinstance(number_of_accounts, bool) or not isinstance(number_of_accounts, int):
        raise ValueError("number_of_accounts must be a whole number")
    if number_of_accounts < 1:
        raise ValueError("number_of_accounts must be at least 1")

    return {
        "comment_ids": comment_ids,
        "user_ids": user_ids,
        "number_of_accounts": number_of_accounts,
    }


def _save_processing_request(payload: dict[str, object]) -> int:
    """Insert a request; the table default populates StartingDate."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    insert_sql = """
        INSERT INTO dbo.InvestingUIProcessing
            (NumberOfAccounts, CommentIds, UserIds)
        OUTPUT INSERTED.Id
        VALUES (?, ?, ?)
    """
    with pyodbc.connect(DB_CONNECTION_STRING, timeout=15) as connection:
        cursor = connection.cursor()
        cursor.execute(
            insert_sql,
            payload["number_of_accounts"],
            json.dumps(payload["comment_ids"], separators=(",", ":")),
            json.dumps(payload["user_ids"], separators=(",", ":")),
        )
        row = cursor.fetchone()
        connection.commit()
    return int(row[0])


def _fetch_batches_from_tracker():
    """Fetch all rows from BackendProcessingTracker and group into batches."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    query = """
        SELECT task_id, account_email, comment_ids, user_ids, status, is_success, starting_date
        FROM dbo.BackendProcessingTracker
        ORDER BY starting_date DESC, task_id DESC
    """
    with pyodbc.connect(DB_CONNECTION_STRING, timeout=15) as connection:
        cursor = connection.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()

    batches = []
    current_batch = None

    for row in rows:
        task_id = row[0]
        account_email = row[1]
        comment_ids = row[2] or ""
        user_ids = row[3] or ""
        status = row[4] or ""
        is_success = row[5] or ""
        starting_date = row[6]

        start_dt_str = starting_date.strftime("%Y-%m-%d %H:%M:%S") if starting_date else ""

        is_same = False
        if current_batch is not None:
            time_diff = (
                abs((current_batch["_last_date"] - starting_date).total_seconds())
                if (current_batch["_last_date"] and starting_date)
                else 999999
            )
            if time_diff <= 60 and current_batch["comment_ids"] == comment_ids and current_batch["user_ids"] == user_ids:
                is_same = True

        succ_match = re.search(r"success:\s*(\d+)", is_success, re.IGNORECASE)
        fail_match = re.search(r"failure:\s*(\d+)", is_success, re.IGNORECASE)

        status_lower = status.lower()
        is_completed = False
        s_count = 0
        f_count = 0

        if succ_match or fail_match:
            is_completed = True
            s_count = int(succ_match.group(1)) if succ_match else 0
            f_count = int(fail_match.group(1)) if fail_match else 0
        elif status_lower == "completed":
            is_completed = True
            s_count = 1
            f_count = 0
        elif status_lower in ("failed", "error"):
            is_completed = True
            s_count = 0
            f_count = 1
        else:
            is_completed = False
            s_count = 0
            f_count = 0

        record = {
            "task_id": task_id,
            "account_email": account_email,
            "status": status,
            "is_success": is_success,
            "is_completed": is_completed,
            "success_count": s_count,
            "failure_count": f_count,
            "starting_date": start_dt_str,
        }

        if is_same:
            current_batch["records"].append(record)
            current_batch["total_accounts"] += 1
            current_batch["total_success"] += s_count
            current_batch["total_failure"] += f_count
            if not is_completed:
                current_batch["is_completed"] = False
            current_batch["_last_date"] = starting_date
        else:
            current_batch = {
                "starting_date": start_dt_str,
                "_last_date": starting_date,
                "comment_ids": comment_ids,
                "user_ids": user_ids,
                "total_accounts": 1,
                "total_success": s_count,
                "total_failure": f_count,
                "is_completed": is_completed,
                "records": [record],
            }
            batches.append(current_batch)

    total_batches = len(batches)
    for idx, b in enumerate(batches):
        b["batch_number"] = total_batches - idx
        b.pop("_last_date", None)

    return batches


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/logs")
@require_auth
def get_logs():
    try:
        batches = _fetch_batches_from_tracker()
        return jsonify({
            "success": True,
            "total_batches": len(batches),
            "batches": batches,
        })
    except Exception as error:
        app.logger.exception("Could not fetch logs from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


def _extract_comment_id(url: str) -> str:
    """Extract numeric comment ID from investing.com commentary URL."""
    if not url:
        return ""
    match = re.search(r'[?&]comment=(\d+)', url, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'/comment/(\d+)', url, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'(\d{6,})', url)
    if match:
        return match.group(1)
    return ""


def _fetch_distinct_comment_users(hours: int = 6) -> list[dict]:
    """Fetch all users from dbo.users merged with distinct users found in dbo.comment_urls."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    users_by_id = {}
    users_by_name = {}

    with pyodbc.connect(DB_CONNECTION_STRING, timeout=15) as connection:
        cursor = connection.cursor()

        # 1. Fetch from dbo.users (configured users table)
        try:
            cursor.execute("SELECT id, user_name FROM dbo.users ORDER BY user_name ASC")
            for row in cursor.fetchall():
                uid = str(row[0] or "").strip()
                uname = (row[1] or "").strip()
                if uid or uname:
                    user_entry = {"user_name": uname, "user_id": uid}
                    if uid:
                        users_by_id[uid] = user_entry
                    if uname:
                        users_by_name[uname.lower()] = user_entry
        except Exception:
            app.logger.warning("Could not read dbo.users table for comment users dropdown")

        # 2. Also fetch any distinct users from dbo.comment_urls
        try:
            cursor.execute("""
                SELECT DISTINCT user_name, user_id
                FROM dbo.comment_urls
                WHERE ((user_name IS NOT NULL AND user_name != '') OR (user_id IS NOT NULL AND user_id != ''))
            """)
            for row in cursor.fetchall():
                uname = (row[0] or "").strip()
                uid = str(row[1] or "").strip()
                if not uid and not uname:
                    continue

                # Match by ID first
                if uid and uid in users_by_id:
                    existing = users_by_id[uid]
                    if not existing.get("user_name") and uname:
                        existing["user_name"] = uname
                        users_by_name[uname.lower()] = existing
                # Match by Name
                elif uname and uname.lower() in users_by_name:
                    existing = users_by_name[uname.lower()]
                    if not existing.get("user_id") and uid:
                        existing["user_id"] = uid
                        users_by_id[uid] = existing
                else:
                    user_entry = {"user_name": uname, "user_id": uid}
                    if uid:
                        users_by_id[uid] = user_entry
                    if uname:
                        users_by_name[uname.lower()] = user_entry
        except Exception:
            app.logger.warning("Could not read dbo.comment_urls for comment users dropdown")

    # Gather unique user dictionaries
    seen_ids = set()
    unique_users = []
    for u in list(users_by_id.values()) + list(users_by_name.values()):
        ptr = id(u)
        if ptr not in seen_ids:
            seen_ids.add(ptr)
            unique_users.append(u)

    sorted_users = sorted(
        unique_users,
        key=lambda u: (u["user_name"].lower() if u["user_name"] else u["user_id"])
    )
    return sorted_users


def _fetch_24h_comments(
    page: int = 1,
    page_size: int = 10,
    hours: int = 6,
    status_filter: str = "",
    user_filter = None,
    search_query: str = ""
) -> dict:
    """Fetch comments fetched within the last 6 hours from InvestingDB.dbo.comment_urls with optional multiple users and comment search."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    offset = max(0, (page - 1) * page_size)
    where_clauses = ["fetched_at >= DATEADD(hour, -?, sysdatetime())"]
    params = [hours]

    if status_filter:
        where_clauses.append("status = ?")
        params.append(status_filter)

    # Normalize user_filter to list of strings
    user_list = []
    if isinstance(user_filter, (list, tuple, set)):
        user_list = [str(u).strip() for u in user_filter if str(u).strip()]
    elif isinstance(user_filter, str) and user_filter.strip():
        user_list = [u.strip() for u in user_filter.split(",") if u.strip()]

    if user_list:
        user_clauses = []
        for u in user_list:
            user_clauses.append("(user_name = ? OR user_name LIKE ? OR CAST(user_id AS NVARCHAR) = ?)")
            params.extend([u, f"%{u}%", u])
        if user_clauses:
            where_clauses.append(f"({' OR '.join(user_clauses)})")

    if search_query:
        if user_list:
            where_clauses.append("(Comments LIKE ? OR url LIKE ?)")
            params.extend([f"%{search_query}%", f"%{search_query}%"])
        else:
            where_clauses.append("(Comments LIKE ? OR user_name LIKE ? OR CAST(user_id AS NVARCHAR) LIKE ? OR url LIKE ?)")
            params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])

    where_sql = " AND ".join(where_clauses)

    count_query = f"SELECT COUNT(*) FROM dbo.comment_urls WHERE {where_sql}"
    data_query = f"""
        SELECT id, url, fetched_at, user_id, status, Comments, user_name
        FROM dbo.comment_urls
        WHERE {where_sql}
        ORDER BY fetched_at DESC, id DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
    """

    with pyodbc.connect(DB_CONNECTION_STRING, timeout=15) as connection:
        cursor = connection.cursor()
        cursor.execute(count_query, *params)
        total_count = cursor.fetchone()[0]

        cursor.execute(data_query, *(params + [offset, page_size]))
        rows = cursor.fetchall()

    comments = []
    for row in rows:
        row_id = row[0]
        url = row[1] or ""
        fetched_at = row[2]
        user_id = str(row[3]) if row[3] is not None else ""
        status = row[4] or "not processed"
        comment_text = row[5] or ""
        user_name = row[6] or ""

        fetched_at_str = fetched_at.strftime("%Y-%m-%d %H:%M:%S") if fetched_at else ""
        comment_id = _extract_comment_id(url)

        comments.append({
            "id": row_id,
            "url": url,
            "comment_id": comment_id,
            "user_id": user_id,
            "user_name": user_name,
            "comment_text": comment_text,
            "status": status,
            "fetched_at": fetched_at_str,
        })

    total_pages = max(1, (total_count + page_size - 1) // page_size) if total_count > 0 else 1

    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "comments": comments,
    }


def _update_comments_status(ids: list[int] = None, comment_ids: list[str] = None, new_status: str = "reported") -> int:
    """Update status of comments in dbo.comment_urls."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    if not ids and not comment_ids:
        return 0

    updated_count = 0
    with pyodbc.connect(DB_CONNECTION_STRING, timeout=15) as connection:
        cursor = connection.cursor()

        if ids:
            int_ids = [int(i) for i in ids if str(i).isdigit()]
            if int_ids:
                placeholders = ",".join("?" for _ in int_ids)
                sql = f"UPDATE dbo.comment_urls SET status = ? WHERE id IN ({placeholders})"
                cursor.execute(sql, new_status, *int_ids)
                updated_count += cursor.rowcount

        if comment_ids:
            for cid in comment_ids:
                if str(cid).strip():
                    sql = "UPDATE dbo.comment_urls SET status = ? WHERE url LIKE ?"
                    cursor.execute(sql, new_status, f"%comment={str(cid).strip()}%")
                    updated_count += cursor.rowcount

        connection.commit()
    return updated_count


@app.get("/api/comments")
@require_auth
def get_comments():
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = max(1, min(100, int(request.args.get("page_size", 10))))
        hours = max(1, int(request.args.get("hours", 6)))
        status_filter = request.args.get("status", "").strip()
        
        # Support multiple ?user=... params, or comma-separated ?user=A,B, or ?users=...
        user_filters = request.args.getlist("user") or request.args.getlist("users")
        if not user_filters:
            single_user = (request.args.get("user") or request.args.get("users") or "").strip()
            if single_user:
                user_filters = [u.strip() for u in single_user.split(",") if u.strip()]

        search_query = (request.args.get("search") or request.args.get("q") or "").strip()

        data = _fetch_24h_comments(
            page=page,
            page_size=page_size,
            hours=hours,
            status_filter=status_filter,
            user_filter=user_filters,
            search_query=search_query
        )
        return jsonify({"success": True, **data})
    except Exception as error:
        app.logger.exception("Could not fetch comments from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.get("/api/comments/users")
@require_auth
def get_comments_users():
    try:
        hours = max(1, int(request.args.get("hours", 6)))
        users = _fetch_distinct_comment_users(hours=hours)
        return jsonify({"success": True, "users": users})
    except Exception as error:
        app.logger.exception("Could not fetch comment users from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.post("/api/comments/status")
@require_auth
def update_comments_status_endpoint():
    try:
        data = request.get_json(silent=True) or {}
        ids = data.get("ids") or []
        comment_ids = data.get("comment_ids") or []
        status = str(data.get("status") or "reported").strip()

        updated = _update_comments_status(ids=ids, comment_ids=comment_ids, new_status=status)
        return jsonify({"success": True, "updated_count": updated, "status": status})
    except Exception as error:
        app.logger.exception("Could not update comment status in SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


def _fetch_users(page: int = 1, page_size: int = 20, search: str = "") -> dict:
    """Fetch paginated list of users from dbo.users table."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    offset = max(0, (page - 1) * page_size)
    where_clauses = []
    params = []

    if search:
        where_clauses.append("(CAST(id AS NVARCHAR) LIKE ? OR user_name LIKE ?)")
        search_param = f"%{search}%"
        params.extend([search_param, search_param])

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    count_query = f"SELECT COUNT(*) FROM dbo.users {where_sql}"
    data_query = f"""
        SELECT id, user_name
        FROM dbo.users
        {where_sql}
        ORDER BY id DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
    """

    with pyodbc.connect(DB_CONNECTION_STRING, timeout=15) as connection:
        cursor = connection.cursor()
        cursor.execute(count_query, *params)
        total_count = cursor.fetchone()[0]

        cursor.execute(data_query, *(params + [offset, page_size]))
        rows = cursor.fetchall()

    users = [{"id": str(r[0]), "user_name": r[1] or ""} for r in rows]
    total_pages = max(1, (total_count + page_size - 1) // page_size) if total_count > 0 else 1

    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "users": users,
    }


def _add_user(user_id: int, user_name: str) -> tuple[bool, str]:
    """Insert a user into dbo.users only if not already present."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    with pyodbc.connect(DB_CONNECTION_STRING, timeout=15) as connection:
        cursor = connection.cursor()
        # Check if user already exists
        cursor.execute("SELECT COUNT(*) FROM dbo.users WHERE id = ?", user_id)
        count = cursor.fetchone()[0]
        if count > 0:
            return False, f"User with ID {user_id} already exists in database."

        cursor.execute("INSERT INTO dbo.users (id, user_name) VALUES (?, ?)", user_id, user_name)
        connection.commit()
    return True, f"User {user_name} (ID: {user_id}) added successfully."


@app.get("/api/users")
@require_auth
def get_users():
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = max(1, min(100, int(request.args.get("page_size", 20))))
        search = request.args.get("search", "").strip()

        data = _fetch_users(page=page, page_size=page_size, search=search)
        return jsonify({"success": True, **data})
    except Exception as error:
        app.logger.exception("Could not fetch users from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.post("/api/users")
@require_auth
def add_user_endpoint():
    try:
        data = request.get_json(silent=True) or {}
        raw_user_id = str(data.get("user_id") or data.get("id") or "").strip()
        user_name = str(data.get("user_name") or "").strip()

        if not raw_user_id or not raw_user_id.isdigit():
            return jsonify({
                "success": False,
                "error": "User ID must be a valid positive integer."
            }), 400

        if not user_name:
            return jsonify({
                "success": False,
                "error": "User name is required."
            }), 400

        user_id = int(raw_user_id)
        success, message = _add_user(user_id, user_name)

        if not success:
            return jsonify({
                "success": False,
                "error": message,
                "already_exists": True
            }), 409

        return jsonify({
            "success": True,
            "message": message,
            "user": {"id": str(user_id), "user_name": user_name}
        }), 201
    except Exception as error:
        app.logger.exception("Could not add user to SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


def _delete_user(user_id: int) -> tuple[bool, str]:
    """Delete a user from dbo.users by ID."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    with pyodbc.connect(DB_CONNECTION_STRING, timeout=15) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM dbo.users WHERE id = ?", user_id)
        if cursor.fetchone()[0] == 0:
            return False, f"User with ID {user_id} not found."

        cursor.execute("DELETE FROM dbo.users WHERE id = ?", user_id)
        connection.commit()
    return True, f"User with ID {user_id} deleted successfully."


@app.delete("/api/users/<int:user_id>")
@require_auth
def delete_user_endpoint(user_id: int):
    try:
        success, message = _delete_user(user_id)
        if not success:
            return jsonify({
                "success": False,
                "error": message,
            }), 404
        return jsonify({
            "success": True,
            "message": message,
        }), 200
    except Exception as error:
        app.logger.exception("Could not delete user from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.delete("/api/users")
@require_auth
def delete_user_body_endpoint():
    try:
        data = request.get_json(silent=True) or {}
        raw_id = request.args.get("id") or request.args.get("user_id") or data.get("user_id") or data.get("id")
        if not raw_id or not str(raw_id).strip().isdigit():
            return jsonify({
                "success": False,
                "error": "Valid user ID is required."
            }), 400
        user_id = int(str(raw_id).strip())
        success, message = _delete_user(user_id)
        if not success:
            return jsonify({
                "success": False,
                "error": message,
            }), 404
        return jsonify({
            "success": True,
            "message": message,
        }), 200
    except Exception as error:
        app.logger.exception("Could not delete user from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.post("/api/store")
@require_auth
def store_processing_request():
    try:
        payload = _validate_payload(request.get_json(silent=True))
        processing_id = _save_processing_request(payload)
        # Automatically mark reported comment URLs in dbo.comment_urls
        try:
            _update_comments_status(comment_ids=payload.get("comment_ids", []), new_status="reported")
        except Exception:
            app.logger.warning("Could not auto-update comment status in comment_urls table")
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception as error:
        app.logger.exception("Could not save reporting request to SQL Server")
        return jsonify({
            "error": f"Database error: {str(error)}"
        }), 500

    return jsonify({
        "processing_id": processing_id,
        "lambda_api_url": LAMBDA_API_URL,
        "message": "Request saved successfully",
    }), 201


@app.route("/api/run", methods=["GET", "POST"])
def run_scraper_endpoint():
    """Trigger the comment scraper/runner task. Sends ONLY selected users in a clean payload."""
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or {}

            # Extract users ONLY from the 'users' array — this is the single source of truth
            raw_users = data.get("users") or []
            users = []

            if isinstance(raw_users, list):
                for item in raw_users:
                    if isinstance(item, dict):
                        uname = str(item.get("user_name") or item.get("userName") or item.get("username") or item.get("name") or "").strip()
                        uid = str(item.get("user_id") or item.get("userId") or "").strip()
                        # If uid equals uname and is not numeric, it's not a real ID
                        if uid == uname and not uid.isdigit():
                            uid = ""
                        if uname or uid:
                            users.append({"user_name": uname, "user_id": uid})
                    elif isinstance(item, (str, int)):
                        val = str(item).strip()
                        if val.isdigit():
                            users.append({"user_name": "", "user_id": val})
                        elif val:
                            users.append({"user_name": val, "user_id": ""})

            # Fallback: if no 'users' array, try single user fields
            if not users:
                user_name = str(data.get("user_name") or data.get("user") or "").strip()
                user_id = str(data.get("user_id") or "").strip()
                if user_name or user_id:
                    users.append({"user_name": user_name, "user_id": user_id})

            # DB lookup to resolve missing user_id or user_name
            if users and DB_CONNECTION_STRING and pyodbc:
                try:
                    with pyodbc.connect(DB_CONNECTION_STRING, timeout=10) as connection:
                        cursor = connection.cursor()
                        for u in users:
                            uid = u.get("user_id", "").strip()
                            uname = u.get("user_name", "").strip()

                            # Resolve user_id from user_name
                            if (not uid or not uid.isdigit()) and uname:
                                try:
                                    cursor.execute("SELECT TOP 1 id FROM dbo.users WHERE LOWER(user_name) = LOWER(?)", uname)
                                    row = cursor.fetchone()
                                    if row and row[0]:
                                        u["user_id"] = str(row[0]).strip()
                                    else:
                                        cursor.execute("SELECT TOP 1 user_id FROM dbo.comment_urls WHERE LOWER(user_name) = LOWER(?) AND user_id IS NOT NULL AND user_id != ''", uname)
                                        row2 = cursor.fetchone()
                                        if row2 and row2[0]:
                                            u["user_id"] = str(row2[0]).strip()
                                except Exception:
                                    pass

                            # Resolve user_name from user_id
                            if not uname and uid and uid.isdigit():
                                try:
                                    cursor.execute("SELECT TOP 1 user_name FROM dbo.users WHERE id = ?", int(uid))
                                    row = cursor.fetchone()
                                    if row and row[0]:
                                        u["user_name"] = str(row[0]).strip()
                                    else:
                                        cursor.execute("SELECT TOP 1 user_name FROM dbo.comment_urls WHERE user_id = ? AND user_name IS NOT NULL AND user_name != ''", uid)
                                        row2 = cursor.fetchone()
                                        if row2 and row2[0]:
                                            u["user_name"] = str(row2[0]).strip()
                                except Exception:
                                    pass
                except Exception as db_err:
                    app.logger.warning(f"Could not resolve user names/ids from DB: {db_err}")

            # Build clean lists
            resolved_names = [u["user_name"] for u in users if u.get("user_name")]
            resolved_ids = [u["user_id"] for u in users if u.get("user_id")]
            primary_name = resolved_names[0] if resolved_names else ""
            primary_id = resolved_ids[0] if resolved_ids else ""

            # Log to terminal
            print("\n" + "=" * 70, flush=True)
            print(">>> [SCRAPER API TRIGGERED] <<<", flush=True)
            print("Method: POST", flush=True)
            if users:
                print(f"Users ({len(users)}):", flush=True)
                for idx, u in enumerate(users, 1):
                    print(f"  #{idx}  Name='{u['user_name']}'  ID='{u['user_id']}'", flush=True)
            else:
                print("No specific user → ALL users in DB", flush=True)
            print("=" * 70 + "\n", flush=True)
            app.logger.info(f"[SCRAPER] POST users={users}")

            # Build the EXACT clean payload matching Postman format
            clean_payload = {
                "users": users,
                "user_names": resolved_names,
                "user_ids": resolved_ids,
                "user_name": primary_name,
                "user": primary_name or primary_id
            }

            # Forward to external scraper service asynchronously if configured
            if SCRAPER_API_URL and SCRAPER_API_URL != request.url and not SCRAPER_API_URL.startswith("/api/run"):
                def _do_forward(url, body):
                    try:
                        import urllib.request
                        req = urllib.request.Request(
                            url,
                            data=json.dumps(body).encode("utf-8"),
                            headers={"Content-Type": "application/json", "Accept": "application/json"},
                            method="POST"
                        )
                        print(f"Forwarding to: {url}", flush=True)
                        print(f"Payload: {json.dumps(body)}", flush=True)
                        
                        with urllib.request.urlopen(req, timeout=50) as resp:
                            print("\n" + "=" * 70, flush=True)
                            print(">>> [SCRAPER RESPONSE] <<<", flush=True)
                            print("=" * 70 + "\n", flush=True)
                            resp_text = resp.read().decode("utf-8")
                            print(f"Scraper response [{resp.status}]: {resp_text[:250]}", flush=True)
                            app.logger.info(f"Forwarded to {url}, status={resp.status}")
                    except Exception as fwd_err:
                        print(f"Forward notice ({url}): {fwd_err}", flush=True)
                        app.logger.warning(f"Could not forward to {url}: {fwd_err}")

                import threading
                threading.Thread(target=_do_forward, args=(SCRAPER_API_URL, clean_payload), daemon=True).start()

            return jsonify({
                "success": True,
                "message": f"Scraper triggered for {len(users)} user(s)." if users else "Scraper triggered for all users.",
                "users": users,
                "user_names": resolved_names,
                "user_ids": resolved_ids,
                "user_name": primary_name,
                "user": primary_name or primary_id
            }), 200

        # GET request — run for all users
        print("\n" + "=" * 70, flush=True)
        print(">>> [SCRAPER API TRIGGERED] <<<", flush=True)
        print("Method: GET → ALL users", flush=True)
        print("=" * 70 + "\n", flush=True)
        app.logger.info("[SCRAPER] GET → all users")

        if SCRAPER_API_URL and SCRAPER_API_URL != request.url and not SCRAPER_API_URL.startswith("/api/run"):
            def _do_get_forward(url):
                try:
                    import urllib.request
                    req = urllib.request.Request(url, method="GET")
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        print(f"Scraper GET response [{resp.status}]", flush=True)
                        app.logger.info(f"Forwarded GET to {url}, status={resp.status}")
                except Exception as fwd_err:
                    print(f"Forward notice ({url}): {fwd_err}", flush=True)
                    app.logger.warning(f"Could not forward GET to {url}: {fwd_err}")

            import threading
            threading.Thread(target=_do_get_forward, args=(SCRAPER_API_URL,), daemon=True).start()

        return jsonify({
            "success": True,
            "message": "Scraper triggered for all users."
        }), 200
    except Exception as error:
        app.logger.exception("Error in /api/run endpoint")
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=os.getenv("FLASK_DEBUG") == "1")
