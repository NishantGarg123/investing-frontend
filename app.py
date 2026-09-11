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
LAMBDA_API_URL = os.getenv(
    "LAMBDA_API_URL",
    "https://nr9andj3qe.execute-api.us-east-2.amazonaws.com/dev/investing-dev",
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

# In-memory active session tokens: token -> {"email": email, "expires_at": epoch_seconds}
_ACTIVE_TOKENS: dict[str, dict] = {}
TOKEN_TTL_SECONDS = 24 * 3600  # 24 hours validity


def _clean_expired_tokens():
    """Purge expired sessions from memory."""
    now = time.time()
    expired = [tok for tok, data in _ACTIVE_TOKENS.items() if data["expires_at"] < now]
    for tok in expired:
        _ACTIVE_TOKENS.pop(tok, None)


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
    if time.time() > session["expires_at"]:
        _ACTIVE_TOKENS.pop(token, None)
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
    })


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


def _fetch_24h_comments(page: int = 1, page_size: int = 10, hours: int = 24, status_filter: str = "") -> dict:
    """Fetch comments fetched within the last 24 hours from InvestingDB.dbo.comment_urls."""
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
        hours = max(1, int(request.args.get("hours", 24)))
        status_filter = request.args.get("status", "").strip()

        data = _fetch_24h_comments(page=page, page_size=page_size, hours=hours, status_filter=status_filter)
        return jsonify({"success": True, **data})
    except Exception as error:
        app.logger.exception("Could not fetch comments from SQL Server")
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


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=os.getenv("FLASK_DEBUG") == "1")
