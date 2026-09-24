"""Investing Reporter Frontend Server with Universal SQL API Integration.

Serves the web portal (index.html), processes all database operations (SELECT, INSERT,
UPDATE, DELETE, UPSERT) via the Universal Raw SQL Execution API (/api/query and /api/sql)
on the backend service (port 3000), and forwards scraper jobs (/api/run) and billing requests.
"""

import json
import os
from pathlib import Path
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------------------
# Backend & Scraper API Configuration
# ---------------------------------------------------------------------------
BACKEND_API_URL = (
    os.getenv("BACKEND_API_URL")
    or os.getenv("API_BASE")
    or "http://localhost:3000"
).strip().rstrip("/")

SCRAPER_API_URL = (
    os.getenv("SCRAPER_API_URL")
    or f"{BACKEND_API_URL}/api/run"
).strip()

BILLING_API_URL = (
    os.getenv("BILLING_API_URL")
    or f"{BACKEND_API_URL}/api/billing/ecs-fargate"
).strip()

BILLING_API_KEY = (
    os.getenv("BILLING_API_KEY")
    or os.getenv("API_KEY")
    or os.getenv("X_API_KEY")
    or "ak_live_7e8b4f1c9a3d5206e12f84b9c7a0d143"
).strip()

LAMBDA_API_URL = os.getenv(
    "LAMBDA_API_URL",
    "https://al4vj8u8yh.execute-api.us-west-2.amazonaws.com/dev/investing-scrapper",
).strip()

AUTH_EMAIL = os.getenv("AUTH_EMAIL", "admin@investing.com").strip()
AUTH_ID = os.getenv("AUTH_ID", "").strip()
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "InvestAdmin21").strip()


# ---------------------------------------------------------------------------
# API Key Helper
# ---------------------------------------------------------------------------
def _get_x_api_key() -> str:
    """Retrieve API key from .env (X_API_KEY / API_KEY) or request headers."""
    try:
        req_key = (
            request.headers.get("X-API-Key")
            or request.headers.get("x-api-key")
            or request.headers.get("X_API_KEY")
            or request.args.get("api_key")
            or request.args.get("x_api_key")
        )
        if req_key and str(req_key).strip():
            return str(req_key).strip()
    except RuntimeError:
        pass

    return (
        os.getenv("X_API_KEY")
        or os.getenv("API_KEY")
        or os.getenv("x_api_key")
        or os.getenv("BILLING_API_KEY")
        or "ak_live_7e8b4f1c9a3d5206e12f84b9c7a0d143"
    ).strip()


# ---------------------------------------------------------------------------
# Helper: Forward Requests to Backend API Container (Port 3000)
# ---------------------------------------------------------------------------
def _forward_to_container(
    endpoint: str,
    method: str = "GET",
    params: dict = None,
    json_data: dict = None,
    timeout: int = 35,
) -> tuple[dict, int]:
    base_urls = [BACKEND_API_URL]
    if "localhost" in BACKEND_API_URL or "127.0.0.1" in BACKEND_API_URL:
        base_urls.append(BACKEND_API_URL.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal"))
    elif "74.207.229.12" in BACKEND_API_URL:
        base_urls.append(BACKEND_API_URL.replace("74.207.229.12", "host.docker.internal"))

    api_key_val = _get_x_api_key()
    last_error = None

    for base in base_urls:
        clean_endpoint = "/" + endpoint.lstrip("/")
        full_url = base + clean_endpoint
        if params:
            query_str = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None and v != ""}, doseq=True)
            if query_str:
                full_url += ("&" if "?" in full_url else "?") + query_str

        headers = {
            "Accept": "application/json",
            "User-Agent": "InvestingReporterFrontend/1.0",
        }
        if api_key_val:
            headers["X-API-Key"] = api_key_val

        body_bytes = None
        if json_data is not None:
            headers["Content-Type"] = "application/json"
            body_bytes = json.dumps(json_data).encode("utf-8")

        req = urllib.request.Request(full_url, data=body_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_data = resp.read().decode("utf-8")
                try:
                    return json.loads(resp_data), resp.status
                except Exception:
                    return {"success": True, "raw": resp_data}, resp.status
        except urllib.error.HTTPError as http_err:
            try:
                err_body = http_err.read().decode("utf-8")
                return json.loads(err_body), http_err.code
            except Exception:
                return {"success": False, "error": f"HTTP {http_err.code}: {http_err.reason}"}, http_err.code
        except Exception as err:
            last_error = err
            continue

    return {
        "success": False,
        "error": f"Backend SQLite/Scraper service unavailable at {BACKEND_API_URL}: {str(last_error)}"
    }, 503


# ---------------------------------------------------------------------------
# Universal SQL Execution Helper
# ---------------------------------------------------------------------------
def execute_sql_query(query: str, params: list = None, timeout: int = 35) -> tuple[dict, int]:
    """Execute raw SQL query via POST /api/query on the backend SQLite service."""
    payload = {
        "query": query,
        "params": params if params is not None else []
    }
    return _forward_to_container(
        endpoint="/api/query",
        method="POST",
        json_data=payload,
        timeout=timeout
    )


# ---------------------------------------------------------------------------
# Remote Schema Initializer
# ---------------------------------------------------------------------------
def _init_remote_schema():
    """Ensure standard tables exist on remote SQLite backend."""
    tables = [
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            user_name TEXT
        );""",
        """CREATE TABLE IF NOT EXISTS comment_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            user_id INTEGER,
            status TEXT DEFAULT 'not processed',
            fetched_at TEXT,
            Comments TEXT,
            user_name TEXT
        );""",
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_comment_urls_user_url
           ON comment_urls (user_id, url);""",
        """CREATE TABLE IF NOT EXISTS InvestingUIProcessing (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            NumberOfAccounts INTEGER,
            CommentIds TEXT,
            UserIds TEXT,
            StartingDate TEXT DEFAULT (datetime('now', 'localtime'))
        );""",
        """CREATE TABLE IF NOT EXISTS BackendProcessingTracker (
            task_id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_email TEXT,
            comment_ids TEXT,
            user_ids TEXT,
            status TEXT,
            is_success TEXT,
            starting_date TEXT DEFAULT (datetime('now', 'localtime'))
        );"""
    ]
    def _run():
        time.sleep(1)
        for q in tables:
            try:
                execute_sql_query(q, timeout=10)
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()


_init_remote_schema()

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Core Web & Config Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/config")
def get_config():
    return jsonify({
        "backend_api_url": BACKEND_API_URL,
        "api_key": _get_x_api_key(),
        "lambda_api_url": LAMBDA_API_URL,
        "scraper_api_url": SCRAPER_API_URL,
        "billing_api_url": BILLING_API_URL,
        "billing_api_key": BILLING_API_KEY,
    })


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

    allowed_identifiers = {AUTH_EMAIL.lower(), "admin@investing.com"}
    if AUTH_ID:
        allowed_identifiers.add(AUTH_ID.lower())

    if identifier.lower() not in allowed_identifiers or password != AUTH_PASSWORD:
        return jsonify({
            "success": False,
            "error": "Invalid email/ID or password. Login failed."
        }), 401

    display_name = AUTH_EMAIL if identifier.lower() == AUTH_EMAIL.lower() else identifier

    return jsonify({
        "success": True,
        "message": "Login successful",
        "token": "authenticated_session",
        "email": display_name,
    })


@app.get("/api/auth/verify")
def verify_auth():
    return jsonify({
        "success": True,
        "authenticated": True,
        "email": AUTH_EMAIL,
    })


@app.post("/api/logout")
def logout():
    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })


# ---------------------------------------------------------------------------
# Universal Raw SQL Execution API Proxy (/api/query & /api/sql)
# ---------------------------------------------------------------------------

@app.route("/api/query", methods=["POST"])
@app.route("/api/sql", methods=["POST"])
def raw_sql_endpoint():
    """Forward raw SQL query to the Universal SQL Execution API on port 3000."""
    data = request.get_json(silent=True) or {}
    query = data.get("query") or ""
    params = data.get("params") or []
    if not query:
        return jsonify({"success": False, "error": "Query string is required"}), 400

    res_data, status_code = execute_sql_query(query, params)
    return jsonify(res_data), status_code


# ---------------------------------------------------------------------------
# Generic Frontend Data API (Routed via Universal SQL API)
# ---------------------------------------------------------------------------

@app.route("/api/frontend-data", methods=["GET", "POST", "PUT", "DELETE"])
def frontend_data_endpoint():
    """Execute generic frontend-data CRUD operations via the Universal SQL API."""
    # GET -> Read Data
    if request.method == "GET":
        table = request.args.get("table", "users").strip()
        if table not in ("users", "comment_urls", "InvestingUIProcessing", "BackendProcessingTracker"):
            table = "users"

        limit = max(1, min(500, int(request.args.get("limit", 50))))
        offset = max(0, int(request.args.get("offset", 0)))
        search = request.args.get("search", "").strip()

        where_clauses = []
        params = []
        if search:
            if table == "users":
                where_clauses.append("(id LIKE ? OR user_name LIKE ?)")
                params.extend([f"%{search}%", f"%{search}%"])
            elif table == "comment_urls":
                where_clauses.append("(Comments LIKE ? OR user_name LIKE ? OR url LIKE ?)")
                params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        
        count_res, _ = execute_sql_query(f"SELECT COUNT(*) as count FROM {table} {where_sql}", params)
        total_count = 0
        if count_res.get("success") and count_res.get("data"):
            total_count = count_res["data"][0].get("count") or count_res["data"][0].get("COUNT(*)") or 0

        rows_res, status_code = execute_sql_query(
            f"SELECT * FROM {table} {where_sql} ORDER BY 1 DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        )
        data = rows_res.get("data", []) if rows_res.get("success") else []

        return jsonify({
            "success": rows_res.get("success", True),
            "table": table,
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "data": data,
            "rows": data
        }), status_code

    # POST / PUT -> Insert / Upsert Data
    data = request.get_json(silent=True) or {}
    table = data.get("table") or request.args.get("table") or "users"
    action = str(data.get("action") or "upsert").lower()

    if table not in ("users", "comment_urls", "InvestingUIProcessing", "BackendProcessingTracker"):
        table = "users"

    payload_data = data.get("data") or data.get("user") or data.get("record")
    if not payload_data or not isinstance(payload_data, dict):
        payload_data = {k: v for k, v in data.items() if k not in ("table", "action")}

    if not payload_data:
        return jsonify({"success": False, "error": "No data fields provided"}), 400

    cols = list(payload_data.keys())
    vals = list(payload_data.values())
    placeholders = ", ".join("?" for _ in cols)
    col_names = ", ".join(cols)

    if action in ("upsert", "replace"):
        sql = f"INSERT OR REPLACE INTO {table} ({col_names}) VALUES ({placeholders})"
    else:
        sql = f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})"

    res_data, status_code = execute_sql_query(sql, vals)
    if not res_data.get("success"):
        return jsonify(res_data), status_code

    return jsonify({
        "success": True,
        "message": f"Data saved to {table} successfully",
        "table": table,
        "action": action,
        "id": res_data.get("last_insert_rowid"),
        "data": payload_data
    }), 201


# ---------------------------------------------------------------------------
# Users APIs (Routed via Universal SQL API)
# ---------------------------------------------------------------------------

@app.get("/api/users")
def get_users():
    page = max(1, int(request.args.get("page", 1)))
    page_size = max(1, min(100, int(request.args.get("page_size", 20))))
    search = request.args.get("search", "").strip()
    offset = (page - 1) * page_size

    where_sql = ""
    params = []
    if search:
        where_sql = "WHERE (CAST(id AS TEXT) LIKE ? OR user_name LIKE ?)"
        params = [f"%{search}%", f"%{search}%"]

    count_res, _ = execute_sql_query(f"SELECT COUNT(*) as count FROM users {where_sql}", params)
    total_count = 0
    if count_res.get("success") and count_res.get("data"):
        total_count = count_res["data"][0].get("count") or count_res["data"][0].get("COUNT(*)") or 0

    rows_res, status_code = execute_sql_query(
        f"SELECT id, user_name FROM users {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [page_size, offset]
    )
    users = []
    if rows_res.get("success") and rows_res.get("data"):
        users = [{"id": str(r.get("id")), "user_name": r.get("user_name") or ""} for r in rows_res["data"]]

    total_pages = max(1, (total_count + page_size - 1) // page_size) if total_count > 0 else 1

    return jsonify({
        "success": rows_res.get("success", True),
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "users": users
    }), status_code


@app.post("/api/users")
def add_user_endpoint():
    data = request.get_json(silent=True) or {}
    raw_user_id = str(data.get("user_id") or data.get("id") or "").strip()
    user_name = str(data.get("user_name") or "").strip()

    if not raw_user_id or not raw_user_id.isdigit():
        return jsonify({"success": False, "error": "User ID must be a valid positive integer."}), 400
    if not user_name:
        return jsonify({"success": False, "error": "User name is required."}), 400

    user_id = int(raw_user_id)
    existing_res, _ = execute_sql_query("SELECT id FROM users WHERE id = ?", [user_id])
    if existing_res.get("success") and existing_res.get("data") and len(existing_res["data"]) > 0:
        return jsonify({
            "success": False,
            "error": f"User with ID {user_id} already exists in database.",
            "already_exists": True
        }), 409

    ins_res, status_code = execute_sql_query("INSERT INTO users (id, user_name) VALUES (?, ?)", [user_id, user_name])
    if not ins_res.get("success"):
        return jsonify(ins_res), status_code

    return jsonify({
        "success": True,
        "message": f"User {user_name} (ID: {user_id}) added successfully.",
        "user": {"id": str(user_id), "user_name": user_name}
    }), 201


@app.delete("/api/users/<int:user_id>")
def delete_user_endpoint(user_id: int):
    del_res, status_code = execute_sql_query("DELETE FROM users WHERE id = ?", [user_id])
    if not del_res.get("success"):
        return jsonify(del_res), status_code
    if del_res.get("rows_affected", 0) == 0:
        return jsonify({"success": False, "error": f"User with ID {user_id} not found."}), 404

    return jsonify({
        "success": True,
        "message": f"User with ID {user_id} deleted successfully."
    }), 200


@app.delete("/api/users")
def delete_user_body_endpoint():
    data = request.get_json(silent=True) or {}
    raw_id = request.args.get("id") or request.args.get("user_id") or data.get("user_id") or data.get("id")
    if not raw_id or not str(raw_id).strip().isdigit():
        return jsonify({"success": False, "error": "Valid user ID is required."}), 400
    return delete_user_endpoint(int(str(raw_id).strip()))


# ---------------------------------------------------------------------------
# Comments APIs (Routed via Universal SQL API)
# ---------------------------------------------------------------------------

def _extract_comment_id(url: str) -> str:
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


@app.get("/api/comments")
def get_comments():
    page = max(1, int(request.args.get("page", 1)))
    page_size = max(1, min(100, int(request.args.get("page_size", 10))))
    hours = max(1, int(request.args.get("hours", 6)))
    status_filter = request.args.get("status", "").strip()
    search_query = (request.args.get("search") or request.args.get("q") or "").strip()
    user_filters = request.args.getlist("user") or request.args.getlist("users")

    offset = (page - 1) * page_size
    where_clauses = []
    params = []

    if status_filter:
        where_clauses.append("status = ?")
        params.append(status_filter)

    if user_filters:
        u_clauses = []
        for u in user_filters:
            u_str = str(u).strip()
            if u_str:
                u_clauses.append("(user_name = ? OR user_name LIKE ? OR CAST(user_id AS TEXT) = ?)")
                params.extend([u_str, f"%{u_str}%", u_str])
        if u_clauses:
            where_clauses.append(f"({' OR '.join(u_clauses)})")

    if search_query:
        where_clauses.append("(Comments LIKE ? OR user_name LIKE ? OR CAST(user_id AS TEXT) LIKE ? OR url LIKE ?)")
        params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    
    count_res, _ = execute_sql_query(f"SELECT COUNT(*) as count FROM comment_urls {where_sql}", params)
    total_count = 0
    if count_res.get("success") and count_res.get("data"):
        total_count = count_res["data"][0].get("count") or count_res["data"][0].get("COUNT(*)") or 0

    rows_res, status_code = execute_sql_query(f"""
        SELECT id, url, fetched_at, user_id, status, Comments, user_name
        FROM comment_urls
        {where_sql}
        ORDER BY fetched_at DESC, id DESC
        LIMIT ? OFFSET ?
    """, params + [page_size, offset])

    comments = []
    if rows_res.get("success") and rows_res.get("data"):
        for r in rows_res["data"]:
            url_str = r.get("url") or ""
            comments.append({
                "id": r.get("id"),
                "url": url_str,
                "comment_id": _extract_comment_id(url_str),
                "user_id": str(r.get("user_id") or ""),
                "user_name": r.get("user_name") or "",
                "comment_text": r.get("Comments") or "",
                "status": r.get("status") or "not processed",
                "fetched_at": r.get("fetched_at") or "",
            })

    total_pages = max(1, (total_count + page_size - 1) // page_size) if total_count > 0 else 1

    return jsonify({
        "success": rows_res.get("success", True),
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "comments": comments
    }), status_code


@app.get("/api/comments/users")
def get_comments_users():
    users_by_id = {}
    
    res_users, _ = execute_sql_query("SELECT id, user_name FROM users ORDER BY user_name ASC")
    if res_users.get("success") and res_users.get("data"):
        for r in res_users["data"]:
            uid = str(r.get("id") or "").strip()
            uname = (r.get("user_name") or "").strip()
            if uid or uname:
                users_by_id[uid or uname] = {"user_name": uname, "user_id": uid}

    res_comments, _ = execute_sql_query("SELECT DISTINCT user_name, user_id FROM comment_urls WHERE user_name IS NOT NULL OR user_id IS NOT NULL")
    if res_comments.get("success") and res_comments.get("data"):
        for r in res_comments["data"]:
            uid = str(r.get("user_id") or "").strip()
            uname = (r.get("user_name") or "").strip()
            key = uid or uname
            if key and key not in users_by_id:
                users_by_id[key] = {"user_name": uname, "user_id": uid}

    sorted_users = sorted(
        users_by_id.values(),
        key=lambda u: (u["user_name"].lower() if u["user_name"] else u["user_id"])
    )
    return jsonify({"success": True, "users": sorted_users})


@app.post("/api/comments/status")
def update_comments_status_endpoint():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids") or []
    comment_ids = data.get("comment_ids") or []
    status = str(data.get("status") or "reported").strip()

    updated_count = 0
    if ids:
        int_ids = [int(i) for i in ids if str(i).isdigit()]
        if int_ids:
            placeholders = ",".join("?" for _ in int_ids)
            res, _ = execute_sql_query(f"UPDATE comment_urls SET status = ? WHERE id IN ({placeholders})", [status] + int_ids)
            if res.get("success"):
                updated_count += res.get("rows_affected", 0)

    if comment_ids:
        for cid in comment_ids:
            if str(cid).strip():
                res, _ = execute_sql_query("UPDATE comment_urls SET status = ? WHERE url LIKE ?", [status, f"%comment={str(cid).strip()}%"])
                if res.get("success"):
                    updated_count += res.get("rows_affected", 0)

    return jsonify({"success": True, "updated_count": updated_count, "status": status})


# ---------------------------------------------------------------------------
# Store & Logs APIs (Routed via Universal SQL API)
# ---------------------------------------------------------------------------

@app.post("/api/store")
def store_processing_request():
    data = request.get_json(silent=True) or {}
    number_of_accounts = data.get("number_of_accounts", 1)
    comment_ids = json.dumps(data.get("comment_ids", []), separators=(",", ":"))
    user_ids = json.dumps(data.get("user_ids", []), separators=(",", ":"))

    ins_res, status_code = execute_sql_query(
        "INSERT INTO InvestingUIProcessing (NumberOfAccounts, CommentIds, UserIds) VALUES (?, ?, ?)",
        [number_of_accounts, comment_ids, user_ids]
    )
    processing_id = ins_res.get("last_insert_rowid")

    # Auto-mark reported comments
    for cid in data.get("comment_ids", []):
        if str(cid).strip():
            execute_sql_query("UPDATE comment_urls SET status = 'reported' WHERE url LIKE ?", [f"%comment={str(cid).strip()}%"])

    return jsonify({
        "processing_id": processing_id,
        "lambda_api_url": LAMBDA_API_URL,
        "message": "Request saved successfully",
    }), 201


@app.get("/api/logs")
def get_logs():
    res_logs, status_code = execute_sql_query("""
        SELECT task_id, account_email, comment_ids, user_ids, status, is_success, starting_date
        FROM BackendProcessingTracker
        ORDER BY starting_date DESC, task_id DESC
    """)
    batches = []
    if res_logs.get("success") and res_logs.get("data"):
        for r in res_logs["data"]:
            batches.append({
                "task_id": r.get("task_id"),
                "account_email": r.get("account_email") or "",
                "comment_ids": r.get("comment_ids") or "",
                "user_ids": r.get("user_ids") or "",
                "status": r.get("status") or "",
                "is_success": r.get("is_success") or "",
                "starting_date": r.get("starting_date") or "",
            })

    return jsonify({
        "success": res_logs.get("success", True),
        "total_batches": len(batches),
        "batches": batches
    }), status_code


# ---------------------------------------------------------------------------
# Scraper Trigger API (Forwarded to Scraper Container on Port 3000)
# ---------------------------------------------------------------------------

@app.route("/api/run", methods=["GET", "POST"])
def run_scraper_endpoint():
    """Trigger scraper job in background container on port 3000."""
    data = request.get_json(silent=True) if request.method == "POST" else None
    res_data, status_code = _forward_to_container(
        endpoint="/api/run",
        method=request.method,
        params=dict(request.args) if request.method == "GET" else None,
        json_data=data
    )
    return jsonify(res_data), status_code


# ---------------------------------------------------------------------------
# Billing APIs (Forwarded to Backend / AWS Billing Endpoint)
# ---------------------------------------------------------------------------

@app.get("/api/billing/ecs-fargate")
@app.get("/api/billing")
def get_billing_ecs_fargate():
    """Fetch ECS Fargate billing metrics with API Key."""
    res_data, status_code = _forward_to_container(
        endpoint="/api/billing/ecs-fargate",
        method="GET",
        params=dict(request.args)
    )
    return jsonify(res_data), status_code


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=os.getenv("FLASK_DEBUG") == "1")
