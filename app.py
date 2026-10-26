"""Investing Reporter frontend request store with Authentication.

The browser authenticates via POST /api/login using hardcoded/env credentials.
Subsequent calls to /api/store, /api/logs, and /api/config require Authorization: Bearer <token>.
"""

import json
import os
from pathlib import Path
import re
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo
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
ECS_TRACKER_API_URL = os.getenv(
    "ECS_TRACKER_API_URL",
    "https://0ix0sky0j6.execute-api.us-west-2.amazonaws.com/dev/ecs-tracker",
).strip()
ECS_CLEANUP_TOKEN = os.getenv("ECS_CLEANUP_TOKEN", "##ECSDELETE##").strip()
IST_TIMEZONE = ZoneInfo("Asia/Kolkata")


def _get_db_connection(timeout: int = 15):
    """Obtain a pyodbc connection, automatically falling back to available ODBC drivers if needed."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    try:
        return pyodbc.connect(DB_CONNECTION_STRING, timeout=timeout)
    except pyodbc.InterfaceError as initial_err:
        try:
            installed = pyodbc.drivers()
            for d in ["ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server", "SQL Server"]:
                if d in installed:
                    new_cs = re.sub(r"Driver=\{[^}]+\}", f"Driver={{{d}}}", DB_CONNECTION_STRING)
                    if d == "SQL Server":
                        new_cs = re.sub(r";Encrypt=[^;]+", "", new_cs)
                        new_cs = re.sub(r";TrustServerCertificate=[^;]+", "", new_cs)
                        new_cs = re.sub(r";Server=tcp:", ";Server=", new_cs)
                    return pyodbc.connect(new_cs, timeout=timeout)
        except Exception:
            pass
        raise initial_err


# ---------------------------------------------------------------------------
# Super Admin Authentication (Exclusive access to Billing section)
# ---------------------------------------------------------------------------
SUPER_ADMIN_EMAIL = (
    os.getenv("SUPER_ADMIN_EMAIL")
    or os.getenv("SUPERADMIN_EMAIL")
    or "superadmin@investing.com"
).strip()

SUPER_ADMIN_ID = (
    os.getenv("SUPER_ADMIN_ID")
    or os.getenv("SUPERADMIN_ID")
    or "superadmin"
).strip()

SUPER_ADMIN_PASSWORD = (
    os.getenv("SUPER_ADMIN_PASSWORD")
    or os.getenv("SUPERADMIN_PASSWORD")
    or "SuperAdmin@Investing2026"
).strip()

# ---------------------------------------------------------------------------
# Standard User Authentication Configuration (Configured via .env or fallback)
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
    or "admin"
).strip()

AUTH_PASSWORD = (
    os.getenv("AUTH_PASSWORD")
    or os.getenv("ADMIN_PASSWORD")
    or os.getenv("LOGIN_PASSWORD")
    or os.getenv("AUTH_PASS")
    or os.getenv("LOGIN_PASS")
    or "InvestAdmin21"
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


# Active session tokens: token -> {"email": email, "role": role, "is_super_admin": bool, "expires_at": epoch_seconds}
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


def _authenticate_user(identifier: str, password: str) -> tuple[bool, dict | None]:
    """Validate credentials against Super Admin, Standard Admin/User, and any ADDITIONAL_USERS."""
    if not identifier or not password:
        return False, None

    norm_id = identifier.lower().strip()

    # 1. Super Admin authentication
    super_admin_identifiers = set()
    if SUPER_ADMIN_EMAIL:
        super_admin_identifiers.add(SUPER_ADMIN_EMAIL.lower())
    if SUPER_ADMIN_ID:
        super_admin_identifiers.add(SUPER_ADMIN_ID.lower())

    if norm_id in super_admin_identifiers and password == SUPER_ADMIN_PASSWORD:
        return True, {
            "email": SUPER_ADMIN_EMAIL if norm_id == SUPER_ADMIN_EMAIL.lower() else (SUPER_ADMIN_EMAIL or identifier),
            "role": "super_admin",
            "is_super_admin": True,
        }

    # 2. Standard Admin/User authentication
    standard_identifiers = set()
    if AUTH_EMAIL:
        standard_identifiers.add(AUTH_EMAIL.lower())
    if AUTH_ID:
        standard_identifiers.add(AUTH_ID.lower())
    if not standard_identifiers:
        standard_identifiers.add("admin@investing.com")

    if norm_id in standard_identifiers and password == AUTH_PASSWORD:
        return True, {
            "email": AUTH_EMAIL if norm_id == AUTH_EMAIL.lower() else (AUTH_EMAIL or identifier),
            "role": "admin",
            "is_super_admin": False,
        }

    # 3. Optional ADDITIONAL_USERS from environment variable (JSON or comma separated)
    extra_users_str = os.getenv("ADDITIONAL_USERS", "").strip()
    if extra_users_str:
        try:
            if extra_users_str.startswith("["):
                extra_users = json.loads(extra_users_str)
                for u in extra_users:
                    u_email = str(u.get("email") or u.get("id") or "").strip()
                    u_pass = str(u.get("password") or "").strip()
                    u_role = str(u.get("role") or "user").strip()
                    if norm_id == u_email.lower() and password == u_pass:
                        return True, {
                            "email": u_email,
                            "role": u_role,
                            "is_super_admin": (u_role == "super_admin"),
                        }
            else:
                for entry in extra_users_str.split(","):
                    parts = [p.strip() for p in entry.split(":") if p.strip()]
                    if len(parts) >= 2:
                        u_email = parts[0]
                        u_pass = parts[1]
                        u_role = parts[2] if len(parts) >= 3 else "user"
                        if norm_id == u_email.lower() and password == u_pass:
                            return True, {
                                "email": u_email,
                                "role": u_role,
                                "is_super_admin": (u_role == "super_admin"),
                            }
        except Exception as e:
            app.logger.warning(f"Failed to parse ADDITIONAL_USERS: {e}")

    return False, None


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


def require_super_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_bearer_token()
        valid, session = _is_valid_token(token)
        if not valid or not session:
            return jsonify({
                "success": False,
                "error": "Unauthorized. Please log in.",
                "code": "UNAUTHORIZED"
            }), 401
        if not session.get("is_super_admin"):
            return jsonify({
                "success": False,
                "error": "Forbidden. Super admin access required to view billing.",
                "code": "FORBIDDEN"
            }), 403
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

    is_valid, user_profile = _authenticate_user(identifier, password)
    if not is_valid or not user_profile:
        return jsonify({
            "success": False,
            "error": "Invalid email/ID or password. Login failed."
        }), 401

    token = secrets.token_hex(32)
    expires_at = time.time() + TOKEN_TTL_SECONDS
    display_name = user_profile["email"]
    role = user_profile["role"]
    is_super_admin = user_profile["is_super_admin"]

    _ACTIVE_TOKENS[token] = {
        "email": display_name,
        "role": role,
        "is_super_admin": is_super_admin,
        "expires_at": expires_at,
    }
    _save_persisted_tokens()

    return jsonify({
        "success": True,
        "message": "Login successful",
        "token": token,
        "email": display_name,
        "role": role,
        "is_super_admin": is_super_admin,
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
        "email": session.get("email", ""),
        "role": session.get("role", "admin"),
        "is_super_admin": bool(session.get("is_super_admin", False)),
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
# System Configuration (Default Accounts, Global Settings)
# ---------------------------------------------------------------------------
_SYSTEM_CONFIG_FILE = BASE_DIR / ".system_config.json"
DEFAULT_NUMBER_OF_ACCOUNTS = 10


def _load_cached_system_config() -> dict:
    """Load cached system config from disk."""
    if not _SYSTEM_CONFIG_FILE.exists():
        return {}
    try:
        with open(_SYSTEM_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_cached_system_config(cfg: dict):
    """Persist system config to disk."""
    try:
        with open(_SYSTEM_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def _init_system_config_table():
    """Ensure dbo.system_config table exists in SQL Server."""
    if pyodbc is None or not DB_CONNECTION_STRING:
        return
    try:
        with _get_db_connection(timeout=10) as connection:
            cursor = connection.cursor()
            cursor.execute("""
                IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'system_config')
                BEGIN
                    CREATE TABLE dbo.system_config (
                        config_key NVARCHAR(100) PRIMARY KEY,
                        config_value NVARCHAR(500) NOT NULL,
                        updated_at DATETIME DEFAULT GETDATE(),
                        updated_by NVARCHAR(255)
                    );
                END
            """)
            connection.commit()
    except Exception as e:
        app.logger.warning(f"Could not initialize dbo.system_config: {e}")


def _get_default_accounts_count() -> int:
    """Return default number of accounts configured (defaults to 10)."""
    # 1. Check DB first if available
    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                cursor.execute("SELECT config_value FROM dbo.system_config WHERE config_key = 'default_number_of_accounts'")
                row = cursor.fetchone()
                if row and row[0]:
                    val = int(str(row[0]).strip())
                    if val >= 1:
                        cached = _load_cached_system_config()
                        if cached.get("default_number_of_accounts") != val:
                            cached["default_number_of_accounts"] = val
                            _save_cached_system_config(cached)
                        return val
        except Exception:
            pass

    # 2. Check local file cache
    cached = _load_cached_system_config()
    if "default_number_of_accounts" in cached:
        try:
            val = int(cached["default_number_of_accounts"])
            if val >= 1:
                return val
        except Exception:
            pass

    return DEFAULT_NUMBER_OF_ACCOUNTS


def _set_default_accounts_count(count: int, updated_by: str = "superadmin") -> tuple[bool, str, int]:
    """Persist default number of accounts configured in DB and local file cache."""
    if count < 1:
        return False, "Default number of accounts must be at least 1.", _get_default_accounts_count()

    # 1. Update file cache
    cached = _load_cached_system_config()
    cached["default_number_of_accounts"] = count
    cached["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    cached["updated_by"] = updated_by
    _save_cached_system_config(cached)

    # 2. Update DB
    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            _init_system_config_table()
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                cursor.execute("""
                    MERGE dbo.system_config AS target
                    USING (SELECT 'default_number_of_accounts' AS config_key, ? AS config_value, ? AS updated_by) AS source
                    ON (target.config_key = source.config_key)
                    WHEN MATCHED THEN
                        UPDATE SET target.config_value = source.config_value,
                                   target.updated_at = GETDATE(),
                                   target.updated_by = source.updated_by
                    WHEN NOT MATCHED THEN
                        INSERT (config_key, config_value, updated_at, updated_by)
                        VALUES (source.config_key, source.config_value, GETDATE(), source.updated_by);
                """, str(count), updated_by)
                connection.commit()
        except Exception as e:
            app.logger.warning(f"Could not persist default_number_of_accounts in dbo.system_config: {e}")

    return True, f"Default number of accounts set to {count}.", count


# ---------------------------------------------------------------------------
# App & Protected API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/config")
@require_auth
def get_config():
    token = _get_bearer_token()
    _, session = _is_valid_token(token)
    is_super = bool(session and session.get("is_super_admin"))

    cfg = {
        "lambda_api_url": LAMBDA_API_URL,
        "scraper_api_url": SCRAPER_API_URL,
        "ecs_tracker_api_url": ECS_TRACKER_API_URL,
        "default_number_of_accounts": _get_default_accounts_count(),
    }
    if is_super:
        cfg["billing_api_url"] = BILLING_API_URL
        cfg["billing_api_key"] = BILLING_API_KEY
    else:
        cfg["billing_api_url"] = ""
        cfg["billing_api_key"] = ""
    return jsonify(cfg)


@app.get("/api/billing/ecs-fargate")
@app.get("/api/billing")
@require_super_admin
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
            for k, v in request.args.items():
                if k not in ("token", "api_key") and v:
                    query_params[k] = [v]
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

    # Extract action value from "value" or "action" (default: "report_spam")
    raw_action = payload.get("value") or payload.get("action") or payload.get("action_type")
    if not raw_action:
        if payload.get("upvote"):
            raw_action = "upvote"
        elif payload.get("downvote"):
            raw_action = "downvote"
        elif payload.get("post_comment") or payload.get("comment") or payload.get("comments") or payload.get("accounts"):
            raw_action = "post_comment"
        else:
            raw_action = "report_spam"

    action_str = str(raw_action).strip().lower()
    if action_str in ("post_comment", "postcomment", "post-comment", "post comment", "comment"):
        action_value = "post_comment"
    elif action_str in ("report", "report_spam", "spam", "reported"):
        action_value = "report_spam"
    elif action_str in ("upvote", "upvoted"):
        action_value = "upvote"
    elif action_str in ("downvote", "downvoted"):
        action_value = "downvote"
    else:
        action_value = "report_spam"

    return {
        "comment_ids": comment_ids,
        "user_ids": user_ids,
        "number_of_accounts": number_of_accounts,
        "name": "ACTION_TYPE",
        "value": action_value,
    }


def _save_processing_request(payload: dict[str, object]) -> int:
    """Insert a request; the table default populates StartingDate."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    with _get_db_connection(timeout=15) as connection:
        cursor = connection.cursor()
        cursor.execute("""
            IF COL_LENGTH('dbo.InvestingUIProcessing', 'ActionType') IS NULL
                ALTER TABLE dbo.InvestingUIProcessing ADD ActionType NVARCHAR(30) NULL;
        """)
        has_starting_date = True
        try:
            cursor.execute("SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'InvestingUIProcessing' AND COLUMN_NAME = 'StartingDate'")
            has_starting_date = bool(cursor.fetchone())
        except Exception:
            has_starting_date = True

        if has_starting_date:
            cursor.execute("""
                INSERT INTO dbo.InvestingUIProcessing
                    (NumberOfAccounts, CommentIds, UserIds, ActionType, StartingDate)
                OUTPUT INSERTED.Id
                VALUES (?, ?, ?, ?, GETDATE())
            """,
                payload["number_of_accounts"],
                json.dumps(payload["comment_ids"], separators=(",", ":")),
                json.dumps(payload["user_ids"], separators=(",", ":")),
                payload.get("value", "report_spam"),
            )
        else:
            cursor.execute("""
                INSERT INTO dbo.InvestingUIProcessing
                    (NumberOfAccounts, CommentIds, UserIds, ActionType)
                OUTPUT INSERTED.Id
                VALUES (?, ?, ?, ?)
            """,
                payload["number_of_accounts"],
                json.dumps(payload["comment_ids"], separators=(",", ":")),
                json.dumps(payload["user_ids"], separators=(",", ":")),
                payload.get("value", "report_spam"),
            )
        row = cursor.fetchone()
        connection.commit()
    return int(row[0])


def _record_report_activity(user_ids: list[str], processing_id: int | None = None) -> None:
    """Record each accepted report with a server timestamp for hourly limiting.

    The processing table remains the source for the existing daily limit.  This
    separate, append-only activity log avoids inferring the one-hour window from
    processing records whose timestamps may be legacy or adjusted externally.
    """
    cleaned_user_ids = [str(user_id).strip() for user_id in user_ids if str(user_id).strip()]
    if not cleaned_user_ids or pyodbc is None or not DB_CONNECTION_STRING:
        return

    _init_user_limits_table()
    try:
        with _get_db_connection(timeout=10) as connection:
            cursor = connection.cursor()
            for user_id in cleaned_user_ids:
                cursor.execute("""
                    INSERT INTO dbo.user_report_activity (user_id, processing_id, reported_at)
                    VALUES (?, ?, GETDATE())
                """, user_id, processing_id)
            connection.commit()
    except Exception as error:
        # The existing processing-table calculation remains a safe fallback if
        # a deployment has not yet created the activity table.
        app.logger.warning(f"Could not record hourly report activity: {error}")


def _normalize_action_type(raw_val: object, default: str = "report_spam") -> str:
    """Normalize action type to standard keys: report_spam, upvote, downvote, or post_comment."""
    if not raw_val:
        return default
    val = str(raw_val).strip().lower()
    if "post_comment" in val or "post comment" in val or "postcomment" in val:
        return "post_comment"
    if "upvote" in val:
        return "upvote"
    if "downvote" in val:
        return "downvote"
    if "report" in val or "spam" in val:
        return "report_spam"
    return default


def _extract_id_tokens(val: object) -> set[str]:
    """Extract numeric/string/email tokens from JSON arrays or comma/space-separated strings."""
    if not val:
        return set()
    s = str(val).strip()
    if not s:
        return set()
    tokens = set()
    try:
        parsed = json.loads(s)
        if isinstance(parsed, list):
            for x in parsed:
                item_s = str(x).strip().lower()
                if item_s:
                    tokens.add(item_s)
            return tokens
        elif isinstance(parsed, dict):
            for v in parsed.values():
                item_s = str(v).strip().lower()
                if item_s:
                    tokens.add(item_s)
            return tokens
    except Exception:
        pass

    parts = re.split(r'[,;|\n\r]+', s)
    for p in parts:
        clean = p.strip().strip('"\'[]{}()').strip().lower()
        if clean:
            tokens.add(clean)

    for word in re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|\w+', s):
        tokens.add(word.lower())

    return tokens


def _parse_tracker_datetime(val, assume_utc: bool = False):
    parsed = None
    if isinstance(val, datetime):
        parsed = val
    if not val:
        return None
    if parsed is None:
        s = str(val).strip()
        try:
            parsed = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            pass
        if parsed is None:
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(s[:19], fmt)
                    break
                except Exception:
                    pass
    if parsed is None:
        return None

    # UI processing timestamps are UTC, while legacy tracker timestamps are
    # already stored as IST. Normalize both to an aware IST datetime before
    # matching, displaying, and sorting.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc if assume_utc else IST_TIMEZONE)
    return parsed.astimezone(IST_TIMEZONE)


def _fetch_batches_from_tracker(days: int = 3, action_filter: str = ""):
    """Fetch dashboard batches from BackendProcessingTracker, matched to their UI requests when available."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    with _get_db_connection(timeout=15) as connection:
        cursor = connection.cursor()

        # Check if an action type column exists on BackendProcessingTracker; safely add ActionType column if missing
        tracker_action_col = None
        try:
            cursor.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'BackendProcessingTracker'
            """)
            tracker_cols = [str(r[0]).lower() for r in cursor.fetchall()]
            for possible in ("action_type", "actiontype", "action", "task_type", "tasktype"):
                if possible in tracker_cols:
                    tracker_action_col = possible
                    break
            if not tracker_action_col:
                try:
                    cursor.execute("""
                        IF COL_LENGTH('dbo.BackendProcessingTracker', 'ActionType') IS NULL
                            ALTER TABLE dbo.BackendProcessingTracker ADD ActionType NVARCHAR(30) NULL;
                    """)
                    connection.commit()
                    tracker_action_col = "ActionType"
                except Exception as alter_err:
                    app.logger.warning(f"Could not add ActionType column to BackendProcessingTracker: {alter_err}")
        except Exception:
            tracker_action_col = None

        # 1. Fetch all UI processing requests within window (each is an authoritative batch run)
        ui_requests = []
        try:
            has_num_accs = False
            try:
                cursor.execute("""
                    SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_NAME = 'InvestingUIProcessing' AND COLUMN_NAME = 'NumberOfAccounts'
                """)
                has_num_accs = bool(cursor.fetchone())
            except Exception:
                has_num_accs = False

            sel_cols = "Id, CommentIds, UserIds, ActionType, StartingDate" + (", NumberOfAccounts" if has_num_accs else "")
            cursor.execute(f"""
                SELECT {sel_cols}
                FROM dbo.InvestingUIProcessing
                WHERE StartingDate >= DATEADD(day, -?, sysdatetime())
                ORDER BY StartingDate DESC, Id DESC
            """, days + 1)
            for urow in cursor.fetchall():
                proc_id = urow[0]
                c_raw = str(urow[1] or "").strip()
                u_raw = str(urow[2] or "").strip()
                act_raw = str(urow[3] or "").strip()
                s_date = urow[4]
                n_accs = int(urow[5]) if (has_num_accs and len(urow) > 5 and urow[5] is not None) else None
                ui_requests.append({
                    "id": proc_id,
                    "comment_ids_raw": c_raw,
                    "user_ids_raw": u_raw,
                    "comment_tokens": _extract_id_tokens(c_raw),
                    "user_tokens": _extract_id_tokens(u_raw),
                    "action_type": _normalize_action_type(act_raw),
                    "starting_date": s_date,
                    "number_of_accounts": n_accs,
                })
        except Exception as e:
            app.logger.warning(f"Could not read InvestingUIProcessing: {e}")

        # 2. Query BackendProcessingTracker
        if tracker_action_col:
            query = f"""
                SELECT task_id, account_email, comment_ids, user_ids, status, is_success, starting_date, {tracker_action_col}
                FROM dbo.BackendProcessingTracker
                WHERE starting_date >= DATEADD(day, -?, sysdatetime())
                ORDER BY starting_date DESC, task_id DESC
            """
        else:
            query = """
                SELECT task_id, account_email, comment_ids, user_ids, status, is_success, starting_date
                FROM dbo.BackendProcessingTracker
                WHERE starting_date >= DATEADD(day, -?, sysdatetime())
                ORDER BY starting_date DESC, task_id DESC
            """
        cursor.execute(query, days)
        rows = cursor.fetchall()

    # Initialize batch buckets for each UI request
    ui_batches = {}
    for ureq in ui_requests:
        uid = ureq["id"]
        s_dt = _parse_tracker_datetime(ureq["starting_date"], assume_utc=True)
        dt_str = s_dt.strftime("%Y-%m-%d %H:%M:%S") if s_dt else ""
        ui_batches[uid] = {
            "ui_id": uid,
            "starting_date": dt_str,
            "_dt": s_dt,
            "comment_ids": ureq["comment_ids_raw"],
            "user_ids": ureq["user_ids_raw"],
            "action_type": ureq["action_type"],
            "total_accounts": ureq["number_of_accounts"] or 19,
            "total_success": 0,
            "total_failure": 0,
            "is_completed": True,
            "records": [],
            "_accounts_set": set(),
            "_c_tokens": ureq["comment_tokens"],
            "_u_tokens": ureq["user_tokens"],
            "_has_records": False,
            "_any_in_progress": False,
            "_tracker_latest_dt": None,
        }

    # Match tracker tasks to the corresponding UI batch
    unmatched_records = []
    tasks_to_update_action = []

    for row in rows:
        task_id = row[0]
        account_email = row[1]
        comment_ids = row[2] or ""
        user_ids = row[3] or ""
        status = row[4] or ""
        is_success = row[5] or ""
        starting_date = row[6]

        explicit_row_action = None
        if tracker_action_col and len(row) > 7 and row[7]:
            raw_act_cell = str(row[7]).strip()
            if raw_act_cell:
                explicit_row_action = _normalize_action_type(raw_act_cell, default="")

        is_post_comment_row = bool(
            explicit_row_action == "post_comment"
            or "@" in str(user_ids)
            or "@" in str(comment_ids)
            or (account_email and "@" in account_email and account_email in str(user_ids))
        )

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
        elif status_lower in ("completed", "success"):
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

        row_dt = _parse_tracker_datetime(starting_date)
        start_dt_str = row_dt.strftime("%Y-%m-%d %H:%M:%S IST") if row_dt else ""

        record = {
            "task_id": task_id,
            "account_email": account_email,
            "status": status,
            "is_success": is_success,
            "is_completed": is_completed,
            "success_count": s_count,
            "failure_count": f_count,
            "starting_date": start_dt_str,
            "action_type": explicit_row_action or ("post_comment" if is_post_comment_row else None),
            "_dt": row_dt,
            "comment_ids": comment_ids,
            "user_ids": user_ids,
        }

        row_c_tokens = _extract_id_tokens(comment_ids)
        row_u_tokens = _extract_id_tokens(user_ids)
        acc_clean = (account_email or "").strip().lower()
        has_acc_clean = bool(acc_clean and acc_clean not in ("—", "-", ""))

        best_match_id = None
        best_score = -999999999

        for ureq in ui_requests:
            uid = ureq["id"]
            u_batch = ui_batches[uid]
            u_dt = u_batch["_dt"]
            u_action = ureq["action_type"]
            u_c_tokens = ureq["comment_tokens"]
            u_u_tokens = ureq["user_tokens"]

            # Action compatibility filter
            # 1. Post comment requests strictly match post comment tasks, and vice versa
            if u_action == "post_comment" and not is_post_comment_row:
                continue
            if u_action != "post_comment" and is_post_comment_row:
                continue

            # 2. Strict voting conflict filter: if tracker specifically specified 'upvote',
            # it cannot match a 'downvote' UI run (and vice versa)
            if explicit_row_action in ("upvote", "downvote") and u_action in ("upvote", "downvote") and explicit_row_action != u_action:
                continue

            # 3. If UI run is report_spam, but tracker record explicitly has a vote action (upvote or downvote)
            if u_action == "report_spam" and explicit_row_action in ("upvote", "downvote"):
                continue

            # (Note: If tracker action is 'report_spam' or empty, but UI run is 'upvote' or 'downvote',
            # it is permitted to match the UI run because the backend worker may log tasks under the generic
            # tracker table default 'report_spam'. The authoritative action is u_action from InvestingUIProcessing.)

            time_diff = (row_dt - u_dt).total_seconds() if (row_dt and u_dt) else 0

            # A backend task belongs to a UI run submitted before it (allowing up to 300s clock skew)
            if time_diff < -300:
                continue

            has_comment_tokens = bool(row_c_tokens and u_c_tokens)
            if has_comment_tokens:
                c_overlap = bool(row_c_tokens.intersection(u_c_tokens))
                if c_overlap:
                    # Direct match on comment ID tokens!
                    time_penalty = max(0, time_diff)
                    score = 10000000 - time_penalty
                    # Exact action match bonus
                    if explicit_row_action and explicit_row_action == u_action:
                        score += 500000
                else:
                    # Both have comment tokens, but DO NOT overlap.
                    continue
            else:
                score = 0
                if explicit_row_action and explicit_row_action == u_action:
                    score += 200000

                if row_u_tokens and u_u_tokens and row_u_tokens.intersection(u_u_tokens):
                    score += 500000
                elif acc_clean and acc_clean in u_u_tokens:
                    score += 400000

                if u_action == "post_comment":
                    score += 300000

                time_penalty = max(0, time_diff)
                score -= time_penalty

            if score > best_score:
                best_score = score
                best_match_id = uid

        if best_match_id is not None and best_score > 0:
            target_batch = ui_batches[best_match_id]
            matched_action = target_batch["action_type"]
            record["action_type"] = matched_action
            target_batch["records"].append(record)
            target_batch["_has_records"] = True
            if row_dt and (
                target_batch["_tracker_latest_dt"] is None
                or row_dt > target_batch["_tracker_latest_dt"]
            ):
                target_batch["_tracker_latest_dt"] = row_dt
            target_batch["total_success"] += s_count
            target_batch["total_failure"] += f_count
            if has_acc_clean:
                target_batch["_accounts_set"].add(acc_clean)
            if not is_completed:
                target_batch["_any_in_progress"] = True

            # If BackendProcessingTracker has an action column and its stored value is not matched_action
            # (e.g. was 'report_spam' or NULL for a downvote or upvote job), record task to sync in DB
            if tracker_action_col and task_id and explicit_row_action != matched_action:
                tasks_to_update_action.append((matched_action, task_id))
        else:
            if not record.get("action_type"):
                record["action_type"] = explicit_row_action or ("post_comment" if is_post_comment_row else "report_spam")
            unmatched_records.append(record)

    # Persist updated action types to BackendProcessingTracker if needed
    if tracker_action_col and tasks_to_update_action:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                for m_act, t_id in tasks_to_update_action:
                    cursor.execute(f"""
                        UPDATE dbo.BackendProcessingTracker
                        SET {tracker_action_col} = ?
                        WHERE task_id = ?
                    """, m_act, t_id)
                connection.commit()
        except Exception as sync_err:
            app.logger.warning(f"Could not sync ActionType to BackendProcessingTracker: {sync_err}")

    # 3. Group any unmatched records into standalone fallback batches
    fallback_batches = []
    if unmatched_records:
        curr_fb = None
        for r in unmatched_records:
            r_c_tokens = _extract_id_tokens(r["comment_ids"])
            r_u_tokens = _extract_id_tokens(r["user_ids"])
            r_acc = (r["account_email"] or "").strip().lower()

            is_same = False
            if curr_fb is not None:
                t_diff = abs((curr_fb["_dt"] - r["_dt"]).total_seconds()) if (curr_fb["_dt"] and r["_dt"]) else 999999
                same_action = (curr_fb["action_type"] == r["action_type"])
                token_overlap = bool(
                    (r_c_tokens and curr_fb["_c_tokens"] and r_c_tokens.intersection(curr_fb["_c_tokens"]))
                    or (r_u_tokens and curr_fb["_u_tokens"] and r_u_tokens.intersection(curr_fb["_u_tokens"]))
                )
                if same_action and (token_overlap and t_diff <= 1800 or t_diff <= 120):
                    is_same = True

            if is_same:
                curr_fb["records"].append(r)
                if r_acc and r_acc not in ("—", "-", ""):
                    curr_fb["_accounts_set"].add(r_acc)
                curr_fb["total_success"] += r["success_count"]
                curr_fb["total_failure"] += r["failure_count"]
                if not r["is_completed"]:
                    curr_fb["_any_in_progress"] = True
                curr_fb["_c_tokens"].update(r_c_tokens)
                curr_fb["_u_tokens"].update(r_u_tokens)
                if r["comment_ids"] and r["comment_ids"] not in curr_fb["_raw_comments"]:
                    curr_fb["_raw_comments"].append(r["comment_ids"])
            else:
                acc_set = {r_acc} if (r_acc and r_acc not in ("—", "-", "")) else set()
                curr_fb = {
                    "starting_date": r["starting_date"],
                    "_dt": r["_dt"],
                    "comment_ids": r["comment_ids"],
                    "user_ids": r["user_ids"] or r["account_email"],
                    "action_type": r["action_type"],
                    "total_accounts": 1,
                    "total_success": r["success_count"],
                    "total_failure": r["failure_count"],
                    "is_completed": r["is_completed"],
                    "records": [r],
                    "_accounts_set": acc_set,
                    "_c_tokens": set(r_c_tokens),
                    "_u_tokens": set(r_u_tokens),
                    "_raw_comments": [r["comment_ids"]] if r["comment_ids"] else [],
                    "_any_in_progress": not r["is_completed"],
                }
                fallback_batches.append(curr_fb)

    # 4. Finalize tracker-backed batches and standalone tracker fallbacks.
    # A UI submission by itself is not an execution log: showing it before the
    # worker creates a BackendProcessingTracker row produces misleading empty
    # "In Progress" cards. Keep the dashboard tracker-driven as before.
    batches = []

    for b in ui_batches.values():
        if b["_has_records"]:
            if b["_accounts_set"]:
                b["total_accounts"] = len(b["_accounts_set"])
            elif not b.get("total_accounts"):
                b["total_accounts"] = len(b["records"])

            b["is_completed"] = not b["_any_in_progress"]
            # Tracker activity is the execution log's timestamp and must drive
            # both the displayed time and the latest-first ordering.
            if b["_tracker_latest_dt"]:
                b["_dt"] = b["_tracker_latest_dt"]
                b["starting_date"] = b["_dt"].strftime("%Y-%m-%d %H:%M:%S IST")
            batches.append(b)

    for fb in fallback_batches:
        if fb["_accounts_set"]:
            fb["total_accounts"] = len(fb["_accounts_set"])
        else:
            fb["total_accounts"] = len(fb["records"])
        fb["is_completed"] = not fb["_any_in_progress"]
        if len(fb.get("_raw_comments", [])) > 1:
            fb["comment_ids"] = json.dumps(fb["_raw_comments"])
        batches.append(fb)

    # Sort all batches descending by run date (newest first)
    epoch = datetime(1970, 1, 1, tzinfo=IST_TIMEZONE)
    batches.sort(key=lambda x: (x.get("_dt") or epoch), reverse=True)

    # 5. Apply action_filter if specified
    if action_filter:
        act_filt = str(action_filter).strip().lower()
        if act_filt in ("post_comment", "postcomment", "post-comment", "comment", "comments"):
            batches = [b for b in batches if b.get("action_type") == "post_comment"]
        elif act_filt in ("reports", "report", "dashboard", "report_spam", "spam", "votes"):
            batches = [b for b in batches if b.get("action_type") != "post_comment"]
        elif act_filt in ("upvote", "downvote"):
            batches = [b for b in batches if b.get("action_type") == act_filt]

    total_batches = len(batches)
    for idx, b in enumerate(batches):
        b["batch_number"] = total_batches - idx
        b.pop("_dt", None)
        b.pop("_accounts_set", None)
        b.pop("_c_tokens", None)
        b.pop("_u_tokens", None)
        b.pop("_has_records", None)
        b.pop("_any_in_progress", None)
        b.pop("_tracker_latest_dt", None)
        b.pop("_raw_comments", None)
        b.pop("ui_id", None)

    return batches


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/logs")
@require_auth
def get_logs():
    try:
        days = request.args.get("days", default=3, type=int)
        if not days or days < 1:
            days = 3
        action = request.args.get("action") or request.args.get("action_type") or request.args.get("type") or ""
        batches = _fetch_batches_from_tracker(days=days, action_filter=action)
        return jsonify({
            "success": True,
            "total_batches": len(batches),
            "batches": batches,
            "days": days,
            "action": action,
        })
    except Exception as error:
        app.logger.exception("Could not fetch logs from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.get("/api/post-comment/logs")
@app.get("/api/post-comments/logs")
@require_auth
def get_post_comment_logs():
    try:
        days = request.args.get("days", default=3, type=int)
        if not days or days < 1:
            days = 3
        batches = _fetch_batches_from_tracker(days=days, action_filter="post_comment")
        return jsonify({
            "success": True,
            "total_batches": len(batches),
            "batches": batches,
            "days": days,
            "action": "post_comment",
        })
    except Exception as error:
        app.logger.exception("Could not fetch post comment logs from SQL Server")
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

    with _get_db_connection(timeout=15) as connection:
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
    """Fetch recent comments with optional processing group, user, and text filters."""
    if pyodbc is None:
        raise RuntimeError("pyodbc is not installed")
    if not DB_CONNECTION_STRING:
        raise RuntimeError("DB_CONNECTION_STRING is not configured")

    offset = max(0, (page - 1) * page_size)
    where_clauses = ["fetched_at >= DATEADD(hour, -?, sysdatetime())"]
    params = [hours]

    if status_filter == "processed":
        where_clauses.append("LOWER(COALESCE(NULLIF(LTRIM(RTRIM(status)), ''), 'not processed')) <> 'not processed'")
    elif status_filter == "not processed":
        where_clauses.append("LOWER(COALESCE(NULLIF(LTRIM(RTRIM(status)), ''), 'not processed')) = 'not processed'")
    elif status_filter:
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

    with _get_db_connection(timeout=15) as connection:
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

        if hasattr(fetched_at, "strftime"):
            fetched_at_str = fetched_at.strftime("%Y-%m-%d %H:%M:%S")
        else:
            fetched_at_str = str(fetched_at) if fetched_at else ""
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
    with _get_db_connection(timeout=15) as connection:
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
        hours = max(1, int(request.args.get("hours", 168)))
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
        u_pairs = [(str(c.get("user_id") or "").strip(), str(c.get("user_name") or "").strip()) for c in data.get("comments", [])]
        user_limits_map = _get_user_limits_map(u_pairs)

        return jsonify({"success": True, **data, "user_limits": user_limits_map})
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
        hours = max(1, int(request.args.get("hours", 168)))
        users = _fetch_distinct_comment_users(hours=hours)
        return jsonify({"success": True, "users": users})
    except Exception as error:
        app.logger.exception("Could not fetch comment users from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.get("/api/comments/reported-accounts")
@require_auth
def get_reported_accounts():
    """Fetch email accounts that have already processed one or more comment IDs."""
    try:
        c_id = (request.args.get("comment_id") or request.args.get("cid") or "").strip()
        c_ids_raw = request.args.getlist("comment_ids") or request.args.getlist("cids")
        if not c_ids_raw and request.args.get("comment_ids"):
            c_ids_raw = [x.strip() for x in request.args.get("comment_ids").split(",") if x.strip()]

        target_cids = []
        if c_id and c_id not in target_cids:
            target_cids.append(c_id)
        for x in c_ids_raw:
            cleaned = str(x).strip()
            if cleaned and cleaned not in target_cids:
                target_cids.append(cleaned)

        if not target_cids:
            return jsonify({"success": True, "accounts": []})

        accounts = []
        with _get_db_connection(timeout=10) as conn:
            cursor = conn.cursor()
            clauses = ["comment_ids LIKE ?" for _ in target_cids]
            params = [f"%{cid}%" for cid in target_cids]
            sql = f"""
                SELECT DISTINCT account_email
                FROM dbo.BackendProcessingTracker
                WHERE account_email IS NOT NULL
                  AND LTRIM(RTRIM(account_email)) <> ''
                  AND ({' OR '.join(clauses)})
                ORDER BY account_email ASC
            """
            cursor.execute(sql, *params)
            for row in cursor.fetchall():
                email = str(row[0] or "").strip()
                if email and email not in accounts:
                    accounts.append(email)

        return jsonify({"success": True, "comment_ids": target_cids, "accounts": accounts})
    except Exception as error:
        app.logger.warning(f"Could not fetch reported accounts for comments: {error}")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}",
            "accounts": []
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


# Daily User Comment Report Limits (Super Admin Only)
# ---------------------------------------------------------------------------
_USER_LIMITS_FILE = BASE_DIR / ".user_limits.json"


def _load_cached_user_limits() -> dict[str, dict]:
    """Load cached custom user daily limits from disk."""
    if not _USER_LIMITS_FILE.exists():
        return {}
    try:
        with open(_USER_LIMITS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_cached_user_limits(limits: dict[str, dict]):
    """Persist custom user daily limits to disk."""
    try:
        with open(_USER_LIMITS_FILE, "w", encoding="utf-8") as f:
            json.dump(limits, f, indent=2)
    except Exception:
        pass


def _init_user_limits_table():
    """Ensure dbo.user_report_limits table exists in SQL Server with both daily and hourly limit columns."""
    if pyodbc is None or not DB_CONNECTION_STRING:
        return
    try:
        with _get_db_connection(timeout=10) as connection:
            cursor = connection.cursor()
            cursor.execute("""
                IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_report_limits')
                BEGIN
                    CREATE TABLE dbo.user_report_limits (
                        user_id BIGINT PRIMARY KEY,
                        user_name NVARCHAR(255),
                        max_daily_comments INT NOT NULL DEFAULT 3,
                        max_hourly_comments INT NOT NULL DEFAULT 2,
                        updated_at DATETIME DEFAULT GETDATE(),
                        updated_by NVARCHAR(255)
                    );
                END
                ELSE
                BEGIN
                    IF COL_LENGTH('dbo.user_report_limits', 'max_hourly_comments') IS NULL
                        ALTER TABLE dbo.user_report_limits ADD max_hourly_comments INT NOT NULL DEFAULT 2;
                END

                IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_report_activity')
                BEGIN
                    CREATE TABLE dbo.user_report_activity (
                        id BIGINT IDENTITY(1,1) PRIMARY KEY,
                        user_id NVARCHAR(255) NOT NULL,
                        processing_id BIGINT NULL,
                        reported_at DATETIME NOT NULL DEFAULT GETDATE()
                    );
                    CREATE INDEX IX_user_report_activity_user_time
                        ON dbo.user_report_activity (user_id, reported_at DESC);
                END
            """)
            try:
                # Ensure StartingDate on dbo.InvestingUIProcessing has default and backfill any NULLs
                cursor.execute("""
                    IF COL_LENGTH('dbo.InvestingUIProcessing', 'StartingDate') IS NOT NULL
                    BEGIN
                        UPDATE dbo.InvestingUIProcessing SET StartingDate = GETDATE() WHERE StartingDate IS NULL;
                    END
                """)
            except Exception:
                pass
            connection.commit()
    except Exception as e:
        app.logger.warning(f"Could not initialize dbo.user_report_limits: {e}")


def _get_user_report_activity_stats() -> tuple[dict[str, int], dict[str, dict]]:
    """Calculate daily report counts (last 24h) and hourly report stats (last 60m) per user ID and user name from dbo.InvestingUIProcessing."""
    daily_counts = {}
    hourly_stats = {}  # key -> {"count": int, "elapsed": list[int]}
    if pyodbc is None or not DB_CONNECTION_STRING:
        return daily_counts, hourly_stats
    try:
        # Pre-build lookup map between user_id and user_name across users, comment_urls, and user_report_limits
        id_to_name = {}
        name_to_id = {}
        with _get_db_connection(timeout=10) as connection:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT id, user_name FROM dbo.users WHERE user_name IS NOT NULL")
                for ur in cursor.fetchall():
                    if ur[0] and ur[1]:
                        s_id = str(ur[0]).strip()
                        s_nm = str(ur[1]).strip().lower()
                        id_to_name[s_id] = s_nm
                        name_to_id[s_nm] = s_id
            except Exception:
                pass

            try:
                cursor.execute("SELECT DISTINCT user_id, user_name FROM dbo.comment_urls WHERE user_id IS NOT NULL AND user_name IS NOT NULL AND user_id != ''")
                for ur in cursor.fetchall():
                    if ur[0] and ur[1]:
                        s_id = str(ur[0]).strip()
                        s_nm = str(ur[1]).strip().lower()
                        if s_id not in id_to_name:
                            id_to_name[s_id] = s_nm
                        if s_nm not in name_to_id:
                            name_to_id[s_nm] = s_id
            except Exception:
                pass

            try:
                cursor.execute("SELECT user_id, user_name FROM dbo.user_report_limits WHERE user_name IS NOT NULL AND user_name != ''")
                for ur in cursor.fetchall():
                    if ur[0] and ur[1]:
                        s_id = str(ur[0]).strip()
                        s_nm = str(ur[1]).strip().lower()
                        if s_id not in id_to_name:
                            id_to_name[s_id] = s_nm
                        if s_nm not in name_to_id:
                            name_to_id[s_nm] = s_id
            except Exception:
                pass

            def _add_hourly_activity(user_id: str, elapsed_seconds: int) -> None:
                """Add one hourly activity under its ID and any known user-name alias."""
                uid_clean = str(user_id).strip()
                if not uid_clean:
                    return
                keys_to_increment = {uid_clean, uid_clean.lower()}
                if uid_clean in id_to_name:
                    keys_to_increment.add(id_to_name[uid_clean])
                if uid_clean.lower() in name_to_id:
                    keys_to_increment.add(name_to_id[uid_clean.lower()])
                for key in keys_to_increment:
                    if key not in hourly_stats:
                        hourly_stats[key] = {"count": 0, "elapsed": []}
                    hourly_stats[key]["count"] += 1
                    hourly_stats[key]["elapsed"].append(max(0, int(elapsed_seconds)))

            # New report submissions are recorded explicitly for the hourly
            # window. Their matching processing rows are skipped below, while
            # legacy rows remain a fallback; daily counts retain their existing
            # processing-table behavior.
            hourly_activity_available = False
            recorded_processing_ids = set()
            try:
                cursor.execute("""
                    SELECT user_id, processing_id,
                           DATEDIFF(second, reported_at, GETDATE()) AS elapsed_seconds
                    FROM dbo.user_report_activity
                    WHERE reported_at >= DATEADD(hour, -1, GETDATE())
                    ORDER BY reported_at ASC
                """)
                hourly_activity_available = True
                for activity_row in cursor.fetchall():
                    if activity_row[1] is not None:
                        recorded_processing_ids.add(int(activity_row[1]))
                    _add_hourly_activity(activity_row[0], activity_row[2] or 0)
            except Exception:
                # Older deployments use the processing-table fallback below.
                hourly_activity_available = False

            # Query UI processing requests for reporting actions across last 24h
            # Accept ActionType NULL, empty, or variations of report/spam
            # Treat NULL StartingDate as current date so newly submitted records are never dropped
            cursor.execute("""
                SELECT Id, UserIds,
                       ISNULL(StartingDate, GETDATE()) AS StartingDate,
                       DATEDIFF(second, ISNULL(StartingDate, GETDATE()), GETDATE()) AS diff_getdate,
                       DATEDIFF(second, ISNULL(StartingDate, GETDATE()), SYSDATETIME()) AS diff_sysdatetime,
                       DATEDIFF(second, ISNULL(StartingDate, GETDATE()), GETUTCDATE()) AS diff_utc
                FROM dbo.InvestingUIProcessing
                WHERE (ActionType IS NULL OR ActionType = '' OR LOWER(ActionType) IN ('report_spam', 'report', 'spam', 'reported'))
                  AND (
                    StartingDate IS NULL
                    OR StartingDate >= DATEADD(hour, -24, GETDATE())
                    OR StartingDate >= DATEADD(hour, -24, SYSDATETIME())
                    OR StartingDate >= DATEADD(hour, -24, GETUTCDATE())
                    OR CAST(StartingDate AS DATE) = CAST(GETDATE() AS DATE)
                    OR CAST(StartingDate AS DATE) = CAST(SYSDATETIME() AS DATE)
                  )
                ORDER BY Id ASC
            """)
            rows = cursor.fetchall()
            for r in rows:
                processing_id = r[0]
                raw = r[1]
                diff_gd = r[3]
                diff_sys = r[4]
                diff_utc = r[5]
                if not raw:
                    continue

                # Determine if this row was within the last 60 minutes (3600 seconds)
                # Check all diff calculations in range [-300, 3660] seconds to neutralize any clock/timezone differences
                valid_diffs = [d for d in (diff_gd, diff_sys, diff_utc) if d is not None and -300 <= d <= 3660]
                is_within_hour = len(valid_diffs) > 0 or diff_gd is None
                elapsed_sec = max(0, min(valid_diffs)) if valid_diffs else (max(0, diff_gd) if diff_gd is not None else 0)

                try:
                    raw_str = str(raw or "").strip()
                    uids = []
                    if raw_str.startswith("[") or raw_str.startswith("{"):
                        try:
                            parsed_json = json.loads(raw_str)
                            if isinstance(parsed_json, list):
                                uids = [str(x).strip() for x in parsed_json if str(x).strip()]
                            elif isinstance(parsed_json, dict):
                                uids = [str(x).strip() for x in parsed_json.values() if str(x).strip()]
                        except Exception:
                            pass
                    if not uids:
                        import re
                        uids = [x.strip().strip('"\'') for x in re.split(r'[\r\n,;]+', raw_str) if x.strip().strip('"\'')]

                    for u in uids:
                        uid_clean = str(u).strip()
                        if not uid_clean:
                            continue

                        # Register both the raw token (whether numeric ID or name) and its resolved counterpart
                        keys_to_increment = {uid_clean, uid_clean.lower()}
                        if uid_clean in id_to_name:
                            keys_to_increment.add(id_to_name[uid_clean])
                        if uid_clean.lower() in name_to_id:
                            keys_to_increment.add(name_to_id[uid_clean.lower()])

                        for k in keys_to_increment:
                            daily_counts[k] = daily_counts.get(k, 0) + 1
                            if is_within_hour and (
                                not hourly_activity_available or processing_id not in recorded_processing_ids
                            ):
                                if k not in hourly_stats:
                                    hourly_stats[k] = {"count": 0, "elapsed": []}
                                hourly_stats[k]["count"] += 1
                                hourly_stats[k]["elapsed"].append(int(elapsed_sec))
                except Exception:
                    pass
    except Exception as e:
        app.logger.warning(f"Could not query reported activity stats: {e}")
    return daily_counts, hourly_stats


def _get_today_reported_counts_by_user() -> dict[str, int]:
    """Calculate the number of comments reported in the last 24 hours / today per user ID from dbo.InvestingUIProcessing."""
    daily_counts, _ = _get_user_report_activity_stats()
    return daily_counts


def _format_remaining_time(remaining_seconds: int) -> str:
    """Format remaining seconds into friendly human-readable time string (e.g. '28 minutes', '45 seconds')."""
    if remaining_seconds <= 0:
        return ""
    mins = (remaining_seconds + 59) // 60
    if mins > 1:
        return f"{mins} minutes"
    if mins == 1 and remaining_seconds > 60:
        return "1 minute"
    return f"{remaining_seconds} seconds"


def _get_user_limits_map(user_ids: list = None) -> dict[str, dict]:
    """Return a fast lookup dictionary of daily limits, hourly limits, reported counts, and remaining time for users."""
    _init_user_limits_table()
    custom_limits = _load_cached_user_limits()
    if pyodbc and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                cursor.execute("""
                    SELECT user_id, user_name, max_daily_comments,
                           ISNULL(max_hourly_comments, 2) AS max_hourly_comments,
                           updated_at, updated_by
                    FROM dbo.user_report_limits
                """)
                for r in cursor.fetchall():
                    uid = str(r[0]).strip()
                    uname = r[1] or ""
                    daily_val = int(r[2]) if r[2] is not None else 3
                    hourly_val = int(r[3]) if r[3] is not None else 2
                    dt_str = r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else ""
                    up_by = r[5] or "superadmin"
                    custom_limits[uid] = {
                        "user_id": uid,
                        "user_name": uname,
                        "max_daily_comments": max(3, daily_val),
                        "max_hourly_comments": max(1, hourly_val),
                        "updated_at": dt_str,
                        "updated_by": up_by,
                        "is_custom": True,
                    }
        except Exception as e:
            app.logger.warning(f"Could not read dbo.user_report_limits in _get_user_limits_map: {e}")

    today_counts, hourly_stats = _get_user_report_activity_stats()
    result = {}

    def _add_user_record(uid: str = "", uname: str = ""):
        uid_clean = str(uid).strip() if uid else ""
        uname_clean = str(uname).strip() if uname else ""
        if not uid_clean and not uname_clean:
            return

        # Attempt to resolve missing user_id or user_name
        limit_data = custom_limits.get(uid_clean) if uid_clean else None
        if not limit_data and uname_clean:
            for cl in custom_limits.values():
                if cl.get("user_name", "").lower() == uname_clean.lower():
                    limit_data = cl
                    break

        if limit_data:
            max_daily = max(3, int(limit_data.get("max_daily_comments", 3)))
            max_hourly = max(1, int(limit_data.get("max_hourly_comments", 2)))
            is_custom = True
            resolved_name = limit_data.get("user_name") or uname_clean
            if not uid_clean and limit_data.get("user_id"):
                uid_clean = str(limit_data.get("user_id")).strip()
        else:
            max_daily = 3
            max_hourly = 2
            is_custom = False
            resolved_name = uname_clean

        reported_daily = (today_counts.get(uid_clean) if uid_clean else None) or (today_counts.get(resolved_name.lower()) if resolved_name else None) or 0
        remaining_daily = max(0, max_daily - reported_daily)

        h_info = (hourly_stats.get(uid_clean) if uid_clean else None) or (hourly_stats.get(resolved_name.lower()) if resolved_name else None) or {"count": 0, "elapsed": []}
        reported_hourly = h_info["count"]
        remaining_hourly = max(0, max_hourly - reported_hourly)

        # Calculate remaining time if hourly limit reached
        hourly_reset_seconds = 0
        hourly_reset_text = ""
        if reported_hourly >= max_hourly:
            if h_info.get("elapsed"):
                elapsed_sorted = sorted(h_info["elapsed"], reverse=True)
                idx = max(0, len(elapsed_sorted) - max_hourly)
                oldest_blocking_elapsed = elapsed_sorted[idx]
                hourly_reset_seconds = max(1, 3600 - oldest_blocking_elapsed)
                hourly_reset_text = _format_remaining_time(hourly_reset_seconds)
            if not hourly_reset_text or hourly_reset_seconds <= 0:
                hourly_reset_seconds = 3600
                hourly_reset_text = "59 minutes"

        rec = {
            "user_id": uid_clean,
            "user_name": resolved_name,
            "max_daily_comments": max_daily,
            "max_hourly_comments": max_hourly,
            "reported_today": reported_daily,
            "remaining_today": remaining_daily,
            "reported_hourly": reported_hourly,
            "remaining_hourly": remaining_hourly,
            "hourly_reset_seconds": hourly_reset_seconds,
            "hourly_reset_text": hourly_reset_text,
            "is_custom": is_custom,
            "reset_hours": 24,
        }
        if uid_clean:
            result[uid_clean] = rec
        if resolved_name:
            result[resolved_name.lower()] = rec

    if user_ids:
        for u in user_ids:
            if isinstance(u, (tuple, list)) and len(u) >= 2:
                _add_user_record(str(u[0]), str(u[1]))
            elif isinstance(u, (tuple, list)) and len(u) == 1:
                _add_user_record(str(u[0]), "")
            else:
                _add_user_record(str(u), "")

    for uid, cl in custom_limits.items():
        _add_user_record(uid, cl.get("user_name") or "")

    for uid in today_counts.keys():
        if uid not in result:
            _add_user_record(uid, "")

    for uid in hourly_stats.keys():
        if uid not in result:
            _add_user_record(uid, "")

    return result


def _fetch_user_limits(search: str = "") -> dict:
    """Fetch all users along with their configured daily and hourly reporting limits and activity counts."""
    _init_user_limits_table()

    # 1. Fetch base users (from dbo.users merged with distinct users from dbo.comment_urls)
    try:
        all_users = _fetch_distinct_comment_users(hours=168)
    except Exception:
        all_users = []

    # Fallback to dbo.users direct fetch if distinct comment users failed or returned empty
    if not all_users and pyodbc and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                cursor.execute("SELECT id, user_name FROM dbo.users ORDER BY user_name ASC")
                all_users = [{"user_id": str(r[0]), "user_name": r[1] or ""} for r in cursor.fetchall()]
        except Exception:
            all_users = []

    # 2. Fetch custom limits from dbo.user_report_limits
    custom_limits = _load_cached_user_limits()
    if pyodbc and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                cursor.execute("""
                    SELECT user_id, user_name, max_daily_comments,
                           ISNULL(max_hourly_comments, 2) AS max_hourly_comments,
                           updated_at, updated_by
                    FROM dbo.user_report_limits
                """)
                for r in cursor.fetchall():
                    uid = str(r[0]).strip()
                    uname = r[1] or ""
                    daily_val = int(r[2]) if r[2] is not None else 3
                    hourly_val = int(r[3]) if r[3] is not None else 2
                    dt_str = r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else ""
                    up_by = r[5] or "superadmin"
                    custom_limits[uid] = {
                        "user_id": uid,
                        "user_name": uname,
                        "max_daily_comments": max(3, daily_val),
                        "max_hourly_comments": max(1, hourly_val),
                        "updated_at": dt_str,
                        "updated_by": up_by,
                        "is_custom": True,
                    }
            _save_cached_user_limits(custom_limits)
        except Exception as e:
            app.logger.warning(f"Could not read dbo.user_report_limits: {e}")

    # 3. Fetch today's reported counts and hourly stats
    today_counts, hourly_stats = _get_user_report_activity_stats()

    # 4. Merge and build user entries
    user_map = {}
    for u in all_users:
        uid = str(u.get("user_id") or u.get("id") or "").strip()
        uname = (u.get("user_name") or "").strip()
        if not uid and not uname:
            continue
        key = uid if uid else uname.lower()
        if key not in user_map:
            user_map[key] = {
                "id": uid,
                "user_id": uid,
                "user_name": uname,
            }
        else:
            if not user_map[key].get("user_name") and uname:
                user_map[key]["user_name"] = uname
            if not user_map[key].get("user_id") and uid:
                user_map[key]["user_id"] = uid
                user_map[key]["id"] = uid

    # Include any custom limit entries that might not be in the users table yet
    for uid, cl in custom_limits.items():
        if uid not in user_map:
            user_map[uid] = {
                "id": uid,
                "user_id": uid,
                "user_name": cl.get("user_name") or "",
            }

    results = []
    custom_count = 0
    for key, u in user_map.items():
        uid = u.get("user_id", "").strip()
        uname = u.get("user_name", "").strip()

        # Check custom limit by user_id first, then case-insensitive user_name
        limit_data = custom_limits.get(uid)
        if not limit_data and uname:
            for cl in custom_limits.values():
                if cl.get("user_name", "").lower() == uname.lower():
                    limit_data = cl
                    break

        if limit_data:
            max_daily = max(3, int(limit_data.get("max_daily_comments", 3)))
            max_hourly = max(1, int(limit_data.get("max_hourly_comments", 2)))
            is_custom = True
            updated_at = limit_data.get("updated_at") or ""
            updated_by = limit_data.get("updated_by") or ""
            custom_count += 1
        else:
            max_daily = 3
            max_hourly = 2
            is_custom = False
            updated_at = ""
            updated_by = ""

        reported_today = today_counts.get(uid) or (today_counts.get(uname.lower()) if uname else None) or 0
        remaining_today = max(0, max_daily - reported_today)

        h_info = hourly_stats.get(uid) or (hourly_stats.get(uname.lower()) if uname else None) or {"count": 0, "elapsed": []}
        reported_hourly = h_info["count"]
        remaining_hourly = max(0, max_hourly - reported_hourly)

        hourly_reset_seconds = 0
        hourly_reset_text = ""
        if reported_hourly >= max_hourly:
            if h_info.get("elapsed"):
                elapsed_sorted = sorted(h_info["elapsed"], reverse=True)
                idx = max(0, len(elapsed_sorted) - max_hourly)
                oldest_blocking_elapsed = elapsed_sorted[idx]
                hourly_reset_seconds = max(1, 3600 - oldest_blocking_elapsed)
                hourly_reset_text = _format_remaining_time(hourly_reset_seconds)
            if not hourly_reset_text or hourly_reset_seconds <= 0:
                hourly_reset_seconds = 3600
                hourly_reset_text = "59 minutes"

        results.append({
            "id": uid,
            "user_id": uid,
            "user_name": uname,
            "max_daily_comments": max_daily,
            "max_hourly_comments": max_hourly,
            "default_limit": 3,
            "default_hourly_limit": 2,
            "is_custom": is_custom,
            "reported_today": reported_today,
            "remaining_today": remaining_today,
            "reported_hourly": reported_hourly,
            "remaining_hourly": remaining_hourly,
            "hourly_reset_seconds": hourly_reset_seconds,
            "hourly_reset_text": hourly_reset_text,
            "updated_at": updated_at,
            "updated_by": updated_by,
        })

    # Sort: custom limits first, then alphabetical by user_name
    results.sort(key=lambda x: (not x["is_custom"], (x["user_name"].lower() if x["user_name"] else x["user_id"])))

    # Apply search filter
    if search:
        s_lower = search.strip().lower()
        results = [
            x for x in results
            if s_lower in x["user_name"].lower() or s_lower in x["user_id"].lower()
        ]

    return {
        "users": results,
        "total": len(results),
        "custom_count": custom_count,
        "default_min": 3,
        "default_hourly": 2,
        "default_number_of_accounts": _get_default_accounts_count(),
    }


def _save_user_limit(
    user_id: int,
    user_name: str,
    max_comments: int = 3,
    max_hourly_comments: int = 2,
    updated_by: str = "superadmin"
) -> tuple[bool, str, dict]:
    """Save or update the maximum daily and hourly comments allowed for a user."""
    if max_comments < 3:
        return False, "Minimum allowed daily limit is 3 comments per user.", {}
    if max_hourly_comments < 1:
        return False, "Minimum allowed hourly limit is 1 comment per user.", {}

    _init_user_limits_table()

    saved_user = {
        "user_id": str(user_id),
        "user_name": user_name,
        "max_daily_comments": max_comments,
        "max_hourly_comments": max_hourly_comments,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "updated_by": updated_by,
        "is_custom": True,
    }

    # 1. Update local cache
    cached = _load_cached_user_limits()
    cached[str(user_id)] = saved_user
    _save_cached_user_limits(cached)

    # 2. Update SQL Server dbo.user_report_limits
    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=15) as connection:
                cursor = connection.cursor()
                cursor.execute("""
                    MERGE dbo.user_report_limits AS target
                    USING (SELECT ? AS user_id, ? AS user_name, ? AS max_daily_comments, ? AS max_hourly_comments, ? AS updated_by) AS source
                    ON (target.user_id = source.user_id)
                    WHEN MATCHED THEN
                        UPDATE SET target.max_daily_comments = source.max_daily_comments,
                                   target.max_hourly_comments = source.max_hourly_comments,
                                   target.user_name = source.user_name,
                                   target.updated_at = GETDATE(),
                                   target.updated_by = source.updated_by
                    WHEN NOT MATCHED THEN
                        INSERT (user_id, user_name, max_daily_comments, max_hourly_comments, updated_at, updated_by)
                        VALUES (source.user_id, source.user_name, source.max_daily_comments, source.max_hourly_comments, GETDATE(), source.updated_by);
                """, user_id, user_name, max_comments, max_hourly_comments, updated_by)
                connection.commit()
        except Exception as e:
            app.logger.warning(f"Could not persist limit in dbo.user_report_limits (cached locally): {e}")

    return True, f"Limits for {user_name or f'ID {user_id}'} set to {max_comments} comments/day and {max_hourly_comments} comments/hour.", saved_user


def _reset_user_limit(user_id: int) -> tuple[bool, str]:
    """Reset a user's daily and hourly limits back to defaults (3 daily, 2 hourly)."""
    cached = _load_cached_user_limits()
    cached.pop(str(user_id), None)
    _save_cached_user_limits(cached)

    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                cursor.execute("DELETE FROM dbo.user_report_limits WHERE user_id = ?", user_id)
                connection.commit()
        except Exception as e:
            app.logger.warning(f"Could not delete from dbo.user_report_limits: {e}")

    return True, "Limits reset to default (3 comments/day, 2 comments/hour)."


def _check_daily_report_limits(user_ids: list[str]) -> tuple[bool, str]:
    """Verify that reporting these user_ids does not exceed each user's max daily limit or hourly limit."""
    if not user_ids:
        return True, ""
    try:
        # Count requested per user_id in this payload
        requested_counts = {}
        for uid in user_ids:
            uid_str = str(uid).strip()
            if uid_str:
                requested_counts[uid_str] = requested_counts.get(uid_str, 0) + 1

        limits_map = _get_user_limits_map(list(requested_counts.keys()))

        for uid, req_cnt in requested_counts.items():
            info = limits_map.get(uid) or {}
            max_daily = info.get("max_daily_comments", 3)
            max_hourly = info.get("max_hourly_comments", 2)
            user_name = info.get("user_name", "")
            name_disp = f"'{user_name}' " if user_name else ""

            # 1. Hourly Limit Check
            already_hourly = info.get("reported_hourly", 0)
            if already_hourly + req_cnt > max_hourly:
                remaining_time_str = info.get("hourly_reset_text") or "a few minutes"
                return False, (
                    f"Please wait, hourly limit reached for user {name_disp}(ID: {uid}). "
                    f"Hourly limit of {max_hourly} comment{'s' if max_hourly != 1 else ''} per hour reached. "
                    f"Already reported this hour: {already_hourly}, requested: {req_cnt}. "
                    f"Try again after {remaining_time_str}."
                )

            # 2. Daily Limit Check
            already_daily = info.get("reported_today", 0)
            if already_daily + req_cnt > max_daily:
                return False, (
                    f"Daily reporting limit reached for user {name_disp}(ID: {uid}). "
                    f"Daily limit of {max_daily} is completed. All of its limit is reached. "
                    f"Already reported today: {already_daily}, requested: {req_cnt}. "
                    f"Limit will be reset after 24 hours."
                )
    except Exception as e:
        app.logger.warning(f"Error checking report limits: {e}")
    return True, ""


@app.get("/api/user-limits/status")
@require_auth
def get_user_limits_status():
    """Fetch user daily reporting limits and today's reported counts (accessible to any authenticated user)."""
    try:
        user_ids = request.args.getlist("user_id") or request.args.getlist("user_ids")
        if not user_ids:
            single = (request.args.get("user_id") or request.args.get("user_ids") or "").strip()
            if single:
                user_ids = [u.strip() for u in single.split(",") if u.strip()]
        data = _get_user_limits_map(user_ids if user_ids else None)
        return jsonify({"success": True, "limits": data})
    except Exception as error:
        app.logger.exception("Could not fetch user limits status")
        return jsonify({"success": False, "error": str(error)}), 500


@app.get("/api/user-limits")
@require_super_admin
def get_user_limits():
    """Fetch all users and their daily reporting limits (Super Admin only)."""
    try:
        search = request.args.get("search", "").strip()
        data = _fetch_user_limits(search=search)
        return jsonify({"success": True, **data})
    except Exception as error:
        app.logger.exception("Could not fetch user limits")
        return jsonify({
            "success": False,
            "error": f"Error loading user limits: {str(error)}"
        }), 500


@app.post("/api/user-limits")
@require_super_admin
def update_user_limit():
    """Update the maximum comments per day and per hour for a user (Super Admin only)."""
    try:
        data = request.get_json(silent=True) or {}
        raw_user_id = str(data.get("user_id") or data.get("id") or "").strip()
        user_name = str(data.get("user_name") or data.get("name") or "").strip()
        raw_max_daily = data.get("max_comments") if data.get("max_comments") is not None else data.get("max_daily_comments", data.get("limit"))
        raw_max_hourly = data.get("max_hourly_comments") if data.get("max_hourly_comments") is not None else data.get("hourly_limit")

        if not raw_user_id or not raw_user_id.isdigit():
            return jsonify({
                "success": False,
                "error": "Valid positive numeric user ID is required."
            }), 400

        user_id = int(raw_user_id)

        # Retrieve existing limits if partially updating
        custom_limits = _load_cached_user_limits()
        existing = custom_limits.get(str(user_id), {})

        # Parse daily limit (default 3, min 3)
        if raw_max_daily is not None:
            try:
                max_daily = int(raw_max_daily)
            except (TypeError, ValueError):
                return jsonify({
                    "success": False,
                    "error": "Daily comments count must be a valid integer."
                }), 400
            if max_daily < 3:
                return jsonify({
                    "success": False,
                    "error": "Minimum allowed daily comments count is 3 per day."
                }), 400
        else:
            max_daily = int(existing.get("max_daily_comments", 3))

        # Parse hourly limit (default 2, min 1)
        if raw_max_hourly is not None:
            try:
                max_hourly = int(raw_max_hourly)
            except (TypeError, ValueError):
                return jsonify({
                    "success": False,
                    "error": "Hourly comments count must be a valid integer."
                }), 400
            if max_hourly < 1:
                return jsonify({
                    "success": False,
                    "error": "Minimum allowed hourly comments count is 1 per hour."
                }), 400
        else:
            max_hourly = int(existing.get("max_hourly_comments", 2))

        token = _get_bearer_token()
        _, session = _is_valid_token(token)
        updated_by = (session or {}).get("email", "superadmin")

        success, message, saved_user = _save_user_limit(
            user_id,
            user_name,
            max_comments=max_daily,
            max_hourly_comments=max_hourly,
            updated_by=updated_by
        )
        if not success:
            return jsonify({"success": False, "error": message}), 400

        return jsonify({
            "success": True,
            "message": message,
            "user": saved_user,
        }), 200
    except Exception as error:
        app.logger.exception("Could not update user limit")
        return jsonify({
            "success": False,
            "error": f"Error updating user limit: {str(error)}"
        }), 500


@app.post("/api/user-limits/reset")
@require_super_admin
def reset_user_limit_endpoint():
    """Reset a user limit back to default 3 (Super Admin only)."""
    try:
        data = request.get_json(silent=True) or {}
        raw_user_id = str(data.get("user_id") or data.get("id") or "").strip()
        if not raw_user_id or not raw_user_id.isdigit():
            return jsonify({
                "success": False,
                "error": "Valid numeric user ID is required."
            }), 400
        user_id = int(raw_user_id)
        success, message = _reset_user_limit(user_id)
        return jsonify({"success": True, "message": message}), 200
    except Exception as error:
        app.logger.exception("Could not reset user limit")
        return jsonify({
            "success": False,
            "error": f"Error resetting limit: {str(error)}"
        }), 500


@app.get("/api/user-limits/default-accounts")
@app.get("/api/system-limits/default-accounts")
@require_auth
def get_default_accounts_endpoint():
    """Fetch the configured default number of accounts."""
    try:
        val = _get_default_accounts_count()
        return jsonify({"success": True, "default_number_of_accounts": val})
    except Exception as error:
        app.logger.exception("Could not fetch default accounts")
        return jsonify({"success": False, "error": str(error)}), 500


@app.post("/api/user-limits/default-accounts")
@app.post("/api/system-limits/default-accounts")
@require_super_admin
def set_default_accounts_endpoint():
    """Update the default number of accounts (Super Admin only)."""
    try:
        data = request.get_json(silent=True) or {}
        raw_val = data.get("default_number_of_accounts") if data.get("default_number_of_accounts") is not None else (data.get("count") if data.get("count") is not None else data.get("accounts"))
        if raw_val is None:
            return jsonify({"success": False, "error": "default_number_of_accounts is required."}), 400
        try:
            val = int(raw_val)
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Default number of accounts must be a valid integer."}), 400

        if val < 1:
            return jsonify({"success": False, "error": "Default number of accounts must be at least 1."}), 400

        token = _get_bearer_token()
        _, session = _is_valid_token(token)
        updated_by = (session or {}).get("email", "superadmin")

        success, msg, new_count = _set_default_accounts_count(val, updated_by=updated_by)
        if not success:
            return jsonify({"success": False, "error": msg}), 400
        return jsonify({"success": True, "message": msg, "default_number_of_accounts": new_count})
    except Exception as error:
        app.logger.exception("Could not update default accounts")
        return jsonify({"success": False, "error": str(error)}), 500


# ---------------------------------------------------------------------------
# Email Accounts & Credentials Storage (dbo.investing_accounts)
# ---------------------------------------------------------------------------
DEFAULT_COMMENT_URL = "https://www.investing.com/commodities/silver-commentary"
_ACCOUNTS_FILE = BASE_DIR / ".investing_accounts.json"


def _load_cached_investing_accounts() -> list[dict]:
    """Load cached investing email accounts from disk."""
    if not _ACCOUNTS_FILE.exists():
        return []
    try:
        with open(_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def _save_cached_investing_accounts(accounts: list[dict]):
    """Persist investing email accounts to disk cache."""
    try:
        with open(_ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(accounts, f, indent=2)
    except Exception:
        pass


def _init_investing_accounts_table():
    """Ensure dbo.investing_accounts table exists in SQL Server and has is_enabled column."""
    if pyodbc is None or not DB_CONNECTION_STRING:
        return
    try:
        with _get_db_connection(timeout=10) as connection:
            cursor = connection.cursor()
            cursor.execute("""
                IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'investing_accounts')
                BEGIN
                    CREATE TABLE dbo.investing_accounts (
                        id INT IDENTITY(1,1) PRIMARY KEY,
                        username NVARCHAR(255) NOT NULL,
                        email NVARCHAR(255) NOT NULL,
                        password NVARCHAR(255) NOT NULL,
                        created_at DATETIME DEFAULT GETDATE(),
                        is_enabled BIT NOT NULL DEFAULT 1
                    );
                END
                ELSE
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM sys.columns 
                        WHERE object_id = OBJECT_ID('dbo.investing_accounts') 
                        AND name = 'is_enabled'
                    )
                    BEGIN
                        ALTER TABLE dbo.investing_accounts ADD is_enabled BIT DEFAULT 1;
                        EXEC('UPDATE dbo.investing_accounts SET is_enabled = 1 WHERE is_enabled IS NULL');
                    END
                END
            """)
            connection.commit()
    except Exception as e:
        app.logger.warning(f"Could not initialize dbo.investing_accounts: {e}")


def _fetch_investing_accounts(include_passwords: bool = False, search: str = "", status_filter: str = "") -> list[dict]:
    """Fetch accounts from dbo.investing_accounts table, falling back to local cache."""
    _init_investing_accounts_table()
    accounts = []
    db_success = False

    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                try:
                    cursor.execute("""
                        SELECT id, username, email, password, created_at, is_enabled
                        FROM dbo.investing_accounts
                        ORDER BY id ASC
                    """)
                    for r in cursor.fetchall():
                        acc_id = int(r[0])
                        uname = str(r[1] or "").strip()
                        email = str(r[2] or "").strip()
                        pwd = str(r[3] or "")
                        dt = r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else ""
                        is_en = bool(r[5]) if len(r) > 5 and r[5] is not None else True
                        accounts.append({
                            "id": acc_id,
                            "username": uname,
                            "email": email,
                            "password": pwd,
                            "created_at": dt,
                            "is_enabled": is_en,
                        })
                    db_success = True
                except Exception:
                    # Fallback if column selection fails
                    cursor.execute("""
                        SELECT id, username, email, password, created_at
                        FROM dbo.investing_accounts
                        ORDER BY id ASC
                    """)
                    for r in cursor.fetchall():
                        acc_id = int(r[0])
                        uname = str(r[1] or "").strip()
                        email = str(r[2] or "").strip()
                        pwd = str(r[3] or "")
                        dt = r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else ""
                        accounts.append({
                            "id": acc_id,
                            "username": uname,
                            "email": email,
                            "password": pwd,
                            "created_at": dt,
                            "is_enabled": True,
                        })
                    db_success = True

                if db_success:
                    _save_cached_investing_accounts(accounts)
        except Exception as e:
            app.logger.warning(f"Could not query dbo.investing_accounts from DB: {e}")

    if not db_success:
        accounts = _load_cached_investing_accounts()

    # Normalize is_enabled
    for a in accounts:
        if "is_enabled" not in a:
            a["is_enabled"] = True
        else:
            a["is_enabled"] = bool(a["is_enabled"])

    if search:
        s_lower = search.strip().lower()
        accounts = [
            a for a in accounts
            if s_lower in str(a.get("username", "")).lower() or s_lower in str(a.get("email", "")).lower()
        ]

    if status_filter:
        s_filt = status_filter.strip().lower()
        if s_filt in ("enable", "enabled", "1", "true", "active"):
            accounts = [a for a in accounts if a.get("is_enabled", True)]
        elif s_filt in ("disable", "disabled", "0", "false", "inactive"):
            accounts = [a for a in accounts if not a.get("is_enabled", True)]

    if not include_passwords:
        sanitized = []
        for a in accounts:
            is_en = bool(a.get("is_enabled", True))
            sanitized.append({
                "id": a.get("id"),
                "username": a.get("username", ""),
                "email": a.get("email", ""),
                "has_password": bool(a.get("password")),
                "created_at": a.get("created_at", ""),
                "is_enabled": is_en,
                "status": "enabled" if is_en else "disabled",
            })
        return sanitized

    return accounts


def _add_investing_account(username: str, email: str, password: str, is_enabled: bool = True) -> tuple[bool, str, dict]:
    """Add a new investing account into SQL Server (and cache)."""
    email_clean = str(email or "").strip()
    pwd_clean = str(password or "").strip()
    uname_clean = str(username or "").strip()

    if not uname_clean and email_clean and "@" in email_clean:
        uname_clean = email_clean.split("@")[0]

    if not email_clean or not pwd_clean:
        return False, "Email and password are both required.", {}

    _init_investing_accounts_table()
    cached = _load_cached_investing_accounts()

    # Check for duplicate email
    for a in cached:
        if str(a.get("email", "")).strip().lower() == email_clean.lower():
            return False, f"An account with email '{email_clean}' already exists.", {}

    new_id = (max([a.get("id", 0) for a in cached], default=0) + 1)
    dt_str = time.strftime("%Y-%m-%d %H:%M:%S")

    account_data = {
        "id": new_id,
        "username": uname_clean,
        "email": email_clean,
        "password": pwd_clean,
        "created_at": dt_str,
        "is_enabled": bool(is_enabled),
    }

    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                cursor.execute("SELECT COUNT(*) FROM dbo.investing_accounts WHERE LOWER(email) = LOWER(?)", email_clean)
                if cursor.fetchone()[0] > 0:
                    return False, f"An account with email '{email_clean}' already exists in database.", {}

                try:
                    cursor.execute("""
                        INSERT INTO dbo.investing_accounts (username, email, password, is_enabled)
                        OUTPUT INSERTED.Id
                        VALUES (?, ?, ?, ?)
                    """, uname_clean, email_clean, pwd_clean, 1 if is_enabled else 0)
                    row = cursor.fetchone()
                    if row and row[0]:
                        account_data["id"] = int(row[0])
                    connection.commit()
                except Exception:
                    cursor.execute("""
                        INSERT INTO dbo.investing_accounts (username, email, password)
                        OUTPUT INSERTED.Id
                        VALUES (?, ?, ?)
                    """, uname_clean, email_clean, pwd_clean)
                    row = cursor.fetchone()
                    if row and row[0]:
                        account_data["id"] = int(row[0])
                    connection.commit()
        except Exception as e:
            app.logger.warning(f"Could not insert into dbo.investing_accounts (using local cache): {e}")

    # Re-fetch or update cache
    cached = [a for a in cached if a.get("id") != account_data["id"] and a.get("email", "").lower() != email_clean.lower()]
    cached.append(account_data)
    _save_cached_investing_accounts(cached)

    sanitized = {
        "id": account_data["id"],
        "username": account_data["username"],
        "email": account_data["email"],
        "has_password": True,
        "created_at": account_data["created_at"],
        "is_enabled": account_data["is_enabled"],
        "status": "enabled" if account_data["is_enabled"] else "disabled",
    }
    return True, f"Email '{email_clean}' added successfully.", sanitized


def _delete_investing_account(account_id: int) -> tuple[bool, str]:
    """Delete an investing account by ID from SQL Server and cache."""
    _init_investing_accounts_table()
    cached = _load_cached_investing_accounts()
    found = any(a.get("id") == account_id for a in cached)

    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=10) as connection:
                cursor = connection.cursor()
                cursor.execute("DELETE FROM dbo.investing_accounts WHERE id = ?", account_id)
                if cursor.rowcount > 0:
                    found = True
                connection.commit()
        except Exception as e:
            app.logger.warning(f"Could not delete from dbo.investing_accounts: {e}")

    cached = [a for a in cached if a.get("id") != account_id]
    _save_cached_investing_accounts(cached)

    if not found:
        return False, f"Account with ID {account_id} not found."

    return True, f"Account ID {account_id} deleted successfully."


def _delete_investing_accounts_batch(account_ids: list[int]) -> tuple[int, str]:
    """Delete multiple investing accounts by IDs from SQL Server and cache."""
    if not account_ids:
        return 0, "No accounts specified for deletion."
    _init_investing_accounts_table()
    deleted_count = 0
    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=15) as connection:
                cursor = connection.cursor()
                placeholders = ",".join(["?"] * len(account_ids))
                cursor.execute(f"DELETE FROM dbo.investing_accounts WHERE id IN ({placeholders})", *account_ids)
                deleted_count = cursor.rowcount
                connection.commit()
        except Exception as e:
            app.logger.warning(f"Could not batch delete from dbo.investing_accounts: {e}")

    cached = _load_cached_investing_accounts()
    id_set = set(account_ids)
    before_len = len(cached)
    cached = [a for a in cached if a.get("id") not in id_set]
    _save_cached_investing_accounts(cached)
    if deleted_count == 0:
        deleted_count = before_len - len(cached)

    return deleted_count, f"Successfully deleted {deleted_count} account(s)."


def _update_investing_accounts_status(account_ids: list[int], is_enabled: bool) -> tuple[int, str]:
    """Enable or disable one or more investing accounts in SQL Server and cache."""
    if not account_ids:
        return 0, "No accounts specified."

    _init_investing_accounts_table()
    updated_count = 0
    bit_val = 1 if is_enabled else 0
    status_label = "enabled" if is_enabled else "disabled"

    if pyodbc is not None and DB_CONNECTION_STRING:
        try:
            with _get_db_connection(timeout=15) as connection:
                cursor = connection.cursor()
                placeholders = ",".join(["?"] * len(account_ids))
                cursor.execute(
                    f"UPDATE dbo.investing_accounts SET is_enabled = ? WHERE id IN ({placeholders})",
                    bit_val,
                    *account_ids
                )
                updated_count = cursor.rowcount
                connection.commit()
        except Exception as e:
            app.logger.warning(f"Could not update status in dbo.investing_accounts: {e}")

    cached = _load_cached_investing_accounts()
    id_set = set(account_ids)
    cache_updated = 0
    for a in cached:
        if a.get("id") in id_set:
            a["is_enabled"] = is_enabled
            cache_updated += 1
    _save_cached_investing_accounts(cached)

    if updated_count == 0:
        updated_count = cache_updated

    return updated_count, f"Successfully marked {updated_count} account(s) as {status_label}."


def _build_post_comment_payload(req_data: dict) -> tuple[dict | None, str | None]:
    """Extract non-blank comments and count for Lambda dispatch.
    
    Lambda manages account credentials and proxies internally via LAMBDA_ACCOUNTS,
    so NO emails, passwords, or URLs are sent in the post request payload.
    """
    if not isinstance(req_data, dict):
        return None, "Request body must be a JSON object"

    raw_comments = []
    if req_data.get("comment"):
        raw_comments = [req_data["comment"]]
    elif isinstance(req_data.get("comments"), list):
        raw_comments = req_data["comments"]
    elif isinstance(req_data.get("entries"), list):
        raw_comments = [e.get("comment", "") for e in req_data["entries"] if isinstance(e, dict)]
    elif isinstance(req_data.get("accounts"), list):
        raw_comments = [a.get("comment", "") for a in req_data["accounts"] if isinstance(a, dict)]

    non_blank_comments = [str(c).strip() for c in raw_comments if str(c).strip()]

    if not non_blank_comments:
        return None, "No active comments provided. Please write at least one non-blank comment."

    num_accounts = len(non_blank_comments)

    payload = {
        "value": "post_comment",
        "action_type": "post_comment",
        "number_of_accounts": num_accounts,
        "comments": non_blank_comments,
    }

    return payload, None



# ---------------------------------------------------------------------------
# Account Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/accounts")
@app.get("/api/emails")
@require_auth
def get_accounts_endpoint():
    try:
        search = request.args.get("search", "").strip()
        status_filter = request.args.get("status", "").strip() or request.args.get("filter", "").strip()
        accounts = _fetch_investing_accounts(include_passwords=False, search=search, status_filter=status_filter)
        return jsonify({
            "success": True,
            "total": len(accounts),
            "accounts": accounts,
        })
    except Exception as error:
        app.logger.exception("Could not fetch investing accounts")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.post("/api/accounts")
@app.post("/api/emails")
@require_auth
def add_account_endpoint():
    try:
        data = request.get_json(silent=True) or {}
        username = str(data.get("username") or data.get("user_name") or data.get("name") or "").strip()
        email = str(data.get("email") or "").strip()
        password = str(data.get("password") or data.get("pass") or "").strip()
        is_enabled = bool(data.get("is_enabled", True))

        if not email or "@" not in email:
            return jsonify({"success": False, "error": "Valid email address is required."}), 400
        if not password:
            return jsonify({"success": False, "error": "Password is required."}), 400
        if not username:
            username = email.split("@")[0]

        success, message, account = _add_investing_account(username, email, password, is_enabled=is_enabled)
        if not success:
            return jsonify({"success": False, "error": message}), 409

        return jsonify({
            "success": True,
            "message": message,
            "account": account,
        }), 201
    except Exception as error:
        app.logger.exception("Could not add investing account")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.post("/api/accounts/status")
@app.post("/api/emails/status")
@app.patch("/api/accounts/status")
@app.patch("/api/emails/status")
@app.put("/api/accounts/status")
@app.put("/api/emails/status")
@require_auth
def update_accounts_status_batch_endpoint():
    try:
        data = request.get_json(silent=True) or {}
        raw_ids = data.get("ids") or data.get("account_ids") or []
        if not raw_ids:
            single_id = data.get("id") or data.get("account_id") or request.args.get("id")
            if single_id is not None:
                raw_ids = [single_id]

        int_ids = [int(x) for x in raw_ids if str(x).isdigit()]
        if not int_ids:
            return jsonify({"success": False, "error": "No valid numeric account IDs provided."}), 400

        if "is_enabled" in data:
            is_enabled = bool(data["is_enabled"])
        elif "status" in data:
            st = str(data["status"]).strip().lower()
            is_enabled = st in ("enable", "enabled", "active", "1", "true")
        elif "action" in data:
            act = str(data["action"]).strip().lower()
            is_enabled = act in ("enable", "enabled", "activate")
        else:
            return jsonify({"success": False, "error": "Must specify 'is_enabled' (true/false) or 'status' ('enabled'/'disabled')."}), 400

        count, message = _update_investing_accounts_status(int_ids, is_enabled)
        return jsonify({
            "success": True,
            "message": message,
            "updated_count": count,
            "is_enabled": is_enabled,
            "status": "enabled" if is_enabled else "disabled",
            "account_ids": int_ids,
        }), 200
    except Exception as error:
        app.logger.exception("Could not update investing accounts status")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.patch("/api/accounts/<int:account_id>/status")
@app.patch("/api/emails/<int:account_id>/status")
@app.put("/api/accounts/<int:account_id>/status")
@app.put("/api/emails/<int:account_id>/status")
@app.post("/api/accounts/<int:account_id>/status")
@app.post("/api/emails/<int:account_id>/status")
@require_auth
def update_single_account_status_endpoint(account_id: int):
    try:
        data = request.get_json(silent=True) or {}
        if "is_enabled" in data:
            is_enabled = bool(data["is_enabled"])
        elif "status" in data:
            st = str(data["status"]).strip().lower()
            is_enabled = st in ("enable", "enabled", "active", "1", "true")
        elif "action" in data:
            act = str(data["action"]).strip().lower()
            is_enabled = act in ("enable", "enabled", "activate")
        else:
            return jsonify({"success": False, "error": "Must specify 'is_enabled' (true/false) or 'status' ('enabled'/'disabled')."}), 400

        count, message = _update_investing_accounts_status([account_id], is_enabled)
        return jsonify({
            "success": True,
            "message": message,
            "updated_count": count,
            "account_id": account_id,
            "is_enabled": is_enabled,
            "status": "enabled" if is_enabled else "disabled",
        }), 200
    except Exception as error:
        app.logger.exception("Could not update account status")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.delete("/api/accounts/<int:account_id>")
@app.delete("/api/emails/<int:account_id>")
@require_auth
def delete_account_by_id_endpoint(account_id: int):
    try:
        success, message = _delete_investing_account(account_id)
        if not success:
            return jsonify({"success": False, "error": message}), 404
        return jsonify({"success": True, "message": message}), 200
    except Exception as error:
        app.logger.exception("Could not delete investing account")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


@app.delete("/api/accounts")
@app.delete("/api/emails")
@require_auth
def delete_account_body_endpoint():
    try:
        data = request.get_json(silent=True) or {}
        raw_ids = data.get("ids") or data.get("account_ids") or []
        if isinstance(raw_ids, list) and len(raw_ids) > 0:
            int_ids = [int(x) for x in raw_ids if str(x).isdigit()]
            if not int_ids:
                return jsonify({"success": False, "error": "No valid numeric account IDs provided."}), 400
            count, message = _delete_investing_accounts_batch(int_ids)
            return jsonify({"success": True, "message": message, "deleted_count": count}), 200

        raw_id = request.args.get("id") or data.get("id") or data.get("account_id")
        if not raw_id or not str(raw_id).isdigit():
            return jsonify({"success": False, "error": "Valid numeric account ID is required."}), 400
        account_id = int(str(raw_id).strip())
        success, message = _delete_investing_account(account_id)
        if not success:
            return jsonify({"success": False, "error": message}), 404
        return jsonify({"success": True, "message": message}), 200
    except Exception as error:
        app.logger.exception("Could not delete investing account")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500


# ---------------------------------------------------------------------------
# Post Comment Endpoints
# ---------------------------------------------------------------------------

@app.post("/run-post-comment")
@app.post("/api/post-comment")
def run_post_comment():
    """Trigger posting comments to investing.com."""
    try:
        data = request.get_json(silent=True) or {}
        payload, err_msg = _build_post_comment_payload(data)
        if err_msg or not payload:
            return jsonify({
                "success": False,
                "error": err_msg or "Failed to prepare comment payload."
            }), 400

        num_accounts = payload.get("number_of_accounts", 0)

        # 1. Save request in dbo.InvestingUIProcessing
        processing_id = None
        if DB_CONNECTION_STRING and pyodbc:
            try:
                acc_list = [a.get("email") for a in data.get("accounts", []) if isinstance(a, dict) and a.get("email")]
                processing_id = _save_processing_request({
                    "number_of_accounts": num_accounts,
                    "comment_ids": payload.get("comments", []),
                    "user_ids": acc_list,
                    "value": "post_comment",
                })
            except Exception as e:
                app.logger.warning(f"Could not save post_comment to dbo.InvestingUIProcessing: {e}")

        # 2. Forward to LAMBDA_API_URL
        lambda_response = None
        lambda_error = None
        upstream_status = 200

        if LAMBDA_API_URL:
            try:
                body = json.dumps(payload).encode("utf-8")
                outbound = urllib.request.Request(
                    LAMBDA_API_URL,
                    data=body,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(outbound, timeout=35) as response:
                    resp_body = response.read().decode("utf-8", errors="replace")
                    try:
                        lambda_response = json.loads(resp_body) if resp_body else {}
                    except json.JSONDecodeError:
                        lambda_response = {"message": resp_body}
                    upstream_status = response.status
            except urllib.error.HTTPError as error:
                resp_body = error.read().decode("utf-8", errors="replace")
                try:
                    lambda_response = json.loads(resp_body) if resp_body else {}
                except json.JSONDecodeError:
                    lambda_response = {"error": resp_body or str(error)}
                upstream_status = error.code
                if error.code == 504:
                    lambda_response = {
                        "message": "Comment posting job was submitted to AWS and is executing in the background for all active accounts.",
                        "status": "running",
                        "statusCode": 200,
                        "upstream_status": 504,
                    }
                    upstream_status = 200
            except (urllib.error.URLError, TimeoutError, socket.timeout) as error:
                reason = getattr(error, "reason", error)
                reason_str = str(reason).lower()
                if "timed out" in reason_str or "timeout" in reason_str or "504" in reason_str:
                    lambda_response = {
                        "message": "Comment posting job was submitted to AWS and is executing in the background for all active accounts.",
                        "status": "running",
                        "statusCode": 200,
                        "timeout": True,
                    }
                    upstream_status = 200
                else:
                    lambda_error = str(reason)
                    upstream_status = 502

        # Return sanitized accounts (passwords omitted from response)
        sanitized_accounts = [
            {
                "email": a.get("email"),
                "comment": a.get("comment"),
                "url": a.get("url") or DEFAULT_COMMENT_URL,
            }
            for a in payload.get("accounts", [])
        ]

        return jsonify({
            "success": True if upstream_status == 200 else False,
            "message": f"Successfully submitted comment posting for {num_accounts} account(s).",
            "number_of_accounts": num_accounts,
            "action_type": "post_comment",
            "url": payload.get("url", DEFAULT_COMMENT_URL),
            "accounts": sanitized_accounts,
            "comments": payload.get("comments", []),
            "processing_id": processing_id,
            "lambda_api_url": LAMBDA_API_URL,
            "lambda_response": lambda_response,
            "error": lambda_error,
        }), upstream_status
    except Exception as error:
        app.logger.exception("Error in run_post_comment endpoint")
        return jsonify({
            "success": False,
            "error": str(error)
        }), 500




@app.post("/api/store")
@require_auth
def store_processing_request():
    try:
        payload = _validate_payload(request.get_json(silent=True))
        action_val = payload.get("value", "report_spam")
        if action_val in ("report_spam", "report"):
            allowed, limit_err = _check_daily_report_limits(payload.get("user_ids", []))
            if not allowed:
                return jsonify({"error": limit_err}), 400
        processing_id = _save_processing_request(payload)
        if action_val in ("report_spam", "report"):
            _record_report_activity(payload.get("user_ids", []), processing_id)
        # Automatically mark reported / upvoted / downvoted comment URLs in dbo.comment_urls
        try:
            status_map = {
                "report_spam": "reported",
                "report": "reported",
                "upvote": "upvoted",
                "downvote": "downvoted",
            }
            new_status = status_map.get(action_val, "reported")
            _update_comments_status(
                comment_ids=payload.get("comment_ids", []),
                new_status=new_status,
            )
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


@app.post("/api/report")
@require_auth
def report_comments():
    """Forward a validated reporting payload server-side to avoid browser CORS failures."""
    try:
        raw_payload = request.get_json(silent=True) or {}
        payload = _validate_payload(raw_payload)
        action_val = payload.get("value", "report_spam")
        if action_val in ("report_spam", "report") and not raw_payload.get("processing_id"):
            allowed, limit_err = _check_daily_report_limits(payload.get("user_ids", []))
            if not allowed:
                return jsonify({"error": limit_err}), 400
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    # The normal browser flow sends processing_id after /api/store has performed
    # the authoritative validation and activity recording. Direct API calls
    # without that ID continue to receive the existing server-side validation.
    if not LAMBDA_API_URL:
        return jsonify({"error": "Reporting API URL is not configured."}), 503

    try:
        body = json.dumps(payload).encode("utf-8")
        outbound = urllib.request.Request(
            LAMBDA_API_URL,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(outbound, timeout=30) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            try:
                response_data = json.loads(response_body) if response_body else {}
            except json.JSONDecodeError:
                response_data = {"message": response_body}
            return jsonify(response_data), response.status
    except urllib.error.HTTPError as error:
        response_body = error.read().decode("utf-8", errors="replace")
        try:
            response_data = json.loads(response_body) if response_body else {}
        except json.JSONDecodeError:
            response_data = {"error": response_body or str(error)}
        if error.code == 504:
            return jsonify({
                "message": (
                    "The reporting job was submitted to AWS and is executing in the background for all configured accounts."
                ),
                "status": "running",
                "statusCode": 200,
                "upstream_status": 504,
            }), 200
        return jsonify(response_data), error.code
    except (urllib.error.URLError, TimeoutError, socket.timeout) as error:
        reason = getattr(error, "reason", error)
        reason_str = str(reason).lower()
        if "timed out" in reason_str or "timeout" in reason_str or "504" in reason_str:
            app.logger.info("Reporting API request dispatched; AWS execution continuing in background: %s", error)
            return jsonify({
                "message": (
                    "The reporting job was submitted to AWS and is executing in the background for all configured accounts."
                ),
                "status": "running",
                "statusCode": 200,
                "timeout": True,
            }), 200
        app.logger.exception("Could not reach reporting API")
        return jsonify({"error": f"Could not reach reporting API: {reason}"}), 502


@app.post("/api/ecs-tracker")
@require_auth
def ecs_tracker_cleanup():
    """Forward ECS cleanup request to AWS Lambda."""
    if not ECS_TRACKER_API_URL:
        return jsonify({"error": "ECS Tracker API URL is not configured."}), 503

    payload = {
        "token": ECS_CLEANUP_TOKEN,
        "body": {
            "token": ECS_CLEANUP_TOKEN
        }
    }

    try:
        body = json.dumps(payload).encode("utf-8")
        outbound = urllib.request.Request(
            ECS_TRACKER_API_URL,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(outbound, timeout=45) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            try:
                response_data = json.loads(response_body) if response_body else {}
                if isinstance(response_data, dict) and "body" in response_data and isinstance(response_data["body"], str):
                    try:
                        inner = json.loads(response_data["body"])
                        response_data.update(inner)
                    except Exception:
                        pass
            except json.JSONDecodeError:
                response_data = {"message": response_body}
            return jsonify(response_data), response.status
    except urllib.error.HTTPError as error:
        response_body = error.read().decode("utf-8", errors="replace")
        try:
            response_data = json.loads(response_body) if response_body else {}
            if isinstance(response_data, dict) and "body" in response_data and isinstance(response_data["body"], str):
                try:
                    inner = json.loads(response_data["body"])
                    response_data.update(inner)
                except Exception:
                    pass
        except json.JSONDecodeError:
            response_data = {"error": response_body or str(error)}
        return jsonify(response_data), error.code
    except Exception as error:
        app.logger.exception("Could not reach ECS tracker cleanup API")
        return jsonify({"error": f"Could not reach ECS cleanup API: {error}"}), 502


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

            # Build the EXACT clean payload matching Postman forma
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
