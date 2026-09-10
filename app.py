"""Investing Reporter frontend request store.

The browser calls POST /api/store to record the request in SQL Server. It then
calls API Gateway directly; API Gateway is responsible for invoking Lambda.
"""

import json
import os
from pathlib import Path
import re
import pyodbc
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DB_CONNECTION_STRING = os.getenv("DB_CONNECTION_STRING", "").strip()
LAMBDA_API_URL = os.getenv(
    "LAMBDA_API_URL",
    "https://nr9andj3qe.execute-api.us-east-2.amazonaws.com/dev/investing-dev",
).strip()

app = Flask(__name__)


@app.get("/api/config")
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
    """Fetch all rows from BackendProcessingTracker and group into batches.
    
    Batches are grouped by:
    1. Records starting within 60 seconds of each other.
    2. Exact matching comment_ids and user_ids.
    Ordered newest batch first.
    """
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

        # Check if consecutive row belongs to the current batch (gap <= 60s and same IDs)
        is_same = False
        if current_batch is not None:
            time_diff = (
                abs((current_batch["_last_date"] - starting_date).total_seconds())
                if (current_batch["_last_date"] and starting_date)
                else 999999
            )
            if time_diff <= 60 and current_batch["comment_ids"] == comment_ids and current_batch["user_ids"] == user_ids:
                is_same = True

        # Parse completion and success/failure counts
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
            # Status is still in-progress (e.g. "Starting on investing", "created from lambda")
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

    # Assign sequential batch numbers and remove temporary keys
    total_batches = len(batches)
    for idx, b in enumerate(batches):
        b["batch_number"] = total_batches - idx
        b.pop("_last_date", None)

    return batches


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/logs")
def get_logs():
    try:
        batches = _fetch_batches_from_tracker()
        return jsonify({
            "success": True,
            "total_batches": len(batches),
            "batches": batches,
        })
    except pyodbc.Error as error:
        app.logger.exception("Could not fetch logs from SQL Server")
        return jsonify({
            "success": False,
            "error": f"Database error: {str(error)}"
        }), 500
    except RuntimeError as error:
        app.logger.exception("Frontend database is not configured")
        return jsonify({"success": False, "error": str(error)}), 500


@app.post("/api/store")
def store_processing_request():
    try:
        payload = _validate_payload(request.get_json(silent=True))
        processing_id = _save_processing_request(payload)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except pyodbc.Error as error:
        app.logger.exception("Could not save reporting request to SQL Server")
        return jsonify({
            "error": f"Database error: {str(error)}"
        }), 500
    except RuntimeError as error:
        app.logger.exception("Frontend database is not configured")
        return jsonify({"error": str(error)}), 500

    return jsonify({
        "processing_id": processing_id,
        "lambda_api_url": LAMBDA_API_URL,
        "message": "Request saved successfully",
    }), 201


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=os.getenv("FLASK_DEBUG") == "1")
