"""Investing Reporter frontend request store.

The browser calls POST /api/store to record the request in SQL Server. It then
calls API Gateway directly; API Gateway is responsible for invoking Lambda.
"""

import json
import os
from pathlib import Path
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


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


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
