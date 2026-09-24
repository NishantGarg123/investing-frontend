# Investing Comment Reporter — Frontend

Web portal for the Investing Comment Reporter system, now fully integrated with the **Universal Raw SQL Execution API** (`/api/query` and `/api/sql`).

---

## 🚀 Key Architecture Changes

Instead of connecting directly to a local SQLite database file, all database read, write, upsert, and delete operations now route through the Universal Raw SQL Execution API running on the backend service (`http://localhost:3000`).

### 1. Universal SQL API Specifications
- **Endpoint:** `POST http://localhost:3000/api/query` *(alias: `POST /api/sql`)*
- **Headers:**
  - `Content-Type: application/json`
  - `X-API-Key: ak_live_7e8b4f1c9a3d5206e12f84b9c7a0d143`
- **Request Body:**
  ```json
  {
    "query": "SELECT * FROM users ORDER BY id DESC LIMIT 10",
    "params": []
  }
  ```

---

## 🛠️ Two-Place Implementation

### Place 1: Frontend Client (`index.html`)
The frontend provides the `runQuery` helper function and has updated `saveFrontendData` / `getFrontendData` to run raw SQL queries directly:

```javascript
// Universal Raw SQL helper function (accessible globally via window.runQuery)
const API_BASE = "http://localhost:3000";
const API_KEY = "ak_live_7e8b4f1c9a3d5206e12f84b9c7a0d143";

export async function runQuery(sql, params = []) {
  const response = await fetch(`${API_BASE}/api/query`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY
    },
    body: JSON.stringify({
      query: sql,
      params: params
    })
  });
  return await response.json();
}
```

#### Usage Examples in Frontend:
```javascript
// 1. SELECT Query
const users = await runQuery("SELECT * FROM users WHERE id = ?", [200548123]);
console.log(users.data);

// 2. INSERT / UPSERT Query
const result = await runQuery(
  "INSERT OR REPLACE INTO users (id, user_name) VALUES (?, ?)",
  [200548124, "TraderOne"]
);
console.log(result.message);
```

---

### Place 2: Frontend Web Server (`app.py`)
All endpoints in `app.py` (`/api/users`, `/api/comments`, `/api/store`, `/api/logs`, `/api/frontend-data`) have been refactored to execute raw SQL against `http://localhost:3000/api/query` via `execute_sql_query()` rather than opening local SQLite database connections.

In addition, `app.py` exposes `/api/query` and `/api/sql` proxies to forward client requests to the backend service.

---

## 🏃 Running the Services

### Start Backend API Server:
```powershell
cd C:\inverosoft\Investing-fetch_url2
uvicorn app:app --host 0.0.0.0 --port 3000 --reload
```

### Start Frontend Server:
```powershell
cd C:\inverosoft\Investing-frontend
python app.py
```