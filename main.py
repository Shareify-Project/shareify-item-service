"""
Shareify Item Service
- Add item with image support
- Delete item (owner only)
- Get all items / Get item by ID
"""

import os
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
import httpx

app = FastAPI(title="Shareify Item Service", version="1.1.0")
# -- POSTGRESQL HOTFIX: SQLite Polyfill --------------------------------------
# Automatically translates SQLite conn.execute() and '?' to PostgreSQL syntax
import psycopg2
from psycopg2.extensions import connection

def _sqlite_to_psycopg2_execute(self, query, vars=None):
    if '?' in query:
        query = query.replace('?', '%s')
    cursor = self.cursor()
    cursor.execute(query, vars)
    return cursor

connection.execute = _sqlite_to_psycopg2_execute
# ----------------------------------------------------------------------------
import time
from fastapi import Request
from prometheus_client import make_asgi_app, Counter, Histogram

# -- Prometheus Metrics ------------------------------------------------------
REQUEST_COUNT = Counter("http_requests_total", "Total requests", ["method", "endpoint", "http_status"])
REQUEST_LATENCY = Histogram("http_request_duration_seconds", "Latency", ["method", "endpoint"])

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    method = request.method
    endpoint = request.url.path
    if endpoint == "/metrics":
        return await call_next(request)
        
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    REQUEST_COUNT.labels(method=method, endpoint=endpoint, http_status=response.status_code).inc()
    REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(process_time)
    
    return response


# ── Config ──────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("JWT_SECRET", "shareify-secret-key-2024")
ALGORITHM = "HS256"
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:shareify-secure-db-pass@postgres-db:5432/item_service")
INVENTORY_SERVICE_URL = os.getenv("INVENTORY_SERVICE_URL", "http://localhost:8003")

VALID_CATEGORIES = ["Electronics", "Furniture", "Kitchen", "Tools"]
security = HTTPBearer()

# ── Database ────────────────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    # Using IF NOT EXISTS and adding image_url column
    conn.execute("""
        CREATE TABLE IF NOT EXISTS items (
            item_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            price_per_day REAL NOT NULL,
            image_url TEXT,
            created_at TEXT NOT NULL
        )
    """)
    # Migration: Add image_url column if it doesn't exist (for existing DBs)
    try:
        conn.execute("ALTER TABLE items ADD COLUMN image_url TEXT")
    except sqlite3.OperationalError:
        pass # Already exists
        
    conn.commit()
    conn.close()

@app.on_event("startup")
def startup():
    init_db()

# ── Schemas ─────────────────────────────────────────────────────────────────
class ItemCreate(BaseModel):
    title: str
    category: str
    price_per_day: float
    image_url: str = None

# ── Auth ────────────────────────────────────────────────────────────────────
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ── Endpoints ───────────────────────────────────────────────────────────────
@app.post("/items")
def add_item(item: ItemCreate, payload: dict = Depends(verify_token)):
    if item.category not in VALID_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category. Must be one of: {VALID_CATEGORIES}",
        )
    if item.price_per_day <= 0:
        raise HTTPException(status_code=400, detail="Price must be positive")

    item_id = str(uuid.uuid4())
    owner_id = payload["user_id"]
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO items (item_id, owner_id, title, category, price_per_day, image_url, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (item_id, owner_id, item.title, item.category, item.price_per_day, item.image_url,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()

    # Notify Inventory Service
    try:
        httpx.post(f"{INVENTORY_SERVICE_URL}/initialize", json={"item_id": item_id}, timeout=5.0)
    except Exception as e:
        print(f"[WARN] Could not notify inventory service: {e}")

    return {"message": "Item added successfully", "item_id": item_id}

@app.get("/items")
def get_items(category: str = Query(None), q: str = Query(None)):
    conn = get_db()
    try:
        query = "SELECT * FROM items WHERE 1=1"
        params = []
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        if q:
            query += " AND title LIKE ?"
            params.append(f"%{q}%")
            
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

@app.get("/items/{item_id}")
def get_item(item_id: str):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM items WHERE item_id = ?", (item_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Item not found")
        return dict(row)
    finally:
        conn.close()

@app.delete("/items/{item_id}")
def delete_item(item_id: str, payload: dict = Depends(verify_token)):
    user_id = payload["user_id"]
    conn = get_db()
    try:
        # Check if item exists and user is owner
        row = conn.execute("SELECT owner_id FROM items WHERE item_id = ?", (item_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Item not found")
        if row["owner_id"] != user_id:
            raise HTTPException(status_code=403, detail="You can only delete your own items")

        # Delete from items table
        conn.execute("DELETE FROM items WHERE item_id = ?", (item_id,))
        conn.commit()

        # Notify Inventory Service to delete as well
        try:
            httpx.delete(f"{INVENTORY_SERVICE_URL}/inventory/{item_id}", timeout=5.0)
        except Exception as e:
            print(f"[WARN] Could not notify inventory service of deletion: {e}")

        return {"message": "Item deleted successfully"}
    finally:
        conn.close()

@app.get("/health")
def health():
    return {"status": "healthy", "service": "shareify-item-service"}




