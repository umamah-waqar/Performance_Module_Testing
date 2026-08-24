import time
import random
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(
    title="Performance Test Bench",
    description="Mock target application for Nova Performance Workflow testing",
    version="1.0.0"
)

# Mock in-memory database
USERS_DB = [
    {"id": 1, "username": "alice", "role": "admin"},
    {"id": 2, "username": "bob", "role": "developer"},
    {"id": 3, "username": "carol", "role": "tester"}
]


class ItemPayload(BaseModel):
    name: str
    price: float


# 1. Fast Baseline Route (Expected: ~5-15ms latency, 0% error rate)
@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Ultra-fast route for measuring baseline server throughput."""
    return {"status": "healthy", "service": "performance-bench"}


#  2. Standard Query Route (Expected: ~10-30ms latency) 
@app.get("/api/v1/users", status_code=status.HTTP_200_OK)
def get_users():
    """Standard endpoint returning in-memory entity list."""
    return {"total": len(USERS_DB), "data": USERS_DB}


# 3. Moderate Latency Route (Expected: ~200-300ms latency)
@app.get("/api/v1/search", status_code=status.HTTP_200_OK)
def search_catalog(query: str = "default"):
    """Simulates database index scan or third-party service query."""
    time.sleep(0.25)
    return {"query": query, "results": ["item_alpha", "item_beta"]}


# 4. High Latency Bottleneck Route (Expected: >2000ms latency -> SLA Breach)
@app.get("/api/v1/reports/heavy", status_code=status.HTTP_200_OK)
def generate_heavy_report():
    """Simulates unoptimized SQL aggregation or heavy compute bottleneck."""
    time.sleep(2.1)
    return {"report": "generated", "execution_time_sec": 2.1}


# 5. Unstable / High 5xx Failure Route (Expected: ~30% 500 crashes)
@app.get("/api/v1/unstable", status_code=status.HTTP_200_OK)
def flaky_endpoint():
    """Simulates database deadlocks or unhandled exceptions under concurrency."""
    if random.random() < 0.35:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Simulated server crash / database pool exhausted."
        )
    return {"status": "success", "message": "Request survived random failure"}


#  6. Client Misconfiguration / 4xx Route (Expected: 422/400 errors)
@app.post("/api/v1/items", status_code=status.HTTP_201_CREATED)
def create_item(item: ItemPayload):
    """Expects JSON payload; parameterless GET requests will trigger 404/405/422."""
    return {"status": "created", "item": item}