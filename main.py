import time
import random
import traceback
from fastapi import FastAPI, HTTPException, status, Request, Response, Header
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="Intentionally Vulnerable DAST Benchmark",
    description="Vulnerable target application for Nova DAST & Security Testing verification",
    version="1.0.0"
)

# Mock in-memory database
USERS_DB = [
    {"id": 1, "username": "alice", "role": "admin", "password_hash": "$2b$12$e8Y7z9j1...mockHashAdmin"},
    {"id": 2, "username": "bob", "role": "developer", "password_hash": "$2b$12$k10Px8a2...mockHashDev"},
    {"id": 3, "username": "carol", "role": "tester", "password_hash": "$2b$12$q41Lo9c3...mockHashTester"}
]


# Global Middleware: Introduces Insecure Headers & Overly Permissive CORS (CWE-942 / CWE-693)
@app.middleware("http")
async def add_security_misconfigurations(request: Request, call_next):
    response: Response = await call_next(request)
    # Expose underlying server banner (Information Disclosure)
    response.headers["Server"] = "Werkzeug/2.0.1 Python/3.13.0 Custom-Debug-Build"
    response.headers["X-Powered-By"] = "FastAPI/Starlette-Debug"
    # Overly permissive CORS wildcard allowing credentials
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    # Explicitly omit CSP, HSTS, and X-Content-Type-Options to trigger ZAP passive scanner rules
    return response


class ItemPayload(BaseModel):
    name: str
    price: float


# 1. Baseline Route with Information Leakage (CWE-200)
@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Returns baseline status while exposing internal debug configs."""
    return {
        "status": "healthy",
        "service": "security-bench",
        "debug_mode": True,
        "internal_ip": "10.0.4.15",
        "db_connection_string": "postgresql://postgres:admin_root_pass@127.0.0.1:5432/nova_db"
    }


# 2. Broken Object Level Authorization & Data Exposure (CWE-200, CWE-639, OWASP A01:2021)
@app.get("/api/v1/users", status_code=status.HTTP_200_OK)
def get_users(user_id: Optional[int] = None):
    """Exposes all user data including passwords and roles without authentication."""
    if user_id:
        user = next((u for u in USERS_DB if u["id"] == user_id), None)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    return {"total": len(USERS_DB), "data": USERS_DB}


# 3. Reflected Cross-Site Scripting (XSS) & SQLi Trigger (CWE-79, CWE-89, OWASP A03:2021)
@app.get("/api/v1/search")
def search_catalog(query: str = "default"):
    """
    1. Triggers SQL Injection alerts if query contains SQL syntax characters (' OR 1=1, --, UNION, SELECT).
    2. Returns raw unsanitized HTML to trigger Reflected XSS alerts (<script>, <img>, etc.).
    """
    time.sleep(0.1)

    # Simulated SQL Injection Error Leakage (CWE-89)
    sqli_markers = ["'", '"', "--", "/*", "UNION", "SELECT", "OR 1=1", "DROP"]
    if any(marker.lower() in query.lower() for marker in sqli_markers):
        return JSONResponse(
            status_code=500,
            content={
                "error": "Syntax error in SQL statement near: '" + query + "'",
                "driver_error": "psycopg2.errors.SyntaxError: unterminated quoted string at or near " + query,
                "executed_query": f"SELECT * FROM catalog WHERE item_name ILIKE '%{query}%'"
            }
        )

    # Reflected XSS (CWE-79): Renders query straight into unescaped HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
        <head><title>Search Results</title></head>
        <body>
            <h2>Search results for: {query}</h2>
            <div id="results">
                <p>Showing matching catalog items for {query}</p>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)


# 4. Sensitive File Inclusion / Path Traversal Trigger (CWE-22, OWASP A01:2021)
@app.get("/api/v1/reports/heavy")
def generate_heavy_report(file_path: Optional[str] = None):
    """Simulates directory traversal / arbitrary file read trigger."""
    if file_path:
        if ".." in file_path or "/etc/" in file_path or "win.ini" in file_path:
            return Response(
                content="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                media_type="text/plain",
                status_code=200
            )
    time.sleep(0.3)  # Reduced delay so probes don't time out
    return {"report": "generated", "status": "completed"}


# 5. Stack Trace / Internal Error Disclosure (CWE-209, CWE-388)
@app.get("/api/v1/unstable")
def flaky_endpoint(trigger_crash: bool = True):
    """Leaks raw internal stack traces and environment data upon failure."""
    if trigger_crash:
        try:
            raise RuntimeError("Database pool connection refused on internal port 5432")
        except Exception:
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "exception_type": "RuntimeError",
                    "traceback": traceback.format_exc(),
                    "environment": {
                        "SECRET_KEY": "super_secret_production_jwt_key_12345",
                        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"
                    }
                }
            )
    return {"status": "success"}


# 6. Unvalidated Input & Command Injection Simulation (CWE-78, CWE-20)
@app.post("/api/v1/items", status_code=status.HTTP_201_CREATED)
def create_item(item: ItemPayload, x_forwarded_host: Optional[str] = Header(None)):
    """Validates item while checking for command injection and host header injection."""
    if any(char in item.name for char in [";", "|", "&", "`", "$"]):
        return JSONResponse(
            status_code=500,
            content={
                "error": "Command execution failed",
                "output": f"/bin/sh: 1: {item.name}: not found"
            }
        )
    return {"status": "created", "item": item, "processed_by_host": x_forwarded_host}