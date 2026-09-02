import time
import random
import traceback
import hashlib
import hmac
import os
import logging
import re
from fastapi import FastAPI, HTTPException, status, Request, Response, Header, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, List

# Single FastAPI instance with comprehensive benchmarking metadata
app = FastAPI(
    title="Comprehensive Compliance, Security & Performance Benchmark",
    description="Dual-state benchmark with both intentionally vulnerable and compliant reference implementations for Nova verification.",
    version="1.0.0"
)

security_bearer = HTTPBearer(auto_error=False)

# ==============================================================================
# ORIGINAL MOCK DATA & SCHEMAS
# ==============================================================================

USERS_DB = [
    {"id": 1, "username": "alice", "role": "admin", "password_hash": "$2b$12$e8Y7z9j1...mockHashAdmin", "email": "alice@nova.io"},
    {"id": 2, "username": "bob", "role": "developer", "password_hash": "$2b$12$k10Px8a2...mockHashDev", "email": "bob@nova.io"},
    {"id": 3, "username": "carol", "role": "tester", "password_hash": "$2b$12$q41Lo9c3...mockHashTester", "email": "carol@nova.io"}
]

ITEMS_DB = []


class ItemPayload(BaseModel):
    name: str
    price: float


# ==============================================================================
# ORIGINAL MIDDLEWARE & INTENTIONAL MISCONFIGURATIONS
# ==============================================================================

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


# ==============================================================================
# ORIGINAL VULNERABLE BENCHMARK ENDPOINTS (DAST / SAST / PERFORMANCE TRIGGERS)
# ==============================================================================

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
    time.sleep(2.1)  # Synthetic blocking delay: triggers ISO 25010 Time Behavior violation
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


# ==============================================================================
# ORIGINAL INTENTIONAL COMPLIANCE TARGETS (ISO 27001 & ISO 25010)
# ==============================================================================

# 7. ISO 27001 Annex A.9.4.3: Hardcoded Static Secrets Detection
JWT_STATIC_SECRET = "secret_key = 'super_insecure_jwt_hardcoded_token_xyz987'"
STRIPE_API_KEY = "api_key = 'sk_live_51AbcDefGhIjKlMnOpQrStUvWxYz123456'"


# 8. ISO 27001 Annex A.10.1.1: Weak/Deprecated Cryptography & Plaintext PII Logging
@app.post("/api/v1/auth/insecure-hash")
def insecure_hash_and_logging(password: str, user_email: str):
    """
    1. Triggers COMP-PRIV-003: MD5/SHA1 usage breaches cryptographic controls.
    2. Triggers COMP-PRIV-002: Logging plaintext sensitive credentials/PII.
    """
    print(f"[SECURITY AUDIT] Received login attempt for user password: {password}")
    logging.info(f"Processing secret data for email: {user_email}")

    # Deprecated hashing primitive (triggers ISO 27001 Annex A.10.1.1)
    weak_md5_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
    weak_sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest()

    return {
        "md5": weak_md5_hash,
        "sha1": weak_sha1_hash,
        "status": "insecure_hashing_completed"
    }


# 9. ISO 25010 Maintainability: Extreme Cyclomatic Complexity (> 20 Threshold)
@app.get("/api/v1/admin/complex-logic")
def evaluate_excessive_cyclomatic_complexity(level: int = 1):
    """
    Triggers ISO 25010 Maintainability violation by introducing 24 branch conditions.
    Threshold is capped at 20.
    """
    score = 0
    if level == 1: score += 1
    if level == 2: score += 2
    if level == 3: score += 3
    if level == 4: score += 4
    if level == 5: score += 5
    if level == 6: score += 6
    if level == 7: score += 7
    if level == 8: score += 8
    if level == 9: score += 9
    if level == 10: score += 10
    if level == 11: score += 11
    if level == 12: score += 12
    if level == 13: score += 13
    if level == 14: score += 14
    if level == 15: score += 15
    if level == 16: score += 16
    if level == 17: score += 17
    if level == 18: score += 18
    if level == 19: score += 19
    if level == 20: score += 20
    if level == 21: score += 21
    if level == 22: score += 22
    if level == 23: score += 23
    if level == 24: score += 24

    return {"calculated_score": score, "complexity": "exceeds_threshold_20"}


# ==============================================================================
# COMPLIANT REFERENCE IMPLEMENTATIONS (PASSING CONTROLS FOR BALANCED SCORE)
# ==============================================================================

class SecureUserResponse(BaseModel):
    id: int
    username: str
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    role: str


class SecurePasswordRequest(BaseModel):
    user_email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    password: str = Field(..., min_length=8, description="Secure password minimum 8 chars")


class SecureItemPayload(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    price: float = Field(..., gt=0.0)


def require_authenticated_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)) -> dict:
    """ISO 27001 Annex A.9.4.2: Enforces valid bearer token dependency."""
    if not credentials or not credentials.credentials or credentials.credentials == "invalid":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Missing or invalid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"user_id": 1, "username": "alice", "role": "admin"}


# Compliant 1: Secure, Zero-Leakage Health Check (ISO 25010 Time Behavior Passing)
@app.get("/api/v2/health/secure", tags=["Compliant Reference"])
def secure_health_check():
    """ISO 25010 Compliant: Sub-millisecond response without config leakage."""
    return {"status": "healthy", "service": "nova-core", "code": 200}


# Compliant 2: Authenticated User Inventory (ISO 27001 Access Control Passing)
@app.get("/api/v2/users/secure", response_model=List[SecureUserResponse], tags=["Compliant Reference"])
def get_secure_users(
    user_id: Optional[int] = Query(None, ge=1),
    auth_user: dict = Depends(require_authenticated_user)
):
    """ISO 27001 Compliant: Sanitized user data protected by authorization."""
    results = [
        {"id": u["id"], "username": u["username"], "email": u.get("email", f"{u['username']}@nova.io"), "role": u["role"]}
        for u in USERS_DB
    ]
    if user_id:
        filtered = [u for u in results if u["id"] == user_id]
        if not filtered:
            raise HTTPException(status_code=404, detail="User not found")
        return filtered
    return results


# Compliant 3: Secure Key Derivation (ISO 27001 Cryptography Control Passing)
@app.post("/api/v2/auth/secure-hash", tags=["Compliant Reference"])
def secure_cryptographic_hash(payload: SecurePasswordRequest):
    """
    ISO 27001 (Annex A.10.1.1 / CWE-327 Compliant):
    Uses PBKDF2 HMAC-SHA256 with 100,000 iterations and a cryptographically secure random salt.
    """
    dynamic_salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        payload.password.encode("utf-8"),
        dynamic_salt,
        100_000
    )
    return {
        "status": "secure_hashing_completed",
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": 100_000,
        "key_fingerprint": derived_key.hex()[:16]
    }


# Compliant 4: Low-Complexity Modular Logic (ISO 25010 Maintainability Passing)
@app.get("/api/v2/admin/modular-logic", tags=["Compliant Reference"])
def evaluate_modular_maintainable_logic(
    level: int = Query(1, ge=1, le=50),
    auth_user: dict = Depends(require_authenticated_user)
):
    """
    ISO 25010 Maintainability Compliant:
    Uses mathematical mapping instead of nested branch statements (Cyclomatic Complexity = 1).
    """
    calculated_score = (level * (level + 1)) // 2
    return {
        "calculated_score": calculated_score,
        "cyclomatic_complexity": 1,
        "status": "within_threshold"
    }


# Compliant 5: Safe Query Processing (ISO 25010 Time Behavior & OWASP A03 Passing)
@app.get("/api/v2/catalog/optimized-search", tags=["Compliant Reference"])
def secure_search_catalog(
    query: str = Query("default", min_length=1, max_length=50),
    auth_user: dict = Depends(require_authenticated_user)
):
    """ISO 25010 Compliant: Zero artificial delay, input bounded, authenticated."""
    return {
        "query": query,
        "results_count": 2,
        "results": [f"Item matching '{query}' - A", f"Item matching '{query}' - B"]
    }