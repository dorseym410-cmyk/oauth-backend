from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
import os

# Store credentials in ENV (VERY IMPORTANT)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "password123")


def login_admin(username: str, password: str):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        response = JSONResponse({"status": "logged_in"})
        response.set_cookie(
            key="admin_session",
            value="authenticated",
            httponly=True,
            secure=True,
            samesite="lax",
            path="/"
        )
        return response
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


def require_admin(request: Request):
    session = request.cookies.get("admin_session")
    if session != "authenticated":
        raise HTTPException(status_code=401, detail="Unauthorized")