from fastapi import HTTPException
import os

# =========================
# ADMIN CREDENTIALS
# =========================
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "password123")


def login_admin(username: str, password: str):
    if not username or not password:
        return {"error": "Username and password are required"}

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {
            "status": "logged_in",
            "username": username
        }

    return {"error": "Invalid credentials"}