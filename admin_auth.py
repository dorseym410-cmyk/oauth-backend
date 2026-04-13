import os

# =========================
# CONFIG (ENV VARIABLES)
# =========================
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "password123")


# =========================
# LOGIN ADMIN (JWT MODE)
# =========================
def login_admin(username: str, password: str):
    # 🔥 Always return a dict (never Response)

    if not username or not password:
        return {"error": "Missing credentials"}

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"success": True}

    return {"error": "Invalid credentials"}