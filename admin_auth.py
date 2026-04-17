import os


def login_admin(username: str, password: str):
    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")

    if not username or not password:
        return {"error": "Username and password are required"}

    if username != admin_username or password != admin_password:
        return {"error": "Invalid admin credentials"}

    return {
        "success": True,
        "username": username,
        "role": "admin",
    }