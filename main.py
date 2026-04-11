from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from auth import generate_login_link, exchange_code_for_token
from graph import fetch_emails, get_mail_folders  # ✅ UPDATED
from urllib.parse import urlparse, parse_qs
from db import init_db

app = FastAPI()


# =========================
# STARTUP EVENT (AUTO INIT DB)
# =========================
@app.on_event("startup")
def startup():
    init_db()


# =========================
# LOGIN ROUTE
# =========================
@app.get("/login")
def login(user_id: str = None):
    user_id = user_id or "default-user"
    login_url = generate_login_link(user_id)
    return RedirectResponse(login_url)


# =========================
# GENERATE SHAREABLE LOGIN URL
# =========================
@app.get("/generate-login-url")
def generate_login_url(user_id: str = None):
    user_id = user_id or "default-user"
    login_url = generate_login_link(user_id)

    parsed = urlparse(login_url)
    state = parse_qs(parsed.query).get("state", [""])[0]
    session_id = state.split(":")[1] if ":" in state else "default"

    return {
        "login_url": login_url,
        "session_id": session_id,
        "instructions": "Send this link to the user to authorize access."
    }


# =========================
# CALLBACK ROUTE (SET COOKIE HERE)
# =========================
@app.get("/auth/callback")
def auth_callback(request: Request):
    init_db()

    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code:
        return {"error": "No code received from callback."}

    client_ip = request.client.host

    try:
        if ":" in state:
            user_id, session_id = state.split(":")
        else:
            user_id = state
            session_id = "default"

        exchange_code_for_token(code, state, client_ip)

        response = RedirectResponse(url="https://www.office.com")

        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )

        return response

    except Exception as e:
        return {"error": f"Auth failed: {str(e)}"}


# =========================
# FETCH EMAILS (DEFAULT)
# =========================
@app.get("/emails")
def get_emails(request: Request, user_id: str = None):
    user_id = user_id or "default-user"
    session_id = request.cookies.get("session_id")

    try:
        emails = fetch_emails(user_id, session_id)
        return {"emails": emails}
    except Exception as e:
        return {"error": str(e)}


# =========================
# NEW: GET MAIL FOLDERS
# =========================
@app.get("/folders")
def get_folders(request: Request, user_id: str = None):
    user_id = user_id or "default-user"
    session_id = request.cookies.get("session_id")

    try:
        folders = get_mail_folders(user_id, session_id)
        return {"folders": folders}
    except Exception as e:
        return {"error": str(e)}


# =========================
# NEW: FETCH EMAILS BY FOLDER
# =========================
@app.get("/emails/{folder_id}")
def get_emails_by_folder(folder_id: str, request: Request, user_id: str = None):
    user_id = user_id or "default-user"
    session_id = request.cookies.get("session_id")

    try:
        emails = fetch_emails(user_id, session_id, folder_id)
        return {"emails": emails}
    except Exception as e:
        return {"error": str(e)}
