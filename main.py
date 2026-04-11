from fastapi import FastAPI, Request, Query
from fastapi.responses import RedirectResponse
from auth import generate_login_link, exchange_code_for_token
from graph import fetch_emails

app = FastAPI()


# =========================
# LOGIN ROUTE
# =========================
@app.get("/login")
def login(user_id: str = None):
    """
    Redirects a user to Microsoft login page.
    Optional user_id allows tracking.
    """
    user_id = user_id or "default-user"
    login_url = generate_login_link(user_id)
    return RedirectResponse(login_url)


# =========================
# GENERATE SHAREABLE LOGIN URL
# =========================
@app.get("/generate-login-url")
def generate_login_url(user_id: str = None):
    """
    Returns a Microsoft login URL for a user that can be shared.
    """
    user_id = user_id or "default-user"
    login_url = generate_login_link(user_id)
    return {
        "login_url": login_url,
        "instructions": "Send this link to the user to authorize access."
    }


# =========================
# CALLBACK ROUTE
# =========================
@app.get("/auth/callback")
def auth_callback(request: Request):
    """
    Handles the OAuth callback from Microsoft.
    Exchanges code for token and saves it for the specific user.
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")  # user_id passed in state
    if not code:
        return {"error": "No code received from callback."}

    try:
        exchange_code_for_token(code, state)
        return {"success": f"Token acquired and saved for user '{state}'!"}
    except Exception as e:
        return {"error": str(e)}


# =========================
# FETCH EMAILS ROUTE
# =========================
@app.get("/emails")
def get_emails(user_id: str = None):
    """
    Fetch emails for a specific user. Refreshes token if needed.
    """
    user_id = user_id or "default-user"
    try:
        emails = fetch_emails(user_id)
        return {"emails": emails}
    except Exception as e:
        return {"error": str(e)}