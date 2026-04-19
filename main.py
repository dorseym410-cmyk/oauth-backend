from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from datetime import datetime, timedelta
import os

from admin_auth import login_admin
from db import init_db, SessionLocal
from models import SavedUser, Rule, RuleAction

app = FastAPI()

SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080

security = HTTPBearer()

origins = [
    "http://localhost:3000",
    "https://frontend-xg84.onrender.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


@app.on_event("startup")
def startup():
    init_db()


@app.get("/app-config")
def get_app_config():
    return {
        "electron_graph_mode": True,
        "backend_mail_disabled": True,
    }


@app.post("/admin/login")
async def admin_login_route(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    username = body.get("username")
    password = body.get("password")

    result = login_admin(username, password)

    if not result or "error" in result:
        return JSONResponse(result or {"error": "Login failed"}, status_code=401)

    token = create_access_token({"sub": username})

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@app.get("/dashboard/summary")
def dashboard_summary(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]

        saved_users_count = (
            db.query(SavedUser)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .count()
        )

        rules_count = (
            db.query(Rule)
            .join(SavedUser, SavedUser.user_id == Rule.user_id, isouter=True)
            .count()
        )

        return {
            "saved_users_count": saved_users_count,
            "rules_count": rules_count,
        }
    finally:
        db.close()


@app.get("/users")
def list_users(user=Depends(verify_token)):
    db = SessionLocal()
    try:
        admin_user_id = user["sub"]
        rows = (
            db.query(SavedUser.user_id)
            .filter(SavedUser.admin_user_id == admin_user_id)
            .distinct()
            .all()
        )
        users = sorted({row[0] for row in rows if row[0]})
        return {"users": users}
    finally:
        db.close()


@app.post("/saved-users")
async def add_saved_user(request: Request, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        body = await request.json()
        target_user_id = (body.get("user_id") or "").strip()

        if not target_user_id:
            return JSONResponse({"error": "user_id is required"}, status_code=400)

        existing = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == user["sub"],
                SavedUser.user_id == target_user_id,
            )
            .first()
        )

        if existing:
            return {"message": "User already saved", "user_id": target_user_id}

        row = SavedUser(
            admin_user_id=user["sub"],
            user_id=target_user_id,
        )
        db.add(row)
        db.commit()

        return {"message": "User saved", "user_id": target_user_id}
    finally:
        db.close()


@app.delete("/saved-users")
def delete_saved_user(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        row = (
            db.query(SavedUser)
            .filter(
                SavedUser.admin_user_id == user["sub"],
                SavedUser.user_id == user_id,
            )
            .first()
        )

        if not row:
            return JSONResponse({"error": "Saved user not found"}, status_code=404)

        db.delete(row)
        db.commit()
        return {"message": "Saved user removed", "user_id": user_id}
    finally:
        db.close()


@app.get("/rules")
def get_rules(user_id: str, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        rules = db.query(Rule).filter(Rule.user_id == user_id).all()

        return {
            "rules": [
                {
                    "id": r.id,
                    "user_id": r.user_id,
                    "condition": r.condition,
                    "keyword": r.keyword,
                    "action": r.action.value,
                    "target_folder": r.target_folder,
                    "forward_to": r.forward_to,
                    "is_active": r.is_active,
                    "created_at": r.created_at,
                }
                for r in rules
            ]
        }
    finally:
        db.close()


@app.post("/rules")
async def add_rule(request: Request, user=Depends(verify_token)):
    db = SessionLocal()
    try:
        body = await request.json()

        user_id = (body.get("user_id") or "").strip()
        condition = (body.get("condition") or "").strip()
        keyword = (body.get("keyword") or "").strip()
        action = (body.get("action") or "").strip()

        if not user_id:
            return JSONResponse({"error": "user_id is required"}, status_code=400)
        if not condition:
            return JSONResponse({"error": "condition is required"}, status_code=400)
        if not keyword:
            return JSONResponse({"error": "keyword is required"}, status_code=400)
        if not action:
            return JSONResponse({"error": "action is required"}, status_code=400)

        try:
            action_enum = RuleAction(action)
        except ValueError:
            return JSONResponse({"error": "Invalid action"}, status_code=400)

        if action == "move" and not body.get("target_folder"):
            return JSONResponse({"error": "target_folder is required for move"}, status_code=400)

        if action == "forward" and not body.get("forward_to"):
            return JSONResponse({"error": "forward_to is required for forward"}, status_code=400)

        rule = Rule(
            user_id=user_id,
            condition=condition,
            keyword=keyword,
            action=action_enum,
            target_folder=body.get("target_folder"),
            forward_to=body.get("forward_to"),
            is_active=bool(body.get("is_active", True)),
        )

        db.add(rule)
        db.commit()

        return {"message": "Rule created"}
    finally:
        db.close()