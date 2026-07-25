"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import os
from pathlib import Path
import json
import uuid
import hashlib
import secrets

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


# --- Simple file-based user storage and auth helpers ---
current_dir = Path(__file__).parent
data_dir = current_dir.parent / "data"
users_file = data_dir / "users.json"

def _ensure_users_file():
    data_dir.mkdir(parents=True, exist_ok=True)
    if not users_file.exists():
        users_file.write_text(json.dumps({"users": {}, "tokens": {}}))

def load_users():
    _ensure_users_file()
    return json.loads(users_file.read_text())

def save_users(data):
    _ensure_users_file()
    users_file.write_text(json.dumps(data, indent=2))

def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000)
    return dk.hex(), salt

def create_user(email: str, password: str, is_admin: bool = False):
    data = load_users()
    if email in data["users"]:
        raise ValueError("User already exists")
    pwd_hash, salt = _hash_password(password)
    data["users"][email] = {"password_hash": pwd_hash, "salt": salt, "is_admin": is_admin}
    save_users(data)

def verify_user(email: str, password: str) -> bool:
    data = load_users()
    u = data["users"].get(email)
    if not u:
        return False
    pwd_hash, _ = _hash_password(password, u["salt"])
    return secrets.compare_digest(pwd_hash, u["password_hash"])

def create_token_for(email: str) -> str:
    data = load_users()
    token = uuid.uuid4().hex
    data["tokens"][token] = email
    save_users(data)
    return token

def get_email_for_token(token: str) -> str | None:
    data = load_users()
    return data.get("tokens", {}).get(token)


class SignupModel(BaseModel):
    email: str
    password: str

class LoginModel(BaseModel):
    email: str
    password: str

def get_current_user(authorization: str | None = Header(None)) -> dict:
    """Dependency that returns the authenticated user dict or raises 401."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split()[1]
    email = get_email_for_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    data = load_users()
    user = data["users"].get(email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {"email": email, "is_admin": user.get("is_admin", False)}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, current_user: dict = Depends(get_current_user)):
    """Sign up the authenticated student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")
    # Get the specific activity
    activity = activities[activity_name]

    email = current_user["email"]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, current_user: dict = Depends(get_current_user)):
    """Unregister the authenticated student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    email = current_user["email"]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}


# --- Authentication endpoints ---
@app.post("/auth/signup")
def auth_signup(payload: SignupModel):
    try:
        create_user(payload.email, payload.password)
    except ValueError:
        raise HTTPException(status_code=400, detail="User already exists")
    token = create_token_for(payload.email)
    return {"token": token}


@app.post("/auth/login")
def auth_login(payload: LoginModel):
    if not verify_user(payload.email, payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token_for(payload.email)
    return {"token": token}


@app.get("/auth/me")
def auth_me(current_user: dict = Depends(get_current_user)):
    return current_user
