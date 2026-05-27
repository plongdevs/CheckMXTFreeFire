from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import json
import os
from garena_tools import (
    add_recovery_email, check_recovery_email, check_platforms,
    cancel_recovery_email, revoke_token, extract_eat_from_input,
    eat_to_access, eat_to_jwt, access_to_jwt, guest_to_jwt, decode_jwt
)

app = FastAPI(title="Garena Free Fire Tools API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
async def serve_frontend():
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "index.html")
    if os.path.exists(frontend_path):
        return FileResponse(frontend_path)
    return {"message": "Garena Free Fire Tools API", "version": "1.0.0"}

# Security
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database (JSON file for simplicity)
DB_FILE = "users.json"

def load_users():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(DB_FILE, 'w') as f:
        json.dump(users, f)

# Models
class User(BaseModel):
    username: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Garena Tools Models
class AddEmailRequest(BaseModel):
    email: str
    access_token: str
    otp: str
    security_code: str

class CheckEmailRequest(BaseModel):
    access_token: str

class CheckPlatformsRequest(BaseModel):
    access_token: str

class CancelEmailRequest(BaseModel):
    access_token: str

class RevokeTokenRequest(BaseModel):
    access_token: str

class EatToAccessRequest(BaseModel):
    eat_token: str

class EatToJwtRequest(BaseModel):
    eat_token: str

class AccessToJwtRequest(BaseModel):
    access_token: str

class GuestToJwtRequest(BaseModel):
    uid: str
    password: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    users = load_users()
    user = users.get(username)
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.get("/")
async def root():
    return {"message": "Garena Free Fire Tools API", "version": "1.0.0"}

@app.post("/register")
async def register(user: User):
    users = load_users()
    
    if user.username in users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email already exists
    for u in users.values():
        if u.get("email") == user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
    
    users[user.username] = {
        "username": user.username,
        "email": user.email,
        "hashed_password": get_password_hash(user.password),
        "created_at": datetime.utcnow().isoformat()
    }
    
    save_users(users)
    return {"message": "User registered successfully"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    users = load_users()
    user = users.get(form_data.username)
    
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "created_at": current_user["created_at"]
    }

# Garena Tools Endpoints
@app.post("/api/add-recovery-email")
async def api_add_recovery_email(request: AddEmailRequest, current_user: dict = Depends(get_current_user)):
    result = add_recovery_email(request.email, request.access_token, request.otp, request.security_code)
    return result

@app.post("/api/check-recovery-email")
async def api_check_recovery_email(request: CheckEmailRequest, current_user: dict = Depends(get_current_user)):
    result = check_recovery_email(request.access_token)
    return result

@app.post("/api/check-platforms")
async def api_check_platforms(request: CheckPlatformsRequest, current_user: dict = Depends(get_current_user)):
    result = check_platforms(request.access_token)
    return result

@app.post("/api/cancel-recovery-email")
async def api_cancel_recovery_email(request: CancelEmailRequest, current_user: dict = Depends(get_current_user)):
    result = cancel_recovery_email(request.access_token)
    return result

@app.post("/api/revoke-token")
async def api_revoke_token(request: RevokeTokenRequest, current_user: dict = Depends(get_current_user)):
    result = revoke_token(request.access_token)
    return result

@app.post("/api/eat-to-access")
async def api_eat_to_access(request: EatToAccessRequest, current_user: dict = Depends(get_current_user)):
    eat = extract_eat_from_input(request.eat_token)
    if not eat:
        return {"success": False, "message": "Không tách được EAT token!"}
    try:
        access = eat_to_access(eat)
        if access:
            return {"success": True, "access_token": access}
        else:
            return {"success": False, "message": "Không lấy được Access Token"}
    except Exception as e:
        return {"success": False, "message": f"Lỗi: {str(e)}"}

@app.post("/api/eat-to-jwt")
async def api_eat_to_jwt(request: EatToJwtRequest, current_user: dict = Depends(get_current_user)):
    eat = extract_eat_from_input(request.eat_token)
    if not eat:
        return {"success": False, "message": "Không tách được EAT token!"}
    try:
        jwt_token = eat_to_jwt(eat)
        decoded = decode_jwt(jwt_token)
        return {"success": True, "jwt_token": jwt_token, "decoded": decoded}
    except Exception as e:
        return {"success": False, "message": f"Lỗi: {str(e)}"}

@app.post("/api/access-to-jwt")
async def api_access_to_jwt(request: AccessToJwtRequest, current_user: dict = Depends(get_current_user)):
    try:
        jwt_token = access_to_jwt(request.access_token)
        decoded = decode_jwt(jwt_token)
        return {"success": True, "jwt_token": jwt_token, "decoded": decoded}
    except Exception as e:
        return {"success": False, "message": f"Lỗi: {str(e)}"}

@app.post("/api/guest-to-jwt")
async def api_guest_to_jwt(request: GuestToJwtRequest, current_user: dict = Depends(get_current_user)):
    try:
        jwt_token = guest_to_jwt(request.uid, request.password)
        decoded = decode_jwt(jwt_token)
        return {"success": True, "jwt_token": jwt_token, "decoded": decoded}
    except Exception as e:
        return {"success": False, "message": f"Lỗi: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
