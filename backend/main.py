import os
import re
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
import bcrypt
from supabase import create_client, Client

# --- Supabase Configuration ---
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://uvhbjitcxbnjvofoargw.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "sb_publishable_coxaCf9Jn1_97EU8mTsX7Q_s7bWKw5j")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- FastAPI App ---
app = FastAPI(title="Sentinel AI API", version="2.0.0")

# --- CORS Configuration ---
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")
ALLOWED_ORIGINS = [
    FRONTEND_URL,
    "http://localhost:5173",
    "http://localhost:3000",
    "*"  # Allow all for development
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security Configuration ---
SECRET_KEY = os.environ.get("SECRET_KEY", "sentinel-ai-secret-key-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# --- Pydantic Models ---
class User(BaseModel):
    id: Optional[str] = None
    username: str
    email: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str

class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class PIIRequest(BaseModel):
    text: str
    custom_patterns: Optional[Dict[str, str]] = None

class PIIResponse(BaseModel):
    original_text: str
    redacted_text: str
    detected_pii: List[Dict[str, Any]]
    risk_level: str

# --- Utility Functions ---
def calculate_risk(detected: List[Dict[str, str]]) -> str:
    if not detected:
        return "None"
    
    high_sensitivity = {"AADHAAR", "PAN", "PASSPORT", "CREDIT_CARD", "CVV", "ATM_PIN"}
    medium_sensitivity = {"VOTER_ID", "GSTIN"}
    
    has_high = any(item['type'] in high_sensitivity for item in detected)
    has_medium = any(item['type'] in medium_sensitivity for item in detected)
    total_count = len(detected)
    
    if has_high or total_count > 5:
        return "High"
    if has_medium or total_count >= 3:
        return "Medium"
    return "Low"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(authorization: str = Header(None)):
    """Validate JWT token and return the authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not authorization or not authorization.startswith("Bearer "):
        raise credentials_exception
    
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        if username is None:
            raise credentials_exception
        return {"id": user_id, "username": username}
    except JWTError:
        raise credentials_exception

# --- Regex Patterns ---
PATTERNS = {
    "AADHAAR": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
    "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "PASSPORT": r"\b[A-Z]{1}[0-9]{7}\b",
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE": r"\b(\+91[\-\s]?)?[6789]\d{9}\b",
    "VOTER_ID": r"\b[A-Z]{3}[0-9]{7}\b",
    "GSTIN": r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b",
    "ATM_PIN": r"\b\d{4,6}\b",
    "CREDIT_CARD": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
    "CVV": r"\b\d{3}\b",
    "DOB": r"\b\d{2}[\-/\.]\d{2}[\-/\.]\d{4}\b"
}

def detect_and_redact(text: str, custom_patterns: Optional[Dict[str, str]] = None):
    detected = []
    
    all_patterns = PATTERNS.copy()
    if custom_patterns:
        all_patterns.update(custom_patterns)
        
    for pii_type, pattern in all_patterns.items():
        try:
            matches = re.finditer(pattern, text)
            for match in matches:
                value = match.group()
                detected.append({
                    "type": pii_type,
                    "value": value,
                    "start": match.start(),
                    "end": match.end()
                })
        except re.error:
            continue
    
    text_list = list(text)
    for item in detected:
        for i in range(item['start'], item['end']):
            text_list[i] = '*'
    
    redacted_text = "".join(text_list)
    return redacted_text, detected

# --- Auth Routes ---

@app.post("/api/register", response_model=Token)
async def register(user: UserCreate):
    """Register a new user account."""
    # Check if username exists
    existing = supabase.table("users").select("*").eq("username", user.username).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash password and create user
    hashed_password = get_password_hash(user.password)
    
    result = supabase.table("users").insert({
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password
    }).execute()
    
    if not result.data:
        raise HTTPException(status_code=500, detail="Failed to create user")
    
    new_user = result.data[0]
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "user_id": new_user["id"]},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "username": user.username}

@app.post("/api/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and receive an access token."""
    result = supabase.table("users").select("*").eq("username", form_data.username).execute()
    
    if not result.data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    user = result.data[0]
    
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"], "user_id": user["id"]},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "username": user["username"]}

@app.get("/api/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user info."""
    return current_user

# --- Protected PII Routes ---

@app.post("/api/scan", response_model=PIIResponse)
async def scan_text(request: PIIRequest, current_user: dict = Depends(get_current_user)):
    """Scan text for PII (requires authentication)."""
    redacted, detected = detect_and_redact(request.text, request.custom_patterns)
    risk_level = calculate_risk(detected)
    
    # Save to Supabase
    supabase.table("scan_history").insert({
        "user_id": current_user["id"],
        "original_text": request.text,
        "redacted_text": redacted,
        "detected_pii_json": json.dumps(detected),
        "risk_level": risk_level
    }).execute()
    
    return PIIResponse(
        original_text=request.text,
        redacted_text=redacted,
        detected_pii=detected,
        risk_level=risk_level
    )

@app.get("/api/history")
async def get_history(current_user: dict = Depends(get_current_user)):
    """Get scan history for authenticated user."""
    result = supabase.table("scan_history").select("*").eq(
        "user_id", current_user["id"]
    ).order("created_at", desc=True).execute()
    
    history = []
    for entry in result.data:
        history.append({
            "id": entry["id"],
            "redacted_text": entry["redacted_text"],
            "detected_pii": json.loads(entry["detected_pii_json"]),
            "risk_level": entry["risk_level"],
            "timestamp": entry["created_at"]
        })
    return history

# --- Public Routes ---

@app.get("/api/health")
def health_check():
    """Public health check endpoint."""
    return {"status": "healthy", "message": "Sentinel AI API is active.", "database": "Supabase"}
