import os
import re
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# --- Database Configuration ---
# Supports Supabase PostgreSQL, or fallback to local SQLite for development
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    # Fix for older postgres:// URLs
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
else:
    SQLALCHEMY_DATABASE_URL = "sqlite:///./sentinel.db"

if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Database Models ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255))
    scans = relationship("ScanHistoryDB", back_populates="owner")

class ScanHistoryDB(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    original_text = Column(Text)
    redacted_text = Column(Text)
    detected_pii_json = Column(Text)
    risk_level = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("UserDB", back_populates="scans")

# Create tables
Base.metadata.create_all(bind=engine)

# --- Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- FastAPI App ---
app = FastAPI(title="Sentinel AI API", version="2.0.0")

# --- CORS Configuration ---
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173")
ALLOWED_ORIGINS = [
    FRONTEND_URL,
    "http://localhost:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security Configuration ---
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# --- Pydantic Models ---
class User(BaseModel):
    username: str
    email: Optional[str] = None
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None

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

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Validate JWT token and return the authenticated user."""
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
    
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None:
        raise credentials_exception
    return user

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
async def register(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user account."""
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    if user.email:
        db_email = db.query(UserDB).filter(UserDB.email == user.email).first()
        if db_email:
            raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = UserDB(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "username": user.username}

@app.post("/api/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login and receive an access token."""
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "username": user.username}

@app.get("/api/users/me", response_model=User)
async def read_users_me(current_user: UserDB = Depends(get_current_user)):
    """Get current authenticated user info."""
    return current_user

# --- Protected PII Routes ---

@app.post("/api/scan", response_model=PIIResponse)
async def scan_text(
    request: PIIRequest,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Scan text for PII (requires authentication)."""
    redacted, detected = detect_and_redact(request.text, request.custom_patterns)
    risk_level = calculate_risk(detected)
    
    scan_history = ScanHistoryDB(
        original_text=request.text,
        redacted_text=redacted,
        detected_pii_json=json.dumps(detected),
        risk_level=risk_level,
        user_id=current_user.id
    )
    db.add(scan_history)
    db.commit()
    
    return PIIResponse(
        original_text=request.text,
        redacted_text=redacted,
        detected_pii=detected,
        risk_level=risk_level
    )

@app.get("/api/history")
async def get_history(
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan history for authenticated user."""
    history = db.query(ScanHistoryDB).filter(
        ScanHistoryDB.user_id == current_user.id
    ).order_by(ScanHistoryDB.timestamp.desc()).all()
    
    results = []
    for entry in history:
        results.append({
            "id": entry.id,
            "redacted_text": entry.redacted_text,
            "detected_pii": json.loads(entry.detected_pii_json),
            "risk_level": entry.risk_level,
            "timestamp": entry.timestamp.isoformat() + "Z"
        })
    return results

# --- Public Routes ---

@app.get("/api/health")
def health_check():
    """Public health check endpoint."""
    return {"status": "healthy", "message": "Sentinel AI API is active."}
