from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import re
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# --- Database Configuration ---
import os
# Check for persistent database URL (e.g. Postgres on Neon/Supabase)
# Fallback to ephemeral SQLite in /tmp for Vercel, or local SQLite
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
elif os.environ.get("VERCEL"):
    SQLALCHEMY_DATABASE_URL = "sqlite:////tmp/sentinel.db"
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
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String)
    scans = relationship("ScanHistoryDB", back_populates="owner")

class ScanHistoryDB(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    original_text = Column(Text)
    redacted_text = Column(Text)
    detected_pii_json = Column(Text) # Storing as JSON string
    risk_level = Column(String, nullable=True)
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
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Set to False when using wildcard origins with Bearer tokens
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security Configuration ---
SECRET_KEY = "supersecretkey_change_me_in_prod"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Pydantic Models ---
class User(BaseModel):
    username: str
    email: Optional[str] = None
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

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

async def get_current_user(token: Optional[str] = None, db: Session = Depends(get_db)):
    # Legacy function kept for compatibility, returns a guest user
    user = db.query(UserDB).filter(UserDB.username == "guest").first()
    if not user:
        hashed_password = get_password_hash("guest_pass")
        user = UserDB(username="guest", hashed_password=hashed_password)
        db.add(user)
        db.commit()
        db.refresh(user)
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
    
    # 1. Merge default and custom patterns
    all_patterns = PATTERNS.copy()
    if custom_patterns:
        all_patterns.update(custom_patterns)
        
    # 1. Collect all matches
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
            continue # Skip invalid regex
    
    # Sort detected by start position to handle overrides correctly if desired, 
    # but the character list method already handles overlapping ranges.
    
    # 2. Mask the text using a character list to handle overlaps correctly
    text_list = list(text)
    for item in detected:
        for i in range(item['start'], item['end']):
            text_list[i] = '*'
    
    redacted_text = "".join(text_list)
    return redacted_text, detected

# --- Routes ---

@app.post("/register", response_model=Token)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = UserDB(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
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
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: UserDB = Depends(get_current_user)):
    return current_user

@app.post("/scan", response_model=PIIResponse)
async def scan_text(request: PIIRequest, db: Session = Depends(get_db)):
    current_user = await get_current_user(db=db)
    redacted, detected = detect_and_redact(request.text, request.custom_patterns)
    risk_level = calculate_risk(detected)
    
    # Save scan history
    import json
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

@app.get("/history")
async def get_history(db: Session = Depends(get_db)):
    current_user = await get_current_user(db=db)
    history = db.query(ScanHistoryDB).filter(ScanHistoryDB.user_id == current_user.id).order_by(ScanHistoryDB.timestamp.desc()).all()
    results = []
    import json
    for entry in history:
        results.append({
            "id": entry.id,
            "redacted_text": entry.redacted_text,
            "detected_pii": json.loads(entry.detected_pii_json),
            "risk_level": entry.risk_level,
            "timestamp": entry.timestamp.isoformat() + "Z"
        })
    return results

@app.get("/api/health")
def read_root():
    return {"message": "Sentinel AI API is active."}

# --- Replit/Unified Deployment: Serve Frontend Static Files ---
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")

if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="static")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        # Prevent intercepting API routes
        if full_path.startswith(("token", "register", "scan", "history", "api")):
            raise HTTPException(status_code=404)
        
        index_file = os.path.join(frontend_path, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"error": "Frontend build not found. Run 'npm run build' in the frontend directory."}
else:
    @app.get("/")
    def root_no_frontend():
        return {"message": "API Active. Frontend build not detected in /frontend/dist"}

# Note: Static file serving removed for Vercel compatibility. 
# Replit users should run the frontend separately or use the previous unified commit.
