# CNC VisionCut Backend - FastAPI con Alembic y JWT Auth
# --------------------------------------------------------
# Proyecto: CNC VisionCut
# Descripción: API REST para carga de diseños, parseo CAD/CV, simulación, generación de G-code
#    y protección con OAuth2/JWT.

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import Optional, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from uuid import uuid4
from datetime import datetime, timedelta
import os

from sqlalchemy import create_engine, Column, String, Integer, JSON as SAJSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.exc import SQLAlchemyError

from services.parse_cad import CADParser

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Database Setup
DATABASE_URL = "sqlite:///./cvc.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Project(Base):
    __tablename__ = "projects"
    id = Column(String, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    vectors = relationship("Vector", back_populates="project", cascade="all, delete", passive_deletes=True)
    __table_args__ = (UniqueConstraint("id", name="uq_project_id"),)

class Vector(Base):
    __tablename__ = "vectors"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    data = Column(SAJSON, nullable=False)
    project = relationship("Project", back_populates="vectors")

class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    full_name = Column(String(100), nullable=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String, nullable=False)
    disabled = Column(Integer, default=0)

# Pydantic Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class UserBase(BaseModel):
    username: str
    email: Optional[str]
    full_name: Optional[str]
    disabled: bool

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    email: str
    full_name: Optional[str]

class GCodeParams(BaseModel):
    project_id: str
    feed_rate: float = Field(..., gt=0)
    spindle_speed: int = Field(..., gt=0)
    tool_diameter: float = Field(..., gt=0)
    pass_depth: float = Field(..., gt=0)

# FastAPI App
app = FastAPI(title="CNC VisionCut Backend")
UPLOAD_DIR = "uploads"
GCODE_DIR = "gcode"
ALLOWED_EXTENSIONS = {".dxf", ".svg", ".stl", ".obj"}
for d in (UPLOAD_DIR, GCODE_DIR): os.makedirs(d, exist_ok=True)

# Dependency: DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auth Helpers
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
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
    user = db.query(User).filter(User.username == username).first()
    if not user or user.disabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user

# Startup: create tables and parser
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    global cad_parser
    cad_parser = CADParser(upload_dir=UPLOAD_DIR)

# Signup endpoint
@app.post("/signup", response_model=UserBase)
async def signup(user_in: UserCreate, db=Depends(get_db)) -> UserBase:
    if db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Username or email already registered")
    user = User(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hash_password(user_in.password),
        disabled=0
    )
    db.add(user)
    db.commit()
    return UserBase(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        disabled=bool(user.disabled)
    )

# Token endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db=Depends(get_db)
) -> Token:
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token({"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")

# Current user endpoint
@app.get("/users/me", response_model=UserBase)
async def read_users_me(current_user: User = Depends(get_current_user)) -> UserBase:
    return UserBase(
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        disabled=bool(current_user.disabled)
    )

# Upload endpoint
@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    db=Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"File type not allowed: {ext}")
    project_id = str(uuid4())
    saved_name = f"{project_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, saved_name)
    with open(file_path, "wb") as f:
        f.write(await file.read())
    try:
        raw_vectors = cad_parser.parse(saved_name)
    except Exception:
        raw_vectors = []
    vectors = []
    for poly in raw_vectors:
        norm_poly = []
        for pt in poly:
            if isinstance(pt, complex):
                norm_poly.append([pt.real, pt.imag])
            else:
                norm_poly.append(pt)
        vectors.append(norm_poly)
    project = Project(id=project_id, filename=saved_name)
    db.add(project)
    db.flush()
    for v in vectors:
        db.add(Vector(project_id=project_id, data=v))
    db.commit()
    return JSONResponse({"project_id": project_id})

# Simulation endpoint (always returns empty list if no vectors)
@app.get("/simulation/{project_id}")
async def simulation(
    project_id: str,
    db=Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    rows = db.query(Vector).filter(Vector.project_id == project_id).all()
    vecs = [r.data for r in rows]
    params = {"feed_rate": 1000, "spindle_speed": 12000, "tool_diameter": 3.175, "pass_depth": 1.0}
    return JSONResponse({"simulation": {"vectors": vecs, "params": params}})

# G-code endpoint (always generates file even if no vectors)
@app.post("/gcode")
async def generate_gcode(
    params: GCodeParams,
    db=Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    rows = db.query(Vector).filter(Vector.project_id == params.project_id).all()
    vecs = [r.data for r in rows]
    lines = [
        f"; CNC VisionCut G-code for project {params.project_id}",
        "G21",
        "G90",
        f"F{params.feed_rate}",
        f"S{params.spindle_speed}"
    ]
    for poly in vecs:
        if len(poly) < 2:
            continue
        x0, y0 = poly[0][0], poly[0][1]
        lines.append(f"G0 X{x0:.3f} Y{y0:.3f}")
        lines.append("M3")
        for x, y in poly[1:]:
            lines.append(f"G1 X{x:.3f} Y{y:.3f} Z{-params.pass_depth:.3f}")
        lines.append("M5")
    os.makedirs(GCODE_DIR, exist_ok=True)
    out_file = os.path.join(GCODE_DIR, f"{params.project_id}.nc")
    with open(out_file, "w") as f:
        f.write("\n".join(lines))
    return JSONResponse({"gcode_url": f"/download/{params.project_id}"})

# Download endpoint
@app.get("/download/{project_id}")
async def download(
    project_id: str,
    current_user: User = Depends(get_current_user)
) -> FileResponse:
    file_path = os.path.join(GCODE_DIR, f"{project_id}.nc")
    if not os.path.exists(file_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="G-code not found")
    return FileResponse(file_path, media_type="text/plain", filename=f"{project_id}.nc")


