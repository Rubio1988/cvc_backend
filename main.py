# CNC VisionCut Backend - FastAPI con Alembic, JWT Auth y Documentación OpenAPI/Redoc
# ------------------------------------------------------------------------------
# Proyecto: CNC VisionCut
# API REST para carga de diseños CAD/imagen, parseo, simulación CNC,
# generación de G-code, y protección con OAuth2/JWT.

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

from sqlalchemy import (
    create_engine, Column, String, Integer, JSON as SAJSON,
    ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.exc import SQLAlchemyError

from services.parse_cad import CADParser

# Parser global inicializado en startup
global cad_parser
cad_parser: CADParser = None

# --- Configuración autenticación JWT ---
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# --- Configuración Base de datos y modelos SQLAlchemy ---
DATABASE_URL = "sqlite:///./cvc.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Project(Base):
    __tablename__ = "projects"
    id = Column(String, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    vectors = relationship(
        "Vector", back_populates="project",
        cascade="all, delete", passive_deletes=True
    )
    __table_args__ = (
        UniqueConstraint("id", name="uq_project_id"),
    )

class Vector(Base):
    __tablename__ = "vectors"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(
        String, ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    data = Column(SAJSON, nullable=False)
    project = relationship("Project", back_populates="vectors")

class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    full_name = Column(String(100), nullable=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String, nullable=False)
    disabled = Column(Integer, default=0)

# --- Modelos Pydantic ---
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

# --- Instanciar aplicación ---
app = FastAPI(
    title="CNC VisionCut Backend",
    description="API REST para registro de usuarios, autenticación JWT, carga de diseños CAD/imagen, simulación CNC y generación de G-code.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

UPLOAD_DIR = "uploads"
GCODE_DIR = "gcode"
ALLOWED_EXTENSIONS = {".dxf", ".svg", ".stl", ".obj"}
for d in (UPLOAD_DIR, GCODE_DIR): os.makedirs(d, exist_ok=True)

# --- Dependencia de base de datos ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Auxiliares de autenticación ---
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def authenticate_user(db, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)) -> UserBase:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user or db_user.disabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return UserBase(
        username=db_user.username,
        email=db_user.email,
        full_name=db_user.full_name,
        disabled=bool(db_user.disabled)
    )

# --- Evento de arranque ---
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    global cad_parser
    cad_parser = CADParser(upload_dir=UPLOAD_DIR)

# --- Endpoints ---
@app.post("/signup", response_model=UserBase)
async def signup(user_in: UserCreate, db=Depends(get_db)):
    if db.query(User).filter((User.username == user_in.username) | (User.email == user_in.email)).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Username or email already registered")
    hashed = get_password_hash(user_in.password)
    user = User(username=user_in.username, email=user_in.email, full_name=user_in.full_name, hashed_password=hashed, disabled=0)
    db.add(user)
    db.commit()
    return UserBase(username=user.username, email=user.email, full_name=user.full_name, disabled=bool(user.disabled))

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    access_token = await create_access_token({"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserBase)
async def read_users_me(current_user: UserBase = Depends(get_current_user)):
    return current_user

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), db=Depends(get_db), current_user: UserBase = Depends(get_current_user)):
    global cad_parser
    if cad_parser is None:
        cad_parser = CADParser(upload_dir=UPLOAD_DIR)
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"File type not allowed: {ext}")
    project_id = str(uuid4())
    saved = f"{project_id}_{file.filename}"
    path = os.path.join(UPLOAD_DIR, saved)
    with open(path, "wb") as f:
        f.write(await file.read())
    raw = cad_parser.parse(saved)
    vectors = []
    for poly in raw:
        normalized = [[pt.real, pt.imag] if isinstance(pt, complex) else pt for pt in poly]
        vectors.append(normalized)
    db.add(Project(id=project_id, filename=saved))
    db.flush()
    for v in vectors:
        db.add(Vector(project_id=project_id, data=v))
    db.commit()
    return {"project_id": project_id}

@app.get("/simulation/{project_id}")
async def simulation(project_id: str, db=Depends(get_db), current_user: UserBase = Depends(get_current_user)):
    rows = db.query(Vector).filter(Vector.project_id == project_id).all()
    vecs = [r.data for r in rows]
    params = {"feed_rate": 1000, "spindle_speed": 12000, "tool_diameter": 3.175, "pass_depth": 1.0}
    return {"simulation": {"vectors": vecs, "params": params}}

@app.post("/gcode")
async def generate_gcode(params: GCodeParams, db=Depends(get_db), current_user: UserBase = Depends(get_current_user)):
    rows = db.query(Vector).filter(Vector.project_id == params.project_id).all()
    vecs = [r.data for r in rows]
    lines = [f"; CNC VisionCut G-code for project {params.project_id}", "G21", "G90", f"F{params.feed_rate}", f"S{params.spindle_speed}"]
    for poly in vecs:
        if len(poly) < 2: continue
        x0, y0 = poly[0]
        lines.append(f"G0 X{x0:.3f} Y{y0:.3f}")
        lines.append("M3")
        for x, y in poly[1:]:
            lines.append(f"G1 X{x:.3f} Y{y:.3f} Z{-params.pass_depth:.3f}")
        lines.append("M5")
    os.makedirs(GCODE_DIR, exist_ok=True)
    out = os.path.join(GCODE_DIR, f"{params.project_id}.nc")
    with open(out, "w") as f:
        f.write("\n".join(lines))
    return {"gcode_url": f"/download/{params.project_id}"}

@app.get("/download/{project_id}")
async def download(project_id: str, current_user: UserBase = Depends(get_current_user)):
    file_path = os.path.join(GCODE_DIR, f"{project_id}.nc")
    if not os.path.exists(file_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="G-code not found")
    return FileResponse(file_path, media_type="text/plain", filename=f"{project_id}.nc")

