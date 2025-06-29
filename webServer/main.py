from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Boolean, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
import os
import json
import logging
from datetime import datetime
import pytz

app = FastAPI()
#app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/users")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password = Column(String(50))
    is_admin = Column(Boolean, default=False)


class JSONFormatter(logging.Formatter):
    def format(self, record):

        moscow_tz = pytz.timezone('Europe/Moscow')

        current_time = datetime.now(moscow_tz).strftime("%d/%b/%Y:%H:%M:%S")
        
        log_record = {
            "time_local": current_time,
            "level": record.levelname,
        }

        
        if hasattr(record, 'status'):
            log_record['status'] = record.status
        if hasattr(record, 'username'):
            log_record['username'] = record.username
        
        if hasattr(record, 'password'):
            log_record['password'] = record.password

        if hasattr(record, 'error'):
            log_record['error'] = record.error

        return json.dumps(log_record)




def init_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        db.add_all([
            User(username='ivanov.ii@gmail.com', password='password'),
            User(username='admin', password='admin', is_admin=True),
            User(username='andreev.aa@gmail.com', password='andreev')
        ])
        db.commit()


@app.on_event("startup")
async def startup_event():
    init_db()
    log_dir = "python_backend"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(os.path.join(log_dir, 'auth.log'), delay=False)
    file_handler.setFormatter(JSONFormatter())

    logger.addHandler(file_handler)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



@app.get("/")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def vulnerable_login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...)
):
    try:
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        with engine.connect() as conn:
            result = conn.execute(text(query))
            user = result.fetchone()

        

        if user:
            log_data = {
            'status': 'success',
            'username': username,
            'password': password,
            }
            logging.warning("User login attempt",extra=log_data)
            return RedirectResponse(url="/welcome", status_code=status.HTTP_303_SEE_OTHER)

        log_data = {
            'status': 'failure',
            'username': username,
            'password': password,
            }
        logging.warning("User login attempt",extra=log_data)
        return {"status": "error", "message": "Invalid credentials"}

    except Exception as e:
        log_data = {
            'status': 'error',
            'username': username,
            'password': password,
            'error': str(e)
        }
        logging.error("An error occurred during login",extra=log_data)
        raise HTTPException(status_code=500, detail=str(e))
    

@app.get("/welcome", response_class=HTMLResponse)
async def welcome_page(request: Request):
    return templates.TemplateResponse("welcome.html", {"request": request})