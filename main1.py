from fastapi import FastAPI, Form, Request, Depends, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, constr
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import URLSafeTimedSerializer
from database import SessionLocal, engine
from models import User, Event, PendingEvent
from schemas import UserSchema
from database import Base
import smtplib
from typing import List, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from jinja2 import Template
from starlette.status import HTTP_401_UNAUTHORIZED
from functools import wraps
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from datetime import datetime

app = FastAPI()
# Configure the session middleware with a secret key
app.add_middleware(SessionMiddleware, secret_key="b436b7880fc6857423bb4be8")

templates = Jinja2Templates(directory="templates")

Base.metadata.create_all(bind=engine)

# Serializer for generating and verifying tokens
serializer = URLSafeTimedSerializer("b436b7880fc6857423bb4be8")

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class EmailSettings(BaseModel):
    MAIL_USERNAME: EmailStr
    MAIL_PASSWORD: constr(min_length=1)  # Enforce non-empty string
    MAIL_PORT: int
    MAIL_SERVER: str
    MAIL_FROM: EmailStr
    MAIL_STARTTLS: bool
    MAIL_SSL_TLS: bool
    USE_CREDENTIALS: bool
    VALIDATE_CERTS: bool

email_settings = EmailSettings(
    MAIL_USERNAME="techprogrammer437@gmail.com",
    MAIL_PASSWORD="efwq idzj hdlp utpr",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_FROM="techprogrammer437@gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False
)

conf = ConnectionConfig(
    MAIL_USERNAME=email_settings.MAIL_USERNAME,
    MAIL_PASSWORD=email_settings.MAIL_PASSWORD,
    MAIL_PORT=email_settings.MAIL_PORT,
    MAIL_SERVER=email_settings.MAIL_SERVER,
    MAIL_FROM=email_settings.MAIL_FROM,
    MAIL_STARTTLS=email_settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=email_settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=email_settings.USE_CREDENTIALS,
    VALIDATE_CERTS=email_settings.VALIDATE_CERTS
)

fm = FastMail(conf)

class NoBackMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

app.add_middleware(NoBackMiddleware)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request):
    user_email = request.session.get('user_email')
    if not user_email:
        raise HTTPException(status_code=403, detail="Not authenticated")
    return user_email

def get_current_admin(request: Request):
    admin = request.session.get('admin')
    if not admin:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return admin

def require_login(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        try:
            get_current_user(request)
            if not request.session.get('authenticated'):
                raise HTTPException(status_code=401, detail="Not authenticated")
        except HTTPException:
            return RedirectResponse(url="/login", status_code=303)
        return await func(request, *args, **kwargs)
    return wrapper

def require_admin(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        try:
            get_current_admin(request)
            if not request.session.get('authenticated'):
                raise HTTPException(status_code=401, detail="Not authenticated")
        except HTTPException:
            return RedirectResponse(url="/admin-login", status_code=303)
        return await func(request, *args, **kwargs)
    return wrapper

def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/", response_class=HTMLResponse)
async def register_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            return templates.TemplateResponse("register.html", {"request": request, "error": "Email already exists"})

        new_user = User(email=email, password=password, is_active=True)  # Set is_active to True
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return templates.TemplateResponse("register.html", {"request": request, "message": "Registration successful. You can now log in."})
    except Exception as e:
        return templates.TemplateResponse("register.html", {"request": request, "error": "An error occurred during registration. Please try again."})

@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user and user.password == password and user.is_active:
        request.session['user_email'] = email
        request.session['authenticated'] = True
        response = RedirectResponse(url="/dashboard", status_code=303)
        return add_no_cache_headers(response)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

@app.get("/dashboard", response_class=HTMLResponse)
@require_login
async def dashboard(request: Request):
    user_email = get_current_user(request)
    if not request.session.get('authenticated'):
        return RedirectResponse(url="/login", status_code=303)
    response = templates.TemplateResponse("dashboard.html", {"request": request, "email": user_email, "is_logged_in": True})
    return add_no_cache_headers(response)

@app.get("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    request.session.pop('user_email', None)
    request.session.pop('admin', None)
    request.session.pop('authenticated', None)
    response = RedirectResponse(url="/login", status_code=303)
    return add_no_cache_headers(response)

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password_post(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Email not found"})

    # Generate password reset token
    token = serializer.dumps(email, salt="password-reset-salt")

    # Create password reset URL
    reset_url = f"{request.url_for('reset_password')}?token={token}"

    # Send email in the background
    background_tasks.add_task(send_reset_email, email, reset_url)

    return templates.TemplateResponse("forgot_password.html",
                                      {"request": request, "message": "Password reset link sent to your email."})

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password(request: Request, token: str):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except Exception:
        return templates.TemplateResponse("reset_password.html",
                                          {"request": request, "error": "Invalid or expired token"})

    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@app.post("/reset-password", response_class=HTMLResponse)
async def reset_password_post(
    request: Request,
    password: str = Form(...),
    token: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except Exception:
        return templates.TemplateResponse("reset_password.html",
                                          {"request": request, "error": "Invalid or expired token"})

    user = db.query(User).filter(User.email == email).first()
    if user:
        user.password = password  # Update password (stored as 'password' for simplicity)
        db.commit()
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse("reset_password.html",
                                      {"request": request, "error": "Something went wrong. Please try again."})

@app.get("/admin-login", response_class=HTMLResponse)
async def admin_login(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})

@app.post("/admin-login", response_class=HTMLResponse)
async def admin_login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "adminpassword":
        request.session['admin'] = username
        request.session['authenticated'] = True
        response = RedirectResponse(url="/admin-dashboard", status_code=303)
        return add_no_cache_headers(response)
    return templates.TemplateResponse("admin_login.html", {"request": request, "error": "Invalid credentials"})

@app.get("/admin-dashboard", response_class=HTMLResponse)
@require_admin
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    admin = get_current_admin(request)
    if not request.session.get('authenticated'):
        return RedirectResponse(url="/admin-login", status_code=303)
    users = db.query(User).all()  # Get all users instead of just pending users
    response = templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "admin": admin,
        "is_logged_in": True,
        "users": users
    })
    return add_no_cache_headers(response)

def send_reset_email(recipient_email: str, reset_url: str):
    sender_email = "techprogrammer437@gmail.com"
    sender_password = "efwq idzj hdlp utpr"
    subject = "Password Reset Request"

    # Load the HTML template from the file
    template_path = os.path.join(os.path.dirname(__file__), "templates", "reset_email_template.html")
    with open(template_path) as file_:
        template = Template(file_.read())

    # Render the template with the reset URL
    html_content = template.render(reset_url=reset_url)

    # Create the email content
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = recipient_email

    # Attach the HTML version of the email
    part = MIMEText(html_content, "html")
    message.attach(part)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())

@app.get("/create-event", response_class=HTMLResponse)
async def create_event(request: Request):
    return templates.TemplateResponse("create_event.html", {"request": request})

def send_email(to_email: str, subject: str, body: str):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "techprogrammer437@gmail.com"
    sender_password = "efwq idzj hdlp utpr"

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        print(f"Email sent to {to_email} successfully!")
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")  # Log SMTP specific errors
        raise
    except Exception as e:
        print(f"Error sending email: {e}")
        raise
    finally:
        server.quit()

async def send_event_request_email(event: PendingEvent, admin_email: str):
    subject = "Event Approval Request"

    # Prepare the context for the template
    context = {
        "name": "Admin",  # Static name for admin
        "event_name": event.event_name,
        "venue_address": event.venue_address,
        "event_date": event.event_date.strftime('%Y-%m-%d'),
        "audience": 'Yes' if event.audience else 'No',
        "delegates": 'Yes' if event.delegates else 'No',
        "speaker": 'Yes' if event.speaker else 'No',
        "nri": 'Yes' if event.nri else 'No',
        "event_id": event.id  # Include event ID in context
    }

    # Render the email body using the template
    template = templates.get_template('event_request_email.html')
    body = template.render(context)

    # Send email to admin
    message = MessageSchema(
        subject=subject,
        recipients=[admin_email],
        body=body,
        subtype="html"
    )

    try:
        await fm.send_message(message)
    except Exception as e:
        print(f"Error sending email: {e}")
        raise

@app.post("/create-event", response_class=HTMLResponse)
async def create_event_post(
    request: Request,
    event_name: str = Form(...),
    venue_address: str = Form(...),
    event_date: str = Form(...),
    audience: bool = Form(False),
    delegates: bool = Form(False),
    speaker: bool = Form(False),
    nri: bool = Form(False),
    db: Session = Depends(get_db)
):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    try:
        event_date_converted = datetime.strptime(event_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD format.")

    new_pending_event = PendingEvent(
        event_name=event_name,
        venue_address=venue_address,
        event_date=event_date_converted,
        audience=audience,
        delegates=delegates,
        speaker=speaker,
        nri=nri,
        user_id=user.id
    )
    db.add(new_pending_event)
    db.commit()
    db.refresh(new_pending_event)
    admin_email = "techprogrammer437@gmail.com"

    try:
        await send_event_request_email(new_pending_event, admin_email)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Could not send email for event approval. Error: {e}")

    return RedirectResponse(url="/events", status_code=303)

@app.get("/events", response_class=HTMLResponse)
async def events(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    # Fetch only approved events
    user_events = db.query(Event).filter(Event.user_id == user.id, Event.status == "approved").all()

    return templates.TemplateResponse("events.html", {"request": request, "email": user_email, "events": user_events})

@app.post("/approve-event/{event_id}")
async def approve_event(event_id: int, db: Session = Depends(get_db)):
    # Fetch the event from the pending_requests table
    pending_event = db.query(PendingEvent).filter(PendingEvent.id == event_id).first()

    if not pending_event:
        raise HTTPException(status_code=404, detail="Event not found in pending requests")

    # Create a new event in the events table
    approved_event = Event(
        event_name=pending_event.event_name,
        venue_address=pending_event.venue_address,
        event_date=pending_event.event_date,
        audience=pending_event.audience,
        delegates=pending_event.delegates,
        speaker=pending_event.speaker,
        nri=pending_event.nri,
        user_id=pending_event.user_id,
        status="approved"  # Status set to 'approved'
    )

    # Add the event to the events table
    db.add(approved_event)
    db.commit()

    # Remove the event from the pending_requests table
    db.delete(pending_event)
    db.commit()

    return RedirectResponse(url="/events", status_code=303)

@app.post("/reject-event/{event_id}")
async def reject_event(event_id: int, db: Session = Depends(get_db)):
    # Fetch the event from the pending_requests table
    pending_event = db.query(PendingEvent).filter(PendingEvent.id == event_id).first()

    if not pending_event:
        raise HTTPException(status_code=404, detail="Event not found in pending requests")

    # Optionally, you can notify the user about the rejection or simply delete the event
    db.delete(pending_event)
    db.commit()

    return RedirectResponse(url="/events", status_code=303)

@app.get("/events", response_class=HTMLResponse)
async def events(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)  # Get the current user's email
    user = db.query(User).filter(User.email == user_email).first()  # Fetch the current user from the database

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    # Fetch only approved events belonging to the user
    user_events = db.query(Event).filter(Event.user_id == user.id).all()

    return templates.TemplateResponse("events.html", {"request": request, "email": user_email, "events": user_events})


@app.get("/edit-event", response_class=HTMLResponse)
async def edit_event(request: Request, db: Session = Depends(get_db)):
    event_id = request.query_params.get("id")
    if not event_id:
        raise HTTPException(status_code=400, detail="Event ID is required")

    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return templates.TemplateResponse("edit_event.html", {"request": request, "event": event})

@app.post("/edit-event", response_class=HTMLResponse)
async def edit_event_post(
    request: Request,
    event_id: int = Form(...),
    event_name: str = Form(...),
    venue_address: str = Form(...),
    event_date: str = Form(...),
    audience: bool = Form(False),
    delegates: bool = Form(False),
    speaker: bool = Form(False),
    nri: bool = Form(False),
    db: Session = Depends(get_db)
):
    user_email = get_current_user(request)  # Get the current user's email
    user = db.query(User).filter(User.email == user_email).first()  # Fetch the current user from the database

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    # Convert event_date string to a Python date object
    try:
        event_date_converted = datetime.strptime(event_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD format.")

    # Fetch the event to update
    event_to_update = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()

    if not event_to_update:
        raise HTTPException(status_code=404, detail="Event not found or not authorized")

    # Update event details
    event_to_update.event_name = event_name
    event_to_update.venue_address = venue_address
    event_to_update.event_date = event_date_converted  # Use the converted date object
    event_to_update.audience = audience
    event_to_update.delegates = delegates
    event_to_update.speaker = speaker
    event_to_update.nri = nri

    db.commit()
    db.refresh(event_to_update)

    # Redirect to dashboard after event update
    return RedirectResponse(url="/events", status_code=303)

@app.post("/delete-event", response_class=HTMLResponse)
async def delete_event(
    request: Request,
    event_id: int = Form(...),
    db: Session = Depends(get_db)
):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    db.delete(event)
    db.commit()
    return RedirectResponse(url="/events", status_code=303)

