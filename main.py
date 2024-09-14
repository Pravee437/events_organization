from fastapi import FastAPI, Form, Request, Depends, HTTPException, BackgroundTasks, UploadFile, File, Path
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm import relationship
from pydantic import BaseModel, EmailStr, constr
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import URLSafeTimedSerializer
from database import SessionLocal, engine
from models import User, Event, PendingEvent, EventForm, ImageModel
from schemas import UserSchema, EventFormCreate, UserDetails, ImageCreate, ImageResponse, ImageBase
from database import Base
import smtplib
import base64
from typing import List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from jinja2 import Template
from starlette.status import HTTP_401_UNAUTHORIZED
from functools import wraps
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from datetime import datetime, timedelta
import qrcode
from io import BytesIO
import json
import os

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="b436b7880fc6857423bb4be8")

templates = Jinja2Templates(directory="templates")

Base.metadata.create_all(bind=engine)

serializer = URLSafeTimedSerializer("b436b7880fc6857423bb4be8")

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class EmailSettings(BaseModel):
    MAIL_USERNAME: EmailStr
    MAIL_PASSWORD: constr(min_length=1)
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

def generate_qr_code(data: dict, file_path: str):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save(file_path)


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

        new_user = User(email=email, password=password, is_restricted=False, create_event=True, create_form=True)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return RedirectResponse(url="/login", status_code=303)
    except Exception as e:
        return templates.TemplateResponse("register.html", {"request": request,
                                                            "error": "An error occurred during registration. Please try again."})


@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def login_post(
        request: Request,
        email: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    if user and user.password == password and user.is_active:
        request.session['user_email'] = email
        request.session['authenticated'] = True
        request.session['is_restricted'] = user.is_restricted
        if user.is_restricted:
            request.session['create_event'] = user.create_event
            request.session['create_form'] = user.create_form
            request.session['view_registrations'] = user.view_registrations
        else:
            request.session['create_event'] = True
            request.session['create_form'] = True
            request.session['view_registrations'] = True

        if user.is_restricted:
            response = RedirectResponse(url="/users-template", status_code=303)
        else:
            response = RedirectResponse(url="/dashboard", status_code=303)
        return add_no_cache_headers(response)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})


@app.get("/dashboard", response_class=HTMLResponse)
@require_login
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted:
        return RedirectResponse(url="/users-template", status_code=303)

    # Fetch all events for the dashboard
    events = db.query(Event).options(joinedload(Event.image)).all()

    response = templates.TemplateResponse("dashboard.html", {
        "request": request,
        "email": user_email,
        "user": user,
        "events": events,
        "is_logged_in": True,
        "create_event": not user.is_restricted or user.create_event,
        "create_form": not user.is_restricted or user.create_form,
        "view_registrations": not user.is_restricted or user.view_registrations
    })
    return add_no_cache_headers(response)

# Add a new route to display the update form
@app.get("/update-registration/{registration_id}", response_class=HTMLResponse)
@require_login
async def update_registration_form(
    request: Request,
    registration_id: int = Path(...),
    db: Session = Depends(get_db)
):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.view_registrations:
        raise HTTPException(status_code=403, detail="Access denied")

    registration = db.query(EventForm).filter(EventForm.id == registration_id).first()
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")

    event = db.query(Event).filter(Event.id == registration.event_id).first()
    if not event or event.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return templates.TemplateResponse("update_registration.html", {
        "request": request,
        "registration": registration,
        "event": event
    })

# Add a new route to handle the update POST request
@app.post("/update-registration/{registration_id}", response_class=HTMLResponse)
@require_login
async def update_registration(
    request: Request,
    registration_id: int = Path(...),
    name: str = Form(...),
    email: str = Form(...),
    phoneno: str = Form(...),
    dropdown: str = Form(...),
    db: Session = Depends(get_db)
):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.view_registrations:
        raise HTTPException(status_code=403, detail="Access denied")

    registration = db.query(EventForm).filter(EventForm.id == registration_id).first()
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")

    event = db.query(Event).filter(Event.id == registration.event_id).first()
    if not event or event.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Update the registration
    registration.name = name
    registration.email = email
    registration.phoneno = phoneno
    registration.dropdown = dropdown

    # Update the QR code
    user_data = {
        'name': name,
        'email': email,
        'phoneno': phoneno,
        'dropdown': dropdown
    }
    qr_code_dir = "static/qrcodes"
    qr_code_path = os.path.join(qr_code_dir, f"{registration.id}.png")
    generate_qr_code(user_data, qr_code_path)

    with open(qr_code_path, "rb") as image_file:
        qr_code_binary = image_file.read()

    registration.qr_code = qr_code_binary

    db.commit()

    return RedirectResponse(url=f"/view-registrations/{event.id}", status_code=303)


@app.get("/view-registrations", response_class=HTMLResponse)
@require_login
async def view_registrations(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.view_registrations:
        raise HTTPException(status_code=403, detail="Access denied")

    events = db.query(Event).filter(Event.user_id == user.id).all()

    return templates.TemplateResponse("view_registrations.html", {
        "request": request,
        "events": events
    })
# Modify the existing view_registrations route to include update links
@app.get("/view-event-registrations/{event_id}", response_class=HTMLResponse)
@require_login
async def view_event_registrations(request: Request, event_id: int, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.view_registrations:
        raise HTTPException(status_code=403, detail="Access denied")

    event = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    registrations = db.query(EventForm).filter(EventForm.event_id == event_id).all()

    return templates.TemplateResponse("event_registrations.html", {
        "request": request,
        "event": event,
        "registrations": registrations
    })

@app.get("/event-registrations/{event_id}", response_class=HTMLResponse)
@require_login
async def event_registrations(request: Request, event_id: int, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.view_registrations:
        raise HTTPException(status_code=403, detail="Access denied")

    event = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    registrations = db.query(EventForm).filter(EventForm.event_id == event_id).all()

    return templates.TemplateResponse("event_registrations.html", {
        "request": request,
        "event": event,
        "registrations": registrations
    })
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

    token = serializer.dumps(email, salt="password-reset-salt")
    reset_url = f"{request.url_for('reset_password')}?token={token}"
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
        user.password = password
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

    # Fetch all users
    users = db.query(User).all()

    # Fetch pending events with associated user information
    pending_events = db.query(PendingEvent, User).join(User, PendingEvent.user_id == User.id).all()

    # Fetch approved events with associated user information
    approved_events = db.query(Event, User).join(User, Event.user_id == User.id).filter(
        Event.status == "approved").all()

    # Get statistics
    total_users = len(users)
    total_pending_events = len(pending_events)
    total_approved_events = len(approved_events)

    # Get event types statistics
    event_types = {
        'Audience': sum(1 for event, _ in approved_events if event.audience),
        'Delegates': sum(1 for event, _ in approved_events if event.delegates),
        'Speaker': sum(1 for event, _ in approved_events if event.speaker),
        'NRI': sum(1 for event, _ in approved_events if event.nri),
    }

    # Get monthly event statistics for the past 6 months
    six_months_ago = datetime.now() - timedelta(days=180)
    monthly_stats = {}
    for event, _ in approved_events:
        if event.event_date >= six_months_ago.date():
            month_key = event.event_date.strftime("%B %Y")
            monthly_stats[month_key] = monthly_stats.get(month_key, 0) + 1

    monthly_data = [{'month': k, 'count': v} for k, v in monthly_stats.items()]
    monthly_data.sort(key=lambda x: datetime.strptime(x['month'], "%B %Y"))

    response = templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "admin": admin,
        "is_logged_in": True,
        "users": users,
        "pending_events": pending_events,
        "approved_events": approved_events,
        "total_users": total_users,
        "total_pending_events": total_pending_events,
        "total_approved_events": total_approved_events,
        "event_types": event_types,
        "monthly_data": monthly_data
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

@app.get("/events", response_class=HTMLResponse)
async def events(request: Request, db: Session = Depends(get_db)):
    try:
        user_email = get_current_user(request)
        user = db.query(User).filter(User.email == user_email).first()

        if not user:
            raise HTTPException(status_code=403, detail="User not found")

        events = db.query(Event).all()  # Fetch all events

        return templates.TemplateResponse("events.html", {
            "request": request,
            "user": user,
            "events": events,
        })
    except HTTPException as e:
        if e.status_code == 403:
            return RedirectResponse(url="/login", status_code=303)
        else:
            raise e

@app.get("/users-template", response_class=HTMLResponse)
@require_login
async def users_template(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    # Fetch only the events associated with the current user for the users template
    events = db.query(Event).filter(Event.user_id == user.id).options(joinedload(Event.image)).all()

    return templates.TemplateResponse("users_template.html", {
        "request": request,
        "user": user,
        "events": events,
        "create_event": not user.is_restricted or user.create_event,
        "create_form": not user.is_restricted or user.create_form,
        "view_registrations": not user.is_restricted or user.view_registrations,
        "can_edit_delete": not user.is_restricted or user.create_event
    })

@app.post("/users-template", response_class=HTMLResponse)
async def users_template_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    create_event: bool = Form(False),
    create_form: bool = Form(False),
    view_registrations:bool =Form(False),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            # Update the user's permissions if they already exist
            user.create_event = create_event
            user.create_form = create_form
            user.view_registrations = view_registrations
            db.commit()
            db.refresh(user)
            return RedirectResponse(url="/login", status_code=303)
        else:
            # Create a new user with the selected permissions
            new_user = User(name=name, email=email, password=password, is_restricted=True, create_event=create_event, create_form=create_form,view_registrations=view_registrations)
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            return RedirectResponse(url="/login", status_code=303)
    except Exception as e:
        return templates.TemplateResponse("users_template.html", {"request": request, "error": "An error occurred during registration. Please try again."})

@app.get("/create-event", response_class=HTMLResponse)
@require_login
async def create_event(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.create_event:
        raise HTTPException(status_code=403, detail="Access denied")

    return templates.TemplateResponse("create_event.html", {"request": request})

# Update the create_event_post function
@app.post("/create-event", response_class=HTMLResponse)
@require_login
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

    if user.is_restricted and not user.create_event:
        raise HTTPException(status_code=403, detail="Access denied")

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
        await send_event_request_email(new_pending_event, admin_email, request)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Could not send email for event approval. Error: {e}")

    return RedirectResponse(url="/pending-events", status_code=303)

# Add a new route for viewing pending events
@app.get("/pending-events", response_class=HTMLResponse)
@require_login
async def pending_events(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    pending_events = db.query(PendingEvent).filter(PendingEvent.user_id == user.id).all()

    return templates.TemplateResponse("pending_events.html", {
        "request": request,
        "user": user,
        "pending_events": pending_events,
    })

# Update the approve_event function to redirect to the events page
@app.post("/approve-event/{event_id}")
async def approve_event(event_id: int, request: Request, db: Session = Depends(get_db)):
    pending_event = db.query(PendingEvent).filter(PendingEvent.id == event_id).first()

    if not pending_event:
        raise HTTPException(status_code=404, detail="Event not found in pending requests")

    approved_event = Event(
        event_name=pending_event.event_name,
        venue_address=pending_event.venue_address,
        event_date=pending_event.event_date,
        audience=pending_event.audience,
        delegates=pending_event.delegates,
        speaker=pending_event.speaker,
        nri=pending_event.nri,
        user_id=pending_event.user_id,
        status="approved")

    db.add(approved_event)
    db.commit()
    db.refresh(approved_event)

    # Get the user's email
    user = db.query(User).filter(User.id == approved_event.user_id).first()
    if user:
        # Send confirmation email
        await send_approval_email(user.email, approved_event, request)

    db.delete(pending_event)
    db.commit()

    return RedirectResponse(url="/events", status_code=303)


async def send_approval_email(user_email: str, event: Event, request: Request):
    subject = "Event Approved - Create Your Form"

    # Generate the URL dynamically
    create_form_url = request.url_for('create_form', event_id=event.id)

    context = {
        "event_name": event.event_name,
        "create_form_url": create_form_url
    }

    template = templates.get_template('event_approval_email.html')
    body = template.render(context)

    message = MessageSchema(
        subject=subject,
        recipients=[user_email],
        body=body,
        subtype="html"
    )

    try:
        await fm.send_message(message)
    except Exception as e:
        print(f"Error sending approval email: {e}")
        # You might want to log this error or handle it differently

@app.post("/reject-event/{event_id}")
async def reject_event(event_id: int, db: Session = Depends(get_db)):
    pending_event = db.query(PendingEvent).filter(PendingEvent.id == event_id).first()

    if not pending_event:
        raise HTTPException(status_code=404, detail="Event not found in pending requests")

    db.delete(pending_event)
    db.commit()

    return RedirectResponse(url="/events", status_code=303)

from fastapi import Path

@app.get("/edit-event/{event_id}", response_class=HTMLResponse)
@require_login
async def edit_event(request: Request, event_id: int, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    if event.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not authorized to edit this event")

    if user.is_restricted and not user.create_event:
        raise HTTPException(status_code=403, detail="Access denied")

    return templates.TemplateResponse("edit_event.html", {"request": request, "event": event})
@app.post("/edit-event/{event_id}", response_class=HTMLResponse)
@require_login
async def edit_event_post(
        request: Request,
        event_id: int,
        event_name: str = Form(...),
        venue_address: str = Form(...),
        event_date: str = Form(...),
        audience: bool = Form(False),
        delegates: bool = Form(False),
        speaker: bool = Form(False),
        nri: bool = Form(False),
        db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.create_event:
        raise HTTPException(status_code=403, detail="Access denied")

    event_to_update = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()
    if not event_to_update:
        raise HTTPException(status_code=404, detail="Event not found or not authorized")

    try:
        event_date_converted = datetime.strptime(event_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD format.")

    event_to_update.event_name = event_name
    event_to_update.venue_address = venue_address
    event_to_update.event_date = event_date_converted
    event_to_update.audience = audience
    event_to_update.delegates = delegates
    event_to_update.speaker = speaker
    event_to_update.nri = nri

    db.commit()
    db.refresh(event_to_update)

    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/delete-event", response_class=HTMLResponse)
@require_login
async def delete_event(
        request: Request,
        event_id: int = Form(...),
        db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    if user.is_restricted and not user.create_event:
        raise HTTPException(status_code=403, detail="Access denied")

    db.delete(event)
    db.commit()

    return RedirectResponse(url="/users-template", status_code=303)

@app.get("/create-form", response_class=HTMLResponse)
@require_login
async def create_form_list(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.create_form:
        raise HTTPException(status_code=403, detail="Access denied")

    events = db.query(Event).filter(Event.user_id == user.id).all()

    return templates.TemplateResponse("create_form_list.html", {
        "request": request,
        "events": events
    })
@app.get("/create-form/{event_id}", response_class=HTMLResponse)
@require_login
async def create_form(request: Request, event_id: int, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.create_form:
        raise HTTPException(status_code=403, detail="Access denied")

    event = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return templates.TemplateResponse("create_form.html", {"request": request, "event": event})

import os

@app.post("/submit-form")
@require_login
async def submit_form(
        request: Request,
        event_id: int = Form(...),
        name: str = Form(...),
        email: str = Form(...),
        phoneno: str = Form(...),
        dropdown: str = Form(...),
        db: Session = Depends(get_db)
):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    new_form_entry = EventForm(
        event_id=event_id,
        name=name,
        email=email,
        phoneno=phoneno,
        dropdown=dropdown,
        qr_code=None
    )
    db.add(new_form_entry)
    db.commit()

    user_data = {
        'name': name,
        'email': email,
        'phoneno': phoneno,
        'dropdown': dropdown
    }

    qr_code_dir = "static/qrcodes"
    os.makedirs(qr_code_dir, exist_ok=True)

    qr_code_path = os.path.join(qr_code_dir, f"{new_form_entry.id}.png")
    try:
        generate_qr_code(user_data, qr_code_path)

        with open(qr_code_path, "rb") as image_file:
            qr_code_binary = image_file.read()

        new_form_entry.qr_code = qr_code_binary
        db.commit()

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error generating QR code: {str(e)}")

    # Set flash message
    request.session['flash_message'] = "Your form has been successfully submitted."

    # Redirect based on user type
    if user.is_restricted:
        return RedirectResponse(url="/users-template", status_code=303)
    else:
        return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/view-registrations/{event_id}", response_class=HTMLResponse)
@require_login
async def view_event_registrations(request: Request, event_id: int, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.view_registrations:
        raise HTTPException(status_code=403, detail="Access denied")

    event = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    registrations = db.query(EventForm).filter(EventForm.event_id == event_id).all()

    return templates.TemplateResponse("event_registrations.html", {
        "request": request,
        "event": event,
        "registrations": registrations
    })

@app.get("/qr-code/{registration_id}")
async def get_qr_code(registration_id: int, db: Session = Depends(get_db)):
    registration = db.query(EventForm).filter(EventForm.id == registration_id).first()
    if not registration or not registration.qr_code:
        raise HTTPException(status_code=404, detail="QR code not found")

    return StreamingResponse(BytesIO(registration.qr_code), media_type="image/png")

@app.get("/view-registration/{registration_id}", response_class=HTMLResponse)
@require_login
async def view_registration(request: Request, registration_id: int, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if user.is_restricted and not user.view_registrations:
        raise HTTPException(status_code=403, detail="Access denied")

    registration = db.query(EventForm).filter(EventForm.id == registration_id).first()
    if not registration:
        raise HTTPException(status_code=404, detail="Registration not found")

    event = db.query(Event).filter(Event.id == registration.event_id, Event.user_id == user.id).first()
    if not event:
        raise HTTPException(status_code=403, detail="Not authorized to view this registration")

    return templates.TemplateResponse("registration_details.html", {
        "request": request,
        "event": event,
        "registration": registration
    })

@app.get("/upload-image/{event_id}", response_class=HTMLResponse)
@require_login
async def upload_image_form(
    request: Request,
    event_id: int = Path(..., title="The ID of the event to upload an image for"),
    db: Session = Depends(get_db)
):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    event = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return templates.TemplateResponse("upload_image.html", {
        "request": request,
        "event_id": event_id,
        "event": event
    })

@app.post("/upload-image/{event_id}", response_class=HTMLResponse)
@require_login
async def upload_image(
    request: Request,
    event_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    event = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    existing_image = db.query(ImageModel).filter(ImageModel.event_id == event_id).first()
    if existing_image:
        db.delete(existing_image)
        db.commit()

    file_content = await file.read()
    image = ImageModel(event_id=event_id, filename=file.filename, data=file_content)

    db.add(image)
    db.commit()
    db.refresh(image)

    return RedirectResponse(url=f"/users-template", status_code=303)
@app.get("/event-image/{event_id}")
async def get_event_image(event_id: int, db: Session = Depends(get_db)):
    image = db.query(ImageModel).filter(ImageModel.event_id == event_id).first()
    if not image:
        raise HTTPException(status_code=404, detail="Image not found")
    return StreamingResponse(BytesIO(image.data), media_type="image/png")

def send_reset_email(recipient_email: str, reset_url: str):
    sender_email = "techprogrammer437@gmail.com"
    sender_password = "efwq idzj hdlp utpr"
    subject = "Password Reset Request"

    template_path = os.path.join(os.path.dirname(__file__), "templates", "reset_email_template.html")
    with open(template_path) as file_:
        template = Template(file_.read())

    html_content = template.render(reset_url=reset_url)

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = recipient_email

    part = MIMEText(html_content, "html")
    message.attach(part)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())

async def send_event_request_email(event: PendingEvent, admin_email: str, request: Request):
    subject = "Event Approval Request"

    # Generate the base URL
    base_url = str(request.base_url)

    context = {
        "name": "Admin",
        "event_name": event.event_name,
        "venue_address": event.venue_address,
        "event_date": event.event_date.strftime('%Y-%m-%d'),
        "audience": 'Yes' if event.audience else 'No',
        "delegates": 'Yes' if event.delegates else 'No',
        "speaker": 'Yes' if event.speaker else 'No',
        "nri": 'Yes' if event.nri else 'No',
        "event_id": event.id,
        "base_url": base_url  # Add the base URL to the context
    }

    template = templates.get_template('event_request_email.html')
    body = template.render(context)

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

def generate_qr_code(data: dict, file_path: str):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(json.dumps(data))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(file_path)
@app.get("/thank-you", response_class=HTMLResponse)
async def thank_you(request: Request):
    return templates.TemplateResponse("thank_you.html", {"request": request})