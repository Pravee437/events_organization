from fastapi import FastAPI, Form, Request, Depends, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
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
from datetime import datetime
import qrcode
from io import BytesIO
import json
import os
from pathlib import Path
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
        request.session['create_event'] = user.create_event
        request.session['create_form'] = user.create_form

        if user.is_restricted:
            response = RedirectResponse(url="/users-template", status_code=303)
        else:
            response = RedirectResponse(url="/dashboard", status_code=303)
        return add_no_cache_headers(response)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})


@app.get("/dashboard", response_class=HTMLResponse)
@require_login
async def dashboard(request: Request):
    user_email = get_current_user(request)
    if request.session.get('is_restricted'):
        return RedirectResponse(url="/users-template", status_code=303)
    response = templates.TemplateResponse("dashboard.html",
                                          {"request": request, "email": user_email, "is_logged_in": True})
    return add_no_cache_headers(response)


@app.get("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    request.session.clear()
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


@app.get("/users-template", response_class=HTMLResponse)
@require_login
async def users_template(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    events = db.query(Event).filter(Event.user_id == user.id).all()

    return templates.TemplateResponse("users_template.html", {
        "request": request,
        "user": user,
        "events": events,
        "create_event": user.create_event or not user.is_restricted,
        "create_form": user.create_form or not user.is_restricted,
        "view_registration": not user.is_restricted  # Assuming view_registration is allowed for non-restricted users
    })

@app.post("/users-template", response_class=HTMLResponse)
async def users_template_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    create_event: bool = Form(False),
    create_form: bool = Form(False),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            return templates.TemplateResponse("users_template.html", {"request": request, "error": "Email already exists"})

        new_user = User(name=name, email=email, password=password, is_restricted=True, create_event=create_event, create_form=create_form)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return RedirectResponse(url="/login", status_code=303)
    except Exception as e:
        return templates.TemplateResponse("users_template.html", {"request": request, "error": "An error occurred during registration. Please try again."})

@app.get("/create-event", response_class=HTMLResponse)
@require_login
async def create_event(request: Request):
    if not request.session.get('create_event'):
        raise HTTPException(status_code=403, detail="Access denied")
    return templates.TemplateResponse("create_event.html", {"request": request})


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
    if not request.session.get('create_event'):
        raise HTTPException(status_code=403, detail="Access denied")

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

    return RedirectResponse(url="/users-template", status_code=303)


@app.get("/events", response_class=HTMLResponse)
@require_login
async def events(request: Request, db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    user_events = db.query(Event).filter(Event.user_id == user.id).all()

    return templates.TemplateResponse("users_template.html", {
        "request": request,
        "user": user,
        "events": user_events,
        "create_event": request.session.get('create_event', False),
        "create_form": request.session.get('create_form', False),
        "view_registration": request.session.get('view_registration', False)
    })


@app.post("/approve-event/{event_id}")
async def approve_event(event_id: int, db: Session = Depends(get_db)):
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
    db.delete(pending_event)
    db.commit()

    return RedirectResponse(url="/events", status_code=303)

@app.post("/reject-event/{event_id}")
async def reject_event(event_id: int, db: Session = Depends(get_db)):
    pending_event = db.query(PendingEvent).filter(PendingEvent.id == event_id).first()

    if not pending_event:
        raise HTTPException(status_code=404, detail="Event not found in pending requests")

    db.delete(pending_event)
    db.commit()

    return RedirectResponse(url="/events", status_code=303)

@app.get("/edit-event", response_class=HTMLResponse)
@require_login
async def edit_event(request: Request, db: Session = Depends(get_db)):
    event_id = request.query_params.get("id")
    if not event_id:
        raise HTTPException(status_code=400, detail="Event ID is required")

    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return templates.TemplateResponse("edit_event.html", {"request": request, "event": event})

@app.post("/edit-event", response_class=HTMLResponse)
@require_login
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
        db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    if not user:
        raise HTTPException(status_code=403, detail="User not found")

    try:
        event_date_converted = datetime.strptime(event_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD format.")

    event_to_update = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()

    if not event_to_update:
        raise HTTPException(status_code=404, detail="Event not found or not authorized")

    event_to_update.event_name = event_name
    event_to_update.venue_address = venue_address
    event_to_update.event_date = event_date_converted
    event_to_update.audience = audience
    event_to_update.delegates = delegates
    event_to_update.speaker = speaker
    event_to_update.nri = nri

    db.commit()
    db.refresh(event_to_update)

    return RedirectResponse(url="/users-template", status_code=303)

@app.post("/delete-event", response_class=HTMLResponse)
@require_login
async def delete_event(
        request: Request,
        event_id: int = Form(...),
        db: Session = Depends(get_db)):
    user_email = get_current_user(request)
    user = db.query(User).filter(User.email == user_email).first()

    event = db.query(Event).filter(Event.id == event_id, Event.user_id == user.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found or not authorized")

    db.delete(event)
    db.commit()

    return RedirectResponse(url="/users-template", status_code=303)


@app.get("/create-form/{event_id}", response_class=HTMLResponse)
@require_login
async def create_form(request: Request, event_id: int, db: Session = Depends(get_db)):
    if not request.session.get('create_form'):
        raise HTTPException(status_code=403, detail="Access denied")

    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return templates.TemplateResponse("create_form.html", {"request": request, "event_id": event_id})

@app.post("/submit-form")
async def submit_form(
        request: Request,
        event_id: int = Form(...),
        name: str = Form(...),
        email: str = Form(...),
        phoneno: str = Form(...),
        dropdown: str = Form(...),
        db: Session = Depends(get_db)
):
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

    # Create the directory if it doesn't exist
    qr_code_dir = Path("static/qrcodes")
    qr_code_dir.mkdir(parents=True, exist_ok=True)

    qr_code_path = qr_code_dir / f"{new_form_entry.id}.png"
    try:
        generate_qr_code(user_data, str(qr_code_path))

        with open(qr_code_path, "rb") as image_file:
            qr_code_binary = image_file.read()

        new_form_entry.qr_code = qr_code_binary
        db.commit()

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error generating QR code: {str(e)}")

    return RedirectResponse(url="/thank-you", status_code=303)

@app.get("/view-registrations/{event_id}", response_class=HTMLResponse)
@require_login
async def view_registrations(request: Request, event_id: int, db: Session = Depends(get_db)):
    if not request.session.get('view_registration'):
        raise HTTPException(status_code=403, detail="Access denied")

    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    registrations = db.query(EventForm).filter(EventForm.event_id == event_id).all()

    return templates.TemplateResponse("event_registrations.html", {
        "request": request,
        "users": registrations,
        "event_name": event.event_name
    })

@app.get("/upload-image/{event_id}", response_class=HTMLResponse)
async def upload_image_form(event_id: int, request: Request, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id).first()

    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return templates.TemplateResponse("upload_image.html", {"request": request, "event_id": event_id})

@app.post("/upload-image/{event_id}")
async def upload_image(event_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id).first()

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

    return {"filename": file.filename, "event_id": event_id}

@app.get("/get-image/{event_id}")
async def get_image(event_id: int, db: Session = Depends(get_db)):
    image = db.query(ImageModel).filter(ImageModel.event_id == event_id).first()

    if not image:
        raise HTTPException(status_code=404, detail="Image not found for this event")

    return StreamingResponse(BytesIO(image.data), media_type="image/jpeg")

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

async def send_event_request_email(event: PendingEvent, admin_email: str):
    subject = "Event Approval Request"

    context = {
        "name": "Admin",
        "event_name": event.event_name,
        "venue_address": event.venue_address,
        "event_date": event.event_date.strftime('%Y-%m-%d'),
        "audience": 'Yes' if event.audience else 'No',
        "delegates": 'Yes' if event.delegates else 'No',
        "speaker": 'Yes' if event.speaker else 'No',
        "nri": 'Yes' if event.nri else 'No',
        "event_id": event.id
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

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)