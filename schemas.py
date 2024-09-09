from pydantic import BaseModel
from typing import Optional
from enum import Enum
from datetime import date

class EventStatusEnum(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class UserSchema(BaseModel):
    id: int
    name: Optional[str]
    email: str
    is_active: bool
    is_restricted: bool
    create_event: bool
    create_form: bool

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    is_restricted: bool = True
    create_event: bool = True  # Changed default to True
    create_form: bool = True   # Changed default to True

class UserLogin(BaseModel):
    email: str
    password: str

class EventCreate(BaseModel):
    event_name: str
    venue_address: str
    event_date: date
    audience: bool
    delegates: bool
    speaker: bool
    nri: bool

class EventResponse(EventCreate):
    id: int
    user_id: int
    status: EventStatusEnum

    class Config:
        from_attributes = True

class EventFormCreate(BaseModel):
    event_id: int
    name: str
    email: str
    phoneno: str
    dropdown: str

class EventFormResponse(EventFormCreate):
    id: int

    class Config:
        from_attributes = True

class UserDetails(BaseModel):
    id: int
    name: str
    email: str
    phoneno: str

    class Config:
        from_attributes = True

class ImageBase(BaseModel):
    filename: str
    event_id: int

class ImageCreate(ImageBase):
    data: bytes

class ImageResponse(ImageBase):
    id: int

    class Config:
        from_attributes = True