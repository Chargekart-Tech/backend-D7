from pydantic import BaseModel, EmailStr
from typing import Optional

# User Model
class User(BaseModel):
    username: str
    email: EmailStr
    contact: str
    full_name: Optional[str] = None
    password: str
    car_number: str
    model_number: str
    model_year: str
    battery_capacity: float


# User Login Model
class UserLogin(BaseModel):
    username: str
    password: str


# User Login Response Model
class UserLoginResponse(BaseModel):
    access_token: str
    token_type: str


# Change Password Input Model
class ChangePasswordInput(BaseModel):
    current_password: str
    new_password: str