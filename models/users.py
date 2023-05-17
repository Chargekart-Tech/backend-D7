from pydantic import BaseModel, EmailStr
from typing import Optional

# User Model
class User(BaseModel):
    username: str
    email: EmailStr
    contact: str
    full_name: Optional[str] = None
    password: str
