from fastapi import APIRouter
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from os import getenv

from models.users import *
from db import db

router = APIRouter()

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Authentication
SECRET_KEY = getenv("JWT_SECRET_KEY", "this_is_my_very_secretive_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 240

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")