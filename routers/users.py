from fastapi import APIRouter, HTTPException, Depends, Response, status, Cookie, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
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

# Verify password using bcrypt
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Get User from MongoDB by Username
def get_user_by_username(username: str):
    user = db.users.find_one({"username": username})
    if user:
        return User(**user)
    else:
        return None

# Authenticate User by Username and Password
def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

# Create Access Token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to check the current user is logged in or not
async def check_current_user(request: Request, access_token: str = Cookie(None)):
    if access_token == None:
        return None
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return None
        user = get_user_by_username(username)
        if user is None:
            return None
        del user.password
        return access_token
    except JWTError:
        return None

# User Login Endpoint
@router.post("/login", response_model=UserLoginResponse)
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), access_token: str = Depends(check_current_user)):
    if access_token:
        response.delete_cookie("access_token")
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        response.delete_cookie('session_cookie_key')
        headers = {"set-cookie": response.headers["set-cookie"]}
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password", headers=headers)
    # Create Access Token and Set Cookie
    new_access_token = create_access_token(data={"sub": user.username})
    response.set_cookie(key="access_token",
                        value=new_access_token, httponly=True)

    return {"access_token": new_access_token, "token_type": "bearer"}