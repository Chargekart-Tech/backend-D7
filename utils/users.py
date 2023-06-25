from fastapi import HTTPException, Request, status, Request
from passlib.context import CryptContext
import phonenumbers

from models.users import *
from utils.users import *
from db import db

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Hash password using bcrypt
def get_password_hash(password: str):
    if len(password) < 6:
        raise HTTPException(
            status_code=400, detail="Password should be atleast 6 characters long")
    return pwd_context.hash(password)


# Verify password using bcrypt
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Check the validity of a phone number
def check_phone_number(phone_number: str):
    try:
        contact = phonenumbers.parse(phone_number, "IN")
        if not phonenumbers.is_valid_number(contact):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid phone number")
    except phonenumbers.phonenumberutil.NumberParseException:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid phone number")
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail = "An Error Occured!")
    
    return True

# Create User in MongoDB
def create_user(user: dict):
    user["password"] = get_password_hash(user["password"])
    result = db.users.insert_one(user)
    return str(result.inserted_id)

# Update User in MongoDB
def update_user(user: dict):
    user["password"] = get_password_hash(user["password"])
    result = db.users.replace_one({"username": user["username"]}, user)
    if not result.modified_count:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update user details!")
    return True

# Update user password in MongoDB
def update_user_password(username: str, password: str):
    hashed_password = get_password_hash(password)
    result = db.users.update_one({"username": username}, {
                        "$set": {"password": hashed_password}})
    if not result.modified_count:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update password!")
    return True

# Get User from MongoDB by Username
def get_user_by_username(username: str):
    user = db.users.find_one({"username": username})
    if user:
        return User(**user)
    else:
        return None

# Get User from MongoDB by Email
def get_user_by_email(email: EmailStr):
    user = db.users.find_one({"email": email})
    if user:
        return User(**user)
    else:
        return None

# Authenticate User by Username and Password
def authenticate_user(username_email: str, password: str):
    if "@" in username_email:
        user = get_user_by_email(username_email)
    else:
        user = get_user_by_username(username_email)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

# Dependency for User Authentication
async def get_current_user(request: Request):
    username = request.session.get('username')
    if username == None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not Authenticated")
    
    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    
    del user.password
    return user

# Function to check the current user is logged in or not
async def check_current_user(request: Request):
    username = request.session.get('username')
    if username == None:
        return None
    
    user = get_user_by_username(username)
    if user is None:
        return None
    
    return username
