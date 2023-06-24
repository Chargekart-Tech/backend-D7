from fastapi import APIRouter, HTTPException, Depends, Response, Request, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import phonenumbers
import re
import ast

from models.users import *
from db import db

router = APIRouter()

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Hash password using bcrypt
def get_password_hash(password: str):
    if len(password) < 6:
        raise HTTPException(
            status_code=400, detail="Password should be atleast 6 characters long")
    return pwd_context.hash(password)


# Verify password using bcrypt
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


# Create User in MongoDB
def create_user(user: dict):
    user["password"] = get_password_hash(user["password"])
    result = db.users.insert_one(user)
    return str(result.inserted_id)

# Update User in MongoDB
def update_user(user: dict):
    user["password"] = get_password_hash(user["password"])
    result = db.users.replace_one({"username": user["username"]}, user)
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
        raise HTTPException(status_code=401, detail="Not Authenticated")
    
    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
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

# User Registration Endpoint
@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserLoginResponse)
async def register(request: Request, response: Response, user: User, username: str = Depends(check_current_user)):
    if username:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return {"username": username}
    
    user.email = user.email.lower()

    # Check if user already exists
    if get_user_by_username(user.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Username already registered")
    if get_user_by_email(user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Email already registered")
    
    if(bool(re.match('^[a-zA-Z0-9]*$',user.username))==False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Username should only contain alphanumeric characters")
    
    try:
        contact = phonenumbers.parse(user.contact, "IN")
        if not phonenumbers.is_valid_number(contact):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid phone number")
    except phonenumbers.phonenumberutil.NumberParseException:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid phone number")
    except Exception:
        raise HTTPException(status_code=500, detail = "An Error Occured!")

    body = await request.body()
    user1 = ast.literal_eval(body.decode())

    # Create User and Set Session
    create_user(user1)

    request.session['username'] = user.username

    return {"username": user.username}

# User Login Endpoint
@router.post("/login", response_model=UserLoginResponse)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), username: str = Depends(check_current_user)):
    if username:
        request.session.pop('username', None)
    
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid username or password", headers={"set-cookie": ""})
    
    # Set Session
    request.session['username'] = user.username

    return {"username": user.username}

# Get Current User Endpoint
@router.get("/details")
async def read_users_me(request: Request, current_user: User = Depends(get_current_user)):
    return current_user

# Get current user or not
@router.get("/current", response_model=UserLoginResponse)
async def check_user(request: Request, username: str = Depends(check_current_user)):
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Unauthorized")
    return {"username": username}

# User Logout
@router.post("/logout")
async def logout(request: Request, current_user: User = Depends(get_current_user)):
    request.session.pop('username', None)
    return {"message": "Logged Out Successfully"}

# Change Password
@router.post("/change-password")
async def change_password(request: Request, passwords: ChangePasswordInput, current_user: User = Depends(get_current_user)):
    user = authenticate_user(current_user.username, passwords.current_password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid password")
    
    hashed_new_password = get_password_hash(passwords.new_password)
    result = db.users.update_one({"username": current_user.username}, {
                        "$set": {"password": hashed_new_password}})
    
    if not result.modified_count:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update password")

    # Set Session
    request.session['username'] = user.username

    return {"message": "Password changed successfully!"}

# User Registration Endpoint
@router.put("/edit", status_code=200)
async def edit(request: Request, response: Response, user: User, current_user: User = Depends(get_current_user)):    
    if user.username != current_user.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Username cannot be changed")

    # Check if user email already exists
    user.email = user.email.lower()
    if user.email != current_user.email and get_user_by_email(user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Email already registered")
    
    try:
        contact = phonenumbers.parse(user.contact, "IN")
        if not phonenumbers.is_valid_number(contact):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid phone number")
    except phonenumbers.phonenumberutil.NumberParseException:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid phone number")
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail = "An Error Occured!")
    
    # Update User and Return Response
    body = await request.body()
    user1 = ast.literal_eval(body.decode())
    changed = update_user(user1)

    if not changed:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update user details")

    return {"message": "User details updated successfully!"}


"""
- Add mailing
- Add forget password API
- Add Google Authentication 
    - https://github.com/kolitiri/fastapi-oidc-react
"""