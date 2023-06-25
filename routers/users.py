from fastapi import APIRouter, HTTPException, Depends, Response, Request, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import re
import ast

from models.users import *
from utils.users import *

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# User Registration Endpoint
@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserLoginResponse)
async def register(request: Request, response: Response, user: User, username: str = Depends(check_current_user)):
    if username:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return {"username": username}
    
    user.email = user.email.lower()

    # Check if user already exists
    if get_user_by_username(user.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Username already registered")
    if get_user_by_email(user.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Email already registered")
    
    if(bool(re.match('^[a-zA-Z0-9]*$',user.username))==False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Username should only contain alphanumeric characters")
    
    check_phone_number(user.contact)

    body = await request.body()
    user1 = ast.literal_eval(body.decode())

    # Create User and Set Session
    create_user(user1)

    request.session['username'] = user.username

    return {"username": user.username}

# User Login Endpoint
@router.post("/login", status_code=status.HTTP_200_OK, response_model=UserLoginResponse)
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
    
    update_user_password(current_user.username, passwords.new_password)

    # Set Session
    request.session['username'] = user.username

    return {"message": "Password changed successfully!"}

# User Registration Endpoint
@router.put("/edit", status_code=status.HTTP_200_OK)
async def edit(request: Request, response: Response, user: User, current_user: User = Depends(get_current_user)):    
    if user.username != current_user.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Username cannot be changed")

    # Check if user email already exists
    user.email = user.email.lower()
    if user.email != current_user.email and get_user_by_email(user.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Email already registered")
    
    check_phone_number(user.contact)
    
    # Update User and Return Response
    body = await request.body()
    user1 = ast.literal_eval(body.decode())
    changed = update_user(user1)

    if not changed:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update user details")

    return {"message": "User details updated successfully!"}


"""
- Add sentry for performance monitoring
    - https://docs.sentry.io/platforms/python/guides/fastapi/?original_referrer=https%3A%2F%2Ffastapi.tiangolo.com%2F
- Remove JWT Token from main env file
- Add mailing
- Add forget password API
- Add Google Authentication 
    - https://github.com/kolitiri/fastapi-oidc-react
"""