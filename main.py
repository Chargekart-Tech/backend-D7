from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from os import getenv
from routers import users, locations

DEBUG = getenv("BACKEND_DEBUG", "False").lower() in ("true", "1", "t")
SESSION_SECRET_KEY = getenv("SESSION_SECRET_KEY", "this_is_my_very_secretive_secret") + "__d7__"

# Create a new FastAPI instance
# FastAPI App
if DEBUG:
    app = FastAPI(
        debug=DEBUG,
        title="ChargeKart",
        description="ChargeKart Backend",
        root_path="/api"
    )
else:
    app = FastAPI(
        debug=DEBUG,
        title="ChargeKart",
        description="ChargeKart Backend",
        docs_url=None,
        redoc_url=None,
        root_path="/api"
    )

# Backend Index Page - For checking purposes
@app.get("/", tags=["General"])
async def index():
    return {"message": "Backend Running!!"}

# Add Session Middleware
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

# Mount the user router on the "/user" path
app.include_router(users.router, prefix="/user", tags=["User"])
app.include_router(locations.router, prefix="/locations", tags=["Locations"])
