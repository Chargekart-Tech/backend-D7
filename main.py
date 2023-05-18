from fastapi import FastAPI
from os import getenv
from routers import users

DEBUG = getenv("BACKEND_DEBUG", "False").lower() in ("true", "1", "t")

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

# Mount the user router on the "/user" path
app.include_router(users.router, prefix="/user", tags=["User"])
