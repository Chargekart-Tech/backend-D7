from fastapi import APIRouter

from db import db
from models.locations import *
from routers.users import check_current_user

router = APIRouter()
    
# Endpoint to get all parking locations
@router.get("/locations")
def get_locations():
    locations = list(db.locations.find({}, {"_id": 0}))
    if len(locations):
        return ManyLocationsResponse(locations = locations)
    return None
