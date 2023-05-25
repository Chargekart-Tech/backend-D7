from fastapi import APIRouter, Depends

from db import db
from models.locations import *
from routers.users import check_current_user, get_current_user

router = APIRouter()

def get_parking_location_by_id(id: int):
    try:
        pl = db.locations.find_one({"locid": id}, {"_id": 0})
        if pl:
            return Location(**pl)
        return None
    except Exception:
        return None
    
# Endpoint to get all locations
@router.get("/all")
def get_locations():
    locations = list(db.locations.find({}, {"_id": 0}))
    if len(locations):
        return ManyLocationsResponse(locations = locations)
    return None

# Endpoint to get a particular location details
@router.get("/location/{locid}")
def get_details_locid(locid: int, _: str = Depends(get_current_user)):
    return get_parking_location_by_id(locid)