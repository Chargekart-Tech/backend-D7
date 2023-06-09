from fastapi import APIRouter, Depends, HTTPException, status, Response
from uuid import uuid4

from db import db
from models.locations import *
from routers.users import check_current_user, get_current_user

router = APIRouter()

def get_parking_location_by_id(id: str):
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
# def get_details_locid(locid: int, _: str = Depends(get_current_user)):
def get_details_locid(locid: str):
    location = get_parking_location_by_id(locid)
    if location:
        return location
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Location not found!")

#Endpoint to add a New Location
@router.post("/new-location")
def add_new_location(location: LocationInput, response: Response):
    existing_location = db.locations.find_one({"name": location.name,
                                               "latitude": location.latitude,
                                               "longitude": location.longitude},
                                              {"_id": 0})
    if existing_location:
        response.status_code = 409
        return {"ERROR": "Exact location already exists.", "locid": existing_location["locid"]}
    
    if(location.pincode and len(str(location.pincode)) != 6):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid Pin Code!")
    
    location.locid = str(uuid4())
    db.locations.insert_one(location.dict())
    return {"locid": location.locid}