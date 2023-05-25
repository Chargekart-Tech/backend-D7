from pydantic import BaseModel
from typing import Optional, List

# Location Model
class Location(BaseModel):
    locid: str
    name: str
    latitude: float
    longitude: float
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = "India"
    pincode: Optional[int] = None

class ManyLocationsResponse(BaseModel):
    locations: List[Location] | None

class LocationInput(BaseModel):
    locid: Optional[str] = None
    name: str
    latitude: float
    longitude: float
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = "India"
    pincode: Optional[int] = None