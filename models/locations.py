from pydantic import BaseModel
from typing import Optional, List


class Coordinates(BaseModel):
    latitude: float
    longitude: float

# Location Model


class Location(BaseModel):
    locid: str
    title: str
    description: str
    coordinates: Coordinates
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = "India"
    pincode: Optional[int] = None


class ManyLocationsResponse(BaseModel):
    locations: List[Location] | None


class LocationInput(BaseModel):
    locid: Optional[str] = None
    title: str
    description: str
    coordinates: Coordinates
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = "India"
    pincode: Optional[int] = None
