from pydantic import BaseModel
from typing import Optional, List

# Location Model
class Location(BaseModel):
    locid: str
    latitude: str
    longitude: str
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = "India"
    pincode: Optional[str] = None
    name: str
