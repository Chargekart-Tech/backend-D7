from pydantic import BaseModel, Field
from typing import Optional, List
import uuid

# Location Model
class Location(BaseModel):
    locid: str = Field(default_factory=uuid.uuid4)
    name: str
    latitude: float
    longitude: float
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = "India"
    pincode: Optional[int] = None

class ManyLocationsResponse(BaseModel):
    locations: List[Location] | None