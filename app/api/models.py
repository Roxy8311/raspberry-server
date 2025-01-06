from databases.interfaces import DatabaseBackend
from pydantic import BaseModel, Field

class Config:
    extra = "forbid"


class UserSchema(BaseModel):
    name: str = Field(..., min_length=3, max_length=50)
    role: str = Field(..., min_length=3, max_length=50)
    hash: str = Field(..., min_length=3, max_length=50)
    salt: str = Field(..., min_length=3, max_length=50)

class DatabaseSchema(BaseModel):
    name: str = Field(..., min_length=3, max_length=50)
    creator: int

class DbLinksSchema(BaseModel):
    user_id: int
    db_id: int

class DbLinksDB(DbLinksSchema):
    id: int
    name: str
    creator: str

class UserDB(UserSchema):
    id: int
    name: str
    role: str

class DatabaseDB(DatabaseSchema):
    id: int
    user_id: int
    db_id: int