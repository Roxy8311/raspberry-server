from databases.interfaces import DatabaseBackend
from pydantic import BaseModel, Field

class Config:
    extra = "forbid"


class UserSchema(BaseModel):
    name: str = Field(..., min_length=3, max_length=50)
    role: str = Field(..., min_length=3, max_length=50)
    hash: str = Field(..., min_length=3, max_length=100)

class DatabaseSchema(BaseModel):
    name: str = Field(..., min_length=3, max_length=50)
    creator: int

class DbLinksSchema(BaseModel):
    user_id: int = Field(..., min_length=3, max_length=50)
    db_id: int

class DbLinksDB(DbLinksSchema):
    id: int
    name: str = Field(..., min_length=3, max_length=50)
    creator: str = Field(..., min_length=3, max_length=50)

class UserDB(UserSchema):
    id: int
    name: str = Field(..., min_length=3, max_length=50)
    role: str

class DatabaseDB(DatabaseSchema):
    id: int
    user_id: int
    db_id: int

class TokenSchema(BaseModel):
    token: str