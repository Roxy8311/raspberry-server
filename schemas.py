from pydantic import BaseModel
from typing import List

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    is_admin: bool
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
