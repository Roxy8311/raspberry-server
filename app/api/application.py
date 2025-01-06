from fastapi import APIRouter, HTTPException, Path, Depends, Request
import jwt

from app.api import crud
from app.api.crud import verify_password
from app.api.models import UserSchema, UserDB, DatabaseSchema, DatabaseDB, DbLinksSchema, DbLinksDB

router = APIRouter()

@router.get("/user/{id}", response_model=UserDB, status_code=200)
async def get_user(id: int = Path(..., gt=0)):
    user = await crud.get_user(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/test")
async def test(request: Request):
    body = await request.json()
    hash = crud.hash_password(body["password"])
    return {"hash": hash}