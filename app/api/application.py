from typing import Optional, List
from urllib import request

from fastapi import APIRouter, HTTPException, Path, Depends, Request
import jwt

from app.api import crud
from app.api.crud import verify_password
from app.api.models import UserNoHash, TokenSchema, UserSchema, UserDB, DatabaseSchema, DatabaseDB, DbLinksSchema, DbLinksDB

router = APIRouter()


def verify_token(request: Request):
    authorization_header = request.headers.get("Authorization")
    if not authorization_header and authorization_header.startswith("Bearer "):
        return False
    verify = crud.verify_jwt_token(authorization_header[7:])
    return verify["valid"]


@router.get("/user/{id}", response_model=UserNoHash, status_code=200)
async def get_user(request: Request, id: int = Path(..., gt=0)):
    if not verify_token(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    user = await crud.get_user(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@router.get("/users", response_model=List[UserNoHash], status_code=200)
async def get_all_user(request: Request):
    if not verify_token(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    users = await crud.get_all_users()
    return [UserNoHash(**dict(user)) for user in users]


@router.post("/hash", status_code=200)
async def test(request: Request):
    body = await request.json()
    hash = crud.hash_password(body["password"])
    return {"hash": hash}


@router.post("/login", response_model=TokenSchema, status_code=200)
async def login(request: Request):
    body = await request.json()
    name = body.get("name")
    password = body.get("password")

    if not name or not password:
        raise HTTPException(status_code=400, detail="Name and password are required")

    user = await crud.get_user_by_name(name)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password, user["hash"]):
        raise HTTPException(status_code=400, detail="Incorrect password")

    token = await crud.create_jwt_token(user_id=user["id"], user_name=user["name"], user_role=user["role"])
    return {"token": token}
