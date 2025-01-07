from typing import Optional

from fastapi import APIRouter, HTTPException, Path, Depends, Request
import jwt

from app.api import crud
from app.api.crud import verify_password
from app.api.models import TokenSchema, UserSchema, UserDB, DatabaseSchema, DatabaseDB, DbLinksSchema, DbLinksDB

router = APIRouter()


def get_jwt_token_from_header(request: Request) -> Optional[str]:
    authorization_header = request.headers.get("Authorization")
    if authorization_header and authorization_header.startswith("Bearer "):
        return authorization_header[7:]
    return None

@router.get("/test_bearer", status_code=200)
async def get_bearer(request: Request):
    token = get_jwt_token_from_header(request)
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    else:
        verify = crud.verify_jwt_token(token)
        return verify["valid"]

@router.get("/user/{id}", response_model=UserDB, status_code=200)
async def get_user(id: int = Path(..., gt=0)):
    user = await crud.get_user(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/hash", status_code=200)
async def test(request: Request):
    body = await request.json()
    hash = crud.hash_password(body["password"])
    return {"hash": hash}

@router.post("/check_token", status_code=200)
async def check_token(request: Request):
    body = await request.json()
    token = body["token"]
    result = crud.verify_jwt_token(token)
    return result["valid"]
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

@router.post("/test_token", status_code=200)
async def test_token(request: Request):
    body = await request.json()
    token = body["token"]
    result = await crud.retrieve_token_data(token)
    return result