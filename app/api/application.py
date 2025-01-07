from http.client import responses
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


@router.get("/database/{id}", response_model=DatabaseSchema, status_code=200)
async def get_database(request: Request, id: int = Path(..., gt=0)):
    if not verify_token(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    database = await crud.get_database(id)
    if not database:
        raise HTTPException(status_code=404, detail="Database not found")
    return database


@router.get("/databases", response_model=List[DatabaseSchema], status_code=200)
async def get_all_databases(request: Request):
    if not verify_token(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    authorization_header = request.headers.get("Authorization")
    token_info = await crud.retrieve_token_data(authorization_header[7:])

    if token_info["role"] != "admin":
        links = await crud.get_db_links_user(token_info["id"])
    else:
        links = await crud.get_all_db_links()

    databases = []
    seen_ids = set()

    for link in links:
        db_data = await crud.get_database(link["db_id"])
        if db_data["id"] not in seen_ids:
            seen_ids.add(db_data["id"])
            databases.append(db_data)

    return [DatabaseSchema(**db_data) for db_data in databases]


@router.post("/database/link", response_model=DbLinksSchema, status_code=201)
async def link_user_to_database(request: Request):
    body = await request.json()

    if not verify_token(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    authorization_header = request.headers.get("Authorization")
    token_info = await crud.retrieve_token_data(authorization_header[7:])

    target_user = await crud.get_user(body["user_id"])
    if not target_user:
        raise HTTPException(status_code=404, detail="Target User not found")

    target_db = await crud.get_database(body["db_id"])
    if not target_db:
        raise HTTPException(status_code=404, detail="Target Database not found")

    test_link = await crud.get_db_links(body["user_id"], body["db_id"])
    if test_link:
        raise HTTPException(status_code=403, detail="User already linked to this database")

    if token_info["role"] != "admin":
        link = await crud.get_db_links(token_info["user_id"], body["db_id"])
        if not link:
            raise HTTPException(status_code=403,
                                detail="Forbidden: Only admins and already linked users can link new users to databases")

    try:
        created_link_id = await crud.link_user_to_database(body["user_id"], body["db_id"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error linking user to database: {str(e)}")

    created_link = {
        "id": created_link_id,
        "user_id": body["user_id"],
        "db_id": body["db_id"],
    }

    return DbLinksSchema(**created_link)


@router.post("/database", response_model=DatabaseDB, status_code=201)
async def create_database(request: Request, database: DatabaseSchema):
    if not verify_token(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    authorization_header = request.headers.get("Authorization")
    token_info = await crud.retrieve_token_data(authorization_header[7:])

    if token_info["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Only admins can create databases")

    try:
        database_id = await crud.post_database(database)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating database: {str(e)}")

    created_database = {
        "id": database_id,
        "name": database.name,
        "creator": database.creator,
    }

    return DatabaseDB(**created_database)
