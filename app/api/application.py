from fastapi import APIRouter, HTTPException, Path, Depends
import jwt

from app.api import crud
from app.api.crud import verify_password
from app.api.models import UserSchema, UserDB, DatabaseSchema, DatabaseDB, DbLinksSchema, DbLinksDB

router = APIRouter()

SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"

@router.get("/user/{id}", response_model=UserDB, status_code=200)
async def get_user(id: int = Path(..., gt=0)):
    user = await crud.get_user(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/login", status_code=200)
async def login(username: str, password: str):
    user = await crud.get_user_by_name(username)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_payload = {"sub": user.username}
    token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

