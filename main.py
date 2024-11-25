import hashlib
import jwt
from typing import Union
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Secret key for signing and verifying JWT tokens
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')

# Fake users database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": hashlib.sha256("secret".encode()).hexdigest(),
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": hashlib.sha256("secret2".encode()).hexdigest(),
        "disabled": True,
    },
}

app = FastAPI()

def hash_string(input_string: str, algorithm: str = 'sha256') -> str:
    """
    Hash a string using the specified hashing algorithm.

    Args:
        input_string (str): The string to be hashed.
        algorithm (str): The hashing algorithm to use ('md5', 'sha1', 'sha256', etc.). Default is 'sha256'.

    Returns:
        str: The hexadecimal representation of the hash.
    """
    try:
        hasher = hashlib.new(algorithm)
        hasher.update(input_string.encode('utf-8'))
        return hasher.hexdigest()
    except ValueError as e:
        return f"Error: {e}"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool = False

class UserInDB(User):
    hashed_password: str

def get_user(db, username: str) -> Union[UserInDB, None]:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

def decode_token(token: str) -> Union[dict, None]:
    """
    Decode and validate a JWT token.

    Args:
        token (str): The JWT token.

    Returns:
        dict: The decoded payload if the token is valid.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

def create_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Create a new JWT token.

    Args:
        data (dict): The payload data to include in the token.
        expires_delta (timedelta | None): Expiration time for the token.

    Returns:
        str: The encoded JWT token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(fake_users_db, form_data.username)
    if not user or user.hashed_password != hash_string(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is disabled",
        )
    access_token = create_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = get_user(fake_users_db, username)
    if user is None:
        raise HTTPException(status_code=400, detail="User not found")
    return user
