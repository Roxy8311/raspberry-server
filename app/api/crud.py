from app.api.models import UserSchema, DatabaseSchema, DbLinksSchema, DbLinksDB
from app.db import users, databases, dbLinks, database
from jose import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def get_user(id: int):
    query = users.select().where(users.c.id == id)
    return await database.fetch_one(query=query)

async def get_user_from_username(username: str):
    query = users.select().where(users.c.name == username)
    return await database.fetch_one(query=query)

async def post_user(payload: UserSchema):
    query = users.insert().values(name=payload.name,
                                  hash=payload.hash,
                                  salt=payload.salt,
                                  role=payload.role)
    return await database.execute(query=query)

async def get_all_users():
    query = users.select()
    return await database.fetch_all(query=query)

async def put_user(id: int, payload: UserSchema):
    query = users.update().where(users.c.id == id).values(name=payload.name,
                                                          hash=payload.hash,
                                                          salt=payload.salt,
                                                          role=payload.role)
    return await database.execute(query=query)

async def del_user(id: int):
    query = users.delete().where(users.c.id == id)
    return await database.execute(query=query)

async def get_database(id: int):
    query = databases.select().where(databases.c.id == id)
    return await database.fetch_one(query=query)

async def post_database(payload: DatabaseSchema):
    query = databases.insert().values(name=payload.name,
                                      creator=payload.creator)
    return await database.execute(query=query)

async def get_all_databases():
    query = databases.select()
    return await database.fetch_all(query=query)

async def put_database(id: int, payload: DatabaseSchema):
    query = databases.update().where(databases.c.id == id).values(name=payload.name,
                                                                  creator=payload.creator)
    return await database.execute(query=query)

async def del_database(id: int):
    query = databases.delete().where(databases.c.id == id)
    return await database.execute(query=query)

async def get_db_links_user(user_id: int):
    query = dbLinks.select().where(dbLinks.c.user_id == user_id)
    return await database.fetch_all(query=query)

async def get_db_links_db(db_id: int):
    query = dbLinks.select().where(dbLinks.c.db_id == db_id)
    return await database.fetch_all(query=query)

async def post_db_links(payload: DbLinksDB):
    query = dbLinks.insert().values(user_id=payload.user_id, db_id=payload.db_id)
    return await database.execute(query=query)

async def del_db_links(user_id: int, db_id: int):
    query = dbLinks.delete().where(dbLinks.c.user_id == user_id).where(dbLinks.c.db_id == db_id)
    return await database.execute(query=query)

async def get_user_by_name(user_name: str):
    query = users.select().where(users.c.name == user_name)
    return await database.fetch_one(query=query)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def verify_jwt_token(token: str, secret_key: str):
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return {"valid": True, "user_id": payload.get("id"), "role": payload.get("role")}
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Token has expired"}
    except jwt.JWTError:
        return {"valid": False, "error": "Invalid token"}


async def create_jwt_token(user_id: int, user_name: str, user_role: str, secret_key: str, expires_in: int = 24) -> str:
    expire_time = datetime.utcnow() + timedelta(hours=expires_in)
    payload = {
        "sub": user_name,
        "id": user_id,
        "role": user_role,
        "exp": expire_time
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")
