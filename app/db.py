import os

from sqlalchemy import (Column, Integer, String, Table, create_engine, MetaData, ForeignKey)
from dotenv import load_dotenv
from databases import Database

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")

# SQLAlchemy
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(50)),
    Column("role", String(50), default="user"),
    Column("hash",String(50))
)

databases = Table(
    "database",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(50)),
    Column("creator", ForeignKey("users.id")),
)

dbLinks = Table(
    "dbLinks",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("db_id", ForeignKey("database.id")),
    Column("user_id", ForeignKey("users.id"))
)

database = Database(DATABASE_URL)
