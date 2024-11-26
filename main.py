from fastapi import Depends, FastAPI, HTTPException, status, Request, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Field, Session, SQLModel, create_engine, select
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Annotated, Dict, List, Any
from datetime import datetime, timedelta
from pydantic import BaseModel
import os
import sqlite3

app = FastAPI()

class User(SQLModel, table=True):
    __tablename__ = "User"
    id: int = Field(primary_key=True)
    name: str = Field(index=True)
    hash: str = Field(index=False)
    salt: str = Field(index=False)
    role: str = Field(index=True, default="viewer")

class Db(SQLModel, table=True):
    __tablename__ = "Db"
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    creator: int = Field(index=True, foreign_key="User.id")
    path: str = Field(index=True)

class DbLink(SQLModel, table=True):
    __tablename__ = "DbLink"
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="User.id")
    db_id: int = Field(index=True, foreign_key="Db.id")

class CreateDbRequest(BaseModel):
    db_name: str

class CreateTableRequest(BaseModel):
    db_name: str
    table_name: str
    columns: dict

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    db_session = Session(engine)
    try:
        yield db_session
    finally:
        db_session.close()

SessionDep = Annotated[Session, Depends(get_session)]

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    return pwd_context.verify(password + salt, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    with Session(engine) as session:
        test_user = User(
            name="testuser",
            hash=pwd_context.hash("testpassword" + "testsalt"),
            salt="testsalt",
            role="admin"
        )
        session.add(test_user)
        session.commit()

def extract_token(request: Request):
    """Extract the token directly from the Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth_header.strip()

def verify_token(token: Annotated[str, Depends(extract_token)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        identification: int = payload.get("id")
        if username is None or role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user information",
                headers={"WWW-Authenticate": "Bearer"},
            )
        print(payload)
        return {"name": username, "role": role, "id": identification}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_user_database_list(user_id: int, user_role: str, session: SessionDep):
    if user_role == "admin":
        statement_link = select(DbLink)
    else :
        statement_link = select(DbLink).where(DbLink.user_id == user_id)

    db_links = session.exec(statement_link).all()

    database_list = []
    for link in db_links:
        statement_db = select(Db).where(Db.id == link.db_id)
        db_entry = session.exec(statement_db).first()
        if db_entry:
            database_list.append({"id": db_entry.id, "name": db_entry.name})

    return database_list


@app.get("/database")
def get_database_user(session: SessionDep, payload: dict = Depends(verify_token)):
    user_id = payload["id"]
    user_role = payload["role"]

    database_list = get_user_database_list(user_id, user_role, session)

    return {"databases": database_list}


@app.post("/token")
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep):
    statement = select(User).where(User.name == form_data.username)
    user = session.exec(statement).first()

    if not user or not verify_password(form_data.password, user.hash, user.salt):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.name, "role": user.role, "id": user.id}, expires_delta=access_token_expires
    )

    return {"token": access_token}
    return {"token": access_token}

@app.post("/create/database")
def create_db(
    session: SessionDep,
    payload: dict = Depends(verify_token),
    body: CreateDbRequest = Body(...)
):
    if payload["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="UNAUTHORIZED: You do not have permission to create ANY database. Ask an Admin to do so.",
        )
    user_id = payload["id"]
    db_name = body.db_name

    if not db_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database name must be provided",
        )

    # Check if the database name already exists in the Db table
    existing_db = session.exec(select(Db).where(Db.name == db_name)).first()
    if existing_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database name already exists",
        )

    # Ensure the ./db_user directory exists
    db_user_dir = "./db_user"
    os.makedirs(db_user_dir, exist_ok=True)

    # Path to the new SQLite file
    new_db_path = os.path.join(db_user_dir, f"{db_name}.db")

    # Add entry in Db table with the file path
    new_db = Db(name=db_name, creator=user_id, path=new_db_path)
    session.add(new_db)
    session.commit()
    session.refresh(new_db)

    # Create a new SQLite file for the schema
    try:
        conn = sqlite3.connect(new_db_path)
        conn.execute("CREATE TABLE example_table (id INTEGER PRIMARY KEY, name TEXT)")
        conn.close()
    except Exception as e:
        session.delete(new_db)  # Rollback Db entry if file creation fails
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating new SQLite file: {str(e)}"
        )

    # Link the creator user to the new database
    db_link = DbLink(user_id=user_id, db_id=new_db.id)
    session.add(db_link)
    session.commit()

    return {
        "message": "New SQLite database created successfully",
        "database": {
            "id": new_db.id,
            "name": new_db.name,
            "creator": new_db.creator,
            "file_path": new_db_path
        }
    }


@app.post("/create/table")
def create_table_in_db(
    request: CreateTableRequest,
    session: SessionDep,
    payload: dict = Depends(verify_token),
):
    """
    Create a table inside the specified database.

    Args:
        request (CreateTableRequest): Contains db_name, table_name, and columns.
        session (SessionDep): Database session.
        payload (dict): The JWT payload to ensure the user is authenticated.

    Returns:
        A success message with details of the created table.
    """
    db_name = request.db_name
    table_name = request.table_name
    columns = request.columns

    if(payload['role'] == "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="UNAUTHORIZED: You do not have permission to edit ANY database as a Viewer",
        )

    statement_db = select(Db).where(Db.name == db_name)
    db = session.exec(statement_db).first()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid Database Name: Database not found.",
        )

    statement_dblink = select(DbLink).where(DbLink.user_id == payload["id"]).where(DbLink.db_id == db.id)
    dblink = session.exec(statement_dblink).first()
    if dblink is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="UNAUTHORIZED: You do not have permission to edit this database.",
        )

    db_user_dir = "./db_user"
    db_path = os.path.join(db_user_dir, f"{db_name}.db")

    if not os.path.exists(db_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Database file {db_name}.db does not exist.",
        )

    columns_with_id = {"id": "INTEGER PRIMARY KEY AUTOINCREMENT"}
    columns_with_id.update(columns)

    column_definitions = ", ".join([f"{col} {dtype}" for col, dtype in columns_with_id.items()])
    create_table_sql = f'CREATE TABLE IF NOT EXISTS "{table_name}" ({column_definitions});'

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}';")
        table_exists = cursor.fetchone()

        if table_exists:
            max_old_levels = 5
            for i in range(1, max_old_levels + 1):
                next_table_name = f"{table_name}{'-old' * i}"
                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{next_table_name}';")
                if cursor.fetchone() is None:
                    cursor.execute(f'ALTER TABLE "{table_name}" RENAME TO "{next_table_name}";')
                    break
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot create new table: Maximum of {max_old_levels} -old versions reached.",
                )

            cursor.execute(create_table_sql)

            cursor.execute(f"PRAGMA table_info('{next_table_name}');")
            old_table_columns = [row[1] for row in cursor.fetchall()]
            common_columns = [col for col in old_table_columns if col in columns_with_id]

            if common_columns:
                columns_str = ", ".join(common_columns)
                cursor.execute(f'INSERT INTO "{table_name}" ({columns_str}) SELECT {columns_str} FROM "{next_table_name}";')

        else:
            cursor.execute(create_table_sql)

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating or updating table: {str(e)}",
        )

    return {
        "message": "Table created successfully (or updated if it already existed)",
        "database": db_name,
        "table": table_name,
        "columns": columns_with_id,
    }

@app.get("/database/get_table", response_model=Dict[str, List[Dict[str, Any]]])
def get_table_list(
    db_name: str,
    session: SessionDep,
    payload: dict = Depends(verify_token),
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get a list of all tables in a specified database along with their columns.

    Args:
        db_name (str): The name of the database.
        session (SessionDep): Database session.
        payload (dict): The JWT payload to ensure the user is authenticated.

    Returns:
        A dictionary containing each table and its column details.
    """

    statement_db = select(Db).where(Db.name == db_name)
    db = session.exec(statement_db).first()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid Database Name: Database not found.",
        )

    statement_dblink = select(DbLink).where(DbLink.user_id == payload["id"]).where(DbLink.db_id == db.id)
    dblink = session.exec(statement_dblink).first()
    if dblink is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="UNAUTHORIZED: You do not have permission to view this database.",
        )

    db_user_dir = "./db_user"
    db_path = os.path.join(db_user_dir, f"{db_name}.db")

    if not os.path.exists(db_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Database file {db_name}.db does not exist.",
        )

    tables_with_columns = {}
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            cursor.execute(f"PRAGMA table_info('{table}');")
            columns = [
                {
                    "name": row[1],
                    "type": row[2],
                    "not_null": bool(row[3]),
                    "default_value": row[4],
                    "primary_key": bool(row[5]),
                }
                for row in cursor.fetchall()
            ]
            tables_with_columns[table] = columns

        conn.close()
    except sqlite3.Error as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving tables and columns: {str(e)}",
        )

    return tables_with_columns





