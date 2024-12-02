# README

## Project Overview

This project is a FastAPI-based application that provides a RESTful API for user authentication, database management, and table operations. It includes features such as user management, database creation, table manipulation, and entry handling. The system uses SQLite as the database engine and relies on JWT for secure user authentication and authorization.

---

## Features

- **User Authentication:**
  - Login with username and password.
  - Password hashing with bcrypt.
  - Token-based authentication using JWT.

- **User Management:**
  - Admins can create new users.
  - Supports multiple roles (`admin`, `user`, `viewer`).
  - Password change functionality.

- **Database Management:**
  - Create, view, and manage SQLite databases.
  - Permissions based on user roles.

- **Table Operations:**
  - Create tables with specified column configurations.
  - Add, edit, and delete entries within tables.
  - Retrieve table schemas and data.

- **API Security:**
  - Role-based access control for critical operations.
  - Protection against unauthorized access with JWT.

---

## Getting Started

### Prerequisites

- Python 3.9+
- SQLite

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Roxy8311/raspberry-server.git
   cd raspberry-server
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Run the Application

Start the FastAPI server:

```bash
uvicorn main:app --reload
```

Access the API documentation at `http://127.0.0.1:8000/docs`.

---

## API Endpoints

### Authentication

- `POST /token` - Obtain a JWT token with username and password.

### User Management

- `POST /create/user` - Create a new user (Admin only).
- `POST /edit/password` - Change the password of an existing user.

### Database Management

- `POST /create/database` - Create a new database (Admin only).
- `GET /database` - Retrieve the list of databases accessible to the user.

### Table Management

- `POST /database/table` - Create or update a table schema.
- `GET /database/get_table` - Retrieve table information.
- `DELETE /database/table` - Delete a specific table.

### Entry Management

- `POST /database/entry/add` - Add a new entry to a table.
- `POST /database/entry/edit` - Edit an existing table entry.
- `DELETE /database/entry` - Delete a specific entry from a table.

---

## Directory Structure

- `main.py` - Main application file containing all API endpoints and logic.
- `db_user/` - Directory for storing user-created SQLite databases.

---

## API Endpoints and Usage Examples

### 1. **Authentication**

#### `POST /token`
Get a JWT token for authenticated routes.

**Request Body**:
```json
{
  "username": "admin",
  "password": "password"
}
```

**Response**:
```json
{
  "token": "eyJhbGciOi..."
}
```

---

### 2. **User Management**

#### `POST /create/user` (Admin Only)
Create a new user.

**Request Body**:
```json
{
  "name": "new_user",
  "role": "viewer"
}
```

**Headers**:
```
Authorization: Bearer <admin_token>
```

**Response**:
```json
{
  "message": "New user created successfully",
  "user": {
    "id": 2,
    "name": "new_user",
    "role": "viewer",
    "password": "RANDOM1234"
  }
}
```

#### `POST /edit/password`
Change the password for an existing user.

**Request Body**:
```json
{
  "name": "user",
  "old_psk": "old_password",
  "new_psk": "new_password"
}
```

**Response**:
```json
{
  "message": "Password updated successfully",
  "user": {
    "id": 1,
    "name": "user"
  }
}
```

---

### 3. **Database Management**

#### `POST /create/database` (Admin Only)
Create a new database.

**Request Body**:
```json
{
  "db_name": "new_database"
}
```

**Headers**:
```
Authorization: Bearer <admin_token>
```

**Response**:
```json
{
  "message": "New SQLite database created successfully",
  "database": {
    "id": 1,
    "name": "new_database",
    "creator": 1,
    "file_path": "./db_user/new_database.db"
  }
}
```

#### `GET /database`
Retrieve the list of databases accessible by the user.

**Headers**:
```
Authorization: Bearer <user_token>
```

**Response**:
```json
{
  "databases": [
    {
      "id": 1,
      "name": "new_database"
    }
  ]
}
```

---

### 4. **Table Operations**

#### `POST /database/table`
Create or update a table schema.

**Request Body**:
```json
{
  "db_name": "new_database",
  "table_name": "example_table",
  "columns": {
    "column1": "TEXT NOT_NULL",
    "column2": "INTEGER FOREIGN_KEY example_table1.id",
    "column3": "TEXT"
  }
}
```

**Headers**:
```
Authorization: Bearer <user_token>
```

**Response**:
```json
{
  "message": "Table created successfully",
  "database": "new_database",
  "table": "example_table",
  "columns": {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "column1": "TEXT NOT NULL",
    "column2": "INTEGER foreign_key(example_table2.id)",
    "column3": "TEXT"
  }
}
```

#### `GET /database/get_table`
Retrieve information about tables in a database.

**Query Parameters**:
```
db_name=new_database
```

**Headers**:
```
Authorization: Bearer <user_token>
```

**Response**:
```json
{
  "example_table": [
    {
      "name": "id",
      "type": "INTEGER",
      "not_null": true,
      "default_value": null,
      "primary_key": true
    },
    {
      "name": "column1",
      "type": "TEXT",
      "not_null": true,
      "default_value": null,
      "primary_key": false
    }
  ]
}
```

#### `DELETE /database/table`
Delete a table from a database.

**Request Body**:
```json
{
  "db": "new_database",
  "table": "example_table"
}
```

**Headers**:
```
Authorization: Bearer <user_token>
```

**Response**:
```json
{
  "detail": "Table successfully deleted."
}
```

---

### 5. **Entry Management**

#### `POST /database/entry/add`
Add an entry to a table.

**Request Body**:
```json
{
  "db": "new_database",
  "table": "example_table",
  "data": {
    "column1": "Sample Text",
    "column2": 123
  }
}
```

**Headers**:
```
Authorization: Bearer <user_token>
```

**Response**:
```json
{
  "message": "Entry added successfully",
  "database": "new_database",
  "table": "example_table",
  "data": {
    "column1": "Sample Text",
    "column2": 123
  },
  "entry_id": 1
}
```

#### `POST /database/entry/edit`
Edit an existing table entry.

**Request Body**:
```json
{
  "db": "new_database",
  "table": "example_table",
  "id": 1,
  "data": {
    "column1": "Updated Text"
  }
}
```

**Headers**:
```
Authorization: Bearer <user_token>
```

**Response**:
```json
{
  "message": "Entry updated successfully",
  "database": "new_database",
  "table": "example_table",
  "id": 1,
  "updated_data": {
    "column1": "Updated Text"
  }
}
```

#### `DELETE /database/entry`
Delete a specific entry from a table.

**Request Body**:
```json
{
  "db": "new_database",
  "table": "example_table",
  "id": 1
}
```

**Headers**:
```
Authorization: Bearer <user_token>
```

**Response**:
```json
{
  "detail": "Entry successfully deleted."
}
```

---

## Security Considerations

- Ensure the `SECRET_KEY` is kept private.
- Always use HTTPS in production environments.
- Validate all user inputs to avoid SQL injection and other attacks.

---

## License

This project is licensed under the MIT License. See `LICENSE` for more information.

---

## Contributions

Contributions, issues, and feature requests are welcome. Feel free to open an issue or submit a pull request.

## Security Considerations

- Always keep the `SECRET_KEY` secure.
- Use HTTPS in production environments.
- Validate user inputs to prevent SQL injection attacks.

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Contributions

Contributions, issues, and feature requests are welcome! Feel free to open an issue or submit a pull request.