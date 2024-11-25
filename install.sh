#!/bin/bash

# Stop on errors
set -e

# Variables
VENV_DIR="myserver-env"
DB_NAME="myappdb"
DB_USER="myappuser"
DB_PASSWORD="securepassword"

echo "Starting setup..."

# Step 1: Install necessary packages (if not already installed)
echo "Installing Python and PostgreSQL packages..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv postgresql postgresql-contrib

# Step 2: Configure PostgreSQL
echo "Configuring PostgreSQL..."
sudo -u postgres psql <<EOF
-- Create database
CREATE DATABASE $DB_NAME;
-- Create user with password
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
-- Grant privileges on database
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
EOF

echo "PostgreSQL setup completed."

# Step 3: Create a Python virtual environment
echo "Creating Python virtual environment in $VENV_DIR..."
python3 -m venv $VENV_DIR

# Step 4: Activate the virtual environment
echo "Activating the virtual environment..."
source $VENV_DIR/bin/activate

# Step 5: Install required Python packages
echo "Installing required Python packages..."
pip install --upgrade pip
pip install fastapi uvicorn psycopg2-binary passlib bcrypt python-jose

echo "Setup completed successfully!"
echo "Database: $DB_NAME"
echo "User: $DB_USER"
echo "Password: $DB_PASSWORD"
echo "To activate the virtual environment, use: source $VENV_DIR/bin/activate"
