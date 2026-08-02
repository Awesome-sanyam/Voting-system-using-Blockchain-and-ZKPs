#!/bin/bash

echo "Creating backend directory..."
mkdir -p backend
cd backend

echo "1. Creating Python Virtual Environment..."
python3 -m venv venv

echo "2. Activating Virtual Environment..."
source venv/bin/activate

echo "3. Installing Dependencies..."

# Installing all required packages for Django, WebSockets, Blockchain, and ML

pip install Django djangorestframework channels daphne web3 psycopg2-binary redis python-dotenv scikit-learn

echo "4. Initializing Django Project..."
django-admin startproject core .
python manage.py startapp api

echo "✅ Backend scaffolded successfully!"