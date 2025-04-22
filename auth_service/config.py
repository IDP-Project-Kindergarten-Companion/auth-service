# --- auth_service/config.py ---
import os
from dotenv import load_dotenv
import datetime

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration class."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a_default_fallback_secret_key')
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/authdb')
    
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'default_jwt_secret_key_needs_change')
    JWT_ALGORITHM = "HS256"

    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=7)
