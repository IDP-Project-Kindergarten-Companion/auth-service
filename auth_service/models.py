# --- auth_service/models.py ---
import datetime # Make sure datetime is imported
from pymongo import MongoClient
from pymongo.uri_parser import parse_uri # Import URI parser
from flask import current_app, g
from bson import ObjectId # Keep ObjectId import

# --- Database Connection Handling (Keep existing get_db, close_db) ---
def get_db():
    """
    Opens a new database connection if there is none yet for the
    current application context. Returns the database object.
    """
    if 'mongo_db' not in g:
        mongo_uri = current_app.config['MONGO_URI']
        uri_dict = parse_uri(mongo_uri)
        db_name = uri_dict.get('database')
        if not db_name:
            raise ValueError(f"Database name not found in MONGO_URI: {mongo_uri}")
        g.mongo_client = MongoClient(mongo_uri)
        g.mongo_db = g.mongo_client[db_name]
    return g.mongo_db

def close_db(e=None):
    """Closes the database connection by closing the client."""
    client = g.pop('mongo_client', None)
    if client is not None:
        client.close()
    g.pop('mongo_db', None)

# --- User Operations ---

def find_user_by_username(username: str) -> dict | None:
    """Finds a user document in the database by username."""
    db = get_db()
    # Ensure you have an index on 'username' in MongoDB for performance
    user = db.users.find_one({"username": username})
    if user:
        user['_id'] = str(user['_id']) # Keep converting ObjectId
    # first_name, last_name will be included automatically if present
    return user

def find_user_by_id(user_id: str) -> dict | None:
    """Finds a user document in the database by their ID string."""
    db = get_db()
    try:
        # Convert string ID back to ObjectId for querying
        obj_id = ObjectId(user_id)
        user = db.users.find_one({"_id": obj_id})
        if user:
            user['_id'] = str(user['_id']) # Convert back for consistency
        # first_name, last_name will be included automatically if present
        return user
    except Exception: # Handle invalid ObjectId format
        return None

# Update save_user signature and add fields to user_data
def save_user(username: str, hashed_password: str, role: str, email: str, first_name: str, last_name: str) -> str:
    """Saves a new user to the database, returns the new user's ID."""
    db = get_db()
    if role not in ['parent', 'teacher']:
        raise ValueError("Invalid role specified")
    if db.users.find_one({"username": username}):
        raise ValueError("Username already exists")
    if email and db.users.find_one({"email": email}):
         raise ValueError("Email already exists")

    user_data = {
        "username": username,
        "password": hashed_password,
        "role": role,
        "email": email,
        "first_name": first_name, # Store first name
        "last_name": last_name,   # Store last name
        "created_at": datetime.datetime.utcnow(),
        "email_verified": False
    }
    result = db.users.insert_one(user_data)
    return str(result.inserted_id)

def update_user_password(user_id: str, new_hashed_password: str) -> bool:
    """Updates the password hash for a given user ID."""
    db = get_db()
    try:
        obj_id = ObjectId(user_id)
        result = db.users.update_one(
            {"_id": obj_id},
            {"$set": {"password": new_hashed_password}}
        )
        # Return True if a document was found and modified
        return result.matched_count > 0
    except Exception:
        return False
