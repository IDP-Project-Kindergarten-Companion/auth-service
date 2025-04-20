# --- auth_service/utils.py ---
import jwt
import datetime
from passlib.context import CryptContext
from flask import current_app
import uuid

# Setup password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hashes a plain text password."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def create_jwt_token(user_id: str, role: str) -> str:
    """Creates a JWT token containing user ID and role."""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=current_app.config['JWT_EXPIRATION_MINUTES'])
    }
    token = jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config['JWT_ALGORITHM']
    )
    return token


def decode_jwt_token(token: str) -> dict | None:
    """Decodes a JWT token, returns payload or None if invalid/expired."""
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=[current_app.config['JWT_ALGORITHM']]
        )
        return payload
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None



def create_access_token(user_id: str, role: str) -> str:
    """Creates a short-lived JWT access token."""
    secret_key = current_app.config['JWT_SECRET_KEY']
    algorithm = current_app.config['JWT_ALGORITHM']
    expires_delta = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']

    to_encode = {
        "sub": user_id, # 'sub' (subject) is standard claim for user ID
        "role": role,
        "type": "access", # Custom claim to identify token type
        "exp": datetime.datetime.utcnow() + expires_delta,
        "iat": datetime.datetime.utcnow(), # Issued at time
        "jti": str(uuid.uuid4()) # Unique Token Identifier (useful for denylisting)
        # Optional standard claims:
        # "iss": current_app.config.get('JWT_ISSUER'), # Issuer
        # "aud": current_app.config.get('JWT_AUDIENCE') # Audience
    }
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt

def create_refresh_token(user_id: str) -> str:
    """Creates a longer-lived JWT refresh token."""
    secret_key = current_app.config['JWT_SECRET_KEY']
    algorithm = current_app.config['JWT_ALGORITHM']
    expires_delta = current_app.config['JWT_REFRESH_TOKEN_EXPIRES']

    to_encode = {
        "sub": user_id, # Only include minimal necessary info (user ID)
        "type": "refresh", # Custom claim to identify token type
        "exp": datetime.datetime.utcnow() + expires_delta,
        "iat": datetime.datetime.utcnow(),
        "jti": str(uuid.uuid4()) # Unique Token Identifier
    }
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt