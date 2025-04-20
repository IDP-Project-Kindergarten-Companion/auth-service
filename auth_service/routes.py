# --- auth_service/routes.py ---
from flask import Blueprint, request, jsonify, g, current_app
# Import new functions/decorators
from .utils import hash_password, verify_password, create_access_token, create_refresh_token
from .models import find_user_by_username, find_user_by_id, save_user, update_user_password
# Import new decorator if created separately, or just use token_required
from .decorators import token_required, refresh_token_required
import traceback
import re # Import regex for more robust email validation

auth_bp = Blueprint('auth', __name__)

# Simple regex for basic email format validation
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

@auth_bp.route('/register', methods=['POST'])
def register():
    """Registers a new user. Requires email, first_name, last_name now."""
    data = request.get_json()
    required_fields = ['username', 'password', 'role', 'email', 'first_name', 'last_name']

    # Check for missing fields
    missing_fields = [field for field in required_fields if not data or not data.get(field)]
    if missing_fields:
        return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}"}), 400

    username = data['username']
    password = data['password']
    role = data.get('role').lower()
    email = data['email']
    first_name = data['first_name']
    last_name = data['last_name']

    # --- Input Validation ---
    if role not in ['parent', 'teacher']:
        return jsonify({"message": "Invalid role. Must be 'parent' or 'teacher'."}), 400

    # Basic validation for names (non-empty strings)
    if not isinstance(first_name, str) or len(first_name.strip()) == 0:
        return jsonify({"message": "First name must be a non-empty string"}), 400
    if not isinstance(last_name, str) or len(last_name.strip()) == 0:
        return jsonify({"message": "Last name must be a non-empty string"}), 400

    # Basic email format validation using regex
    if not re.match(EMAIL_REGEX, email):
         return jsonify({"message": "Invalid email format"}), 400
    # --- End Input Validation ---

    try:
        hashed = hash_password(password)
        # Pass all fields to save_user
        user_id = save_user(username, hashed, role, email, first_name.strip(), last_name.strip())
        # Consider sending verification email here
        return jsonify({"message": "User registered successfully. Please check email for verification.", "user_id": user_id}), 201
    except ValueError as e: # Catches username/email exists errors from save_user
        return jsonify({"message": str(e)}), 409
    except Exception as e:
        current_app.logger.error(f"Registration error: {e}\n{traceback.format_exc()}")
        return jsonify({"message": "An internal error occurred during registration"}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """Logs in a user and returns ACCESS and REFRESH tokens."""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    user = find_user_by_username(username)
    if not user or not verify_password(password, user['password']):
        return jsonify({"message": "Invalid credentials"}), 401

    try:
        # Create both tokens
        access_token = create_access_token(user_id=user['_id'], role=user['role'])
        refresh_token = create_refresh_token(user_id=user['_id'])

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user['_id'],
            "role": user['role']
        }), 200
    except Exception as e:
        current_app.logger.error(f"Login error - token creation failed: {e}\n{traceback.format_exc()}")
        return jsonify({"message": "An internal error occurred during login"}), 500


@auth_bp.route('/refresh', methods=['POST'])
@refresh_token_required # Use the new decorator to validate the refresh token
def refresh():
    """Provides a new access token using a valid refresh token."""
    current_user_id = g.current_user_id
    user = find_user_by_id(current_user_id)
    if not user:
         return jsonify({"message": "User not found"}), 401

    try:
        new_access_token = create_access_token(user_id=user['_id'], role=user['role'])
        return jsonify({"access_token": new_access_token}), 200
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {e}\n{traceback.format_exc()}")
        return jsonify({"message": "An internal error occurred during token refresh"}), 500


@auth_bp.route('/change-password', methods=['POST'])
@token_required # User must be logged in (valid access token)
def change_password():
    """Allows a logged-in user to change their password."""
    user_id = g.current_user_id
    data = request.get_json()
    if not data or not data.get('old_password') or not data.get('new_password'):
        return jsonify({"message": "Missing old_password or new_password"}), 400

    old_password = data['old_password']
    new_password = data['new_password']

    if len(new_password) < 8:
         return jsonify({"message": "New password must be at least 8 characters long"}), 400

    user = find_user_by_id(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    if not verify_password(old_password, user['password']):
        return jsonify({"message": "Incorrect old password"}), 401

    try:
        new_hashed_password = hash_password(new_password)
        success = update_user_password(user_id, new_hashed_password)
        if success:
            return jsonify({"message": "Password updated successfully"}), 200
        else:
             return jsonify({"message": "Failed to update password"}), 500
    except Exception as e:
        current_app.logger.error(f"Change password error: {e}\n{traceback.format_exc()}")
        return jsonify({"message": "An internal error occurred"}), 500


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    Simple logout endpoint. Returns success and relies on the client
    to discard the stored access and refresh tokens.
    """
    return jsonify({"message": "Logout successful. Please discard tokens locally."}), 200


# Update /me route to return names
@auth_bp.route('/me', methods=['GET'])
@token_required # Uses the updated decorator that checks for access token
def get_current_user():
    """Returns info about the logged-in user."""
    user_id = getattr(g, 'current_user_id', None)
    role = getattr(g, 'current_user_role', None)

    if not user_id or not role:
         return jsonify({"message": "Could not identify user from token"}), 401

    user = find_user_by_id(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Return more user details
    return jsonify({
        "message": "Token is valid",
        "user_id": user_id,
        "role": role,
        "username": user.get('username'),
        "email": user.get('email'),
        "first_name": user.get('first_name'),
        "last_name": user.get('last_name')
    }), 200

