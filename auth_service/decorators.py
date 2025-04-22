
from functools import wraps
from flask import request, jsonify, current_app, g
import jwt


def token_required(f):
    """
    Decorator to ensure a valid ACCESS JWT is present and load user info into 'g'.
    Checks token type and (optionally) denylist.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            jwt_secret = current_app.config['JWT_SECRET_KEY']
            jwt_algo = current_app.config['JWT_ALGORITHM']
            payload = jwt.decode(
                token,
                jwt_secret,
                algorithms=[jwt_algo],
            )

            # --- Check token type ---
            if payload.get("type") != "access":
                return jsonify({"message": "Invalid token type provided (expected access)"}), 401

            # --- Token is valid and is an access token ---
            g.current_user_id = payload.get("sub")
            g.current_user_role = payload.get("role")

            if g.current_user_id is None or g.current_user_role is None:
                 return jsonify({"message": "Invalid token payload"}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Access token has expired!"}), 401
        except jwt.InvalidTokenError as e:
            current_app.logger.warning(f"Invalid access token received: {e}")
            return jsonify({"message": "Access token is invalid!"}), 401
        except Exception as e:
            current_app.logger.error(f"Error decoding access token: {e}")
            return jsonify({"message": "Error processing token"}), 500

        return f(*args, **kwargs)
    return decorated_function


def refresh_token_required(f):
    """
    Decorator to ensure a valid REFRESH JWT is present in the request body
    and load user id into 'g'. Checks token type and (optionally) denylist.
    (Assumes refresh token is sent in JSON body, e.g., {"refresh_token": "..."})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        token = data.get('refresh_token') if data else None

        if not token:
            return jsonify({"message": "Refresh token is missing in request body!"}), 400 # Bad request

        try:
            jwt_secret = current_app.config['JWT_SECRET_KEY']
            jwt_algo = current_app.config['JWT_ALGORITHM']
            payload = jwt.decode(
                token,
                jwt_secret,
                algorithms=[jwt_algo]
            )

            # --- Check token type ---
            if payload.get("type") != "refresh":
                return jsonify({"message": "Invalid token type provided (expected refresh)"}), 401

            jti = payload.get("jti")
            # --- Token is valid and is a refresh token ---
            g.current_user_id = payload.get("sub") # Only user ID needed usually
            g.current_refresh_token_jti = jti # Store jti for potential denylisting on logout

            if g.current_user_id is None:
                 return jsonify({"message": "Invalid token payload"}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Refresh token has expired!"}), 401
        except jwt.InvalidTokenError as e:
            current_app.logger.warning(f"Invalid refresh token received: {e}")
            return jsonify({"message": "Refresh token is invalid!"}), 401
        except Exception as e:
            current_app.logger.error(f"Error decoding refresh token: {e}")
            return jsonify({"message": "Error processing token"}), 500

        return f(*args, **kwargs)
    return decorated_function

