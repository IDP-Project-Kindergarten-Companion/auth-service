# tests/test_routes.py
import json
import jwt # Need jwt for mocking decode exceptions
import datetime
from unittest.mock import MagicMock, ANY # Import ANY for flexible argument matching

# Note: We assume utils.hash_password works correctly for these tests.
# You could write separate unit tests just for utils.py functions.

# --- Test Registration ---

def test_register_success(client, mocker):
    """Test successful user registration."""
    # Patch save_user and store the mock object
    mock_save = mocker.patch('auth_service.routes.save_user', return_value="mock_user_id_123")
    # Mock password hashing
    mocker.patch('auth_service.routes.hash_password', return_value="mock_hashed_password")

    user_data = {
        "username": "testuser_reg", "password": "password123", "role": "parent",
        "email": "register@example.com", "first_name": "Test", "last_name": "UserReg"
    }
    response = client.post('/auth/register', json=user_data)

    assert response.status_code == 201
    response_data = response.get_json()
    assert response_data["message"] == "User registered successfully. Please check email for verification."
    assert response_data["user_id"] == "mock_user_id_123"
    # Assert on the stored mock object
    mock_save.assert_called_once_with(
        "testuser_reg", "mock_hashed_password", "parent", "register@example.com", "Test", "UserReg"
    )

def test_register_missing_field(client):
    """Test registration with a missing field."""
    user_data = {
        "password": "password123", "role": "parent", "email": "missing@example.com",
        "first_name": "Test", "last_name": "Missing" # Missing username
    }
    response = client.post('/auth/register', json=user_data)
    assert response.status_code == 400
    assert "Missing required fields: username" in response.get_json()["message"]

def test_register_invalid_email(client):
    """Test registration with an invalid email format."""
    user_data = {
        "username": "testuser_email", "password": "password123", "role": "parent",
        "email": "invalid-email", "first_name": "Test", "last_name": "Email"
    }
    response = client.post('/auth/register', json=user_data)
    assert response.status_code == 400
    assert response.get_json()["message"] == "Invalid email format"

def test_register_user_exists(client, mocker):
    """Test registration when username already exists."""
    mocker.patch('auth_service.routes.hash_password', return_value="mock_hashed_password")
    # Patch save_user to raise the error
    mock_save = mocker.patch('auth_service.routes.save_user', side_effect=ValueError("Username already exists"))

    user_data = {
        "username": "existinguser", "password": "password123", "role": "parent",
        "email": "exists@example.com", "first_name": "Test", "last_name": "Exists"
    }
    response = client.post('/auth/register', json=user_data)
    assert response.status_code == 409 # Conflict
    assert response.get_json()["message"] == "Username already exists"
    # Check it was called (even though it raised an error)
    mock_save.assert_called_once()

# --- Test Login ---

def test_login_success(client, mocker):
    """Test successful user login."""
    mock_user = {
        "_id": "mock_user_id_456", "username": "testuser_login",
        "password": "hashed_password_abc", "role": "teacher",
        "email": "login@example.com", "first_name": "Test", "last_name": "Login"
    }
    # Patch and store mocks
    mock_find_user = mocker.patch('auth_service.routes.find_user_by_username', return_value=mock_user)
    mock_verify_pw = mocker.patch('auth_service.routes.verify_password', return_value=True)
    mock_create_access = mocker.patch('auth_service.routes.create_access_token', return_value="mock_access_token")
    mock_create_refresh = mocker.patch('auth_service.routes.create_refresh_token', return_value="mock_refresh_token")

    login_data = {"username": "testuser_login", "password": "password123"}
    response = client.post('/auth/login', json=login_data)

    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data["access_token"] == "mock_access_token"
    assert response_data["refresh_token"] == "mock_refresh_token"
    assert response_data["user_id"] == "mock_user_id_456"
    assert response_data["role"] == "teacher"
    # Assert calls on stored mocks
    mock_find_user.assert_called_once_with("testuser_login")
    mock_verify_pw.assert_called_once_with("password123", "hashed_password_abc")
    mock_create_access.assert_called_once_with(user_id="mock_user_id_456", role="teacher")
    mock_create_refresh.assert_called_once_with(user_id="mock_user_id_456")


def test_login_wrong_password(client, mocker):
    """Test login with incorrect password."""
    mock_user = { "_id": "mock_user_id_789", "username": "testuser_wrongpw", "password": "hashed_password_def", "role": "parent"}
    mocker.patch('auth_service.routes.find_user_by_username', return_value=mock_user)
    # Patch verify_password to return False
    mock_verify_pw = mocker.patch('auth_service.routes.verify_password', return_value=False)

    login_data = {"username": "testuser_wrongpw", "password": "wrongpassword"}
    response = client.post('/auth/login', json=login_data)

    assert response.status_code == 401 # Unauthorized
    assert response.get_json()["message"] == "Invalid credentials"
    # Check verify_password was called
    mock_verify_pw.assert_called_once_with("wrongpassword", "hashed_password_def")

def test_login_user_not_found(client, mocker):
    """Test login with a username that doesn't exist."""
    # Patch find_user_by_username to return None
    mock_find_user = mocker.patch('auth_service.routes.find_user_by_username', return_value=None)
    # Mock verify_password to check it's NOT called
    mock_verify_pw = mocker.patch('auth_service.routes.verify_password')

    login_data = {"username": "nosuchuser", "password": "password"}
    response = client.post('/auth/login', json=login_data)

    assert response.status_code == 401
    assert response.get_json()["message"] == "Invalid credentials"
    mock_find_user.assert_called_once_with("nosuchuser")
    mock_verify_pw.assert_not_called() # Ensure verify wasn't called if user not found


# --- Test Refresh ---

def test_refresh_success(client, mocker):
    """Test successfully getting a new access token with a refresh token."""
    user_id = "mock_user_id_refresh"
    # Mock jwt.decode called by the decorator
    mock_decode = mocker.patch('auth_service.decorators.jwt.decode', return_value={
        "sub": user_id, "type": "refresh", "jti": "some_jti_refresh"
    })
    # Mock find_user_by_id and store it
    mock_user = {"_id": user_id, "role": "parent"}
    mock_find_user = mocker.patch('auth_service.routes.find_user_by_id', return_value=mock_user)
    # Mock create_access_token and store it
    mock_create_access = mocker.patch('auth_service.routes.create_access_token', return_value="new_mock_access_token")

    response = client.post('/auth/refresh', json={"refresh_token": "dummy_refresh_token"})

    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data["access_token"] == "new_mock_access_token"
    # Assert calls on stored mocks
    mock_decode.assert_called_once()
    mock_find_user.assert_called_once_with(user_id) # Corrected assertion
    mock_create_access.assert_called_once_with(user_id=user_id, role="parent")

def test_refresh_missing_token(client):
    """Test refresh endpoint without providing a refresh token."""
    response = client.post('/auth/refresh', json={})
    assert response.status_code == 400
    assert "Refresh token is missing" in response.get_json()["message"]

def test_refresh_invalid_token(client, mocker):
    """Test refresh with an invalid/expired refresh token."""
    mock_decode = mocker.patch('auth_service.decorators.jwt.decode', side_effect=jwt.ExpiredSignatureError("Token has expired"))

    response = client.post('/auth/refresh', json={"refresh_token": "expired_token"})
    assert response.status_code == 401
    assert "Refresh token has expired!" in response.get_json()["message"]
    mock_decode.assert_called_once() # Check decode was still called

def test_refresh_wrong_token_type(client, mocker):
    """Test refresh with a token that is not a refresh token (e.g., an access token)."""
    mock_decode = mocker.patch('auth_service.decorators.jwt.decode', return_value={
        "sub": "mock_user_id_wrong_type", "type": "access", "jti": "some_jti_wrong_type"
    })

    response = client.post('/auth/refresh', json={"refresh_token": "access_token_used_as_refresh"})
    assert response.status_code == 401
    assert "Invalid token type provided (expected refresh)" in response.get_json()["message"]
    mock_decode.assert_called_once()


# --- Test Change Password ---

def test_change_password_success(client, mocker):
    """Test successfully changing password for a logged-in user."""
    user_id = "user_pass_change_id"
    # Mock decorator effect
    mocker.patch('auth_service.decorators.jwt.decode', return_value={
        "sub": user_id, "role": "parent", "type": "access", "jti": "some_jti_access"
    })
    # Patch and store mocks
    mock_user = {"_id": user_id, "password": "old_hashed_password"}
    mock_find_user = mocker.patch('auth_service.routes.find_user_by_id', return_value=mock_user)
    mock_verify_pw = mocker.patch('auth_service.routes.verify_password', return_value=True)
    mock_hash_pw = mocker.patch('auth_service.routes.hash_password', return_value="new_hashed_password")
    mock_update_pw = mocker.patch('auth_service.routes.update_user_password', return_value=True)

    change_data = {"old_password": "old_password_plain", "new_password": "new_password_plain"}
    headers = {"Authorization": "Bearer dummy_access_token"}
    response = client.post('/auth/change-password', json=change_data, headers=headers)

    assert response.status_code == 200
    assert response.get_json()["message"] == "Password updated successfully"
    # Assert calls on stored mocks
    mock_find_user.assert_called_once_with(user_id)
    mock_verify_pw.assert_called_once_with("old_password_plain", "old_hashed_password") # Corrected assertion
    mock_hash_pw.assert_called_once_with("new_password_plain")
    mock_update_pw.assert_called_once_with(user_id, "new_hashed_password")

def test_change_password_wrong_old_password(client, mocker):
    """Test changing password with incorrect old password."""
    user_id = "user_pass_change_id_wrong"
    mocker.patch('auth_service.decorators.jwt.decode', return_value={
        "sub": user_id, "role": "parent", "type": "access", "jti": "some_jti_access_wrong"
    })
    mock_user = {"_id": user_id, "password": "old_hashed_password"}
    mocker.patch('auth_service.routes.find_user_by_id', return_value=mock_user)
    # Patch verify_password to return False
    mock_verify_pw = mocker.patch('auth_service.routes.verify_password', return_value=False)
    mock_update_pw = mocker.patch('auth_service.routes.update_user_password')

    change_data = {"old_password": "incorrect_old_password", "new_password": "new_password_plain"}
    headers = {"Authorization": "Bearer dummy_access_token"}
    response = client.post('/auth/change-password', json=change_data, headers=headers)

    assert response.status_code == 401
    assert response.get_json()["message"] == "Incorrect old password"
    mock_verify_pw.assert_called_once_with("incorrect_old_password", "old_hashed_password")
    mock_update_pw.assert_not_called()

def test_change_password_missing_field(client, mocker):
    """Test changing password with missing fields."""
    user_id = "user_pass_change_id_missing"
    mocker.patch('auth_service.decorators.jwt.decode', return_value={
        "sub": user_id, "role": "parent", "type": "access", "jti": "some_jti_access_missing"
    })

    change_data = {"old_password": "old_password_plain"}
    headers = {"Authorization": "Bearer dummy_access_token"}
    response = client.post('/auth/change-password', json=change_data, headers=headers)

    assert response.status_code == 400
    assert "Missing old_password or new_password" in response.get_json()["message"]

def test_change_password_no_token(client):
    """Test accessing change password without a token."""
    change_data = {"old_password": "old_password_plain", "new_password": "new_password_plain"}
    response = client.post('/auth/change-password', json=change_data)
    assert response.status_code == 401
    assert "Token is missing" in response.get_json()["message"]


# --- Test Get Current User (/me) ---

def test_get_me_success(client, mocker):
    """Test successfully getting current user details."""
    user_id = "user_me_id"
    mock_payload = {
        "sub": user_id, "role": "teacher", "type": "access", "jti": "some_jti_me"
    }
    mocker.patch('auth_service.decorators.jwt.decode', return_value=mock_payload)
    mock_user = {
        "_id": user_id, "username": "me_user", "role": "teacher",
        "email": "me@example.com", "first_name": "MeFirst", "last_name": "MeLast"
    }
    # Patch find_user_by_id and store it
    mock_find_user = mocker.patch('auth_service.routes.find_user_by_id', return_value=mock_user)

    headers = {"Authorization": "Bearer dummy_access_token"}
    response = client.get('/auth/me', headers=headers)

    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data["user_id"] == user_id
    assert response_data["role"] == "teacher"
    assert response_data["username"] == "me_user"
    # ... check other fields ...
    # Assert call on stored mock
    mock_find_user.assert_called_once_with(user_id) # Corrected assertion

def test_get_me_no_token(client):
    """Test accessing /me without a token."""
    response = client.get('/auth/me')
    assert response.status_code == 401
    assert "Token is missing" in response.get_json()["message"]

def test_get_me_invalid_token(client, mocker):
    """Test accessing /me with an invalid token."""
    mock_decode = mocker.patch('auth_service.decorators.jwt.decode', side_effect=jwt.InvalidTokenError("Invalid token"))
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get('/auth/me', headers=headers)
    assert response.status_code == 401
    assert "Access token is invalid" in response.get_json()["message"]
    mock_decode.assert_called_once() # Check decode was called

# --- Test Logout ---

def test_logout_simple(client):
    """Test the simple logout endpoint."""
    response = client.post('/auth/logout')

    assert response.status_code == 200
    assert response.get_json()["message"] == "Logout successful. Please discard tokens locally."

