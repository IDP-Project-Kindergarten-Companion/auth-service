
## Auth Service Overview

This Auth Service provides user authentication and authorization functionalities for your application. It handles user registration, login, token generation, and protected route access.

## Features

* User Registration: Allows new users to register with a username, password, role (parent or teacher), email, first name, and last name. Includes validation for input data.
* User Login: Authenticates users based on username and password and returns access and refresh JWT tokens upon successful login.
* JWT-Based Authentication:
    * Access Tokens: Short-lived tokens for resource access.
    * Refresh Tokens: Long-lived tokens for obtaining new access tokens.
* Token Refresh: Issues new access tokens using a valid refresh token.
* Change Password: Allows authenticated users to change their passwords.
* User Information Retrieval: Retrieves information about the currently logged-in user.
* Logout:  Logs out a user. Client should discard tokens.
* Middleware/Decorators: Protects routes, requiring valid access or refresh tokens.
* Password Hashing: Uses `passlib` for secure password hashing.

## Technology Stack

* Flask: A Python web framework.
* PyMongo: A MongoDB driver for Python.
* PyJWT: A Python library for encoding and decoding JWTs.
* passlib: A password hashing library.

## Endpoints

### User Registration

* `POST /auth/register`
* **Parameters:** `username`, `password`, `role`, `email`, `first_name`, `last_name`
* **Returns:** `message`, `user_id` (on success)

### User Login

* `POST /auth/login`
* **Parameters:** `username`, `password`
* **Returns:** `access_token`, `refresh_token`, `user_id`, `role` (on success)

### Token Refresh

* `POST /auth/refresh`
* **Parameters:** `refresh_token`
* **Returns:** `access_token` (on success)

### Change Password

* `POST /auth/change-password`
* **Headers**: `Authorization: Bearer <access_token>`
* **Parameters:** `old_password`, `new_password`
* **Returns:** `message` (on success)

### Get Current User Info

* `GET /auth/me`
*   **Headers**: `Authorization: Bearer <access_token>`
* **Returns:** `message`, `user_id`, `role`, `username`, `email`, `first_name`, `last_name`

### Logout

* `POST /auth/logout`
* **Returns:** `message` (on success)
