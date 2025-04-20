# tests/conftest.py
import pytest
from auth_service import create_app

@pytest.fixture(scope='module')
def app():
    """Create and configure a new app instance for each test module."""
    # Create app with testing configuration
    # You might want a specific test config class in config.py later
    app = create_app() # Assumes create_app handles config loading
    app.config.update({
        "TESTING": True,
        # "MONGO_URI": "mongodb://localhost:27017/authdb",
        # "JWT_SECRET_KEY": "thisisajwtsecretkey"
    })

    yield app

@pytest.fixture(scope='module')
def client(app):
    """A test client for the app."""
    return app.test_client()
