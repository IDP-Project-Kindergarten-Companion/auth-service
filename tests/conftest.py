# tests/conftest.py
import pytest
from auth_service import create_app

@pytest.fixture(scope='module')
def app():
    """Create and configure a new app instance for each test module."""
    # Create app with testing configuration
    app = create_app()
    app.config.update({
        "TESTING": True,
    })

    yield app

@pytest.fixture(scope='module')
def client(app):
    """A test client for the app."""
    return app.test_client()
