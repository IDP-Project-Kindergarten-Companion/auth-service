# --- auth_service/__init__.py ---
from flask import Flask
from .config import Config
from .routes import auth_bp
from .models import close_db

def create_app():
    """Factory function to create the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Register database teardown function
    app.teardown_appcontext(close_db)

    # Basic root route for health check or info
    @app.route('/')
    def index():
        return "Auth Service Running"

    return app
