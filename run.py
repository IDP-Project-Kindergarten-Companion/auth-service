# --- run.py (Corrected) ---
from auth_service import create_app

# The Flask CLI (used by 'flask run') automatically detects 'app' or 'create_app'
# You might not even need the line below, but it doesn't hurt
app = create_app()

# This block is only used if you run 'python run.py' directly,
# NOT when using 'flask run' or gunicorn in Docker.
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5051, debug=True)