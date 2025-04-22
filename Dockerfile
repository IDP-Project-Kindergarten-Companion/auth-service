# ==== Stage 1: Build Environment ====
# Use an official Python runtime as a parent image
FROM python:3.11-slim AS builder

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
# This needs to be copied before installing dependencies
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# --no-cache-dir: Disables the cache to keep the image size smaller
# --upgrade pip: Ensures pip is up-to-date
# -r requirements.txt: Installs packages listed in the file
# Note: You can remove 'gunicorn' from requirements.txt if it's there
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code from the current directory (.) into the container at /app
# This copies run.py and the auth_service directory into /app
COPY . /app

# ==== Stage 2: Production Environment ====
# Use a smaller base image for the final production stage
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy installed packages and application code from the builder stage
COPY --from=builder /app /app
# Ensure Python path includes site-packages correctly
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
# Copy executables (like flask)
COPY --from=builder /usr/local/bin /usr/local/bin

# Make port 5051 available to the world outside this container
EXPOSE 5051

# --- Environment Variables for Flask ---
# FLASK_APP tells Flask where your application instance is (in run.py)
ENV FLASK_APP=run.py
# FLASK_RUN_HOST is an alternative way to set the host, covered by --host below
# ENV FLASK_RUN_HOST=0.0.0.0
# Optional: Set Flask environment (e.g., 'production' or 'development')
# ENV FLASK_ENV=production

# --- Command to run the application ---
# Use Flask's built-in development server
# --host=0.0.0.0 makes it accessible outside the container
# --port=5051 matches the EXPOSE directive
CMD ["flask", "run", "--host=0.0.0.0", "--port=5051"]
