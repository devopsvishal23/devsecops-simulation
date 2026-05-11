# ============================================================
# Dockerfile — Builds a container image for our TaskManager API
# ============================================================
# A Dockerfile is a set of instructions for building a container image.
# Each line is a layer. Docker builds them top to bottom.

# FROM: Which base image to start from.
# We use python:3.11-slim — a minimal Python image.
# 'slim' means it has fewer packages than the full image = smaller attack surface.
FROM python:3.11-slim

# !! SECURITY WEAKNESS 7: Running as root !!
# By default, Docker containers run as the root user.
# If an attacker breaks out of the app, they have root access inside the container.
# Our container scanner (Trivy) and IaC scanner (Checkov) will catch this.
# The fix is to add a non-root user. We will do this in Session 4.

# WORKDIR: Sets the working directory inside the container.
# All subsequent commands run from this directory.
WORKDIR /app

# COPY requirements first — Docker caches this layer.
# If requirements haven't changed, Docker reuses the cached layer (faster builds).
COPY requirements.txt .

# RUN: Executes a command inside the container during build.
# We install our Python dependencies here.
RUN pip install --no-cache-dir -r requirements.txt

# COPY: Copies files from our machine into the container.
# We copy the entire app directory.
COPY app/ .

# EXPOSE: Documents which port the container listens on.
# This is informational — it doesn't actually open the port.
EXPOSE 5000

# CMD: The command that runs when the container starts.
CMD ["python", "app.py"]
