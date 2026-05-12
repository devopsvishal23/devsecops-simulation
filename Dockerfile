# ============================================================
# Dockerfile — Secure version
# ============================================================
# SECURITY FIXES APPLIED IN SESSION 4:
# - Non-root user added (fixes Trivy CIS-DI-0001)
# - HEALTHCHECK added
# - Read-only filesystem recommended via runtime flag
# ============================================================

FROM python:3.11-slim

# FIXED: Create a non-root user and group
# Containers should never run as root — if an attacker
# compromises the app, they only get the app user's permissions,
# not root access to the host system.
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/sh --create-home appuser

WORKDIR /app

# Copy and install dependencies as root (needed for pip install)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ .

# Change ownership of app files to our non-root user
RUN chown -R appuser:appgroup /app

# FIXED: Switch to non-root user before running the application
# All subsequent commands and the final CMD run as appuser
USER appuser

EXPOSE 5000

# ADDED: Health check so Docker knows if the app is healthy
# Docker will restart the container if health checks fail
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["python", "app.py"]
