# ============================================================
# Dockerfile — 8TechBank Secure Application
# Task 4.3: Application Sandboxing
# 
# Security design:
#   - Least-privilege non-root user (appuser, UID 1000)
#   - Read-only root filesystem (use Docker run flag --read-only)
#   - Only /tmp is writable (tmpfs mount)
#   - Minimal base image (python:3.11-slim)
#   - No unnecessary packages installed
#   - Resource limits enforced via docker-compose.yml
# ============================================================

FROM python:3.11-slim

# --- Create non-root user (least privilege) ---
RUN groupadd -r appuser && useradd -r -g appuser -u 1000 appuser

# --- Set working directory ---
WORKDIR /app

# --- Install dependencies as root, then lock down ---
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Copy application source ---
COPY src/secure/ ./

# --- Create writable tmp dir owned by appuser ---
RUN mkdir -p /tmp/techbank && chown appuser:appuser /tmp/techbank

# --- Switch to non-root user ---
USER appuser

# --- Expose application port ---
EXPOSE 5001

# --- Environment variables ---
ENV FLASK_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# --- Healthcheck ---
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/')" || exit 1

# --- Entrypoint ---
CMD ["python3", "app.py"]
