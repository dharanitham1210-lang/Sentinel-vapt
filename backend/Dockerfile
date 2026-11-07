FROM python:3.12-slim

# Prevent python from buffering stdout/stderr and writing bytecode
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

# Install system dependencies including nmap and nikto for live scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root system user and group (security requirement)
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -s /bin/bash -m appuser

WORKDIR /app

# Install python dependencies as root first for clean system-wide install
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application source
COPY . .

# Setup writable directories with proper ownership for non-root user
RUN mkdir -p /app/reports /app/uploads /app/artifacts && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

EXPOSE 8000

# Start Uvicorn bound to 0.0.0.0 on the PORT env var provided by Render
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
