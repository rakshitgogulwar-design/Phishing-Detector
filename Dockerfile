# PhishGuard Production Dockerfile
FROM python:3.11-slim

# Install system dependencies (C++ compilers for ML models)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose FastAPI default port
EXPOSE 8000

# Environment settings
ENV PHISHGUARD_ENV=production
ENV PHISHGUARD_HOST=0.0.0.0
ENV PHISHGUARD_PORT=8000

# Launch Gunicorn with Uvicorn workers
CMD ["uvicorn", "app.backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
