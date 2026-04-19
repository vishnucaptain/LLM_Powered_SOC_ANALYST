# Use slim Python 3.11 image for smaller footprint and faster builds
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (minimal for CPU-only setup)
# libpq-dev is included if PostgreSQL client needed in future
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
# Use --no-cache-dir to reduce image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 socanal && chown -R socanal:socanal /app
USER socanal

# Health check to ensure container is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port 8000 (FastAPI default)
EXPOSE 8000

# Start FastAPI application with Uvicorn
# Workers set to 1 for MacBook/low-resource environments
# Can increase for production: --workers 4
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
