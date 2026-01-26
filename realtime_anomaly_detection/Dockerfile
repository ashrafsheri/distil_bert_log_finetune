# Use Python base image with pre-installed ML libraries
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Prevent interactive prompts during apt-get install
ENV DEBIAN_FRONTEND=noninteractive

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies with PyTorch CPU
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch==2.1.0+cpu -f https://download.pytorch.org/whl/torch_stable.html && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY api/ ./api/
COPY models/ ./models/
COPY streaming/ ./streaming/

# Create necessary directories
RUN mkdir -p /app/artifacts/ensemble_model_export /app/logs

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')" || exit 1

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV MODEL_DIR=/app/artifacts/ensemble_model_export
ENV LOG_LEVEL=INFO
ENV ANOMALY_SERVICE_PORT=8001

# Run the application
CMD ["python", "-m", "uvicorn", "api.server_adaptive:app", "--host", "0.0.0.0", "--port", "8001"]