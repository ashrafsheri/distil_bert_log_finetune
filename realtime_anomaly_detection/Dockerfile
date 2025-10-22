# Multi-stage build for optimized image size
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY realtime_anomaly_detection/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Final stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY realtime_anomaly_detection/api/ ./api/
COPY realtime_anomaly_detection/models/ ./models/
COPY realtime_anomaly_detection/streaming/ ./streaming/

# Copy model artifacts (if not mounting as volume)
# COPY artifacts/ensemble_model_export/ ./artifacts/ensemble_model_export/

# Create necessary directories
RUN mkdir -p /app/artifacts/ensemble_model_export /app/logs

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV MODEL_DIR=/app/artifacts/ensemble_model_export
ENV LOG_LEVEL=INFO

# Run the application
CMD ["python", "-m", "uvicorn", "api.server_adaptive:app", "--host", "0.0.0.0", "--port", "8000"]
