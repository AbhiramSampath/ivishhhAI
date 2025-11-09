# Stage 1: Builder for AI model dependencies
FROM python:3.11-slim AS builder

# Install OS packages for audio, language processing, and security
RUN apt-get update && apt-get install -y \
    git build-essential ffmpeg wget curl libsndfile1-dev \
    libssl-dev libffi-dev libx11-dev libgl1-mesa-glx \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Pre-copy requirement files to leverage Docker caching
COPY requirements.txt .

# Install dependencies with pip (optimized)
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime Container (slim, secure)
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    UVICORN_WORKERS=4 \
    APP_PORT=8000 \
    APP_MODULE=backend.app.main:app \
    TZ=UTC

# Set working directory
WORKDIR /app

# Install runtime system packages
RUN apt-get update && apt-get install -y \
    ffmpeg libsndfile1 libx11-6 libgl1-mesa-glx \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /usr/local/include /usr/local/include

# Copy application source
COPY . .

# Expose app port
EXPOSE ${APP_PORT}

# Start the FastAPI app with uvicorn
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
