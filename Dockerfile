# --- Stage 1: Build the frontend ---
FROM node:20-slim AS frontend-builder
WORKDIR /build

# Copy frontend configuration and install dependencies
COPY frontend/package*.json ./
RUN npm install

# Copy frontend source and build
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Final image ---
FROM python:3.14-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    gzip \
    && rm -rf /var/lib/apt/lists/*

# Install step CLI
ENV STEP_VERSION=0.30.2
RUN curl -LO https://github.com/smallstep/cli/releases/download/v${STEP_VERSION}/step_linux_${STEP_VERSION}_amd64.tar.gz \
    && tar -xf step_linux_${STEP_VERSION}_amd64.tar.gz \
    && cp step_${STEP_VERSION}/bin/step /usr/local/bin/ \
    && rm -rf step_linux_${STEP_VERSION}_amd64.tar.gz step_${STEP_VERSION}

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Setup appuser
RUN useradd -m -s /bin/bash appuser

WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy project configuration
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY . .

# Copy built frontend assets from the builder stage
# Vite build puts files in ../static relative to frontend/ (so /static in our final image)
COPY --from=frontend-builder /static ./static

# Ensure appuser owns the app directory
RUN chown -R appuser:appuser /app

USER appuser

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/ || exit 1

EXPOSE 8000

# Use the virtual environment created by uv
ENV PATH="/app/.venv/bin:$PATH"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
