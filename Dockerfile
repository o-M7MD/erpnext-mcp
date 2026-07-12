# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ src/
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels .
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels mcp httpx uvicorn starlette sse-starlette tenacity

# Stage 2: Final runtime image
FROM python:3.11-slim

# Create a non-root user
RUN useradd -m -s /bin/bash mcpuser

WORKDIR /app

# Install dependencies from wheels
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Copy only the built package (installed in site-packages by pip)
# Actually, since it's installed via wheel, the package is already in site-packages
# We don't need to copy src/ again.

# Change ownership
RUN chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

EXPOSE 8000
ENV PORT=8000

CMD ["erpnext-mcp"]
