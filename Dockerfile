FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PORT=10000

# Install git
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ensure playwright chromium browser is installed
RUN python -m playwright install chromium

# Copy application files
COPY . .

# Expose default port
EXPOSE 10000

# Start server using Gunicorn
CMD ["sh", "-c", "gunicorn app:app --workers 1 --threads 8 --timeout 300 --bind 0.0.0.0:${PORT:-10000}"]
