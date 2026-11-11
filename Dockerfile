FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PORT=10000
ENV IS_CONTAINERIZED=true

# System tools + Java 17 JRE headless (required for OWASP ZAP)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    tar \
    ca-certificates \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# External Sentinel security scanners (Linux amd64)
ARG NUCLEI_VERSION=3.3.7
ARG TRIVY_VERSION=0.76.2
ARG GITLEAKS_VERSION=8.21.2
ARG ZAP_VERSION=2.17.0

RUN set -eux; \
    mkdir -p /tmp/ext /opt/zap; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/ext/nuclei.zip; \
    unzip -q /tmp/ext/nuclei.zip -d /tmp/ext/nuclei; \
    mv /tmp/ext/nuclei/nuclei /usr/local/bin/nuclei; \
    chmod +x /usr/local/bin/nuclei; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/ext/trivy.tar.gz; \
    tar -xzf /tmp/ext/trivy.tar.gz -C /tmp/ext trivy; \
    mv /tmp/ext/trivy /usr/local/bin/trivy; \
    chmod +x /usr/local/bin/trivy; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/ext/gitleaks.tar.gz; \
    tar -xzf /tmp/ext/gitleaks.tar.gz -C /tmp/ext gitleaks; \
    mv /tmp/ext/gitleaks /usr/local/bin/gitleaks; \
    chmod +x /usr/local/bin/gitleaks; \
    curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Crossplatform.zip" -o /tmp/ext/zap.zip; \
    unzip -q /tmp/ext/zap.zip -d /opt/zap; \
    chmod +x /opt/zap/ZAP_${ZAP_VERSION}/zap.sh; \
    ln -sf /opt/zap/ZAP_${ZAP_VERSION}/zap.sh /usr/local/bin/zap.sh; \
    rm -rf /tmp/ext; \
    nuclei -update-templates -silent || true

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
