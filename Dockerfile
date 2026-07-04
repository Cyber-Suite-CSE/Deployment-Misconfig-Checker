FROM python:3.11-alpine

WORKDIR /app

# Copy requirements FIRST to use them in the single run command
COPY requirements.txt .
COPY . .

# Install EVERYTHING in one RUN command to minimize layers and ensure cleanup
RUN apk add --no-cache \
    # Runtime Dependencies
    nmap \
    nmap-scripts \
    masscan \
    ruby \
    perl \
    libcurl \
    libffi \
    libxml2 \
    libxslt \
    git \
    bash \
    # Build Dependencies (virtual)
    && apk add --no-cache --virtual .build-deps \
    build-base \
    ruby-dev \
    libffi-dev \
    python3-dev \
    openssl-dev \
    libxml2-dev \
    libxslt-dev \
    curl-dev \
    linux-headers \
    # Install Python dependencies
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    # Install WPScan
    && gem install wpscan --no-document \
    # Install Nikto
    && git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && ln -s /opt/nikto/program/nikto.conf /etc/nikto.conf \
    # Cleanup Build Deps
    && apk del .build-deps \
    # Cleanup Caches and Temp Files
    && rm -rf /root/.cache /var/cache/apk/* /opt/nikto/.git \
    # Cleanup git history from COPY . .
    && rm -rf .git .github

# Run FastAPI app
CMD ["sh", "-c", "uvicorn backend.api:app --host 0.0.0.0 --port 8003"]
