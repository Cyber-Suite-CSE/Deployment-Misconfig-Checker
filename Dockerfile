FROM python:3.11-alpine

WORKDIR /app

# Copy dependency manifest first so code changes don't bust the tool/dependency cache
COPY requirements.txt ./

# Install OS tools and Python deps in a cache-friendly layer
RUN apk add --no-cache \
    # Runtime Dependencies
    nmap \
    nmap-scripts \
    masscan \
    ruby \
    perl \
    perl-json \
    perl-xml-writer \
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
    && printf '%s\n' \
    '#!/bin/sh' \
    'exec perl /opt/nikto/program/nikto.pl -config /opt/nikto/program/nikto.conf "$@"' \
    > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && mkdir -p /etc \
    && ln -sf /opt/nikto/program/nikto.conf /etc/nikto.conf \
    # Verify runtime tools are usable during build
    && perl -MJSON -e 1 \
    && perl -MXML::Writer -e 1 \
    && nikto -Version >/tmp/nikto-version.txt 2>&1 \
    && grep -qi "nikto" /tmp/nikto-version.txt \
    && masscan --version >/tmp/masscan-version.txt 2>&1 || true \
    && grep -q "Masscan version" /tmp/masscan-version.txt \
    # Cleanup Build Deps
    && apk del .build-deps \
    # Cleanup Caches and Temp Files
    && rm -rf /root/.cache /var/cache/apk/* /opt/nikto/.git /tmp/nikto-version.txt /tmp/masscan-version.txt

# Copy application source last so normal code edits reuse the dependency/tool cache
COPY . .

# Run FastAPI app
CMD uvicorn backend.api:app --host 0.0.0.0 --port $PORT
