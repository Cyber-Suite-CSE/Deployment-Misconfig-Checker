FROM python:3.11-slim

# Install system utilities and security tools
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    ruby \
    ruby-dev \
    libcurl4-openssl-dev \
    libffi-dev \
    build-essential \
    curl \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libjson-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto from GitHub
RUN git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    ln -s /opt/nikto/program/nikto.conf /etc/nikto.conf

# Install WPScan
RUN gem install wpscan

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose API port
EXPOSE 8003

# Run FastAPI app
CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8003"]