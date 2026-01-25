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
    && rm -rf /var/lib/apt/lists/*

# Install Nikto from GitHub
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install WPScan
RUN gem install wpscan

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set default port
ENV PORT=8002

# Expose API port
EXPOSE ${PORT}

# Run FastAPI app
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT}"]
