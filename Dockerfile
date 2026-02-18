# Use Python base image
FROM python:3.11-slim

# Install system dependencies for networking tools
RUN apt-get update && apt-get install -y \
    build-essential \
    libnetfilter-queue-dev \
    libpcap-dev \
    tcpdump \
    iptables \
    iproute2 \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
COPY NetMind_Interface/requirements.txt ./interface-requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r interface-requirements.txt

# Copy the rest of the application
COPY . .

# Expose port for the web interface
EXPOSE 9000 9001

# Keep container running for manual execution
CMD ["bash"]
