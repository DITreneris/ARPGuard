FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    python3-dev \
    net-tools \
    iproute2 \
    tcpdump \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs config data visualizations captures

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Add capabilities for packet capture and network management
RUN setcap cap_net_raw,cap_net_admin+eip $(which python3) && \
    setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)

# Expose ports for web interface and WebSocket
EXPOSE 8000 8001

# Set entrypoint
ENTRYPOINT ["python3", "cli.py"]

# Default command (can be overridden)
CMD ["start", "--preset", "basic"] 