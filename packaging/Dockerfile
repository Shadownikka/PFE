FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential libnetfilter-queue-dev libpcap-dev \
    tcpdump iptables iproute2 iw net-tools curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# AI agent requirements only (networking runs natively on host)
COPY requirements-agent.txt .
RUN pip install --no-cache-dir -r requirements-agent.txt \
    && pip install --no-cache-dir flask flask-cors SpeechRecognition

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# No web ports — desktop app runs on host, not in container
EXPOSE 9001

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

CMD ["bash"]
