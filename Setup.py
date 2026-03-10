import os
from os import system
import sys
import time
import subprocess
import shutil

def has_root():
    return os.geteuid() == 0

if not has_root():
  print("[-] Please run as Root... Quitting!!")
  sys.exit(1)
else:
  print("[+] Running as Root")
  print("[+] Installing Deppendies....")
  time.sleep(2)
  system("sudo apt update")
  system("sudo apt install -y python3")
  system("sudo apt install -y python3-pip")
  system("sudo apt install -y git")
  system("sudo apt install -y build-essential python3-dev libnetfilter-queue-dev libnfnetlink-dev libffi-dev iproute2")
  system("sudo apt install -y iptables tcpdump net-tools nftables libpcap-dev iw wireless-tools curl wget")
  system("sudo pip3 install -r requirements.txt --break-system-packages --ignore-installed")
  if os.path.exists("NetMind_Interface/requirements.txt"):
    system("sudo pip3 install -r NetMind_Interface/requirements.txt --break-system-packages --ignore-installed")

  # Docker
  
  if not shutil.which("docker"):
    print("[+] Installing Docker...")
    system("curl -fsSL https://get.docker.com | sh")
  else:
    print("[+] Docker already installed")
  system("sudo systemctl enable docker --now 2>/dev/null")

  # Docker Compose
  r = subprocess.run("docker compose version", shell=True, capture_output=True)
  if r.returncode != 0:
    r2 = subprocess.run("docker-compose --version", shell=True, capture_output=True)
    if r2.returncode != 0:
      print("[+] Installing Docker Compose...")
      system("sudo apt install -y docker-compose-plugin 2>/dev/null || pip3 install --break-system-packages docker-compose")
  print("[+] Docker Compose ready")

  # Build and start services
  compose = "docker compose" if subprocess.run("docker compose version", shell=True, capture_output=True).returncode == 0 else "docker-compose"
  print("[+] Building Docker images...")
  system(f"{compose} build")
  print("[+] Starting services...")
  system(f"{compose} up -d")

  # Pull AI model
  print("[+] Downloading Llama 3.2 model (~2GB)...")
  system("docker exec netmind-ai-agent ollama pull llama3.2 2>/dev/null || true")

  print("\n[✓] Setup complete!")
  print("    Start: sudo docker exec -it netmind-core python3 NetMind.py")
  print("    Grafana: http://localhost:3000 (admin/admin)")
