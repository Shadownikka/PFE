import os
from os import system
import sys
import time


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
  system("sudo pip3 install -r requirements.txt --break-system-packages --ignore-installed")
