# PFE
# 🛡️ Intelligent Bandwidth Management System (IBMS)

## 📝 Project Description
The objective of this project is to develop an intelligent system capable of automatically monitoring and managing local network bandwidth. By leveraging Machine Learning techniques, the system analyzes network traffic and dynamically adjusts bandwidth distribution based on the real-time needs of connected users and devices.

The primary goal is to ensure a fair and efficient allocation of network resources, preventing any single device from excessively consuming bandwidth at the expense of others. The system is designed to be fully automatic and adaptive, operating seamlessly without manual intervention.

---

## ✅ Current Project Status

## ⚙️ Core Tool Functionality
The tool is built to perform four primary actions on connected devices:
1. **Monitor**: Real-time tracking of upload/download speeds.
2. **Block**: Complete internet cut-off for a specific device.
3. **Set Limit**: Cap the bandwidth (e.g., limit a device to 2 Mbps).
4. **Restore**: Remove all restrictions and return to full speed.

---

## ⚠️ Current Technical Challenges (Status: Pre-Alpha)
The core engine is currently facing two major logic bugs that need to be resolved before the AI or Web Interface can be developed:

### 1. Speed Monitoring Failure
* **The Bug**: The speed monitoring output consistently displays "0" or provides completely inaccurate readings.
* **Objective**: Correct the bit-counting logic to properly poll the `wlan0` interface so the system has accurate real-time throughput data.

### 2. Bandwidth Limiter (Hard-Drop Bug)
* **The Bug**: Setting a speed limit currently acts as a "Kill Switch." Instead of capping the speed, it blocks the device completely.
* **Objective**: Transition from a "packet-drop" logic to a "queuing/delay" logic (like Token Bucket Filter) to allow for smooth speed capping without losing the connection.

---

## 🔧 Installation & Setup

1. Clone the repository:
   git clone https://github.com/Shadownikka/PFE.git
   cd PFE

2. Run the automated setup script:
   sudo python3 setup.py

3. Launch the tool:
   sudo python3 main.py
---
Author: Mahdi
Project: PFE (Final Year Project)
Year: 2025-2026
