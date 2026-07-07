# 🛡️ Sentinel Honeypot Manager
### *The Ultimate Command Center for Proactive Threat Intelligence*

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/UI-PyQt6-orange?logo=qt&logoColor=white)](https://www.qt.io/)
[![SSH](https://img.shields.io/badge/Protocol-SSH-lightgrey?logo=ssh&logoColor=white)](https://www.ssh.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/)

**Sentinel Honeypot Manager** is a professional-grade, cross-platform monitoring and control dashboard designed to manage remote honeypot deployments. It provides real-time visibility into malicious activities, automated threat response, and deep log analysis for **Cowrie** and **Dionaea** honeypots.

---

## 🚀 Key Features

| Feature | Description |
| :--- | :--- |
| **Real-time Monitoring** | Live stream of logs from remote honeypots via secure SSH tunneling. |
| **Multi-Honeypot Support** | Native integration with **Cowrie** (SSH/Telnet) and **Dionaea** (Malware/Services). |
| **Advanced Visualization** | Interactive donut charts, event timelines, and risk distribution graphs. |
| **Active Defense** | Instant IP banning via `iptables` and automated security rule enforcement. |
| **Risk Scoring** | Intelligent event classification with customizable risk levels for different threats. |
| **Intrusion Alerts** | Visual and audible emergency alarms (ffplay) when high-risk events are detected. |
| **Session Management** | Securely save and manage multiple honeypot credentials for quick access. |

---

## 🛠️ Technical Architecture

The system operates in a **Client-Server** model where the Manager (Client) communicates with the Honeypot (Trap) over SSH.

### 1. Control Center (Your Local Machine)
The GUI application built with **PyQt6** acts as the central monitoring station.
- **Core Engine**: Asynchronous SSH workers using `paramiko`.
- **Data Processing**: Real-time JSON parsing and risk evaluation.
- **Alert System**: Multi-threaded alarm triggers and system tray notifications.

### 2. The Trap (Honeypot VM)
The remote environment where the actual honeypots are running.
- **Services**: Cowrie and Dionaea running in Docker or as system services.
- **Logs**: Structured JSON logs harvested by the Manager.
- **Firewall**: `iptables` managed by the Manager for active blocking.

---

## 📥 Installation Guide

### Step 1: Prepare the Control Center (Local)
Ensure you have Python 3.8+ installed, then install the required dependencies:

```bash
# Clone the repository
git clone https://github.com/yourusername/honeypot-manager.git
cd honeypot-manager

# Install Python dependencies
pip install PyQt6 paramiko
```

> **Note:** For audible alarms, ensure `ffplay` (part of FFmpeg) is installed and accessible in your system PATH.

### Step 2: Configure the Trap (Remote Honeypot VM)
The manager expects the following environment on the target VM:

1. **Honeypot Software**: Install [Cowrie](https://github.com/cowrie/cowrie) and [Dionaea](https://github.com/Dionaea/dionaea).
2. **Directory Structure**: By default, the tool looks for:
   - Cowrie: `/home/honeypot/honeypot-project/cowrie-logs/cowrie.json`
   - Dionaea: `/home/honeypot/honeypot-project/dionaea/dionaea-logs/dionaea.log`
3. **Permissions**: The SSH user must have `sudo` privileges to execute `iptables` and `netstat` commands.
4. **Dependencies**:
   ```bash
   sudo apt update
   sudo apt install docker.io iptables net-tools
   ```

---

## 🎮 How to Use

1. **Launch the App**:
   ```bash
   python honeypot_manager.py
   ```
2. **Connect**:
   - Enter the **IP Address** and **SSH Port** (default 22) of your Honeypot VM.
   - Enter your **Username** and **Password**.
   - Click **Connect**.
3. **Monitor**:
   - Use the **Live Monitor** tab for real-time traffic.
   - Check **Visual Analytics** for high-level statistics.
   - View **Risk Analysis** to identify the most dangerous attackers.
4. **Defend**:
   - If an attacker is detected, right-click their IP to **Ban** them instantly.
   - Configure **Auto-Defense** in settings to automate the blocking process.

---

## ⚙️ Configuration

You can customize the tool's behavior by editing the paths at the top of `honeypot_manager.py`:

```python
# Remote log paths on the Honeypot VM
HONEYPOT_BASE_PATH = "/home/honeypot/honeypot-project"
COWRIE_LOG_PATH = f"{HONEYPOT_BASE_PATH}/cowrie-logs/cowrie.json"
DIONAEA_LOG_PATH = f"{HONEYPOT_BASE_PATH}/dionaea/dionaea-logs/dionaea.log"
```

---

## 🛡️ Security Disclaimer
This tool is for **educational and research purposes only**. Running a honeypot involves exposing services to the internet, which carries inherent risks. Always ensure your host system is isolated and monitor your logs responsibly.

---

## 🤝 Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.

---
<p align="center">
  Developed with ❤️ for the Cybersecurity Community
</p>
