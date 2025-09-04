# 🔥 ngfw-daemon - Easy Firewall Protection for Everyone

[![Download ngfw-daemon](https://img.shields.io/badge/Download-ngfw--daemon-blue.svg)](https://github.com/Devesh-sen/ngfw-daemon/releases)

## 📘 Description

The **NGFW Daemon** is a Python-based Next Generation Firewall (NGFW) that works alongside **Suricata IDS**, **iptables**, and Suricata’s **fast.log** to detect, log, and dynamically block malicious IPv4 traffic. It ensures your system is protected from unwanted intrusions while enhancing your security capabilities.

## 🚀 Getting Started

To get started with the NGFW Daemon, follow these steps:

1. Ensure your computer runs on a compatible operating system. This application works best with:

   - Linux distributions (e.g., Ubuntu, Fedora)
   - Ensure you have Python 3.x installed.

2. Familiarize yourself with the key components:
   - **Suricata IDS**: This tool helps in detecting threats.
   - **iptables**: A firewall utility to manage network traffic.
   - **fast.log**: A Suricata log file that records network events.

These components work together to provide robust security for your system.

## 📥 Download & Install

Visit this page to download: [GitHub Releases](https://github.com/Devesh-sen/ngfw-daemon/releases).

1. Click on the link above to go to the Releases page.
2. Find the latest version of the NGFW Daemon.
3. Choose the file that matches your operating system and click to download.
4. Once the file is downloaded, follow the installation steps below based on your OS.

### 🔧 Installation Steps

#### For Linux Users:

1. Open the Terminal.
2. Navigate to the directory where you downloaded the file.
3. Run the following command to make it executable:

   ```bash
   chmod +x ngfw-daemon-<version>.py
   ```

4. Start the daemon by typing:

   ```bash
   python3 ngfw-daemon-<version>.py
   ```

5. Follow any additional on-screen instructions to complete the setup.

#### For All Users:

- Make sure that you have an updated version of Python installed.
- Depending on your Linux distribution, you might need to install dependencies. This can usually be done using:

   ```bash
   sudo apt install python3-pip
   ```

- Install required libraries with:

   ```bash
   pip3 install -r requirements.txt
   ```

## ⚙️ Configuration

After installation, you can configure the NGFW Daemon:

1. Locate the configuration file, usually named `ngfw-config.json`.
2. Open it in a text editor.
3. Adjust the settings as needed, such as the logging level and network interfaces to monitor.
4. Save your changes.

## 📊 Usage Guide

Once the installation is complete, and the daemon is running, you can monitor and manage firewall events:

- The daemon will log detected threats in `fast.log`.
- You can check the logs regularly to ensure your network is secure.
- Adjust rules in `iptables` as necessary, based on logged events.

## 📚 Troubleshooting

If you encounter issues:

1. Ensure that all dependencies are correctly installed.
2. Check the terminal output for errors and follow any provided guidance.
3. Make sure the necessary services, like Suricata and iptables, are running.

## 📝 Contributing

If you want to contribute to the NGFW Daemon:

1. Fork the repository.
2. Make your changes.
3. Submit a pull request explaining your additions or fixes.

## 🛠️ Support

If you have questions or need help, consult the Issues section on GitHub. You can report bugs, suggest features, or share feedback.

## 📄 License

This project is licensed under the MIT License. You can use it freely, but please credit the original authors.

For further information, visit us at: [Doc Page](https://github.com/Devesh-sen/ngfw-daemon/releases).

Download the latest version here: [GitHub Releases](https://github.com/Devesh-sen/ngfw-daemon/releases).