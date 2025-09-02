# NGFW Daemon – Project Structure & Setup

## Overview

The **NGFW Daemon** is a Python-based Next Generation Firewall (NGFW) daemon that works alongside **Suricata IDS**, **iptables**, and Suricata’s **fast.log** to detect, log, and dynamically block malicious IPv4 traffic.

It integrates:
- **Custom Suricata rules** for detection
- **Real-time monitoring** of Suricata’s fast.log
- **Automated firewall blocking** using iptables (IPv4 only)
- **Persistent logging** in both human-readable and JSON formats

⚠️ **Note**:  
This project is not a perfect or production-ready script. It is designed as a **learning tool and home lab project**, demonstrating how IDS events can be consumed and acted upon in real time, while producing enriched logs suitable for both analysts and SIEM ingestion.

# Repository Contents

ngfw_daemon.py – The main Python daemon.

- Monitors Suricata fast.log
- Extracts fields like source IP, SID, and rule message
- Applies blocking logic (default: external attacker IPs)
- Produces structured logs

ngfw-daemon.service – A systemd unit file for persistent operation.
- Starts on boot
- Restarts if it crashes
- Loads environment from ngfw.env

ngfw.env – Environment file with tunable configuration (API keys, intervals, fail-open/fail-closed behavior).

custom.rules – Custom Suricata rules. When triggered, the daemon blocks and logs the offending IP.

ngfw_logrotate – Logrotate configuration for automatic log rotation and cleanup.

logs_and_utilities – Runtime logs and helper utilities:

alert.log – Human-readable alerts

alerts.json – JSONL alerts (for SIEMs like ELK, Splunk, Graylog)

blocks.log – Human-readable block events

blocked.json – Snapshot of currently blocked IPs

daemon.log – Operational logs from the daemon

fastlog.offset – Tracks read position in fast.log

firehol_level1.netset – FireHOL threat intelligence feed

post_server.py – Helper script to simulate malicious POST requests or trigger custom rules for testing.

structure.txt – Documentation of project layout and Suricata setup.

# Quickstart Guide

Follow these steps to get the NGFW Daemon up and running on your system.

1. Clone the Repository
git clone https://github.com/<your-username>/ngfw-daemon.git  
cd ngfw-daemon  

2. Install Requirements

Make sure you have Python 3.8+, pip, and Suricata installed.

Install dependencies:

pip install -r requirements.txt  

3. Configure Suricata

Edit your Suricata configuration (usually at /etc/suricata/suricata.yaml).

Locate and configure the af-packet section:

af-packet:
- interface: your-interface (e.g., eth0 or wlp2s0)
  threads: auto
  cluster-id: 99
  cluster-type: cluster_flow
  defrag: yes


Set your home network range under vars:

vars:
  address-groups:
    HOME_NET: "[10.0.0.0/24]"


Enable logging outputs (make sure fast.log is enabled):

- fast:
    enabled: yes
    filename: fast.log
    append: yes


Ensure Suricata loads your rules, including the custom rules file:

default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - custom.rules

4. Adjust File Paths

This project assumes the following default paths:

Suricata alert log:
/var/log/suricata/fast.log

Custom Suricata rules file:
/etc/suricata/rules/custom.rules

Daemon logs & state files (included in repo):

logs_and_utilities/alert.log

logs_and_utilities/alerts.json

logs_and_utilities/blocked.json

logs_and_utilities/blocks.log

logs_and_utilities/daemon.log

logs_and_utilities/fastlog.offset

Important: Update these paths in the source code or configs to match your own environment before running.

5. Configure Log Rotation

To prevent log files from growing too large, configure logrotate.

An example config is provided in:
ngfw_logrotate

6. Run the Daemon

You can run manually for testing:

sudo python3 ngfw_daemon.py


Or install as a systemd service:

sudo cp ngfw-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ngfw-daemon
sudo systemctl start ngfw-daemon


Reminder: Edit paths in ngfw-daemon.service before enabling.

7. Monitor Logs

View live logs:

sudo journalctl -u ngfw-daemon.service -f


Check daemon-specific logs:

tail -f logs_and_utilities/daemon.log

8. Add Custom Rules

Edit your Suricata rules file:

sudo nano /etc/suricata/rules/custom.rules


Example rule:

alert http any any -> any any (msg:"TEST rule"; content:"teststring"; sid:2000001; rev:1;)


Reload Suricata after editing rules:

sudo systemctl restart suricata

That’s it! Your NGFW Daemon is now monitoring Suricata alerts, logging events, and blocking malicious IPs.

Logs & Enrichment

The NGFW daemon produces human-readable logs for analysts and JSON logs for machines.

Example Enriched Logs

Sep 02 11:24:45 Ubuntu python3[993829]: [2025-09-02 11:24:45,563] WARNING: 2025-09-02 11:24:45 BLOCKED 10.0.0.1 (REPUTATION SCORE: 0) [REPUTATION BLOCK (source=firehol)] SID=2000004 MSG="TEST ICMP Ping Detected"
Sep 02 11:24:45 Ubuntu python3[993829]: [2025-09-02 11:24:45,564] INFO: 2025-09-02 11:24:45 ALERT 10.0.0.1 (REPUTATION SCORE: 0) [REPUTATION BLOCK (source=firehol)] SID=2000004 MSG="TEST ICMP Ping Detected"


Each log line captures:
- Timestamp
- Offender IP
- Reputation score (if available)
- Source of intelligence (e.g., FireHOL)
- Rule SID and message
- Action taken (blocked/skipped)
- This format ensures clarity for humans while alerts.json provides structured JSON for SIEMs.

For testing, you can enable blocking of internal devices by:

Setting include_private=True in extract_events_from_fastlog() instead of false

Commenting out these lines in ngfw_daemon.py:

#if ip in LOCAL_IPS or is_private_or_reserved(ip):
#logger.debug(f"Skipping internal/reserved IP {ip}")
#log_alert(ip, reason="INTERNAL/PRIVATE (skipped)", sid=sid, rule_msg=rule_msg)
#continue

This allows lab users to test scenarios where internal hosts are intentionally blocked.
Note:This worked for my 10.0.0.0/24 network

# Limitations
- IPv4-only (no IPv6 support yet).
- Uses iptables backend (not nftables or ufw).
- Single host focus (not distributed).

Useful Commands
Monitor daemon logs: journalctl -u ngfw-daemon.service -f

List iptables rules: sudo iptables -L INPUT -n --line-numbers

Remove rule: sudo iptables -D INPUT 1

Manage Suricata:

sudo systemctl restart suricata

sudo suricata -T -c /etc/suricata/suricata.yaml -v

Manage NGFW Daemon:

sudo systemctl start ngfw-daemon.service

sudo systemctl restart ngfw-daemon.service

sudo systemctl status ngfw-daemon.service

Allow external access: sudo ufw allow 8080/tcp

Run post server for testing: python3 -m post_server.py 8080 --bind 0.0.0.0

# Project Tips & Notes

- Logs in logs_and_utilities/ are included as placeholders.

- Fail-closed vs. fail-open: configurable via FAIL_POLICY in ngfw.env.

- Keep API keys (like ABUSEIPDB_API_KEY) in ngfw.env.

- High alert mode shortens poll intervals during bursts.

- FireHOL IP lists are reloaded automatically.

- Update paths in the code/configs before running.

# Purpose & Summary
The NGFW daemon demonstrates how Suricata alerts can be consumed, enriched, and acted upon automatically.

It highlights:
- IDS + firewall integration
- Dynamic threat intelligence blocking
- Enriched logging for analysts and SIEMs
- A programmable NGFW model in Python

This project was built through trial, error, and iteration — with the goal of showing how practical security tools can be developed, tested, and improved in a lab environment.
