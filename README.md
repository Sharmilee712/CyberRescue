# 🛡️ CyberRescue — Host-Based Intrusion Detection System (HIDS)

CyberRescue is a **Windows-based Host Intrusion Detection System (HIDS)** designed to monitor security events, detect suspicious activity, and generate real-time alerts.

The project focuses on detecting **failed login attempts and potential brute-force attacks** from the Windows Security Event Log and providing security alerts through a centralized Flask dashboard.

---

## 📌 Project Overview

CyberRescue continuously monitors a Windows machine for suspicious security events.

The system consists of:

- 🖥️ **Windows Agent** — monitors Windows Security Event Logs
- ⚙️ **Flask Server** — receives and processes security events
- 📊 **Web Dashboard** — displays logs, alerts, and threat information
- 🚨 **Alert System** — generates desktop and Telegram notifications
- 🧪 **Simulation Module** — provides safe demo scenarios for testing

### High-Level Architecture

```text
┌──────────────────────────────┐
│      Windows Security Log    │
│                              │
│     Event ID 4625            │
│     Failed Login Attempt     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       CyberRescue Agent      │
│                              │
│  • Reads Security Events     │
│  • Extracts relevant fields  │
│  • Filters Event ID 4625     │
└──────────────┬───────────────┘
               │
               │ HTTP POST
               ▼
┌──────────────────────────────┐
│        Flask Server          │
│                              │
│  • Receives events           │
│  • Stores logs               │
│  • Detects brute force       │
│  • Generates alerts          │
└──────────────┬───────────────┘
               │
       ┌───────┴────────┐
       ▼                ▼
┌─────────────┐   ┌───────────────┐
│ Web         │   │ Alert System  │
│ Dashboard   │   │               │
│             │   │ • Desktop     │
│ • Logs      │   │ • Telegram    │
│ • Alerts    │   │               │
│ • Threats   │   │               │
└─────────────┘   └───────────────┘
```
✨ Key Features
🔍 Windows Security Event Monitoring

The CyberRescue agent monitors the Windows Security Event Log and currently focuses on:

Event ID 4625 — An account failed to log on

The agent extracts relevant information such as:

Username
Domain
Source IP address
Event ID
Event record number
Timestamp

Machine accounts ending with $ are ignored to reduce unnecessary events.

🚨 Brute-Force Detection

CyberRescue analyzes repeated failed login attempts to identify potential brute-force activity.

The current detection logic uses:
```text
Threshold = 3 failed login attempts
Time Window = 60 seconds
```

### Detection Flow
```text
Failed Login
     │
     ▼
Event ID 4625
     │
     ▼
Extract Username
     │
     ▼
Check Recent Failed Attempts
     │
     ▼
3 or more attempts
within 60 seconds?
     │
   ┌─┴─┐
   │   │
  YES  NO
   │   │
   ▼   ▼
Alert Continue Monitoring
```

To prevent repeated notifications for the same activity, CyberRescue also uses a short alert suppression period.

🔔 Real-Time Alerting

When a suspicious activity is detected, CyberRescue can generate:

🖥️ Desktop Notification

Windows desktop notifications are generated using winotify.

📱 Telegram Notification

The server can send security alerts through the Telegram Bot API after configuring the bot credentials.

### Alert Workflow
```text
Security Event
      │
      ▼
Detection Engine
      │
      ▼
Threat Detected
      │
      ▼
Create Alert
      │
      ├───────────────┐
      ▼               ▼
Desktop Alert     Telegram Alert
      │               │
      └───────┬───────┘
              ▼
        Dashboard Feed
```
📊 Web Dashboard

The Flask server provides a web dashboard for monitoring the security status of the system.

The dashboard can display information such as:

Total security logs
Active alerts
Failed login activity
Attack feed
Threat level
Suspicious activity details
Event timestamps
Usernames
Source IP addresses

The dashboard communicates with the Flask backend through REST API endpoints.

🧪 Safe Security Simulation

CyberRescue includes simulation endpoints that allow different security scenarios to be demonstrated without performing destructive or malicious actions.

Available simulation scenarios include:

🔐 Brute-force activity
🛑 Firewall disabled
⚠️ Suspicious process
👤 User creation
🔧 Policy tampering
💻 PowerShell activity
🔌 USB insertion
🔑 Privilege escalation

These simulations are designed for safe testing and academic demonstrations.

They generate simulated security events rather than intentionally damaging or compromising the system.

📁 Project Structure

```text
CyberRescue/
│
├── agent/
│   └── agent.py
│
├── server/
│   └── app.py
│
├── static/
│   ├── script.js
│   └── style.css
│
├── templates/
│   └── index.html
│
├── test_notification.py
├── requirements.txt
├── README.md
│
├── agent.py
├── app.py
├── index.html
├── script.js
└── style.css
```

The main runtime components are organized under the agent/, server/, static/, and templates/ directories.

🛠️ Technologies Used
Technology	Purpose
Python	Core implementation
Flask	Backend web server
Flask-CORS	Cross-Origin Resource Sharing
Requests	HTTP communication
PyWin32	Windows Event Log access
Winotify	Windows desktop notifications
Telegram Bot API	Remote security alerts
HTML	Dashboard structure
CSS	Dashboard styling
JavaScript	Dashboard interaction
Windows Event Log	Security event source

⚙️ Requirements

CyberRescue is designed primarily for Windows because the agent reads the Windows Security Event Log.

Install the required Python packages using:

```text
pip install -r requirements.txt
```

The main dependencies are:

```text
Flask
Flask-CORS
Requests
PyWin32
Winotify
```

🚀 Quick Start
1. Clone the Repository
```text
git clone https://github.com/Sharmilee712/CyberRescue.git
cd CyberRescue
```
2. Install Dependencies
```text
pip install -r requirements.txt
```

3. Start the Flask Server
From the project root:
```text
python server/app.py
```

The server runs on:
```text
http://127.0.0.1:5000
```

4. Start the Windows Agent

Open another terminal as Administrator.

From the project root:
```text
python agent/agent.py
```

The agent requires Administrator privileges because Windows Security Event Logs may require elevated access.

The agent polls the Windows Security Event Log periodically and sends detected Event ID 4625 events to the Flask server.

🔐 Telegram Configuration

Telegram alerts require a Telegram bot and chat configuration.

Open:

server/app.py

Locate:

TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID   = "YOUR_CHAT_ID_HERE"

Replace the placeholders with your Telegram bot token and chat ID.

⚠️ Security Warning

Never commit real Telegram credentials, API keys, passwords, or other secrets to GitHub.

For a production implementation, sensitive configuration should be stored using environment variables or another secure secrets-management mechanism.

🔎 Event ID 4625 Detection

CyberRescue currently focuses on Windows:

Event ID: 4625
Description: An account failed to log on

The agent reads Windows Security Events and filters for Event ID 4625.

Relevant information is extracted from the event data, including:

Username
Domain
Source IP
Timestamp
Event ID
Record Number

The extracted event is then sent to the Flask server.

🔄 Event Processing Flow
```text
Windows Security Event Log
          │
          ▼
      Event 4625
          │
          ▼
   CyberRescue Agent
          │
          ▼
 Extract Security Data
          │
          ▼
     HTTP POST
          │
          ▼
      Flask API
          │
          ▼
     Store Event
          │
          ▼
 Brute-Force Detection
          │
      ┌───┴───┐
      ▼       ▼
   Threat    Normal
   Detected  Activity
      │
      ▼
    Alert
      │
 ┌────┴─────┐
 ▼          ▼
Desktop   Telegram
Alert      Alert
```

🧠 Brute-Force Detection Logic

The server maintains recent failed-login events in memory.

The current configuration is:
```text
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW = 60
```
+88++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

This means the system checks whether the same username has generated at least 3 failed login attempts within 60 seconds.

If the threshold is reached, a brute-force alert is generated.
```text
Example
10:00:05 → Failed login → user: admin
10:00:18 → Failed login → user: admin
10:00:31 → Failed login → user: admin
                     │
                     ▼
              3 attempts / 60 sec
                     │
                     ▼
            Brute-Force Alert
```

This is a simple threshold-based detection mechanism intended for demonstration and learning.

🧪 Demo Scenarios

The Flask server includes safe simulation endpoints for demonstrating the alert system.

Available routes include:
```text
/api/simulate/brute_force
/api/simulate/firewall_disabled
/api/simulate/suspicious_process
/api/simulate/user_creation
/api/simulate/policy_tamper
/api/simulate/powershell
/api/simulate/usb_insert
/api/simulate/privilege_escalation
```

These endpoints are intended for controlled demonstrations.

They do not intentionally disable the firewall, create unauthorized accounts, modify system policies, or perform other destructive actions.

🖥️ Faculty / Project Demo Flow

A simple demonstration can follow this sequence:

Step 1 — Start the Flask Server
```text
python server/app.py
```
Step 2 — Open the Dashboard

Open:
```text
http://127.0.0.1:5000
```
Step 3 — Start the Windows Agent

Run the agent as Administrator:
```text
python agent/agent.py
```
Step 4 — Generate Failed Login Activity

Trigger controlled failed login attempts on the test machine.

The Windows Security Log should generate Event ID 4625.

Step 5 — Agent Detects the Event

The agent reads the event and sends it to the Flask server.

Step 6 — Server Processes the Event

The server stores the event and checks for repeated failed login activity.

Step 7 — Alert Generation

If the configured threshold is reached, CyberRescue generates a brute-force alert.

Step 8 — Dashboard Update

The dashboard displays the detected security activity.

🔔 Notification Test

A separate test file is included to verify that Windows desktop notifications are working correctly.

Run:
```text
python test_notification.py
```

Expected output:
```text
✅ Desktop notification sent successfully!
```
If winotify is not installed:
```text
pip install winotify
```
🧩 API Endpoints

The Flask backend provides several API endpoints for communication between the agent, dashboard, and detection system.

Important endpoints include:

Endpoint	Purpose
/api/logs	Receives security events from the agent
/api/dashboard	Provides dashboard statistics
/api/clear	Clears in-memory monitoring data
/api/simulate/brute_force	Simulates brute-force activity
/api/simulate/firewall_disabled	Simulates firewall-related activity
/api/simulate/suspicious_process	Simulates suspicious process activity
/api/simulate/user_creation	Simulates user creation activity
/api/simulate/policy_tamper	Simulates policy tampering
/api/simulate/powershell	Simulates PowerShell activity
/api/simulate/usb_insert	Simulates USB insertion
/api/simulate/privilege_escalation	Simulates privilege escalation
🛡️ Security Considerations

CyberRescue is an academic security monitoring project.

Important considerations include:

Telegram credentials should never be committed to source control.
Production deployments should use environment variables or a secrets manager.
Flask debug mode should be disabled in production.
Authentication and authorization should be implemented before exposing the dashboard to untrusted networks.
Logs should be stored in a persistent and secure database for production use.
Network communication should use HTTPS in production.
Detection thresholds should be tuned to reduce false positives.
Alerting systems should include appropriate rate limiting.
⚠️ Current Limitations

The current implementation is a prototype intended for learning and demonstration.

Current limitations include:
Event monitoring currently focuses on Windows Event ID 4625.
Other security scenarios are primarily demonstrated through simulation endpoints.
Logs and alerts are stored in memory.
Data is lost when the Flask server restarts.
Authentication is not currently implemented for the dashboard/API.
Telegram configuration uses placeholders by default.
Detection logic uses a basic threshold-based approach.
The project is designed for Windows environments.
🚀 Future Enhancements

Possible future improvements include:

 Support for additional Windows Security Event IDs
 Persistent database storage
 User authentication and role-based access
 HTTPS support
 Advanced anomaly detection
 Machine-learning-based threat detection
 IP reputation analysis
 Geolocation-based threat visualization
 SIEM integration
 Email and additional notification channels
 Automated incident response
 Configurable detection rules
 Improved alert correlation
 Production-grade logging and monitoring

Potential future Event IDs to monitor include:
```text
4720  → User account created
4719  → System audit policy changed
4732  → Member added to a security-enabled local group
```
🎓 Learning Outcomes

This project provided practical exposure to:

Host-Based Intrusion Detection Systems
Windows Security Event Logs
Security Event ID analysis
Python programming
Flask REST APIs
Client-server architecture
Windows system monitoring
Security alerting
Brute-force detection
Telegram Bot API integration
Desktop notification systems
Cybersecurity event analysis
Security automation
💡 Project Highlights
🔐 Cybersecurity

Designed a HIDS prototype for monitoring suspicious activity on Windows systems.

🐍 Python

Used Python for event monitoring, backend development, security processing, and automation.

🌐 Flask

Implemented a Flask-based backend for receiving and processing security events.

📊 Security Dashboard

Created a dashboard for visualizing logs, alerts, and threat information.

🚨 Alert Automation

Integrated desktop and Telegram notifications for security events.

🧪 Safe Demonstration

Included controlled simulation scenarios for academic demonstrations without intentionally performing destructive actions.

🎤 Viva Questions
1. What is HIDS?

A Host-Based Intrusion Detection System monitors activities occurring on an individual host or endpoint and identifies potentially suspicious behavior.

2. Why did you use Event ID 4625?

Event ID 4625 represents a failed account logon in Windows Security Event Logs.

Repeated failed logins can be an indicator of password guessing or brute-force activity.

3. How does CyberRescue detect brute force?

The server counts failed login events for the same username within a configured time window.

The current configuration triggers detection when:

3 or more failed login attempts
within 60 seconds
4. Why is the agent required?

The agent runs on the Windows endpoint and reads the local Windows Security Event Log.

It forwards relevant security events to the central Flask server.

5. Why are Administrator privileges required?

Accessing the Windows Security Event Log may require elevated privileges.

Therefore, the agent is intended to be executed from an Administrator terminal.

6. Why use Flask?

Flask provides a lightweight Python framework for implementing the backend APIs and serving the monitoring dashboard.

7. How are alerts generated?

When the server detects a configured security condition, it creates an alert and can send notifications through Windows desktop notifications and Telegram.

8. What is the difference between HIDS and NIDS?

HIDS monitors activity on individual hosts or endpoints.

NIDS monitors network traffic and network-level activity.

9. What is the main limitation of the current system?

The current implementation is a prototype. Real Windows Event Log monitoring primarily focuses on Event ID 4625, while several other attack scenarios are represented using safe simulation endpoints.

📜 Disclaimer

CyberRescue is an educational cybersecurity project developed for learning, testing, and controlled demonstrations.

Do not use the project to monitor systems without proper authorization.

Only perform security testing on systems that you own or have explicit permission to test.
