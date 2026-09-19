# Host-Based Intrusion Detection System (HIDS)
### Final Year Cybersecurity Project — SOC-Style Real-Time Monitoring

---

## Quick Start

```
# 1 — Install dependencies (run once)
pip install flask flask-cors requests pywin32 winotify

# 2 — Configure Telegram (optional but recommended)
#     Open server/app.py and fill in:
#     TELEGRAM_BOT_TOKEN = "your token"
#     TELEGRAM_CHAT_ID   = "your chat id"

# 3 — Start the Flask server (Terminal 1)
cd server
python app.py

# 4 — Start the Windows agent (Terminal 2, run as Administrator)
cd agent
python agent.py

# 5 — Open your browser
#     http://127.0.0.1:5000
```

---

## Project Structure

```
log-monitoring-system/
├── agent/
│   └── agent.py            Windows agent — reads Security Event Log
├── server/
│   └── app.py              Flask backend — detection + alerts + API
├── templates/
│   └── index.html          SOC-style dashboard HTML
├── static/
│   ├── style.css           Dark cybersecurity theme
│   └── script.js           Live polling + chart updates + simulations
├── test_notification.py    Test desktop popups independently
└── requirements.txt        Python dependencies
```

---

## How to Demo to Faculty (Step by Step)

1. **Open the dashboard** at http://127.0.0.1:5000 — show the live SOC UI.
2. Click **"Brute Force Attack"** — watch the Critical alert appear, Telegram fires, desktop popup shows.
3. Click **"Firewall Disabled"** — demonstrate firewall tampering detection.
4. Click **"Suspicious PowerShell"** — show process-based threat.
5. Click **"Privilege Escalation"** — show account abuse scenario.
6. Point to the **Live Attack Feed** updating in real time.
7. Show the **Alert Log table** with color-coded severity.
8. Show the **Attack Type Distribution chart** updating live.
9. Click **"Clear All Data"** to reset between demos.
10. (Optional) Type a wrong Windows password 3 times — show real Event ID 4625 detection.

---

## Viva Q&A Guide

### Q: How does wrong desktop password detection work?
Windows writes **Event ID 4625** ("An account failed to log on") to the
Security Event Log every time an incorrect password is entered at the
login screen or over the network.  The agent reads this log every 5 seconds
using the `win32evtlog` Python library and POSTs each 4625 event to the
Flask server.  The server counts how many 4625 events arrived for the same
username within a 60-second window — if it reaches 3 or more, a brute-force
alert is generated.

### Q: Why is Event ID 4625 important?
It is the primary Windows signal for failed authentication.  Without
monitoring it, an attacker could attempt thousands of passwords on a local or
network account completely silently.  4625 is the foundation of every Windows
brute-force detection rule in commercial SIEMs like Splunk, QRadar, and
Microsoft Sentinel.

### Q: How are Telegram alerts linked to the legitimate user?
The Telegram Bot token and Chat ID are registered by the *owner* of the
system during setup.  When the server calls the Telegram API, it sends a
message to that specific chat — only the owner's phone receives it.  An
attacker at the physical keyboard has no way to intercept the Telegram
message unless they also have the owner's phone.

### Q: Why are desktop notifications useful if the attacker is at the laptop?
Two reasons:
1. In a real corporate environment the attacker is rarely physically at the
   endpoint — they are attacking over the network.
2. Even at the physical machine, the desktop popup + simultaneous Telegram
   means a **remote SOC analyst** is alerted instantly, even if the local
   user does not notice.

### Q: What is special about your project?
- Real-time Event ID 4625 detection — not simulated log parsing.
- Dual-channel alerting: Telegram mobile + Windows desktop popup simultaneously.
- Eight distinct safe intrusion scenarios for live demonstration.
- All detection logic is modular and easy to extend.
- Zero external database — runs entirely on a single Windows laptop.

### Q: These attacks are simple — what is unique here?
The **integration** is what makes it valuable: real OS-level event capture →
intelligent pattern detection (brute force windowing algorithm) → multi-channel
real-time alerting → professional SOC-grade visual dashboard — all in one
lightweight system anyone can run.  Commercial tools like Splunk cost
thousands of dollars and need dedicated servers.  This achieves the same
core detection pipeline on a student laptop in Python.

---

## Future Enhancements

- Add Event ID 4720 (user creation), 4732 (group change), 4719 (policy change)
  detection from the *real* Windows Event Log (not just simulation).
- Replace in-memory storage with SQLite for log persistence across restarts.
- Add WebSocket (Flask-SocketIO) for true push-based real-time updates.
- Add machine-learning anomaly detection (e.g. Isolation Forest on login times).
- Extend agent to monitor Linux via `/var/log/auth.log`.
- Add email alerts as a third notification channel.
- Add geolocation lookup for source IP addresses on the map panel.
