"""
================================================================================
Host-Based Intrusion Detection System - Flask Backend
================================================================================
This is the main server. It:
  - Receives logs from the Windows agent via REST API
  - Detects brute force and other intrusion patterns
  - Stores logs and alerts in memory (no database needed)
  - Sends Telegram alerts
  - Provides data to the dashboard frontend
  - Handles safe demo simulation endpoints
================================================================================
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timedelta
import threading
import requests
import time
import json
import os

# ─────────────────────────────────────────────
# CONFIGURATION  — edit these before running
# ─────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"   # e.g. 7123456789:AAHx...
TELEGRAM_CHAT_ID   = "YOUR_CHAT_ID_HERE"      # e.g. 123456789

# Brute-force detection settings
BRUTE_FORCE_THRESHOLD = 3      # number of failed logins …
BRUTE_FORCE_WINDOW    = 60     # … within this many seconds

# ─────────────────────────────────────────────
# APP INITIALISATION
# ─────────────────────────────────────────────
app = Flask(__name__, template_folder="../templates", static_folder="../static")
CORS(app)   # allow the agent (different port) to POST logs

# ─────────────────────────────────────────────
# IN-MEMORY STORAGE  (thread-safe lock)
# ─────────────────────────────────────────────
lock        = threading.Lock()
logs_store  = []   # all received log events
alerts_store = []  # generated alerts
attack_feed  = []  # human-readable timeline entries
MAX_RECORDS  = 500 # keep memory bounded

# ─────────────────────────────────────────────────────────────────────────────
# HELPER — add a record to a bounded list (newest first)
# ─────────────────────────────────────────────────────────────────────────────
def _append(lst, item):
    lst.insert(0, item)
    if len(lst) > MAX_RECORDS:
        lst.pop()

# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM ALERT
# Send a message to the analyst's Telegram account.
# Linked to the *legitimate user* who configured the bot — not the attacker.
# ─────────────────────────────────────────────────────────────────────────────
def send_telegram_alert(message: str):
    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print(f"[TELEGRAM-SKIP] Configure token to send: {message}")
        return
    url  = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": f"🚨 HIDS ALERT\n\n{message}", "parse_mode": "Markdown"}
    try:
        requests.post(url, data=data, timeout=5)
        print(f"[TELEGRAM] Sent: {message[:80]}")
    except Exception as e:
        print(f"[TELEGRAM-ERROR] {e}")

# ─────────────────────────────────────────────────────────────────────────────
# DESKTOP NOTIFICATION
# Uses winotify (Windows 10/11).  Safe — only shows a popup, touches nothing.
# Useful even when attacker is at the laptop: the *owner* sees it on their
# phone via Telegram simultaneously.
# ─────────────────────────────────────────────────────────────────────────────
def send_desktop_notification(title: str, message: str):
    try:
        from winotify import Notification, audio
        toast = Notification(
            app_id   = "HIDS Monitor",
            title    = title,
            msg      = message,
            duration = "short"
        )
        toast.set_audio(audio.Default, loop=False)
        toast.show()
        print(f"[DESKTOP] {title}: {message[:60]}")
    except ImportError:
        print("[DESKTOP-SKIP] winotify not installed — pip install winotify")
    except Exception as e:
        print(f"[DESKTOP-ERROR] {e}")

# ─────────────────────────────────────────────────────────────────────────────
# ALERT DISPATCHER — called whenever a new alert is generated
# ─────────────────────────────────────────────────────────────────────────────
def dispatch_alert(alert: dict):
    """Store the alert and fire all notification channels."""
    with lock:
        _append(alerts_store, alert)
        feed_entry = {
            "time"    : alert["timestamp"],
            "message" : alert["description"],
            "severity": alert["severity"]
        }
        _append(attack_feed, feed_entry)

    # Run notifications in background so the API response is not delayed
    threading.Thread(
        target=_notify_all,
        args=(alert,),
        daemon=True
    ).start()

def _notify_all(alert):
    msg = (
        f"*{alert['type']}*\n"
        f"Severity: {alert['severity']}\n"
        f"Detail: {alert['description']}\n"
        f"Time: {alert['timestamp']}"
    )
    send_telegram_alert(msg)
    send_desktop_notification(f"⚠ {alert['type']}", alert["description"])

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC — modular functions, easy to explain in viva
# ─────────────────────────────────────────────────────────────────────────────

def detect_brute_force(username: str) -> bool:
    """
    Brute-force detection:
      Count Event ID 4625 (failed login) entries for `username`
      within the last BRUTE_FORCE_WINDOW seconds.
      If count >= BRUTE_FORCE_THRESHOLD → alert.

    Event ID 4625 = "An account failed to log on."
    Windows writes this to the Security Event Log every time a desktop
    password is typed incorrectly, making it perfect for detecting
    repeated failed attempts by an attacker.
    """
    now    = datetime.now()
    cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW)
    count  = 0
    with lock:
        for log in logs_store:
            if (log.get("event_id") == 4625
                    and log.get("username") == username):
                try:
                    t = datetime.fromisoformat(log["timestamp"])
                    if t >= cutoff:
                        count += 1
                except Exception:
                    pass
    return count >= BRUTE_FORCE_THRESHOLD


def already_alerted_brute_force(username: str) -> bool:
    """Prevent duplicate brute-force alerts for the same username."""
    cutoff = datetime.now() - timedelta(seconds=BRUTE_FORCE_WINDOW * 2)
    with lock:
        for a in alerts_store:
            if (a.get("type") == "Brute Force Attack"
                    and a.get("username") == username):
                try:
                    t = datetime.fromisoformat(a["timestamp"])
                    if t >= cutoff:
                        return True
                except Exception:
                    pass
    return False


def make_alert(alert_type, severity, description, username=None, source_ip=None, extra=None):
    """Build a standard alert dictionary."""
    return {
        "id"         : int(time.time() * 1000),
        "type"       : alert_type,
        "severity"   : severity,           # Low / Medium / High / Critical
        "description": description,
        "username"   : username or "N/A",
        "source_ip"  : source_ip or "127.0.0.1",
        "timestamp"  : datetime.now().isoformat(timespec="seconds"),
        "extra"      : extra or {}
    }


# ─────────────────────────────────────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── Receive logs from the Windows agent ──────────────────────────────────────
@app.route("/api/logs", methods=["POST"])
def receive_log():
    """
    The Windows agent POSTs a JSON log entry here.
    Expected shape:
      {
        "event_id"  : 4625,
        "username"  : "Administrator",
        "source_ip" : "192.168.1.10",
        "timestamp" : "2024-01-01T14:42:00",
        "message"   : "An account failed to log on."
      }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    data.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))
    data.setdefault("source"   , "agent")

    with lock:
        _append(logs_store, data)

    # ── Detection: failed login (4625) ────────────────────────────────────
    if data.get("event_id") == 4625:
        username = data.get("username", "Unknown")

        # Single failed login — low severity log
        feed_entry = {
            "time"    : data["timestamp"],
            "message" : f"Failed login attempt — user: {username}",
            "severity": "Medium"
        }
        with lock:
            _append(attack_feed, feed_entry)

        # Check for brute force pattern
        if detect_brute_force(username) and not already_alerted_brute_force(username):
            alert = make_alert(
                alert_type  = "Brute Force Attack",
                severity    = "Critical",
                description = f"Brute force detected: {BRUTE_FORCE_THRESHOLD}+ failed logins in {BRUTE_FORCE_WINDOW}s for user '{username}'",
                username    = username,
                source_ip   = data.get("source_ip", "127.0.0.1")
            )
            dispatch_alert(alert)

    return jsonify({"status": "received"}), 200


# ── Dashboard data endpoint ───────────────────────────────────────────────────
@app.route("/api/dashboard", methods=["GET"])
def dashboard_data():
    """Return all data needed to render the dashboard."""
    with lock:
        total_logs   = len(logs_store)
        total_alerts = len(alerts_store)
        recent_logs  = logs_store[:50]
        recent_alerts = alerts_store[:20]
        recent_feed   = attack_feed[:30]

        # Severity distribution
        sev_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for a in alerts_store:
            s = a.get("severity", "Low")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        # Alert type distribution
        type_counts = {}
        for a in alerts_store:
            t = a.get("type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        # Determine threat level
        if sev_counts["Critical"] > 0:
            threat_level = "CRITICAL"
        elif sev_counts["High"] > 0:
            threat_level = "HIGH"
        elif sev_counts["Medium"] > 0:
            threat_level = "MEDIUM"
        elif total_alerts > 0:
            threat_level = "LOW"
        else:
            threat_level = "NORMAL"

    return jsonify({
        "total_logs"   : total_logs,
        "total_alerts" : total_alerts,
        "threat_level" : threat_level,
        "system_status": "ONLINE",
        "severity_dist": sev_counts,
        "type_dist"    : type_counts,
        "recent_logs"  : recent_logs,
        "recent_alerts": recent_alerts,
        "attack_feed"  : recent_feed,
        "last_updated" : datetime.now().isoformat(timespec="seconds")
    })


# ─────────────────────────────────────────────────────────────────────────────
# SAFE DEMO / SIMULATION ENDPOINTS
# These let you demonstrate every intrusion scenario during your faculty viva
# without needing a real attacker.  No destructive code — purely log injection.
# ─────────────────────────────────────────────────────────────────────────────

def _sim_response(alert):
    dispatch_alert(alert)
    return jsonify({"status": "simulated", "alert": alert}), 200


@app.route("/api/simulate/brute_force", methods=["POST"])
def sim_brute_force():
    """Inject multiple failed login logs then trigger a brute-force alert."""
    username = "Administrator"
    now = datetime.now()
    with lock:
        for i in range(BRUTE_FORCE_THRESHOLD):
            _append(logs_store, {
                "event_id" : 4625,
                "username" : username,
                "source_ip": "10.0.0.99",
                "timestamp": (now - timedelta(seconds=i*5)).isoformat(timespec="seconds"),
                "message"  : "Simulated failed login",
                "source"   : "simulation"
            })
            _append(attack_feed, {
                "time"    : (now - timedelta(seconds=i*5)).isoformat(timespec="seconds"),
                "message" : f"[SIM] Failed login attempt #{i+1} — user: {username}",
                "severity": "Medium"
            })
    alert = make_alert(
        "Brute Force Attack", "Critical",
        f"[DEMO] Brute force: {BRUTE_FORCE_THRESHOLD} failed logins detected for '{username}' from 10.0.0.99",
        username=username, source_ip="10.0.0.99"
    )
    return _sim_response(alert)


@app.route("/api/simulate/firewall_disabled", methods=["POST"])
def sim_firewall():
    alert = make_alert(
        "Firewall Disabled", "Critical",
        "[DEMO] Windows Firewall was disabled on this host. System is now exposed.",
        source_ip="localhost"
    )
    return _sim_response(alert)


@app.route("/api/simulate/suspicious_process", methods=["POST"])
def sim_process():
    alert = make_alert(
        "Suspicious Process", "High",
        "[DEMO] Suspicious process detected: cmd.exe spawned by winword.exe (macro execution pattern).",
        source_ip="localhost"
    )
    return _sim_response(alert)


@app.route("/api/simulate/user_creation", methods=["POST"])
def sim_user_creation():
    alert = make_alert(
        "Unauthorized User Creation", "High",
        "[DEMO] New local account 'hacker_user' created outside business hours (Event ID 4720).",
        username="hacker_user", source_ip="localhost"
    )
    return _sim_response(alert)


@app.route("/api/simulate/policy_tamper", methods=["POST"])
def sim_policy():
    alert = make_alert(
        "Security Policy Tampering", "High",
        "[DEMO] Audit policy changed — failed login auditing disabled (Event ID 4719).",
        source_ip="localhost"
    )
    return _sim_response(alert)


@app.route("/api/simulate/powershell", methods=["POST"])
def sim_powershell():
    alert = make_alert(
        "Suspicious PowerShell", "High",
        "[DEMO] Encoded PowerShell command executed: powershell.exe -EncodedCommand <base64>. Possible obfuscation.",
        source_ip="localhost"
    )
    return _sim_response(alert)


@app.route("/api/simulate/usb_insert", methods=["POST"])
def sim_usb():
    alert = make_alert(
        "USB Device Inserted", "Medium",
        "[DEMO] Unknown USB storage device connected (Event ID 2003). Data exfiltration risk.",
        source_ip="localhost"
    )
    return _sim_response(alert)


@app.route("/api/simulate/privilege_escalation", methods=["POST"])
def sim_privesc():
    alert = make_alert(
        "Privilege Escalation", "Critical",
        "[DEMO] User 'guest' added to Administrators group (Event ID 4732). Privilege escalation detected.",
        username="guest", source_ip="localhost"
    )
    return _sim_response(alert)


# ── Clear all data (for resetting demo) ──────────────────────────────────────
@app.route("/api/clear", methods=["POST"])
def clear_data():
    with lock:
        logs_store.clear()
        alerts_store.clear()
        attack_feed.clear()
    return jsonify({"status": "cleared"}), 200


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  HIDS Server starting on http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
