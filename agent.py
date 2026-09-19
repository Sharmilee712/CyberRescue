"""
================================================================================
Host-Based Intrusion Detection System — Windows Agent
================================================================================
Runs on the monitored Windows machine.

What it does:
  1. Continuously reads the Windows Security Event Log
  2. Looks for Event ID 4625 — "An account failed to log on"
  3. Ships each matching event to the Flask backend via HTTP POST

How Event ID 4625 works:
  - Every time a user types the wrong Windows desktop password, Windows
    writes event 4625 to the Security log.
  - The event contains: username attempted, workstation name, source IP,
    logon type, and failure reason.
  - By collecting these events we can detect repeated failed attempts
    (brute force) and alert the security team in real time.

Why it matters:
  - Brute force on local accounts is a common first step in privilege
    escalation attacks.
  - Without monitoring Event ID 4625 the attack is invisible.

Requirements:
  pip install pywin32 requests
  Run as Administrator (needed to read Security event logs).
================================================================================
"""

import win32evtlog
import win32evtlogutil
import win32con
import winerror
import time
import requests
import json
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────────────────────
SERVER_URL      = "http://127.0.0.1:5000/api/logs"  # Flask backend endpoint
POLL_INTERVAL   = 5    # seconds between log reads
TARGET_EVENT_ID = 4625  # Failed logon — the event we care about

# Keep track of the last event record number so we don't re-send old events
last_record_number = None


def get_failed_login_events():
    """
    Open the Windows Security Event Log and return any new Event ID 4625 entries
    since the last poll.  Returns a list of dicts ready to POST to the server.
    """
    global last_record_number
    events = []

    try:
        # Open the Security log on the local machine
        handle = win32evtlog.OpenEventLog(None, "Security")
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total  = win32evtlog.GetNumberOfEventLogRecords(handle)

        if total == 0:
            win32evtlog.CloseEventLog(handle)
            return events

        records = win32evtlog.ReadEventLog(handle, flags, 0)

        for event in records:
            # ── Filter: only Event ID 4625 ──────────────────────────────────
            if event.EventID & 0xFFFF != TARGET_EVENT_ID:
                continue

            # ── Avoid re-sending already-processed events ────────────────────
            if last_record_number is not None and event.RecordNumber <= last_record_number:
                continue

            last_record_number = event.RecordNumber

            # ── Extract useful fields from the event's InsertionStrings ──────
            # For 4625 the relevant strings are at fixed positions:
            # [5]  = target username
            # [6]  = domain
            # [18] = source network address (IP)
            strings  = event.StringInserts or []
            username = strings[5] if len(strings) > 5 else "Unknown"
            domain   = strings[6] if len(strings) > 6 else ""
            src_ip   = strings[18] if len(strings) > 18 else "N/A"

            # Skip machine accounts (end with $) to reduce noise
            if username.endswith("$"):
                continue

            ts = datetime.fromtimestamp(int(event.TimeGenerated)).isoformat(timespec="seconds")

            log_entry = {
                "event_id"  : TARGET_EVENT_ID,
                "username"  : username,
                "domain"    : domain,
                "source_ip" : src_ip,
                "timestamp" : ts,
                "message"   : f"Failed login attempt for account '{username}' from {src_ip}",
                "source"    : "agent"
            }
            events.append(log_entry)

        win32evtlog.CloseEventLog(handle)

    except Exception as e:
        print(f"[AGENT ERROR] Reading event log: {e}")

    return events


def post_log(log_entry: dict):
    """Send a single log entry to the Flask backend."""
    try:
        resp = requests.post(
            SERVER_URL,
            json=log_entry,
            timeout=5
        )
        if resp.status_code == 200:
            print(f"[AGENT] Sent: {log_entry['message']}")
        else:
            print(f"[AGENT] Server returned {resp.status_code}")
    except requests.exceptions.ConnectionError:
        print("[AGENT] Cannot connect to server — is Flask running?")
    except Exception as e:
        print(f"[AGENT ERROR] POST failed: {e}")


def run():
    print("=" * 60)
    print("  HIDS Windows Agent started")
    print(f"  Monitoring Event ID {TARGET_EVENT_ID} (failed logins)")
    print(f"  Polling every {POLL_INTERVAL}s → {SERVER_URL}")
    print("  Run as Administrator for full access")
    print("=" * 60)

    while True:
        events = get_failed_login_events()
        for event in events:
            post_log(event)
        if not events:
            print(f"[AGENT] No new events at {datetime.now().strftime('%H:%M:%S')}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
