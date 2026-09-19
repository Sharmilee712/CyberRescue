"""
test_notification.py
────────────────────
Quick sanity-check — run this to confirm winotify works on your machine
before running the full system.

Usage:
    python test_notification.py
"""
try:
    from winotify import Notification, audio

    toast = Notification(
        app_id   = "HIDS Monitor",
        title    = "✅ Notification Test",
        msg      = "Desktop notifications are working correctly.",
        duration = "short"
    )
    toast.set_audio(audio.Default, loop=False)
    toast.show()
    print("✅ Desktop notification sent successfully!")

except ImportError:
    print("❌ winotify is not installed.")
    print("   Run:  pip install winotify")
except Exception as e:
    print(f"❌ Notification failed: {e}")
