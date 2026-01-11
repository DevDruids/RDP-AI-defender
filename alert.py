import requests
from winotify import Notification

def attack_alert_telegram(TELEGRAM_TOKEN, CHAT_ID, text):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": text
    }
    requests.post(url, data=payload, timeout=5)

def attack_alert_windows(title, message):
    toast = Notification(
        app_id="RDP AI Defender",
        title=title,
        msg=message,
        duration="long"
    )
    toast.show()


def attack_alert(text, token=None, chat_id=None, windows_title=None):
    if token and chat_id:
        attack_alert_telegram(token, chat_id, text)
    if windows_title:
        attack_alert_windows(windows_title, text)

