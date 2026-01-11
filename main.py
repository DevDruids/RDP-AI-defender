import pandas as pd
import win32evtlog
import time
from datetime import datetime, timedelta
import win32evtlogutil
import win32con
import configparser

from alert import attack_alert
from read_events import readEventLog
from features import add_failed_attempts_by_ip
from ml_model import train_model, FEATURES

ALERT_COOLDOWN = timedelta(minutes=5)


print("[*] Початкове навчання моделі...")

handles = []
for name in [
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
]:
    try:
        h = win32evtlog.OpenEventLog(None, name)
    except OSError as e:
        print(f"[WARN] Не вдалося відкрити EventLog {name}: {e}")
        h = None

    handles.append((name, h))

events = []
for name, h in handles:
    if h:
        events += readEventLog(h, "security" if name == "Security" else "sysmon" if "Sysmon" in name else "rdp")
        win32evtlog.CloseEventLog(h)

if not events:
    print("Немає подій")

events = add_failed_attempts_by_ip(events)
df = pd.DataFrame(events)

model, scaler = train_model(df)

print("[✓] Модель готова. Моніторинг...\n")

EVENT_BUFFER = []
EVENT_SOURCE = "RDP AI Defender"

config = configparser.ConfigParser()
config.read("config.ini")

TELEGRAM_TOKEN = config["TELEGRAM"]['TOKEN']

CHAT_ID = input("Введіть Telegram chat_id для отримання сповіщень(його ви можете отримати в телеграм боті @RDP_attackAlert_bot після вводу команди /chat_id): ").strip()

if not CHAT_ID.isdigit():
    print("❌ Помилка: chat_id має бути числом")
    exit(1)
else:
    print("Дякуємо, сповіщення про ризик атак, будуть надходити вам у телеграм під час роботи програми!")

CHAT_ID = int(CHAT_ID)

last_alert_time = {}
prev_event = {}

def main():
    global EVENT_BUFFER, last_alert_time
    last_seen_time = datetime.now()

    try:
        while True:
            new_events = []

            for name in [
                "Security",
                "Microsoft-Windows-Sysmon/Operational",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
            ]:
                try:
                    h = win32evtlog.OpenEventLog(None, name)
                    new_events += readEventLog(
                        h,
                        "security" if name == "Security" else
                        "sysmon" if "Sysmon" in name else
                        "rdp"
                    )
                    win32evtlog.CloseEventLog(h)
                except OSError as e:
                    print(f"[WARN] Не вдалося прочитати EventLog {name}: {e}")

            new_events = [
                e for e in new_events
                if "time" in e and e["time"] > last_seen_time
            ]

            if not new_events:
                time.sleep(1)
                continue

            EVENT_BUFFER.extend(new_events)
            last_seen_time = max(
                e["time"] for e in new_events if "time" in e
            )

            for e in new_events:
                if e["event_id"] == 4625 and e["logon_type"] in (3, 10):
                    print(
                        f"[FAILED LOGIN] IP={e['source_ip']} "
                        f"TYPE={e['logon_type']} "
                        f"TIME={e['time'].strftime('%H:%M:%S')}"
                    )
                    attack_alert(
                        f"[FAILED LOGIN] IP={e['source_ip']}; TYPE={e['logon_type']}; TIME={e['time'].strftime('%H:%M:%S')}",
                        token=TELEGRAM_TOKEN,
                        chat_id=CHAT_ID
                    )

            cutoff = datetime.now() - timedelta(minutes=5)
            EVENT_BUFFER = [e for e in EVENT_BUFFER if e["time"] >= cutoff]

            EVENT_BUFFER = add_failed_attempts_by_ip(EVENT_BUFFER)
            df = pd.DataFrame(EVENT_BUFFER)

            df["rdp_bruteforce_rule"] = (
                    (df["event_id"] == 4625) &
                    (df["logon_type"].isin([3, 10])) &
                    (df["failed_attempts_5min_by_ip"] >= 5)
            )

            if df.empty:
                time.sleep(1)
                continue

            X = scaler.transform(df[FEATURES].fillna(0))
            df["anomaly"] = model.predict(X)

            alerts = (
                df[
                    (df["rdp_bruteforce_rule"]) |
                    (df["anomaly"] == -1)
                    ]
                .sort_values("failed_attempts_5min_by_ip")
                .drop_duplicates(subset=["source_ip"], keep="last")
            )

            now = datetime.now()
            for _, row in alerts.iterrows():
                ip = row["source_ip"]

                attempts = int(row["failed_attempts_5min_by_ip"])

                if attempts >= 8:
                    severity = "CRITICAL"
                elif attempts >= 5:
                    severity = "HIGH"
                elif attempts >= 3:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                if row["anomaly"] == -1 and severity == "LOW":
                    severity = "MEDIUM"

                prev_event[ip] = {
                    "attempts": attempts,
                    "severity": severity,
                    "time": datetime
                }

                prev = prev_event.get(ip)

                changes_in_smth = {
                    prev is None or
                    prev["attempts"] != attempts or
                    prev["severity"] != severity
                }

                if not changes_in_smth:
                    if ip in last_alert_time and now - last_alert_time[ip] < ALERT_COOLDOWN:
                        continue

                last_alert_time[ip] = now

                print(f"⚠️ RDP BRUTE FORCE | SEVERITY={severity} | IP={ip} | ATTEMPTS={attempts}")
                if severity in ("HIGH", "CRITICAL"):
                    attack_alert(
                        f"⚠️ RDP BRUTE FORCE\n"
                        f"IP: {ip}\n"
                        f"Attempts: {attempts}\n"
                        f"Severity: {severity}",
                        token=TELEGRAM_TOKEN,
                        chat_id=CHAT_ID
                    )

                try:
                    win32evtlogutil.ReportEvent(
                        EVENT_SOURCE,
                        1001,
                        eventType=win32con.EVENTLOG_WARNING_TYPE,
                        strings=[f"RDP brute-force detected from IP {ip}. Attempts: {attempts}"]
                    )
                except Exception as e:
                    print(f"[WARN] Не вдалося записати подію в EventLog: {e}")

            time.sleep(1)
    except KeyboardInterrupt:
        print("\n RDP-checker завершив свою роботу")

if __name__ == "__main__":
    main()