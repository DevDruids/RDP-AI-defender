import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import win32evtlog
import time
from datetime import datetime, timedelta
from winotify import Notification
import win32evtlogutil
import win32con
import requests
import configparser
import json

flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ

SECURITY_EVENTS = {4624, 4625, 4634, 4672}
SYSMON_EVENTS = {1, 3}

time_window_minutes = 15
last_alert_time = {}
ALERT_COOLDOWN = timedelta(minutes=5)

def isRDPEvent(event_id, logon_type, log_source):
    if log_source == "rdp":
        return 1
    if event_id in (4624, 4625) and logon_type in (3, 10):
        return 1
    return 0

def readEventLog(handle, log_type):
    collected_events = []
    time_window = datetime.now() - timedelta(minutes=time_window_minutes)

    if not handle:
        return collected_events

    while True:
        try:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
        except:
            break

        if not events:
            break

        for e in events:
            event_id = e.EventID & 0xFFFF
            dt = e.TimeGenerated

            if dt < time_window:
                continue

            if log_type == "rdp" and event_id != 1149:
                continue
            if log_type == "security" and event_id not in SECURITY_EVENTS:
                continue
            if log_type == "sysmon" and event_id not in SYSMON_EVENTS:
                continue

            logon_type = -1
            if event_id in (4624, 4625) and e.StringInserts:
                try:
                    logon_type = int(e.StringInserts[10])
                except:
                    pass

            strings = e.StringInserts or []
            source_ip = "-"

            if event_id in (4624, 4625):
                for idx in (17, 18, 19, 20):
                    if len(strings) > idx:
                        candidate = strings[idx]
                        if isinstance(candidate, str) and candidate.count(".") == 3:
                            source_ip = candidate
                            break

            collected_events.append({
                "event_id": event_id,
                "logon_type": logon_type,
                "log_source": log_type,
                "hour": dt.hour,
                "weekday": dt.weekday(),
                "is_failed_login": 1 if event_id == 4625 else 0,
                "is_successful_login": 1 if event_id == 4624 else 0,
                "source_ip": source_ip,
                "is_rdp": isRDPEvent(event_id, logon_type, log_type),
                "time": dt
            })

    return collected_events

def add_failed_attempts_by_ip(events):
    for e in events:
        window_start = e["time"] - timedelta(minutes=5)
        e["failed_attempts_5min_by_ip"] = sum(
            1 for x in events
            if x["event_id"] == 4625
            and x["source_ip"] == e["source_ip"]
            and window_start <= x["time"] <= e["time"]
        )
    return events

FEATURES = [
    "hour",
    "weekday",
    "is_failed_login",
    "is_successful_login",
    "logon_type",
    "failed_attempts_5min_by_ip",
    "is_rdp"
]

print("[*] Початкове навчання моделі...")

handles = []
for name in [
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
]:
    try:
        handles.append((name, win32evtlog.OpenEventLog(None, name)))
    except:
        handles.append((name, None))

events = []
for name, h in handles:
    if h:
        events += readEventLog(h, "security" if name == "Security" else "sysmon" if "Sysmon" in name else "rdp")
        win32evtlog.CloseEventLog(h)

if not events:
    print("Немає подій")

events = add_failed_attempts_by_ip(events)
df = pd.DataFrame(events)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(df[FEATURES].fillna(0))

model = IsolationForest(n_estimators=150, contamination=0.03, random_state=42)
model.fit(X_scaled)

print("[✓] Модель готова. Моніторинг...\n")

EVENT_BUFFER = []
last_seen_time = datetime.now()
EVENT_SOURCE = "RDP AI Defender"

config = configparser.ConfigParser()
config.read("config.ini", encoding="utf-8")

TELEGRAM_TOKEN = "8585519060:AAGTJWOVZ2kHGdP6MqW3z5eMfjO4O-o4FiQ"

CHAT_ID = input("Введіть Telegram chat_id для отримання сповіщень(його ви можете отримати в телеграм боті @RDP_attackAlert_bot після вводу команди /chat_id): ").strip()

if not CHAT_ID.isdigit():
    print("❌ Помилка: chat_id має бути числом")
    exit(1)
else:
    print("Дякуємо, сповіщення про ризик атак, будуть надходити вам у телеграм під час роботи програми!")

CHAT_ID = int(CHAT_ID)

def attack_alert(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": text
    }
    requests.post(url, data=payload, timeout=5)


def main():
    global EVENT_BUFFER, last_alert_time

    last_seen_time = datetime.now()
    EVENT_BUFFER = []

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
                except:
                    pass

            new_events = [e for e in new_events if e["time"] > last_seen_time]

            if not new_events:
                time.sleep(1)
                continue

            EVENT_BUFFER.extend(new_events)
            last_seen_time = max(e["time"] for e in new_events)

            for e in new_events:
                if e["event_id"] == 4625 and e["logon_type"] in (3, 10):
                    print(
                        f"[FAILED LOGIN] IP={e['source_ip']} "
                        f"TYPE={e['logon_type']} "
                        f"TIME={e['time'].strftime('%H:%M:%S')}"
                    )
                    attack_alert(
                        f"[FAILED LOGIN] IP={e['source_ip']}; TYPE={e['logon_type']}; TIME={e['time'].strftime('%H:%M:%S')}")

            cutoff = datetime.now() - timedelta(minutes=5)
            EVENT_BUFFER = [e for e in EVENT_BUFFER if e["time"] >= cutoff]

            EVENT_BUFFER = add_failed_attempts_by_ip(EVENT_BUFFER)
            df = pd.DataFrame(EVENT_BUFFER)

            df["rdp_bruteforce_rule"] = (
                    (df["event_id"] == 4625) &
                    (df["logon_type"].isin([3, 10])) &
                    (df["failed_attempts_5min_by_ip"] >= 5)
            )

            X = scaler.transform(df[FEATURES].fillna(0))
            df["anomaly"] = model.predict(X)

            alerts = df[df["rdp_bruteforce_rule"]].drop_duplicates("source_ip")

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

                if ip in last_alert_time and now - last_alert_time[ip] < ALERT_COOLDOWN:
                    continue

                last_alert_time[ip] = now

                print(f"⚠️ RDP BRUTE FORCE | SEVERITY={severity} | IP={ip} | ATTEMPTS={attempts}")
                if severity in ("HIGH", "CRITICAL"):
                    attack_alert(
                        f"⚠️ RDP BRUTE FORCE\n"
                        f"IP: {ip}\n"
                        f"Attempts: {attempts}\n"
                        f"Severity: {severity}"
                    )

                Notification(
                    app_id="RDP AI Defender",
                    title="⚠️ RDP ATTACK DETECTED",
                    msg=f"IP: {ip}\nAttempts: {attempts}\nSeverity: {severity}",
                    duration="long"
                ).show()

                win32evtlogutil.ReportEvent(
                    EVENT_SOURCE,
                    1001,
                    eventType=win32con.EVENTLOG_WARNING_TYPE,
                    strings=[f"RDP brute-force detected from IP {ip}. Attempts: {row['failed_attempts_5min_by_ip']}"]
                )
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n RDP-checker завершив свою роботу")

if __name__ == "__main__":
    main()