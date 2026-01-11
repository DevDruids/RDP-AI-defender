import win32evtlog
from datetime import datetime, timedelta

flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ
SECURITY_EVENTS = {4624, 4625, 4634, 4672}
SYSMON_EVENTS = {1, 3}

time_window_minutes = 15

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
        except Exception:
            break

        if not events:
            break

        for e in events:
            try:
                event_id = getattr(e, "EventID", 0) & 0xFFFF
                dt = getattr(e, "TimeGenerated", datetime.now())
            except Exception:
                continue

            if dt < time_window:
                continue

            if log_type == "rdp" and event_id != 1149:
                continue
            if log_type == "security" and event_id not in SECURITY_EVENTS:
                continue
            if log_type == "sysmon" and event_id not in SYSMON_EVENTS:
                continue

            strings = getattr(e, "StringInserts", []) or []
            logon_type = -1
            source_ip = "-"

            if event_id in (4624, 4625) and strings:
                try:
                    logon_type = int(strings[10])
                except Exception:
                    logon_type = -1

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
                "hour": getattr(dt, "hour", 0),
                "weekday": getattr(dt, "weekday", lambda: 0)(),
                "is_failed_login": 1 if event_id == 4625 else 0,
                "is_successful_login": 1 if event_id == 4624 else 0,
                "source_ip": source_ip,
                "is_rdp": isRDPEvent(event_id, logon_type, log_type),
                "time": dt
            })

    return collected_events
