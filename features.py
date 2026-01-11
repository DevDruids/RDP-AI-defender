from datetime import timedelta

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