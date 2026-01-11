from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = [
    "hour",
    "weekday",
    "is_failed_login",
    "is_successful_login",
    "logon_type",
    "failed_attempts_5min_by_ip",
    "is_rdp"
]

def train_model(df):
    scaler = StandardScaler()
    X = scaler.fit_transform(df[FEATURES].fillna(0))

    model = IsolationForest(
        n_estimators=150,
        contamination=0.03,
        random_state=42
    )
    model.fit(X)

    return model, scaler

