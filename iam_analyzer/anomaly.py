"""Behavioural anomaly detection over normalised audit events.

An IsolationForest is trained on per-event features that capture *how unusual* an
API call is globally and relative to the calling identity. A lightweight rule layer
adds human-readable reasons so analysts can see why an event was flagged.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

SENSITIVE_EVENTS = frozenset(
    {
        "CreateUser",
        "CreateAccessKey",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "UpdateAssumeRolePolicy",
        "AddUserToGroup",
        "DeleteTrail",
        "StopLogging",
        "UpdateTrail",
        "PutEventSelectors",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "DisableKey",
        "ScheduleKeyDeletion",
        "DeleteFlowLogs",
        "GetSecretValue",
    }
)

FEATURES = [
    "hour_sin",
    "hour_cos",
    "event_rarity",
    "user_event_rarity",
    "user_country_rarity",
    "user_ip_rarity",
    "is_error",
    "is_sensitive",
    "is_login",
    "user_burst",
]


def _rarity(df: pd.DataFrame, keys: list[str]) -> pd.Series:
    """-log(relative frequency) of ``keys`` combination; larger = rarer."""
    counts = df.groupby(keys)["event_name"].transform("size")
    if len(keys) == 1:
        total = len(df)
    else:
        total = df.groupby(keys[:-1])["event_name"].transform("size")
    return -np.log(counts / total)


def build_features(events: pd.DataFrame) -> pd.DataFrame:
    """Compute the numeric feature matrix (one row per event)."""
    ts = events["event_time"]
    hour = ts.dt.hour + ts.dt.minute / 60.0
    feats = pd.DataFrame(index=events.index)
    feats["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    feats["hour_cos"] = np.cos(2 * np.pi * hour / 24)
    feats["event_rarity"] = _rarity(events, ["event_name"])
    feats["user_event_rarity"] = _rarity(events, ["user", "event_name"])
    feats["user_country_rarity"] = _rarity(events, ["user", "country_iso3"])
    feats["user_ip_rarity"] = _rarity(events, ["user", "source_ip"])
    feats["is_error"] = events["error_code"].notna().astype(float)
    feats["is_sensitive"] = events["event_name"].isin(SENSITIVE_EVENTS).astype(float)
    feats["is_login"] = events["event_name"].eq("ConsoleLogin").astype(float)

    # Events by the same user within the same 5-minute bucket: bursts of API calls.
    bucket = ts.dt.floor("5min")
    feats["user_burst"] = np.log1p(events.groupby(["user", bucket])["event_name"].transform("size"))
    return feats


def _reasons(events: pd.DataFrame, feats: pd.DataFrame) -> pd.Series:
    hour = events["event_time"].dt.hour
    # Rarity is -log(share); this flags countries/IPs under 10% of a user's activity.
    minor_share = -np.log(0.10)
    rules = {
        "sensitive IAM/logging action": feats["is_sensitive"] > 0,
        "unusual country for user": feats["user_country_rarity"] > minor_share,
        "unusual source IP for user": feats["user_ip_rarity"] > minor_share,
        "rare action for user": feats["user_event_rarity"] > 4.0,
        "off-hours activity": (hour < 6) | (hour >= 22),
        "denied / failed call": feats["is_error"] > 0,
        "burst of API calls": feats["user_burst"] > np.log1p(8),
    }
    reasons = pd.Series("", index=events.index, dtype="object")
    for label, mask in rules.items():
        reasons = reasons.where(~mask, reasons + label + "; ")
    return reasons.str.rstrip("; ")


def detect_anomalies(
    events: pd.DataFrame,
    contamination: float = 0.03,
    random_state: int = 42,
) -> pd.DataFrame:
    """Return ``events`` plus ``anomaly_score`` (0-1), ``is_anomaly`` and ``reasons``."""
    result = events.copy().reset_index(drop=True)
    if len(result) < 10:
        result["anomaly_score"] = 0.0
        result["is_anomaly"] = False
        result["reasons"] = ""
        return result

    feats = build_features(result)
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=1,
    )
    model.fit(feats[FEATURES])
    raw = -model.score_samples(feats[FEATURES])
    span = raw.max() - raw.min()
    result["anomaly_score"] = (raw - raw.min()) / span if span else 0.0
    result["is_anomaly"] = model.predict(feats[FEATURES]) == -1
    result["reasons"] = _reasons(result, feats)
    return result
