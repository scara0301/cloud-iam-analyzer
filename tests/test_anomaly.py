import json

import pytest

from iam_analyzer.anomaly import detect_anomalies
from iam_analyzer.loaders import load_events
from iam_analyzer.sample import attack_marker, generate_cloudtrail


@pytest.fixture(scope="module")
def scored():
    doc = generate_cloudtrail(seed=42)
    events = load_events(json.dumps(doc), "ct.json")
    attack_ips = {r["sourceIPAddress"] for r in doc["Records"] if attack_marker(r)}
    scored = detect_anomalies(events, contamination=0.03)
    scored["injected"] = scored["source_ip"].isin(attack_ips)
    return scored


def test_columns_added(scored):
    assert {"anomaly_score", "is_anomaly", "reasons"} <= set(scored.columns)
    assert scored["anomaly_score"].between(0, 1).all()


def test_flag_rate_matches_contamination(scored):
    rate = scored["is_anomaly"].mean()
    assert 0.02 <= rate <= 0.04


def test_attack_activity_detected(scored):
    attack = scored[scored["injected"]]
    assert len(attack) > 0
    recall = attack["is_anomaly"].mean()
    assert recall >= 0.7, f"only {recall:.0%} of injected attack events flagged"


def test_privilege_escalation_has_reasons(scored):
    row = scored[(scored["event_name"] == "AttachUserPolicy") & scored["injected"]].iloc[0]
    assert row["is_anomaly"]
    assert "sensitive" in row["reasons"]
    assert "unusual country" in row["reasons"]


def test_tiny_input_does_not_crash(scored):
    out = detect_anomalies(
        scored.head(3)[
            ["event_time", "event_name", "user", "source_ip", "country_iso3", "error_code"]
        ]
    )
    assert not out["is_anomaly"].any()
