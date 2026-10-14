"""Streamlit entrypoint: Cloud Security Posture & IAM Privilege Analyzer."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from iam_analyzer.anomaly import detect_anomalies
from iam_analyzer.config import load_settings
from iam_analyzer.iam import analyze_policies, role_risk_summary
from iam_analyzer.loaders import LogFormatError, load_events
from iam_analyzer.sample import generate_cloudtrail, sample_policies
from iam_analyzer.viz import anomaly_geo_map, anomaly_timeline, iam_sunburst

settings = load_settings()
st.set_page_config(page_title=settings.app_title, page_icon="🛡️", layout="wide")


@st.cache_data(show_spinner=False)
def _sample_events(seed: int) -> pd.DataFrame:
    return load_events(json.dumps(generate_cloudtrail(seed)), "sample.json")


@st.cache_data(show_spinner="Scoring events…")
def _score(events: pd.DataFrame, contamination: float) -> pd.DataFrame:
    return detect_anomalies(events, contamination=contamination)


st.title(f"🛡️ {settings.app_title}")
st.caption(
    "Detect identity misconfigurations, excessive privileges and suspicious API "
    "activity from CloudTrail, Azure Activity or GCP Audit logs."
)

with st.sidebar:
    st.header("Data")
    logs = st.file_uploader("Audit logs (JSON / NDJSON / CSV)", type=["json", "csv"])
    policies_file = st.file_uploader("IAM role policies (JSON)", type=["json"])
    st.caption("Leave empty to use built-in synthetic sample data.")
    st.header("Detection")
    contamination = st.slider(
        "Expected anomaly rate",
        min_value=0.005,
        max_value=0.20,
        value=float(settings.default_contamination),
        step=0.005,
        help="IsolationForest contamination: share of events to flag.",
    )

try:
    if logs is not None:
        events = load_events(logs.getvalue(), logs.name)
        source_label = logs.name
    else:
        events = _sample_events(settings.sample_seed)
        source_label = "synthetic sample"
    if events.empty:
        st.warning("No usable events found in the uploaded file.")
        st.stop()
    if len(events) > settings.max_rows:
        st.warning(f"Showing the first {settings.max_rows:,} of {len(events):,} events.")
        events = events.head(settings.max_rows)

    policy_doc = json.loads(policies_file.getvalue()) if policies_file else sample_policies()
except (LogFormatError, json.JSONDecodeError) as exc:
    st.error(f"Could not read input: {exc}")
    st.stop()

scored = _score(events, contamination)
anomalies = scored[scored["is_anomaly"]]
findings, hierarchy = analyze_policies(policy_doc)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analysed", f"{len(scored):,}")
c2.metric("Anomalies flagged", f"{len(anomalies):,}")
c3.metric("Identities involved", anomalies["user"].nunique())
c4.metric(
    "Critical / high IAM findings",
    int(findings["severity"].isin(["critical", "high"]).sum()) if len(findings) else 0,
)
st.caption(f"Source: {source_label} · provider(s): {', '.join(scored['provider'].unique())}")

tab_activity, tab_iam = st.tabs(["API activity anomalies", "IAM privilege analysis"])

with tab_activity:
    left, right = st.columns(2)
    left.plotly_chart(anomaly_geo_map(scored), use_container_width=True)
    right.plotly_chart(anomaly_timeline(scored), use_container_width=True)
    st.subheader("Flagged events")
    st.dataframe(
        anomalies.sort_values("anomaly_score", ascending=False)[
            [
                "event_time",
                "user",
                "event_name",
                "source_ip",
                "country_iso3",
                "error_code",
                "anomaly_score",
                "reasons",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

with tab_iam:
    st.plotly_chart(iam_sunburst(hierarchy), use_container_width=True)
    left, right = st.columns([2, 1])
    with left:
        st.subheader("Findings")
        if findings.empty:
            st.success("No over-privileged policies detected.")
        else:
            st.dataframe(findings, use_container_width=True, hide_index=True)
    with right:
        st.subheader("Role risk")
        st.dataframe(role_risk_summary(hierarchy), use_container_width=True, hide_index=True)
