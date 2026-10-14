"""Plotly figures for the dashboard."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from .loaders import UNKNOWN_COUNTRY


def _empty(message: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font={"size": 16})
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    fig.update_layout(height=360, margin={"l": 0, "r": 0, "t": 30, "b": 0})
    return fig


def anomaly_geo_map(events: pd.DataFrame) -> go.Figure:
    """Choropleth of anomalous events by source country."""
    flagged = events[events["is_anomaly"] & (events["country_iso3"] != UNKNOWN_COUNTRY)]
    if flagged.empty:
        return _empty("No anomalous events with a known country.")
    by_country = (
        flagged.groupby("country_iso3")
        .agg(anomalies=("is_anomaly", "size"), users=("user", "nunique"))
        .reset_index()
    )
    fig = px.choropleth(
        by_country,
        locations="country_iso3",
        locationmode="ISO-3",
        color="anomalies",
        hover_data=["users"],
        color_continuous_scale="Reds",
        title="Anomalous API activity by source country",
    )
    fig.update_geos(showcountries=True, projection_type="natural earth")
    fig.update_layout(margin={"l": 0, "r": 0, "t": 40, "b": 0})
    return fig


def anomaly_timeline(events: pd.DataFrame) -> go.Figure:
    """Anomaly score over time, flagged events highlighted."""
    if events.empty:
        return _empty("No events loaded.")
    fig = px.scatter(
        events,
        x="event_time",
        y="anomaly_score",
        color="is_anomaly",
        color_discrete_map={True: "#d62728", False: "#9aa5b1"},
        hover_data=["user", "event_name", "source_ip", "country_iso3"],
        title="Anomaly score by event",
        labels={"event_time": "Time (UTC)", "anomaly_score": "Anomaly score"},
    )
    fig.update_traces(marker={"size": 6, "opacity": 0.75})
    fig.update_layout(margin={"l": 0, "r": 0, "t": 40, "b": 0}, legend_title="Flagged")
    return fig


def iam_sunburst(hierarchy: pd.DataFrame) -> go.Figure:
    """Role -> policy -> service permission hierarchy, coloured by risk."""
    if hierarchy.empty:
        return _empty("No IAM policies loaded.")
    fig = px.sunburst(
        hierarchy,
        path=["role", "policy", "service"],
        values="count",
        color="risk_score",
        range_color=(0, 4),
        color_continuous_scale="RdYlGn_r",
        title="IAM role to permission hierarchy (colour = risk)",
    )
    fig.update_layout(height=620, margin={"l": 0, "r": 0, "t": 40, "b": 0})
    return fig
