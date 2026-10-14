"""Parse and normalise cloud audit logs (AWS CloudTrail, Azure Activity, GCP Audit).

Every provider is mapped onto the same flat schema (``COLUMNS``) so the analytics
layer is provider-agnostic.

CloudTrail/Azure/GCP logs carry no geolocation. The map view expects an enrichment
column named ``country_iso3`` (ISO 3166-1 alpha-3); rows without it get ``UNK``.
"""

from __future__ import annotations

import io
import json
from typing import Any, Iterable

import pandas as pd

COLUMNS = [
    "event_time",
    "provider",
    "event_name",
    "event_source",
    "user",
    "source_ip",
    "region",
    "user_agent",
    "error_code",
    "country_iso3",
]

UNKNOWN_COUNTRY = "UNK"


class LogFormatError(ValueError):
    """Raised when an uploaded file cannot be interpreted as audit logs."""


def _records_from_json(text: str) -> list[dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Newline-delimited JSON (e.g. GCP log sinks, CloudTrail Lake exports).
        try:
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise LogFormatError(f"Invalid JSON: {exc}") from exc
    if isinstance(data, dict):
        for key in ("Records", "value", "entries", "events", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    if isinstance(data, list):
        return data
    raise LogFormatError("JSON root must be an object or an array of events.")


def _first(df: pd.DataFrame, candidates: Iterable[str]) -> pd.Series:
    """Coalesce the first non-empty value across candidate columns."""
    result = pd.Series([None] * len(df), index=df.index, dtype="object")
    for name in candidates:
        if name in df.columns:
            col = df[name].replace("", None)
            result = result.where(result.notna(), col)
    return result


def _detect_provider(columns: set[str]) -> str:
    if {"eventname", "eventsource"} <= columns:
        return "aws"
    if "protopayload.methodname" in columns:
        return "gcp"
    if "operationname" in columns or "operationname.value" in columns:
        return "azure"
    raise LogFormatError(
        "Unrecognised log schema. Expected AWS CloudTrail, Azure Activity Log "
        "or Google Cloud Audit Log events."
    )


def normalize_events(raw: pd.DataFrame) -> pd.DataFrame:
    """Map a flattened provider-specific frame onto ``COLUMNS``."""
    if raw.empty:
        return pd.DataFrame(columns=COLUMNS)

    df = raw.copy()
    df.columns = [str(c).lower() for c in df.columns]
    provider = _detect_provider(set(df.columns))

    out = pd.DataFrame(index=df.index)
    out["provider"] = provider

    if provider == "aws":
        out["event_time"] = _first(df, ["eventtime", "event_time"])
        out["event_name"] = _first(df, ["eventname"])
        out["event_source"] = _first(df, ["eventsource"])
        out["user"] = _first(
            df,
            [
                "useridentity.arn",
                "useridentity.username",
                "useridentity.principalid",
                "username",
                "arn",
            ],
        )
        out["source_ip"] = _first(df, ["sourceipaddress"])
        out["region"] = _first(df, ["awsregion"])
        out["user_agent"] = _first(df, ["useragent"])
        out["error_code"] = _first(df, ["errorcode"])
    elif provider == "azure":
        out["event_time"] = _first(df, ["eventtimestamp", "time", "submissiontimestamp"])
        out["event_name"] = _first(df, ["operationname.value", "operationname"])
        out["event_source"] = _first(
            df, ["resourceprovidername.value", "resourceprovidername", "category.value"]
        )
        out["user"] = _first(df, ["caller", "claims.upn"])
        out["source_ip"] = _first(df, ["calleripaddress", "claims.ipaddr"])
        out["region"] = _first(df, ["location"])
        out["user_agent"] = None
        status = _first(df, ["status.value", "status"])
        out["error_code"] = status.where(status.astype(str).str.lower() == "failed", None)
    else:  # gcp
        out["event_time"] = _first(df, ["timestamp", "receivetimestamp"])
        out["event_name"] = _first(df, ["protopayload.methodname"])
        out["event_source"] = _first(df, ["protopayload.servicename"])
        out["user"] = _first(df, ["protopayload.authenticationinfo.principalemail"])
        out["source_ip"] = _first(df, ["protopayload.requestmetadata.callerip"])
        out["region"] = _first(df, ["resource.labels.location", "resource.labels.region"])
        out["user_agent"] = _first(df, ["protopayload.requestmetadata.callersupplieduseragent"])
        code = pd.to_numeric(_first(df, ["protopayload.status.code"]), errors="coerce")
        out["error_code"] = code.where(code.fillna(0) != 0, None).astype("object")

    out["country_iso3"] = _first(df, ["country_iso3", "geo.country_iso3", "country"])

    out["event_time"] = pd.to_datetime(out["event_time"], utc=True, errors="coerce")
    out = out.dropna(subset=["event_time", "event_name"])
    out["user"] = out["user"].fillna("unknown")
    out["source_ip"] = out["source_ip"].fillna("unknown")
    out["region"] = out["region"].fillna("unknown")
    out["user_agent"] = out["user_agent"].fillna("unknown")
    out["event_source"] = out["event_source"].fillna("unknown")
    out["country_iso3"] = out["country_iso3"].fillna(UNKNOWN_COUNTRY).astype(str).str.upper()
    out["error_code"] = out["error_code"].where(out["error_code"].notna(), None)

    return out[COLUMNS].sort_values("event_time").reset_index(drop=True)


def load_events(content: bytes | str, filename: str = "events.json") -> pd.DataFrame:
    """Load a CSV/JSON/NDJSON audit-log export into the normalised schema."""
    text = content.decode("utf-8-sig") if isinstance(content, bytes) else content
    if filename.lower().endswith(".csv"):
        try:
            raw = pd.read_csv(io.StringIO(text), dtype=str)
        except (pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
            raise LogFormatError(f"Invalid CSV: {exc}") from exc
    else:
        raw = pd.json_normalize(_records_from_json(text))
    return normalize_events(raw)
