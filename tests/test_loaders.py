import json

import pytest

from iam_analyzer.loaders import COLUMNS, LogFormatError, load_events
from iam_analyzer.sample import generate_cloudtrail


def test_cloudtrail_normalised():
    doc = generate_cloudtrail(seed=1)
    df = load_events(json.dumps(doc), "ct.json")
    assert list(df.columns) == COLUMNS
    assert len(df) == len(doc["Records"])
    assert (df["provider"] == "aws").all()
    assert df["event_time"].is_monotonic_increasing
    assert "svc-deploy" in set(df["user"].str.split("/").str[-1])


def test_ndjson_and_csv():
    rec = generate_cloudtrail(seed=1)["Records"][:5]
    nd = "\n".join(json.dumps(r) for r in rec)
    assert len(load_events(nd, "x.json")) == 5

    csv = "eventTime,eventName,eventSource,userName,sourceIPAddress\n"
    csv += "2025-03-03T10:00:00Z,GetObject,s3.amazonaws.com,alice,203.0.113.10\n"
    df = load_events(csv, "x.csv")
    assert df.loc[0, "user"] == "alice"
    assert df.loc[0, "country_iso3"] == "UNK"


def test_azure_activity_log():
    doc = {
        "value": [
            {
                "eventTimestamp": "2025-03-03T10:00:00Z",
                "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
                "caller": "eve@contoso.com",
                "callerIpAddress": "203.0.113.5",
                "status": {"value": "Failed"},
            }
        ]
    }
    df = load_events(json.dumps(doc), "azure.json")
    assert df.loc[0, "provider"] == "azure"
    assert df.loc[0, "error_code"] == "Failed"


def test_gcp_audit_log():
    doc = [
        {
            "timestamp": "2025-03-03T10:00:00Z",
            "protoPayload": {
                "methodName": "SetIamPolicy",
                "serviceName": "cloudresourcemanager.googleapis.com",
                "authenticationInfo": {"principalEmail": "sa@proj.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "203.0.113.7"},
                "status": {"code": 7},
            },
        }
    ]
    df = load_events(json.dumps(doc), "gcp.json")
    assert df.loc[0, "provider"] == "gcp"
    assert df.loc[0, "event_name"] == "SetIamPolicy"
    assert df.loc[0, "error_code"] == 7


def test_unknown_schema_rejected():
    with pytest.raises(LogFormatError):
        load_events(json.dumps([{"foo": "bar"}]), "bad.json")
    with pytest.raises(LogFormatError):
        load_events("{not json", "bad.json")
