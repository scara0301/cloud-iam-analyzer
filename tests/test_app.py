import json
from pathlib import Path

from streamlit.testing.v1 import AppTest

from iam_analyzer.anomaly import detect_anomalies
from iam_analyzer.iam import analyze_policies
from iam_analyzer.loaders import load_events
from iam_analyzer.sample import generate_cloudtrail, sample_policies
from iam_analyzer.viz import anomaly_geo_map, anomaly_timeline, iam_sunburst

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def test_figures_build():
    events = load_events(json.dumps(generate_cloudtrail()), "x.json")
    scored = detect_anomalies(events)
    _, hierarchy = analyze_policies(sample_policies())
    geo = anomaly_geo_map(scored)
    assert geo.data[0].type == "choropleth"
    assert "RUS" in set(geo.data[0].locations)
    assert anomaly_timeline(scored).data
    assert iam_sunburst(hierarchy).data[0].type == "sunburst"


def test_figures_handle_empty():
    events = load_events(json.dumps(generate_cloudtrail()), "x.json").head(0)
    events["is_anomaly"] = []
    events["anomaly_score"] = []
    assert anomaly_geo_map(events).layout.annotations
    assert iam_sunburst(analyze_policies({})[1]).layout.annotations


def test_app_renders_with_sample_data():
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    assert [m.label for m in at.metric][:2] == ["Events analysed", "Anomalies flagged"]
