from iam_analyzer.iam import analyze_policies, role_risk_summary
from iam_analyzer.sample import sample_policies


def test_findings_cover_known_bad_policies():
    findings, hierarchy = analyze_policies(sample_policies())
    by_role = {(r.role, r.issue) for r in findings.itertuples()}
    assert ("PlatformAdmin", "Full administrator access") in by_role
    assert ("CiDeployRole", "Role assumable by any principal") in by_role
    assert ("CiDeployRole", "Privilege-escalation primitive") in by_role
    assert ("IamManager", "Wildcard on iam") in by_role
    assert findings.iloc[0]["severity"] == "critical"
    assert not hierarchy.empty


def test_least_privilege_role_is_clean():
    findings, _ = analyze_policies(sample_policies())
    assert "DataScientist" in set(findings["role"])  # sagemaker:* on *
    assert "ReadOnlyAuditor" not in set(findings["role"])


def test_deny_statements_carry_no_risk():
    _, hierarchy = analyze_policies(sample_policies())
    deny = hierarchy[hierarchy["effect"] == "Deny"]
    assert not deny.empty and (deny["risk_score"] == 0).all()


def test_role_summary_ranks_admin_first():
    _, hierarchy = analyze_policies(sample_policies())
    assert role_risk_summary(hierarchy).iloc[0]["role"] == "PlatformAdmin"


def test_empty_document():
    findings, hierarchy = analyze_policies({})
    assert findings.empty and hierarchy.empty
