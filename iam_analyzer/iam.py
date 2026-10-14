"""Static analysis of IAM role policies: over-privilege findings + hierarchy data.

Input document shape::

    {"roles": [{"name": str, "trust_policy": {...},
                "policies": [{"name": str, "document": {"Statement": [...]}}]}]}
"""

from __future__ import annotations

from typing import Any

import pandas as pd

HIGH_IMPACT_SERVICES = frozenset({"iam", "sts", "kms", "organizations", "cloudtrail"})
PRIVESC_ACTIONS = frozenset(
    {
        "iam:passrole",
        "iam:createaccesskey",
        "iam:attachuserpolicy",
        "iam:attachrolepolicy",
        "iam:putuserpolicy",
        "iam:putrolepolicy",
        "iam:updateassumerolepolicy",
        "iam:createpolicyversion",
        "iam:setdefaultpolicyversion",
        "sts:assumerole",
    }
)

READ_ONLY_PREFIXES = ("Get", "List", "Describe", "Lookup")

RISK_LABELS = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "admin"}

FINDING_COLUMNS = ["severity", "role", "policy", "issue", "detail"]
HIERARCHY_COLUMNS = [
    "role",
    "policy",
    "service",
    "action",
    "effect",
    "resource",
    "risk_score",
    "risk",
    "count",
]


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _split_action(action: str) -> tuple[str, str]:
    if action == "*":
        return "*", "*"
    service, _, name = action.partition(":")
    return service.lower(), name or "*"


def _action_risk(action: str, resources: list[str]) -> int:
    service, name = _split_action(action)
    all_resources = "*" in resources
    if service == "*" and all_resources:
        return 4
    if service == "*":
        return 3
    wildcard = "*" in name
    if name.startswith(READ_ONLY_PREFIXES):
        return 1 if wildcard or all_resources else 0
    if action.lower() in PRIVESC_ACTIONS and all_resources:
        return 3
    if service in HIGH_IMPACT_SERVICES and wildcard and all_resources:
        return 3
    if wildcard and all_resources:
        return 2
    if wildcard or all_resources:
        return 1
    return 1


def analyze_policies(doc: dict[str, Any]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return ``(findings, hierarchy)`` frames for the supplied role definitions."""
    findings: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []

    for role in doc.get("roles", []):
        role_name = role.get("name", "unnamed-role")

        for stmt in _as_list(role.get("trust_policy", {}).get("Statement")):
            principals = stmt.get("Principal", {})
            aws = _as_list(principals.get("AWS") if isinstance(principals, dict) else principals)
            if stmt.get("Effect") == "Allow" and "*" in aws and "Condition" not in stmt:
                findings.append(
                    {
                        "severity": "critical",
                        "role": role_name,
                        "policy": "(trust policy)",
                        "issue": "Role assumable by any principal",
                        "detail": 'Trust policy allows Principal "*" without a Condition.',
                    }
                )

        for policy in role.get("policies", []):
            policy_name = policy.get("name", "unnamed-policy")
            for stmt in _as_list(policy.get("document", {}).get("Statement")):
                effect = stmt.get("Effect", "Allow")
                resources = [str(r) for r in _as_list(stmt.get("Resource"))] or ["*"]
                actions = [str(a) for a in _as_list(stmt.get("Action"))]

                if "NotAction" in stmt and effect == "Allow":
                    findings.append(
                        {
                            "severity": "high",
                            "role": role_name,
                            "policy": policy_name,
                            "issue": "Allow with NotAction",
                            "detail": "Grants everything except the listed actions.",
                        }
                    )

                for action in actions:
                    service, name = _split_action(action)
                    risk = _action_risk(action, resources) if effect == "Allow" else 0
                    rows.append(
                        {
                            "role": role_name,
                            "policy": policy_name,
                            "service": "ALL" if service == "*" else service,
                            "action": name,
                            "effect": effect,
                            "resource": ", ".join(resources),
                            "risk_score": risk,
                            "risk": RISK_LABELS[risk],
                            "count": 1,
                        }
                    )
                    if effect != "Allow" or risk < 2:
                        continue
                    if risk == 4:
                        issue, severity = "Full administrator access", "critical"
                        detail = "Action * on Resource * grants unrestricted control."
                    elif action.lower() in PRIVESC_ACTIONS:
                        issue, severity = "Privilege-escalation primitive", "high"
                        detail = f"{action} on Resource * enables privilege escalation."
                    elif service in HIGH_IMPACT_SERVICES:
                        issue, severity = f"Wildcard on {service}", "high"
                        detail = f"{action} on Resource * over a high-impact service."
                    else:
                        issue, severity = "Wildcard action and resource", "medium"
                        detail = f"{action} on Resource * violates least privilege."
                    findings.append(
                        {
                            "severity": severity,
                            "role": role_name,
                            "policy": policy_name,
                            "issue": issue,
                            "detail": detail,
                        }
                    )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_df = pd.DataFrame(findings, columns=FINDING_COLUMNS)
    if not findings_df.empty:
        findings_df = (
            findings_df.drop_duplicates()
            .sort_values("severity", key=lambda s: s.map(order))
            .reset_index(drop=True)
        )
    return findings_df, pd.DataFrame(rows, columns=HIERARCHY_COLUMNS)


def role_risk_summary(hierarchy: pd.DataFrame) -> pd.DataFrame:
    """Highest risk score and permission count per role."""
    if hierarchy.empty:
        return pd.DataFrame(columns=["role", "max_risk", "permissions"])
    summary = (
        hierarchy.groupby("role")
        .agg(max_risk=("risk_score", "max"), permissions=("count", "sum"))
        .reset_index()
        .sort_values(["max_risk", "permissions"], ascending=False)
    )
    summary["max_risk"] = summary["max_risk"].map(RISK_LABELS)
    return summary.reset_index(drop=True)
