"""Deterministic synthetic telemetry so the app and tests run without cloud access.

The CloudTrail-shaped data contains a compromised service account (``svc-deploy``)
performing reconnaissance, privilege escalation and defence evasion from an
unfamiliar country at night, plus one benign-but-odd travel login. All addresses
come from RFC 5737 documentation ranges.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

# user -> (home country ISO-3, home IP, region, [(event, source, weight), ...])
_USERS: dict[str, tuple[str, str, str, list[tuple[str, str, int]]]] = {
    "alice": (
        "USA",
        "203.0.113.10",
        "us-east-1",
        [
            ("DescribeInstances", "ec2.amazonaws.com", 40),
            ("GetObject", "s3.amazonaws.com", 35),
            ("ListBuckets", "s3.amazonaws.com", 10),
            ("ConsoleLogin", "signin.amazonaws.com", 5),
        ],
    ),
    "bob": (
        "GBR",
        "203.0.113.25",
        "eu-west-2",
        [
            ("PutObject", "s3.amazonaws.com", 40),
            ("GetObject", "s3.amazonaws.com", 30),
            ("DescribeDBInstances", "rds.amazonaws.com", 10),
            ("ConsoleLogin", "signin.amazonaws.com", 5),
        ],
    ),
    "carol": (
        "IND",
        "203.0.113.40",
        "ap-south-1",
        [
            ("RunInstances", "ec2.amazonaws.com", 10),
            ("DescribeInstances", "ec2.amazonaws.com", 35),
            ("GetMetricData", "monitoring.amazonaws.com", 30),
            ("ConsoleLogin", "signin.amazonaws.com", 5),
        ],
    ),
    "svc-deploy": (
        "USA",
        "198.51.100.5",
        "us-east-1",
        [
            ("UpdateService", "ecs.amazonaws.com", 40),
            ("DescribeServices", "ecs.amazonaws.com", 30),
            ("GetAuthorizationToken", "ecr.amazonaws.com", 20),
        ],
    ),
}

_ATTACK_IP = "192.0.2.77"
_ATTACK_COUNTRY = "RUS"
_ATTACK_SEQUENCE = [
    ("GetCallerIdentity", "sts.amazonaws.com", None),
    ("ListUsers", "iam.amazonaws.com", None),
    ("ListRoles", "iam.amazonaws.com", None),
    ("ListAccessKeys", "iam.amazonaws.com", "AccessDenied"),
    ("CreateUser", "iam.amazonaws.com", None),
    ("CreateAccessKey", "iam.amazonaws.com", None),
    ("AttachUserPolicy", "iam.amazonaws.com", None),
    ("PutUserPolicy", "iam.amazonaws.com", None),
    ("UpdateAssumeRolePolicy", "iam.amazonaws.com", None),
    ("StopLogging", "cloudtrail.amazonaws.com", None),
    ("DeleteTrail", "cloudtrail.amazonaws.com", "AccessDenied"),
    ("GetSecretValue", "secretsmanager.amazonaws.com", None),
    ("PutBucketPolicy", "s3.amazonaws.com", None),
]


def _record(
    when: datetime,
    user: str,
    event: str,
    source: str,
    ip: str,
    region: str,
    country: str,
    error: str | None = None,
    agent: str = "aws-cli/2.15.0",
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": event,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": agent,
        "userIdentity": {
            "type": "IAMUser",
            "userName": user,
            "arn": f"arn:aws:iam::123456789012:user/{user}",
        },
        "country_iso3": country,
    }
    if error:
        rec["errorCode"] = error
    return rec


def generate_cloudtrail(seed: int = 42, days: int = 7) -> dict[str, list[dict]]:
    """Return a CloudTrail-style ``{"Records": [...]}`` document."""
    rng = random.Random(seed)
    start = datetime(2025, 3, 3, tzinfo=timezone.utc)
    records: list[dict[str, Any]] = []

    for day in range(days):
        for user, (country, ip, region, events) in _USERS.items():
            names = [e[:2] for e in events]
            weights = [e[2] for e in events]
            for _ in range(rng.randint(35, 55)):
                event, source = rng.choices(names, weights)[0]
                when = start + timedelta(
                    days=day,
                    hours=rng.randint(8, 18),
                    minutes=rng.randint(0, 59),
                    seconds=rng.randint(0, 59),
                )
                error = "AccessDenied" if rng.random() < 0.01 else None
                records.append(_record(when, user, event, source, ip, region, country, error))

    # Benign outlier: bob logs in from Brazil at 02:00 while travelling.
    records.append(
        _record(
            start + timedelta(days=3, hours=2, minutes=14),
            "bob",
            "ConsoleLogin",
            "signin.amazonaws.com",
            "203.0.113.99",
            "sa-east-1",
            "BRA",
            agent="Mozilla/5.0",
        )
    )

    # Attack: svc-deploy credentials used from an unfamiliar country at 03:xx UTC.
    attack_start = start + timedelta(days=4, hours=3, minutes=7)
    for i, (event, source, error) in enumerate(_ATTACK_SEQUENCE):
        records.append(
            _record(
                attack_start + timedelta(seconds=25 * i),
                "svc-deploy",
                event,
                source,
                _ATTACK_IP,
                "us-east-1",
                _ATTACK_COUNTRY,
                error,
                agent="python-requests/2.31.0",
            )
        )
    for i in range(3):
        records.append(
            _record(
                attack_start - timedelta(minutes=5 - i),
                "svc-deploy",
                "ConsoleLogin",
                "signin.amazonaws.com",
                _ATTACK_IP,
                "us-east-1",
                _ATTACK_COUNTRY,
                "AccessDenied",
                agent="python-requests/2.31.0",
            )
        )

    records.sort(key=lambda r: r["eventTime"])
    return {"Records": records}


def attack_marker(record: dict[str, Any]) -> bool:
    """True for records injected by ``generate_cloudtrail`` as attacker activity."""
    return record["sourceIPAddress"] == _ATTACK_IP


def sample_policies() -> dict[str, Any]:
    """IAM roles with a spread of good and bad policies for the privilege analyzer."""
    admin_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    account_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    return {
        "roles": [
            {
                "name": "PlatformAdmin",
                "trust_policy": account_trust,
                "policies": [
                    {
                        "name": "FullAdmin",
                        "document": {
                            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                        },
                    }
                ],
            },
            {
                "name": "CiDeployRole",
                "trust_policy": admin_trust,
                "policies": [
                    {
                        "name": "DeployPolicy",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["ecs:*", "ecr:GetAuthorizationToken"],
                                    "Resource": "*",
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:PassRole",
                                    "Resource": "*",
                                },
                            ]
                        },
                    }
                ],
            },
            {
                "name": "DataScientist",
                "trust_policy": account_trust,
                "policies": [
                    {
                        "name": "S3ReadOnly",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:GetObject", "s3:ListBucket"],
                                    "Resource": [
                                        "arn:aws:s3:::analytics-data",
                                        "arn:aws:s3:::analytics-data/*",
                                    ],
                                }
                            ]
                        },
                    },
                    {
                        "name": "SageMakerAccess",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sagemaker:*",
                                    "Resource": "*",
                                }
                            ]
                        },
                    },
                ],
            },
            {
                "name": "IamManager",
                "trust_policy": account_trust,
                "policies": [
                    {
                        "name": "IamFull",
                        "document": {
                            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]
                        },
                    },
                    {
                        "name": "DenyDeleteTrail",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Deny",
                                    "Action": [
                                        "cloudtrail:DeleteTrail",
                                        "cloudtrail:StopLogging",
                                    ],
                                    "Resource": "*",
                                }
                            ]
                        },
                    },
                ],
            },
            {
                "name": "ReadOnlyAuditor",
                "trust_policy": account_trust,
                "policies": [
                    {
                        "name": "AuditRead",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "cloudtrail:LookupEvents",
                                        "iam:Get*",
                                        "iam:List*",
                                    ],
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                ],
            },
        ]
    }
