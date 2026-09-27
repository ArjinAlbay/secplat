from __future__ import annotations

import pytest

from secplat.domain.scanning.errors import InvalidTargetValue
from secplat.domain.scanning.value_objects import Severity, TargetKind, TargetRef
from secplat.infrastructure.tools.checkov.adapter import CheckovAdapter


@pytest.fixture()
def adapter() -> CheckovAdapter:
    return CheckovAdapter(binary="checkov")


@pytest.fixture()
def target() -> TargetRef:
    return TargetRef(kind=TargetKind.PATH, value="/srv/projects/demo")


def test_build_args_defaults(adapter: CheckovAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(target, {})
    assert argv[0] == "checkov"
    assert argv[argv.index("-o") + 1] == "json"
    assert "--quiet" in argv
    assert "--compact" in argv
    assert "--soft-fail" in argv
    assert "--skip-path" in argv
    assert "-d" in argv or "-f" in argv
    assert "/srv/projects/demo" in argv


def test_build_args_framework_and_skip(adapter: CheckovAdapter, target: TargetRef) -> None:
    argv = adapter.build_args(
        target,
        {"framework": "terraform", "skip_path": ["custom_dir"]},
    )
    assert "--framework" in argv
    assert argv[argv.index("--framework") + 1] == "terraform"
    assert "custom_dir" in argv


def test_non_path_target_rejected(adapter: CheckovAdapter) -> None:
    with pytest.raises(InvalidTargetValue):
        adapter.build_args(TargetRef(kind=TargetKind.DOMAIN, value="example.com"), {})


def _report_dict() -> dict:
    return {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "Ensure S3 bucket an S3 bucket has an S3 bucket policy",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 15],
                    "resource": "aws_s3_bucket.mybucket",
                    "severity": "HIGH",
                    "guideline": "https://docs.bridgecrew.io/docs/s3_1-bucket-policy",
                },
                {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Ensure S3 bucket has access logging enabled",
                    "file_path": "/s3.tf",
                    "file_line_range": [20, 30],
                    "resource": "aws_s3_bucket.logging",
                    "severity": "LOW",
                },
            ],
            "passed_checks": [],
            "skipped_checks": [],
        },
        "summary": {
            "passed": 0,
            "failed": 2,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": 2,
        },
    }


def test_parse_report_single_dict(adapter: CheckovAdapter) -> None:
    records = adapter.parse_report(_report_dict())
    assert len(records) == 2

    first = records[0]
    assert first.template_id == "CKV_AWS_20"
    assert first.name == "Ensure S3 bucket an S3 bucket has an S3 bucket policy"
    assert first.severity is Severity.HIGH
    assert first.matched_at == "main.tf:1"
    assert first.host == "main.tf"
    assert "resource: aws_s3_bucket.mybucket" in first.extracted
    assert "guideline: https://docs.bridgecrew.io/docs/s3_1-bucket-policy" in first.extracted

    second = records[1]
    assert second.template_id == "CKV_AWS_18"
    assert second.severity is Severity.LOW
    assert second.matched_at == "s3.tf:20"


def test_parse_report_multi_framework_list(adapter: CheckovAdapter) -> None:
    multi_report = [
        _report_dict(),
        {
            "check_type": "dockerfile",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_1",
                        "check_name": "Ensure container does not run as root",
                        "file_path": "/Dockerfile",
                        "file_line_range": [5, 5],
                        "resource": "Dockerfile.",
                        "severity": "CRITICAL",
                    }
                ]
            },
        },
    ]
    records = adapter.parse_report(multi_report)
    assert len(records) == 3
    assert records[2].template_id == "CKV_DOCKER_1"
    assert records[2].severity is Severity.CRITICAL


def test_parse_report_empty_or_invalid(adapter: CheckovAdapter) -> None:
    assert adapter.parse_report({}) == ()
    assert adapter.parse_report([]) == ()
    assert adapter.parse_report({"results": None}) == ()
