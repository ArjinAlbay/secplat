from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

SEVERITY_PENALTIES: dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
    "info": 0,
}

TOOL_CATEGORY_MAP: dict[str, str] = {
    "gitleaks": "secrets",
    "semgrep": "sast",
    "trivy": "sca",
    "checkov": "iac",
    "nuclei": "dast",
    "subfinder": "recon",
    "httpx": "recon",
}


def grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


@dataclass(frozen=True, slots=True)
class CategoryScore:
    category: str
    score: int
    grade: str
    total_findings: int
    counts_by_severity: dict[str, int]


@dataclass(frozen=True, slots=True)
class SecurityScore:
    score: int
    grade: str
    total_findings: int
    penalties: int
    counts_by_severity: dict[str, int]
    categories: dict[str, CategoryScore] = field(default_factory=dict)


def calculate_category_score(
    category: str, counts_by_severity: Mapping[str, int]
) -> CategoryScore:
    penalty = 0
    total = 0
    counts: dict[str, int] = {}
    for sev, count in counts_by_severity.items():
        cnt = int(count)
        counts[sev] = cnt
        total += cnt
        penalty += cnt * SEVERITY_PENALTIES.get(sev.lower(), 0)

    score = max(0, min(100, 100 - penalty))
    grade = grade_from_score(score)
    return CategoryScore(
        category=category,
        score=score,
        grade=grade,
        total_findings=total,
        counts_by_severity=counts,
    )


def calculate_security_score(
    counts_by_severity: Mapping[str, int],
    category_counts: Mapping[str, Mapping[str, int]] | None = None,
) -> SecurityScore:
    total_penalty = 0
    total_findings = 0
    total_counts: dict[str, int] = {}

    for sev, count in counts_by_severity.items():
        cnt = int(count)
        total_counts[sev] = cnt
        total_findings += cnt
        total_penalty += cnt * SEVERITY_PENALTIES.get(sev.lower(), 0)

    overall_score = max(0, min(100, 100 - total_penalty))
    overall_grade = grade_from_score(overall_score)

    categories: dict[str, CategoryScore] = {}
    if category_counts:
        for cat, cat_counts in category_counts.items():
            categories[cat] = calculate_category_score(cat, cat_counts)

    return SecurityScore(
        score=overall_score,
        grade=overall_grade,
        total_findings=total_findings,
        penalties=total_penalty,
        counts_by_severity=total_counts,
        categories=categories,
    )
