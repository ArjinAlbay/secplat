from __future__ import annotations

from secplat.domain.scanning.scoring import (
    calculate_category_score,
    calculate_security_score,
    grade_from_score,
)


def test_grade_mapping() -> None:
    assert grade_from_score(100) == "A"
    assert grade_from_score(90) == "A"
    assert grade_from_score(89) == "B"
    assert grade_from_score(75) == "B"
    assert grade_from_score(74) == "C"
    assert grade_from_score(60) == "C"
    assert grade_from_score(59) == "D"
    assert grade_from_score(40) == "D"
    assert grade_from_score(39) == "F"
    assert grade_from_score(0) == "F"


def test_calculate_category_score_perfect() -> None:
    cat = calculate_category_score("sast", {})
    assert cat.score == 100
    assert cat.grade == "A"
    assert cat.total_findings == 0


def test_calculate_category_score_deductions() -> None:
    # 1 critical (25), 1 high (10), 2 medium (6), 3 low (3) -> total penalty = 44
    cat = calculate_category_score(
        "sast",
        {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 5},
    )
    assert cat.score == 56
    assert cat.grade == "D"
    assert cat.total_findings == 12


def test_calculate_security_score_clamping() -> None:
    score = calculate_security_score({"critical": 10})
    assert score.score == 0
    assert score.grade == "F"
    assert score.penalties == 250


def test_calculate_security_score_with_categories() -> None:
    counts = {"critical": 1, "high": 1}
    cat_counts = {
        "secrets": {"critical": 1},
        "sast": {"high": 1},
    }
    score = calculate_security_score(counts, cat_counts)
    assert score.score == 65
    assert score.grade == "C"
    assert score.penalties == 35
    assert "secrets" in score.categories
    assert score.categories["secrets"].score == 75
    assert score.categories["secrets"].grade == "B"
    assert "sast" in score.categories
    assert score.categories["sast"].score == 90
    assert score.categories["sast"].grade == "A"
