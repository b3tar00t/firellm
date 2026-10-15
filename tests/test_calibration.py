from __future__ import annotations

from firellm.calibration import calibrate


def test_case_one_high_both_axes_strong() -> None:
    severity, explanation = calibrate(delta=0.47, confidence=0.86, indicator_count=3)
    assert severity == "high"
    assert "exceeds high-divergence threshold of 0.40" in explanation
    assert "strong" in explanation


def test_case_two_low_weak() -> None:
    severity, explanation = calibrate(delta=0.12, confidence=0.68, indicator_count=1)
    assert severity == "low"
    assert "below moderate-divergence threshold" in explanation
    assert "weak" in explanation


def test_case_three_medium_single_strong_axis() -> None:
    severity, _ = calibrate(delta=0.25, confidence=0.86, indicator_count=1)
    assert severity == "medium"


def test_case_four_high_both_axes_agree() -> None:
    severity, _ = calibrate(delta=0.42, confidence=0.72, indicator_count=2)
    assert severity == "high"


def test_case_five_high_strong_confidence_multi_indicator() -> None:
    severity, _ = calibrate(delta=0.35, confidence=0.90, indicator_count=2)
    assert severity == "high"
