"""Paired-difference intervals: independent reference checks and coverage labels."""

import math

import pytest

from faultline.compare import (
    clopper_pearson,
    conditional_paired_difference_interval,
    exact_mcnemar,
    paired_difference_interval,
    wilson_interval,
)


def mover_reference(a: int, b: int, c: int, d: int, alpha: float = 0.05):
    """Independent re-derivation of Newcombe's MOVER from its published equations.

    Written separately from the implementation: it recomputes both Wilson limits
    from the score formula, the phi coefficient from the 2x2 table and the MOVER
    combination, so an implementation error cannot agree with it by construction.
    """
    n = a + b + c + d
    z = 1.959963984540054

    def wilson(x: int, total: int) -> tuple[float, float]:
        p = x / total
        centre = (p + z * z / (2 * total)) / (1 + z * z / total)
        half = (
            z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
        )
        return max(0.0, centre - half), min(1.0, centre + half)

    p1 = (b + d) / n
    p2 = (c + d) / n
    l1, u1 = wilson(b + d, n)
    l2, u2 = wilson(c + d, n)
    denom = (a + b) * (b + d) * (a + c) * (c + d)
    rho = ((a * d) - (b * c)) / math.sqrt(denom) if denom else 0.0
    rho = max(-1.0, min(1.0, rho))
    phi = p1 - p2
    left = (p1 - l1) ** 2 + (u2 - p2) ** 2 - 2 * rho * (p1 - l1) * (u2 - p2)
    right = (u1 - p1) ** 2 + (p2 - l2) ** 2 - 2 * rho * (u1 - p1) * (p2 - l2)
    return phi - math.sqrt(max(0.0, left)), phi + math.sqrt(max(0.0, right))


def test_all_concordant_pairs_use_marginal_uncertainty():
    # a=8, d=2, no discordance: the sample difference is exactly 0.
    interval = paired_difference_interval(0, 0, 10, pass_pass=8, fail_fail=2)
    assert interval.method == "newcombe-mover-95"
    assert interval.estimate == 0.0
    assert interval.low < 0 < interval.high
    assert interval.low >= -1.0 and interval.high <= 1.0
    # A conditional interval cannot bound anything without discordance.
    conditional = conditional_paired_difference_interval(0, 0, 10)
    assert conditional.method == "none"
    assert "No discordant pairs" in (conditional.reason or "")


def test_all_discordant_pairs_match_the_reference_formula():
    # a=0, d=0, b=4, c=1: every pair is discordant and rho = -1.
    interval = paired_difference_interval(4, 1, 5, pass_pass=0, fail_fail=0)
    expected_low, expected_high = mover_reference(0, 4, 1, 0)
    assert interval.estimate == pytest.approx(0.6)
    assert interval.low == pytest.approx(max(-1.0, expected_low), abs=1e-9)
    assert interval.high == pytest.approx(min(1.0, expected_high), abs=1e-9)


def test_one_direction_discordance_matches_the_reference_formula():
    # b=6, c=0 with two concordant passes.
    interval = paired_difference_interval(6, 0, 8, pass_pass=2, fail_fail=0)
    expected_low, expected_high = mover_reference(2, 6, 0, 0)
    assert interval.estimate == pytest.approx(0.75)
    assert interval.low == pytest.approx(expected_low, abs=1e-9)
    assert interval.high == pytest.approx(min(1.0, expected_high), abs=1e-9)
    # Both methods sit above zero for six discordant pairs in one direction.
    assert interval.low > 0
    assert conditional_paired_difference_interval(6, 0, 8).low > 0
    # With only three discordant pairs the conditional interval still spans zero
    # while the unconditional score interval is already positive: the coverage
    # claims genuinely differ, which is why they are labelled separately.
    assert paired_difference_interval(3, 0, 5, pass_pass=0, fail_fail=2).low > 0
    assert conditional_paired_difference_interval(3, 0, 5).low < 0


def test_balanced_discordance_centres_on_zero():
    interval = paired_difference_interval(3, 3, 10, pass_pass=2, fail_fail=2)
    expected_low, expected_high = mover_reference(2, 3, 3, 2)
    assert interval.estimate == 0.0
    assert interval.low == pytest.approx(expected_low, abs=1e-9)
    assert interval.high == pytest.approx(expected_high, abs=1e-9)
    assert interval.low < 0 < interval.high
    assert interval.low == pytest.approx(-interval.high, abs=1e-12)


def test_small_sample_sizes_stay_bounded_and_ordered():
    for a, b, c, d in ((0, 1, 0, 0), (0, 1, 1, 0), (1, 0, 0, 0), (0, 0, 1, 1), (0, 2, 0, 1)):
        pairs = a + b + c + d
        interval = paired_difference_interval(b, c, pairs, pass_pass=a, fail_fail=d)
        assert interval.low is not None and interval.high is not None
        assert -1.0 <= interval.low <= interval.estimate <= interval.high <= 1.0
        expected_low, expected_high = mover_reference(a, b, c, d)
        assert interval.low == pytest.approx(max(-1.0, expected_low), abs=1e-9)
        assert interval.high == pytest.approx(min(1.0, expected_high), abs=1e-9)


def test_moderate_sample_matches_the_reference_and_narrows_with_n():
    small = paired_difference_interval(6, 2, 20, pass_pass=8, fail_fail=4)
    expected_low, expected_high = mover_reference(8, 6, 2, 4)
    assert small.low == pytest.approx(expected_low, abs=1e-9)
    assert small.high == pytest.approx(expected_high, abs=1e-9)
    large = paired_difference_interval(60, 20, 200, pass_pass=80, fail_fail=40)
    assert (large.high - large.low) < (small.high - small.low)


def test_large_sample_agrees_with_the_closed_form_wald_interval():
    """Independent asymptotic check: MOVER must approach the paired Wald interval."""
    a, b, c, d = 2000, 300, 100, 600
    n = a + b + c + d
    interval = paired_difference_interval(b, c, n, pass_pass=a, fail_fail=d)
    delta = (b - c) / n
    variance = ((b + c) / n - delta**2) / n
    half_width = 1.959963984540054 * math.sqrt(variance)
    assert interval.low == pytest.approx(delta - half_width, abs=2e-2)
    assert interval.high == pytest.approx(delta + half_width, abs=2e-2)


def test_no_eligible_pairs_is_undefined_with_a_reason():
    interval = paired_difference_interval(0, 0, 0)
    assert interval.method == "none"
    assert interval.coverage == "none"
    assert interval.sample_size == 0
    assert interval.reason == "No complete scored pairs"


def test_extreme_proportions_stay_inside_the_unit_interval():
    for a, b, c, d in (
        (100, 0, 0, 0),
        (0, 100, 0, 0),
        (0, 0, 0, 100),
        (1, 99, 0, 0),
        (0, 0, 1, 99),
    ):
        pairs = a + b + c + d
        interval = paired_difference_interval(b, c, pairs, pass_pass=a, fail_fail=d)
        assert interval.low >= -1.0 and interval.high <= 1.0
        assert interval.low <= interval.estimate <= interval.high


def test_interval_is_antisymmetric_when_the_arms_swap():
    forward = paired_difference_interval(7, 2, 20, pass_pass=6, fail_fail=5)
    backward = paired_difference_interval(2, 7, 20, pass_pass=6, fail_fail=5)
    assert backward.estimate == pytest.approx(-forward.estimate)
    assert backward.low == pytest.approx(-forward.high, abs=1e-9)
    assert backward.high == pytest.approx(-forward.low, abs=1e-9)


def test_condition_and_unconditional_methods_are_labelled_distinctly():
    mover = paired_difference_interval(5, 1, 12, pass_pass=4, fail_fail=2)
    conditional = conditional_paired_difference_interval(5, 1, 12)
    assert mover.coverage == "unconditional-approximate"
    assert conditional.coverage == "conditional-exact"
    assert mover.method != conditional.method
    # Both describe the same point estimate; only the coverage claim differs.
    assert mover.estimate == conditional.estimate


def test_intervals_are_not_significance_tests():
    """A crossing interval and a large p-value must not be presented as a test."""
    interval = paired_difference_interval(2, 0, 6, pass_pass=3, fail_fail=1)
    p_value, reason = exact_mcnemar(2, 0)
    assert interval.low is not None and interval.high is not None
    assert p_value == pytest.approx(0.5)
    assert reason is None
    # The interval is a description; no field claims a decision.
    assert not hasattr(interval, "significant")
    assert wilson_interval(0, 6).low == pytest.approx(0.0, abs=1e-12)
    assert clopper_pearson(0, 6)[1] == pytest.approx(0.4592, abs=5e-4)
