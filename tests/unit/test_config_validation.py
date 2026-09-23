from __future__ import annotations

import math

import pytest

from shadowscan.config import ScanConfig


@pytest.mark.parametrize("value", [1.01, -0.01, math.nan, math.inf, -math.inf, True, None, "invalid"])
def test_min_confidence_rejects_values_outside_finite_unit_interval(value):
    with pytest.raises(ValueError, match="min_confidence"):
        ScanConfig.from_dict({"options": {"min_confidence": value}})


@pytest.mark.parametrize("value", [0, 1, 0.25, "0.75"])
def test_min_confidence_accepts_finite_unit_interval_values(value):
    cfg = ScanConfig.from_dict({"options": {"min_confidence": value}})
    assert cfg.min_confidence == float(value)
