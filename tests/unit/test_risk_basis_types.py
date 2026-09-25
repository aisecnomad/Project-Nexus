"""Reject malformed risk-basis values at the configuration boundary."""

import pytest

from shadowscan.config import ConfigValidationError, ScanConfig


@pytest.mark.parametrize("basis", [["danger"], {"danger": True}])
def test_unhashable_risk_basis_fails_as_configuration_error(basis):
    with pytest.raises(ConfigValidationError):
        ScanConfig(risk_basis=basis)
