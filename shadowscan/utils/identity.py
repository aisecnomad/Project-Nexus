"""Identity scope checks shared by discovery and registry approval."""

from __future__ import annotations

import re

# Some AWS observations use an ARN as their resource even when the connector
# did not populate ``account``. Accept only a genuine account-bearing ARN,
# optionally wrapped by the connector's own ``cloudtrail:`` prefix.
_AWS_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_AWS_ACCOUNT_ARN = re.compile(r"arn:aws(?:-us-gov|-cn)?:[^:]+:[^:]*:([0-9]{12}):.+\Z")


def has_aws_account_scope(provider: str | None, account: str | None, resource: str | None) -> bool:
    """Whether an AWS finding has a valid, consistent account identity."""
    if provider != "aws":
        return True
    account_id = account if isinstance(account, str) and _AWS_ACCOUNT.fullmatch(account) else None
    value = resource.removeprefix("cloudtrail:") if isinstance(resource, str) else ""
    arn = _AWS_ACCOUNT_ARN.match(value)
    if arn is not None:
        return account in (None, "", arn.group(1))
    return account_id is not None
