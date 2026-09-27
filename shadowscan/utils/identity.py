"""Identity scope checks shared by discovery and registry approval."""

from __future__ import annotations

import re

# Some AWS observations use an ARN as their resource even when the connector
# did not populate ``account``. Accept only a genuine account-bearing ARN,
# optionally wrapped by the connector's own ``cloudtrail:`` prefix.
_AWS_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_AWS_ACCOUNT_ARN = re.compile(r"arn:aws(?:-us-gov|-cn)?:[^:]+:[^:]*:([0-9]{12}):.+\Z")
_GOOGLE_CUSTOMER = re.compile(r"C[a-zA-Z0-9]{1,63}\Z")


def google_customer_id(value: object) -> str | None:
    """Accept concrete Workspace customer IDs, never aliases or email domains."""
    return value if isinstance(value, str) and _GOOGLE_CUSTOMER.fullmatch(value) else None


def has_google_workspace_account_scope(provider: str | None, account: str | None) -> bool:
    """Public OAuth client IDs alone cannot identify a customer's grant."""
    return provider != "google-workspace" or google_customer_id(account) is not None


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


# Providers whose canonical resource identifier does not itself encode the
# owning tenant get listed here: an inventory card approving one of their
# resource patterns must also list ``accounts`` explicitly, or the pattern
# could approve a resource ID reused by an unrelated tenant (for example, a
# single third-party OAuth client ID installed by many Google Workspace
# customers). AWS is not listed: has_aws_account_scope already ties an
# approved ARN to one account number structurally, so no separate card-level
# requirement is needed for it.
#
# This is the single place to extend when a new connector's resource ID is
# shown to have the same reused-across-tenants shape; every call site that
# reconciles or stubs a finding reads this one set instead of repeating its
# own hardcoded provider check.
PROVIDERS_REQUIRING_CARD_ACCOUNT_SCOPE = frozenset({"google-workspace"})


def requires_card_account_scope(provider: str | None) -> bool:
    """Whether an inventory card approving ``provider`` must list ``accounts``.

    A resource-pattern-only card can approve a finding for every tenant that
    happens to share the same identifier when the provider's resource IDs are
    not intrinsically tenant-scoped. See
    ``PROVIDERS_REQUIRING_CARD_ACCOUNT_SCOPE`` for which providers need this.
    """
    return provider in PROVIDERS_REQUIRING_CARD_ACCOUNT_SCOPE
