# SPDX-License-Identifier: Apache-2.0
"""Tenant resolution: from a verified principal to that tenant's settings.

The resolver is the only thing that maps a tenant to a Forgejo base URL and
credentials. Tools receive the resolved ``TenantConfig`` and never build a
Forgejo URL from anything a client sent.
"""

from __future__ import annotations

from typing import Protocol

from .auth import Principal
from .config import TenantConfig


class UnknownTenant(LookupError):
    pass


class TenantResolver(Protocol):
    def resolve(self, principal: Principal) -> TenantConfig:
        """Return the tenant's settings, or raise UnknownTenant."""
        ...


class StaticTenantResolver:
    """Tenants listed in the config file (the open-source default)."""

    def __init__(self, tenants: tuple[TenantConfig, ...] | list[TenantConfig]):
        self._tenants = {t.id: t for t in tenants}

    def resolve(self, principal: Principal) -> TenantConfig:
        try:
            return self._tenants[principal.tenant]
        except KeyError:
            raise UnknownTenant(principal.tenant) from None
