"""Regression coverage for adopting RBAC one account at a time."""

from types import SimpleNamespace

from homeassistant.auth.permissions.const import POLICY_CONTROL, POLICY_READ
from homeassistant.core import HomeAssistant

from custom_components.ha_rbac.policy import Evaluator, default_roles


def _user():
    return SimpleNamespace(
        id="child", is_owner=False, system_generated=False, is_admin=False
    )


async def test_unassigned_account_keeps_native_behavior(hass: HomeAssistant) -> None:
    """Installing RBAC alone must not break existing phones or cameras."""
    store = SimpleNamespace(roles=default_roles(), bindings={}, global_deny={})
    permissions = Evaluator(hass, store).async_permissions(_user())
    assert permissions.pass_through


async def test_assigned_read_only_account_is_filtered(hass: HomeAssistant) -> None:
    """Binding the account opts it into enforcement immediately."""
    store = SimpleNamespace(
        roles=default_roles(), bindings={"child": ["read_only"]}, global_deny={}
    )
    permissions = Evaluator(hass, store).async_permissions(_user())
    assert not permissions.pass_through
    assert permissions.check_entity("light.test", POLICY_READ)
    assert not permissions.check_entity("light.test", POLICY_CONTROL)


async def test_missing_assigned_role_does_not_fall_back(hass: HomeAssistant) -> None:
    """Losing a role definition must not make its account unrestricted."""
    store = SimpleNamespace(
        roles=default_roles(), bindings={"child": ["missing"]}, global_deny={}
    )
    permissions = Evaluator(hass, store).async_permissions(_user())
    assert not permissions.pass_through
    assert not permissions.check_entity("light.test", POLICY_READ)


async def test_unassigned_account_still_honors_global_deny(hass: HomeAssistant) -> None:
    """An explicit per-user denial also opts the account into filtering."""
    store = SimpleNamespace(
        roles=default_roles(), bindings={},
        global_deny={"child": {"entities": {"entity_ids": {"lock.test": True}}}},
    )
    permissions = Evaluator(hass, store).async_permissions(_user())
    assert not permissions.pass_through
    assert not permissions.check_entity("lock.test", POLICY_CONTROL)
