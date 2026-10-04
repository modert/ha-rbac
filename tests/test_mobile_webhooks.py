"""Exercise the real Companion dispatcher, including encrypted registrations."""

import json
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from homeassistant.components import webhook
from homeassistant.components.mobile_app import webhook as mobile
from homeassistant.components.mobile_app.helpers import decrypt_payload
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component
from homeassistant.util.decorator import Registry
from nacl.encoding import Base64Encoder, HexEncoder
from nacl.secret import SecretBox
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockUser

from custom_components.ha_rbac.catalog import Catalog
from custom_components.ha_rbac.decide import Decider
from custom_components.ha_rbac.denylog import DenyLog
from custom_components.ha_rbac.filters import REGISTRY
from custom_components.ha_rbac.mobile_webhooks import MobileWebhookGuard
from custom_components.ha_rbac.policy import Evaluator
from custom_components.ha_rbac.store import RbacStore

WEBHOOK_ID = "synthetic-phone-registration"
SECRET = "ab" * 32
ROLE = {
    "id": "limited",
    "name": "Limited",
    "allow": {
        "entities": {
            "entity_ids": {
                "light.allowed": {"read": True, "control": True},
                "light.read_only": {"read": True},
                "zone.allowed": {"read": True},
            }
        }
    },
    "tiers": {"max": "user"},
}


@pytest.fixture(name="phone")
async def phone_fixture(
    hass: HomeAssistant,
    hass_read_only_user: MockUser,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """Bind a synthetic phone to a limited user without loading real devices."""
    for domain in ("websocket_api", "api", "webhook"):
        await async_setup_component(hass, domain, {})
    await hass.async_block_till_done()
    store = RbacStore(hass)
    await store.async_load()
    await store.async_create_role(ROLE)
    await store.async_set_binding(hass_read_only_user.id, ["limited"])
    evaluator = Evaluator(hass, store)
    store.async_add_listener(evaluator.invalidate)
    catalog = Catalog(hass)
    catalog.rebuild()
    decider = Decider(hass, catalog, REGISTRY)
    denylog = DenyLog(hass)
    entry = MockConfigEntry(
        domain="mobile_app",
        data={
            "user_id": hass_read_only_user.id,
            "device_name": "Test phone",
            "webhook_id": WEBHOOK_ID,
            "supports_encryption": False,
            "secret": SECRET,
            "no_legacy_encryption": True,
        },
    )
    entry.add_to_hass(hass)
    hass.data["mobile_app"] = {
        "deleted_ids": [],
        "config_entries": {WEBHOOK_ID: entry},
    }
    webhook.async_register(
        hass, "mobile_app", "Test phone", WEBHOOK_ID, mobile.handle_webhook
    )
    monkeypatch.setattr(mobile, "WEBHOOK_COMMANDS", Registry(mobile.WEBHOOK_COMMANDS))
    guard = MobileWebhookGuard(hass, evaluator, decider, denylog)
    guard.start()
    hass.states.async_set("light.allowed", "off")
    hass.states.async_set("light.read_only", "off")
    hass.states.async_set("light.denied", "off")
    service = AsyncMock()
    hass.services.async_register("light", "turn_on", service)
    yield SimpleNamespace(
        hass=hass,
        user=hass_read_only_user,
        store=store,
        entry=entry,
        guard=guard,
        decider=decider,
        denylog=denylog,
        service=service,
    )
    guard.stop()


async def _send(phone: Any, command: str, data: Any, *, encrypted: bool = False) -> Any:
    """Deliver exactly the envelope Core receives over any webhook transport."""
    envelope = {"type": command, "data": data}
    if encrypted:
        phone.hass.config_entries.async_update_entry(
            phone.entry, data={**phone.entry.data, "supports_encryption": True}
        )
        encrypted_data = SecretBox(SECRET, encoder=HexEncoder).encrypt(
            json.dumps(data).encode(), encoder=Base64Encoder
        )
        envelope = {
            "type": command,
            "encrypted": True,
            "encrypted_data": encrypted_data.decode(),
        }
    return await mobile.handle_webhook(
        phone.hass, WEBHOOK_ID, SimpleNamespace(json=AsyncMock(return_value=envelope))
    )


@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("entity_id", ["light.read_only", "light.denied"])
async def test_forbidden_service_never_reaches_core_handler(
    phone: Any, encrypted: bool, entity_id: str
) -> None:
    """Read permission and encryption cannot turn into control permission."""
    response = await _send(
        phone,
        "call_service",
        {
            "domain": "light",
            "service": "turn_on",
            "service_data": {"entity_id": entity_id},
        },
        encrypted=encrypted,
    )
    assert response.status == 403
    phone.service.assert_not_called()
    denial = phone.denylog.async_recent(1)[0]
    assert denial["user_id"] == phone.user.id
    assert denial["kind"] == "webhook"
    assert denial["resources"] == [entity_id]
    assert WEBHOOK_ID not in json.dumps(denial)
    assert SECRET not in json.dumps(denial)
    body = json.loads(response.body)
    if encrypted:
        body = decrypt_payload(SECRET, body["encrypted_data"])
    assert body["error"]["code"] == "unauthorized"
    assert entity_id not in json.dumps(body)


@pytest.mark.parametrize("encrypted", [False, True])
async def test_allowed_service_keeps_registration_user_context(
    phone: Any, encrypted: bool
) -> None:
    """A permitted action reaches Core once, with the real registration owner."""
    response = await _send(
        phone,
        "call_service",
        {
            "domain": "light",
            "service": "turn_on",
            "service_data": {"entity_id": "light.allowed"},
        },
        encrypted=encrypted,
    )
    assert response.status == 200
    phone.service.assert_awaited_once()
    call = phone.service.call_args.args[0]
    assert call.context.user_id == phone.user.id
    assert call.data == {"entity_id": "light.allowed"}


@pytest.mark.parametrize(
    "command", ["fire_event", "render_template", "conversation_process", "scan_tag"]
)
async def test_unbounded_operations_refused_even_with_allowed_entity(
    phone: Any, command: str
) -> None:
    """An entity-looking field does not bound an event or a template's effects."""
    handler = AsyncMock()
    mobile.WEBHOOK_COMMANDS[command] = handler
    response = await _send(
        phone, command, {"entity_id": "light.allowed"}, encrypted=True
    )
    assert response.status == 403
    handler.assert_not_called()


async def test_future_commands_are_guarded_too(phone: Any) -> None:
    """A command registered after installation must not silently bypass RBAC."""
    handler = AsyncMock()
    mobile.WEBHOOK_COMMANDS["future_operation"] = handler
    assert (await _send(phone, "future_operation", {})).status == 403
    handler.assert_not_called()


async def test_http_uses_registration_owner_even_for_admin_client(
    phone: Any, hass_client: Any
) -> None:
    """An unrelated HTTP bearer identity cannot replace the webhook owner."""
    client = await hass_client()
    response = await client.post(
        f"/api/webhook/{WEBHOOK_ID}",
        json={
            "type": "call_service",
            "data": {
                "domain": "light",
                "service": "turn_on",
                "service_data": {"entity_id": "light.denied"},
            },
        },
    )
    assert response.status == 403
    phone.service.assert_not_called()


async def test_websocket_transport_reaches_the_same_guard(
    phone: Any, hass_ws_client: Any
) -> None:
    """The websocket webhook tunnel must not bypass decrypted enforcement."""
    client = await hass_ws_client(phone.hass)
    await client.send_json(
        {
            "id": 1,
            "type": "webhook/handle",
            "webhook_id": WEBHOOK_ID,
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(
                {
                    "type": "call_service",
                    "data": {
                        "domain": "light",
                        "service": "turn_on",
                        "service_data": {"entity_id": "light.denied"},
                    },
                }
            ),
        }
    )
    response = await client.receive_json()
    assert response["result"]["status"] == 403
    phone.service.assert_not_called()


async def test_ignored_target_cannot_bound_a_service_call(phone: Any) -> None:
    """Only service_data is a target in Core's mobile service schema."""
    response = await _send(
        phone,
        "call_service",
        {
            "domain": "light",
            "service": "turn_on",
            "target": {"entity_id": "light.allowed"},
        },
    )
    assert response.status == 403
    phone.service.assert_not_called()


async def test_explicit_service_denial_applies_on_webhook(phone: Any) -> None:
    """The same command denial applies even when its entity is controllable."""
    await phone.store.async_update_role(
        "limited", {"tiers": {"max": "user", "deny": ["call_service"]}}
    )
    response = await _send(
        phone,
        "call_service",
        {
            "domain": "light",
            "service": "turn_on",
            "service_data": {"entity_id": "light.allowed"},
        },
    )
    assert response.status == 403
    phone.service.assert_not_called()


async def test_sensor_updates_cannot_name_another_registration(phone: Any) -> None:
    """The permitted telemetry path still uses Core's per-registration keys."""
    other = MockConfigEntry(domain="mobile_app", data={})
    other.add_to_hass(phone.hass)
    sensor = er.async_get(phone.hass).async_get_or_create(
        "sensor",
        "mobile_app",
        "other-phone_battery",
        suggested_object_id="other_battery",
        config_entry=other,
    )
    phone.hass.states.async_set(sensor.entity_id, "99")
    response = await _send(
        phone,
        "update_sensor_states",
        [{"type": "sensor", "unique_id": "other-phone_battery", "state": 0}],
    )
    assert json.loads(response.body)["other-phone_battery"]["success"] is False
    assert phone.hass.states.get(sensor.entity_id).state == "99"


@pytest.mark.parametrize(
    ("command", "data"),
    [
        ("update_location", {"gps": [0, 0]}),
        ("update_sensor_states", [{"unique_id": "battery", "state": 50}]),
        ("register_sensor", {"unique_id": "battery"}),
        ("update_registration", {"app_version": "test"}),
        ("enable_encryption", {}),
        ("get_config", {}),
    ],
)
async def test_owned_phone_operations_preserve_the_original_handler(
    phone: Any, command: str, data: Any
) -> None:
    """Telemetry and app maintenance remain registration-scoped in Core."""
    handler = AsyncMock(return_value=SimpleNamespace(status=200))
    mobile.WEBHOOK_COMMANDS[command] = handler
    assert (await _send(phone, command, data, encrypted=True)).status == 200
    handler.assert_awaited_once_with(phone.hass, phone.entry, data)


async def test_zones_are_filtered_before_encryption(phone: Any) -> None:
    """Encrypted replies must not disclose zones absent from the role."""
    phone.hass.states.async_set("zone.allowed", "0", {"latitude": 0, "longitude": 0})
    phone.hass.states.async_set("zone.private", "1", {"latitude": 1, "longitude": 1})
    response = await _send(phone, "get_zones", {}, encrypted=True)
    data = decrypt_payload(SECRET, json.loads(response.body)["encrypted_data"])
    assert [zone["entity_id"] for zone in data] == ["zone.allowed"]


async def test_policy_changes_apply_to_existing_registration(phone: Any) -> None:
    """No phone re-registration is required after a role is revoked."""
    data = {
        "domain": "light",
        "service": "turn_on",
        "service_data": {"entity_id": "light.allowed"},
    }
    assert (await _send(phone, "call_service", data)).status == 200
    phone.service.reset_mock()
    await phone.store.async_create_role(
        {
            "id": "no-access",
            "name": "No access",
            "allow": {},
            "tiers": {"max": "open", "deny": ["*"]},
        }
    )
    await phone.store.async_set_binding(phone.user.id, ["no-access"])
    assert (await _send(phone, "call_service", data)).status == 403
    assert (await _send(phone, "update_location", {})).status == 403
    phone.service.assert_not_called()


@pytest.mark.parametrize("missing", [False, True])
async def test_inactive_or_missing_owner_cannot_use_webhook(
    phone: Any, missing: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A registration secret is insufficient after its user's access ends."""
    if missing:
        phone.hass.config_entries.async_update_entry(
            phone.entry, data={**phone.entry.data, "user_id": "missing-user"}
        )
    else:
        monkeypatch.setattr(phone.user, "is_active", False)
    assert (await _send(phone, "update_location", {})).status == 403
    assert phone.denylog.async_recent(1)[0]["reason"] == "identity"


async def test_unassigned_account_keeps_native_webhooks(phone: Any) -> None:
    """Existing accounts without an RBAC binding keep Core's behavior."""
    await phone.store.async_set_binding(phone.user.id, [])
    handler = AsyncMock(return_value=SimpleNamespace(status=200))
    mobile.WEBHOOK_COMMANDS["fire_event"] = handler
    assert (await _send(phone, "fire_event", {})).status == 200
    handler.assert_awaited_once()


async def test_encryption_authentication_remains_in_core(phone: Any) -> None:
    """The guard cannot make a corrupt encrypted envelope executable."""
    phone.hass.config_entries.async_update_entry(
        phone.entry, data={**phone.entry.data, "supports_encryption": True}
    )
    request = SimpleNamespace(
        json=AsyncMock(
            return_value={
                "type": "call_service",
                "encrypted": True,
                "encrypted_data": "invalid",
            }
        )
    )
    response = await mobile.handle_webhook(phone.hass, WEBHOOK_ID, request)
    assert response.status == 200
    phone.service.assert_not_called()


async def test_unload_restores_original_handlers_and_later_registrations(
    phone: Any,
) -> None:
    """Unloading and reinstalling cannot stack wrappers or lose handlers."""
    handler = AsyncMock()
    mobile.WEBHOOK_COMMANDS["future_operation"] = handler
    phone.guard.stop()
    assert mobile.WEBHOOK_COMMANDS["call_service"] is mobile.webhook_call_service
    assert mobile.WEBHOOK_COMMANDS["future_operation"] is handler
    phone.guard.start()
    assert (await _send(phone, "future_operation", {})).status == 403


async def test_mobile_integration_loaded_later_is_guarded(
    phone: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Adding Companion after RBAC setup must install the same guard."""
    phone.guard.stop()
    module_name = "homeassistant.components.mobile_app.webhook"
    monkeypatch.delitem(sys.modules, module_name)
    phone.guard.start()
    monkeypatch.setitem(sys.modules, module_name, mobile)
    phone.hass.bus.async_fire("component_loaded", {"component": "mobile_app"})
    await phone.hass.async_block_till_done()
    assert (await _send(phone, "fire_event", {})).status == 403


async def test_camera_adapter_uses_read_permissions(
    phone: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Streaming requires a permitted camera; read access is sufficient."""
    original = phone.decider.catalog.tier_for
    monkeypatch.setattr(
        phone.decider.catalog,
        "tier_for",
        lambda name: "open" if name == "camera/stream" else original(name),
    )
    await phone.store.async_update_role(
        "limited",
        {"allow": {"entities": {"entity_ids": {"camera.allowed": {"read": True}}}}},
    )
    phone.hass.states.async_set("camera.allowed", "idle")
    phone.hass.states.async_set("camera.denied", "idle")
    handler = AsyncMock(return_value=SimpleNamespace(status=200))
    mobile.WEBHOOK_COMMANDS["stream_camera"] = handler
    assert (
        await _send(phone, "stream_camera", {"camera_entity_id": "camera.allowed"})
    ).status == 200
    handler.assert_awaited_once()
    handler.reset_mock()
    assert (
        await _send(phone, "stream_camera", {"camera_entity_id": "camera.denied"})
    ).status == 403
    handler.assert_not_called()
