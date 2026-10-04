"""Send through Core's real notify path and return through its webhook path."""

import asyncio
import json
from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from homeassistant.components.group.notify import GroupNotifyPlatform
from homeassistant.components.mobile_app import notify
from homeassistant.components.mobile_app import webhook as mobile
from homeassistant.components.mobile_app.push_notification import PushChannel
from homeassistant.core import Context, ServiceRegistry
from homeassistant.exceptions import HomeAssistantError
from pytest_homeassistant_custom_component.common import MockConfigEntry
from test_mobile_webhooks import (
    SECRET,
    WEBHOOK_ID,
    _send,
    phone_fixture,  # noqa: F401 -- shared pytest fixture
)

from custom_components.ha_rbac import notification_actions as actions

SAFE_ACTION = "ACK_REMINDER"
OTHER_ACTION = "SNOOZE_REMINDER"
RULES = {
    "max": "user",
    "allow": [
        f"mobile_app/notification_action/{name}"
        for name in (SAFE_ACTION, OTHER_ACTION, "REPLY")
    ],
    "deny": ["fire_event"],
}


@pytest.fixture(name="notifications")
async def notifications_fixture(phone: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Stub only push transport, keeping Core notify, groups and events real."""
    await phone.store.async_update_role("limited", {"tiers": RULES})
    phone.hass.config_entries.async_update_entry(
        phone.entry,
        data={
            **phone.entry.data,
            "manufacturer": "Test manufacturer",
            "device_id": "synthetic-device",
            "app_data": {"push_url": "https://example.invalid/push"},
        },
    )
    phone.hass.data["mobile_app"]["push_channel"] = {}
    sent = []

    async def transport(session: Any, entry: Any, data: Any) -> None:
        sent.append((entry, deepcopy(data)))

    monkeypatch.setattr(notify, "_send_message", transport)
    service = notify.MobileAppNotificationService()
    service.hass = phone.hass
    service.registered_targets = {"test_phone": WEBHOOK_ID}
    phone.hass.services.async_register(
        "notify", "test_phone", service._async_notify_message_service
    )

    async def send(
        buttons: list[Any] | None = None,
        *,
        message: str = "A reminder",
        context: Context | None = None,
        service_name: str = "test_phone",
        **data: Any,
    ) -> dict[str, Any]:
        if buttons is not None:
            data["actions"] = buttons
        await phone.hass.services.async_call(
            "notify",
            service_name,
            {"message": message, "data": data},
            blocking=True,
            context=context,
        )
        return sent[-1][1]

    events = []
    unsub = phone.hass.bus.async_listen(actions.EVENT_ACTION, events.append)
    yield SimpleNamespace(
        phone=phone, service=service, send=send, sent=sent, events=events
    )
    unsub()


def _button(action: str = SAFE_ACTION, **kwargs: Any) -> dict[str, Any]:
    return {"action": action, "title": "Acknowledge", **kwargs}


def _reply(outgoing: dict[str, Any], index: int = 0, **fields: Any) -> dict[str, Any]:
    return {
        "event_type": actions.EVENT_ACTION,
        "event_data": {
            "action": outgoing["data"]["actions"][index]["action"],
            **fields,
        },
    }


@pytest.mark.parametrize("encrypted", [False, True])
async def test_sent_allowed_action_returns_original_with_trusted_context(
    notifications: Any, encrypted: bool
) -> None:
    """The phone returns an opaque token; automations see their original action."""
    n = notifications
    original = [_button()]
    outgoing = await n.send(
        original, tag="reminder", action_data={"entity_id": "light.allowed"}
    )
    assert original == [_button()]
    token = outgoing["data"]["actions"][0]["action"]
    assert token.startswith(actions.TOKEN_PREFIX)
    assert SAFE_ACTION not in token
    response = await _send(
        n.phone,
        "fire_event",
        _reply(
            outgoing,
            tag="forged-tag",
            action_data={"entity_id": "light.denied"},
            device_id="forged-device",
            user_id="administrator",
            extra="injected",
        ),
        encrypted=encrypted,
    )
    assert response.status == 200
    await n.phone.hass.async_block_till_done()
    assert len(n.events) == 1
    event = n.events[0]
    assert event.context.user_id == n.phone.user.id
    assert event.data == {
        "action": SAFE_ACTION,
        "device_id": "synthetic-device",
        "tag": "reminder",
        "action_data": {"entity_id": "light.allowed"},
    }


async def test_role_permission_is_required_even_for_a_sent_parent_button(
    notifications: Any,
) -> None:
    """Misrouting a privileged notification cannot grant its actions."""
    n = notifications
    outgoing = await n.send([_button("PRIVILEGED_ACTION"), _button()])
    assert len(outgoing["data"]["actions"]) == 1
    forged = {"event_type": actions.EVENT_ACTION, "event_data": {"action": SAFE_ACTION}}
    assert (await _send(n.phone, "fire_event", forged)).status == 403
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 200


async def test_one_choice_is_atomic_across_concurrent_buttons(
    notifications: Any,
) -> None:
    """One notification cannot be answered twice by racing different buttons."""
    n = notifications
    outgoing = await n.send([_button(), _button(OTHER_ACTION)])
    replies = [_reply(outgoing), _reply(outgoing, 1)]
    results = await asyncio.gather(
        *(_send(n.phone, "fire_event", reply) for reply in replies)
    )
    assert sorted(response.status for response in results) == [200, 403]
    for reply in replies:
        assert (await _send(n.phone, "fire_event", reply)).status == 403
    await n.phone.hass.async_block_till_done()
    assert len(n.events) == 1


async def test_another_phone_cannot_use_the_receipt_even_for_the_same_user(
    notifications: Any,
) -> None:
    """A capability is bound to the exact registration and stored owner."""
    n = notifications
    outgoing = await n.send([_button()])
    other = MockConfigEntry(
        domain="mobile_app",
        data={**n.phone.entry.data, "webhook_id": "another-synthetic-registration"},
    )
    other.add_to_hass(n.phone.hass)
    n.phone.hass.data["mobile_app"]["config_entries"][other.data["webhook_id"]] = other
    response = await mobile.handle_webhook(
        n.phone.hass,
        other.data["webhook_id"],
        SimpleNamespace(
            json=AsyncMock(
                return_value={"type": "fire_event", "data": _reply(outgoing)}
            )
        ),
    )
    assert response.status == 403
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 200


@pytest.mark.parametrize(
    "denials",
    [["mobile_app/fire_event"], [f"mobile_app/notification_action/{SAFE_ACTION}"]],
)
async def test_current_role_revocation_wins_over_an_outstanding_button(
    notifications: Any, denials: list[str]
) -> None:
    """A role denial applies immediately to a button already on the phone."""
    n = notifications
    outgoing = await n.send([_button()])
    await n.phone.store.async_update_role(
        "limited", {"tiers": {**RULES, "deny": denials}}
    )
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 403
    denial = n.phone.denylog.async_recent(1)[0]
    assert denial["reason"] == "tier"
    assert actions.TOKEN_PREFIX not in str(denial)
    assert WEBHOOK_ID not in str(denial)
    assert SECRET not in str(denial)


@pytest.mark.parametrize("change", ["owner", "inactive", "registration", "degraded"])
async def test_identity_or_catalog_change_invalidates_reply(
    notifications: Any, change: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sent button does not freeze identity or bypass fail-closed evaluation."""
    n = notifications
    outgoing = await n.send([_button()])
    if change == "owner":
        n.phone.hass.config_entries.async_update_entry(
            n.phone.entry, data={**n.phone.entry.data, "user_id": "missing-user"}
        )
    elif change == "registration":
        n.phone.hass.config_entries.async_update_entry(
            n.phone.entry, data={**n.phone.entry.data, "webhook_id": "replaced"}
        )
    elif change == "inactive":
        n.phone.user.is_active = False
    else:
        monkeypatch.setattr(n.phone.decider.catalog, "degraded", True)
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 403


@pytest.mark.parametrize("replacement", ["new_buttons", "plain_message", "clear"])
async def test_replacement_or_clear_revokes_previous_tag(
    notifications: Any, replacement: str
) -> None:
    """Buttons removed from a notification stop authorizing replies."""
    n = notifications
    outgoing = await n.send([_button()], tag="same-tag")
    await n.send(
        [_button(OTHER_ACTION)] if replacement == "new_buttons" else None,
        message="clear_notification" if replacement == "clear" else "Updated",
        tag="same-tag",
    )
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 403


async def test_expiry_and_unload_invalidate_buttons(
    notifications: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stale notifications cannot become permanent bearer credentials."""
    n = notifications
    now = actions.monotonic()
    outgoing = await n.send([_button()])
    monkeypatch.setattr(actions, "monotonic", lambda: now + actions.ACTION_TTL + 1)
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 403
    outgoing = await n.send([_button()])
    n.phone.guard.stop()
    n.phone.guard.start()
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 403


@pytest.mark.parametrize("action", ["REPLY", SAFE_ACTION])
async def test_text_input_survives_identifier_rewrite(
    notifications: Any, action: str
) -> None:
    """Android REPLY and behavior=textInput both retain their client UI."""
    n = notifications
    outgoing = await n.send([_button(action, behavior="textInput")])
    assert outgoing["data"]["actions"][0]["behavior"] == "textInput"
    response = await _send(
        n.phone, "fire_event", _reply(outgoing, reply_text="Acknowledged")
    )
    assert response.status == 200
    await n.phone.hass.async_block_till_done()
    assert n.events[0].data["reply_text"] == "Acknowledged"
    assert n.events[0].data["action"] == action


@pytest.mark.parametrize("text", ["unexpected", 42, {"action": "forged"}])
async def test_plain_buttons_do_not_accept_free_form_input(
    notifications: Any, text: Any
) -> None:
    """Unrequested client input is refused without consuming the valid button."""
    n = notifications
    outgoing = await n.send([_button()])
    assert (
        await _send(n.phone, "fire_event", _reply(outgoing, reply_text=text))
    ).status == 403
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 200


async def test_text_reply_size_is_bounded(notifications: Any) -> None:
    """A permitted text reply is still bounded in type and length."""
    n = notifications
    outgoing = await n.send([_button("REPLY")])
    assert (
        await _send(
            n.phone,
            "fire_event",
            _reply(outgoing, reply_text="x" * (actions.MAX_REPLY_LENGTH + 1)),
        )
    ).status == 403


@pytest.mark.parametrize(
    "event_type", ["unrelated_event", "mobile_app_notification_cleared"]
)
async def test_capability_cannot_authorize_another_event(
    notifications: Any, event_type: str
) -> None:
    """Action capabilities confer no general event authority."""
    n = notifications
    outgoing = await n.send([_button()])
    payload = {**_reply(outgoing), "event_type": event_type}
    assert (await _send(n.phone, "fire_event", payload)).status == 403
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 200


@pytest.mark.parametrize("group", [False, True])
async def test_restricted_sender_cannot_mint_capabilities(
    notifications: Any, group: bool
) -> None:
    """Notify groups must not launder a caller by dropping service context."""
    n = notifications
    service_name = "test_phone"
    if group:
        service_name = "test_group"
        service = GroupNotifyPlatform(n.phone.hass, [{"action": "test_phone"}])
        service.registered_targets = {}
        n.phone.hass.services.async_register(
            "notify", service_name, service._async_notify_message_service
        )
    outgoing = await n.send(
        [_button()], context=Context(user_id=n.phone.user.id), service_name=service_name
    )
    assert outgoing["data"]["actions"] == []
    assert not n.phone.guard.notifications._pending


async def test_direct_integration_call_without_service_provenance_cannot_mint(
    notifications: Any,
) -> None:
    """Fail closed when the notify call has no identifiable service origin."""
    n = notifications
    await n.service.async_send_message(
        "Unattributed", target=[WEBHOOK_ID], data={"actions": [_button()]}
    )
    assert n.sent[-1][1]["data"]["actions"] == []


async def test_trusted_and_restricted_concurrent_sends_do_not_share_identity(
    notifications: Any,
) -> None:
    """Task-local provenance prevents one send borrowing another's authority."""
    n = notifications
    await asyncio.gather(
        n.send([_button()], tag="system"),
        n.send([_button()], tag="restricted", context=Context(user_id=n.phone.user.id)),
    )
    sent = {data["data"]["tag"]: data["data"]["actions"] for _, data in n.sent}
    assert len(sent["system"]) == 1
    assert sent["restricted"] == []


async def test_urls_and_ios_aliases(notifications: Any) -> None:
    """Navigation stays native and the legacy identifier cannot escape rewriting."""
    n = notifications
    uri = _button("URI", uri="/dashboard-example/home")
    outgoing = await n.send([uri, {"identifier": SAFE_ACTION, "title": "OK"}])
    assert outgoing["data"]["actions"][0] == uri
    second = outgoing["data"]["actions"][1]
    assert second["action"] == second["identifier"]
    assert second["action"] != SAFE_ACTION
    assert (await _send(n.phone, "fire_event", _reply(outgoing, 1))).status == 200


async def test_local_delivery_and_cloud_fallback_keep_the_same_capability(
    notifications: Any,
) -> None:
    """Transport fallback must not replace or duplicate the pending grant."""
    n = notifications
    local = []
    channel = PushChannel(n.phone.hass, WEBHOOK_ID, True, local.append, Mock())
    n.phone.hass.data["mobile_app"]["push_channel"][WEBHOOK_ID] = channel
    await n.phone.hass.services.async_call(
        "notify",
        "test_phone",
        {"message": "Test", "data": {"actions": [_button()]}},
        blocking=True,
    )
    assert len(local) == 1
    assert n.sent == []
    for pending in channel.pending_confirms.values():
        pending["unsub_scheduled_push_failed"]()
    await channel.async_teardown()
    assert len(n.sent) == 1
    assert _reply(local[0]) == _reply(n.sent[0][1])
    assert (await _send(n.phone, "fire_event", _reply(local[0]))).status == 200
    assert (await _send(n.phone, "fire_event", _reply(n.sent[0][1]))).status == 403


async def test_mixed_recipients_keep_native_parent_actions(
    notifications: Any, hass_admin_user: Any
) -> None:
    """A parent's copy stays native while a restricted phone gets its own token."""
    n = notifications
    parent = MockConfigEntry(
        domain="mobile_app",
        data={
            **n.phone.entry.data,
            "user_id": hass_admin_user.id,
            "webhook_id": "synthetic-parent-phone",
        },
    )
    parent.add_to_hass(n.phone.hass)
    n.phone.hass.data["mobile_app"]["config_entries"][parent.data["webhook_id"]] = (
        parent
    )
    await n.phone.hass.services.async_call(
        "notify",
        "test_phone",
        {"message": "Test", "data": {"actions": [_button()]}},
        blocking=True,
        context=Context(user_id=hass_admin_user.id),
    )
    # Use the generic service so Core receives both registrations.
    n.phone.hass.services.async_register(
        "notify", "both", n.service._async_notify_message_service
    )
    await n.phone.hass.services.async_call(
        "notify",
        "both",
        {
            "message": "Test",
            "target": [WEBHOOK_ID, parent.data["webhook_id"]],
            "data": {"actions": [_button()]},
        },
        blocking=True,
        context=Context(user_id=hass_admin_user.id),
    )
    assert n.sent[-2][1]["data"]["actions"][0]["action"].startswith(
        actions.TOKEN_PREFIX
    )
    assert n.sent[-1][1]["data"]["actions"] == [_button()]


async def test_memory_limits_fail_closed_for_evicted_buttons(
    notifications: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unanswered notifications cannot grow the capability store without bound."""
    n = notifications
    monkeypatch.setattr(actions, "MAX_PER_REGISTRATION", 2)
    monkeypatch.setattr(actions, "MAX_PENDING", 2)
    old = await n.send([_button()])
    await n.send([_button()])
    latest = await n.send([_button()])
    assert len(n.phone.guard.notifications._pending) == 2
    assert (await _send(n.phone, "fire_event", _reply(old))).status == 403
    assert (await _send(n.phone, "fire_event", _reply(latest))).status == 200


async def test_unload_restores_notify_and_service_execution_hooks(
    notifications: Any,
) -> None:
    """Repeated reloads must not stack global wrappers."""
    n = notifications
    wrapped_send = notify.MobileAppNotificationService.async_send_message
    wrapped_execute = ServiceRegistry._execute_service
    n.phone.guard.stop()
    assert (
        notify.MobileAppNotificationService.async_send_message
        is wrapped_send.__wrapped__
    )
    assert ServiceRegistry._execute_service is wrapped_execute.__wrapped__
    n.phone.guard.start()
    outgoing = await n.send([_button()])
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 200


async def test_offline_recipient_does_not_prevent_remaining_delivery(
    notifications: Any,
) -> None:
    """Splitting per-device payloads preserves Core's attempt-all batch behavior."""
    n = notifications
    offline = MockConfigEntry(
        domain="mobile_app",
        data={**n.phone.entry.data, "webhook_id": "offline-phone", "app_data": {}},
    )
    offline.add_to_hass(n.phone.hass)
    n.phone.hass.data["mobile_app"]["config_entries"][offline.data["webhook_id"]] = (
        offline
    )
    n.phone.hass.services.async_register(
        "notify", "both", n.service._async_notify_message_service
    )
    with pytest.raises(HomeAssistantError):
        await n.phone.hass.services.async_call(
            "notify",
            "both",
            {
                "message": "Test",
                "target": [offline.data["webhook_id"], WEBHOOK_ID],
                "data": {"actions": [_button()]},
            },
            blocking=True,
        )
    assert len(n.sent) == 1
    assert (await _send(n.phone, "fire_event", _reply(n.sent[0][1]))).status == 200


async def test_http_and_websocket_share_one_time_receipt(
    notifications: Any, hass_client: Any, hass_ws_client: Any
) -> None:
    """Switching transports cannot replay a button accepted over HTTP."""
    n = notifications
    outgoing = await n.send([_button()])
    envelope = {"type": "fire_event", "data": _reply(outgoing)}
    client = await hass_client()
    assert (
        await client.post(f"/api/webhook/{WEBHOOK_ID}", json=envelope)
    ).status == 200
    ws = await hass_ws_client(n.phone.hass)
    await ws.send_json(
        {
            "id": 1,
            "type": "webhook/handle",
            "webhook_id": WEBHOOK_ID,
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(envelope),
        }
    )
    assert (await ws.receive_json())["result"]["status"] == 403
    await n.phone.hass.async_block_till_done()
    assert len(n.events) == 1


async def test_removing_grant_blocks_existing_button(
    notifications: Any,
) -> None:
    """A current allow is required, not merely the absence of an explicit deny."""
    n = notifications
    outgoing = await n.send([_button()])
    await n.phone.store.async_update_role("limited", {"tiers": {"max": "user"}})
    assert (await _send(n.phone, "fire_event", _reply(outgoing))).status == 403
