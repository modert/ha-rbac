"""Bind an allowed notification reply to a button sent to one registration.

Core's notify service is wrapped before it chooses local or cloud delivery.
Only a trusted service call can issue a reply, and role permission alone cannot
forge one. Core still handles push delivery and the final event's user context.
"""

import sys
from collections.abc import Callable
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass
from functools import wraps
from secrets import token_urlsafe
from time import monotonic
from typing import Any

from homeassistant.core import HomeAssistant, ServiceCall, ServiceRegistry, callback
from homeassistant.exceptions import HomeAssistantError

from .decide import Decider, Decision
from .policy import Evaluator, Permissions

NOTIFY_MODULE = "homeassistant.components.mobile_app.notify"
EVENT_ACTION = "mobile_app_notification_action"
TOKEN_PREFIX = "ha_rbac_"
ACTION_TTL = 24 * 60 * 60
MAX_PENDING = 2048
MAX_PER_REGISTRATION = 64
MAX_ACTIONS = 10
MAX_REPLY_LENGTH = 4096


@dataclass
class _Reply:
    """Server-owned details of one button, never supplied by the reply."""

    entry_id: str
    webhook_id: str
    user_id: str
    action: str
    batch: str
    tag: str | None
    expires: float
    event_data: dict[str, Any]
    text_input: bool


class NotificationActions:
    """Issue bounded, per-phone notification capabilities and consume them once."""

    def __init__(
        self, hass: HomeAssistant, evaluator: Evaluator, decider: Decider
    ) -> None:
        """Create an in-memory store; restarting intentionally expires replies."""
        self._hass = hass
        self._evaluator = evaluator
        self._decider = decider
        self._pending: dict[str, _Reply] = {}
        self._restore: list[tuple[Any, str, Any, Any]] = []
        # None means a direct integration call with no authenticated service
        # origin. Empty means a system service call. Preserve every user in a
        # nested call chain: notify groups drop ServiceCall.context, but inherit
        # contextvars, so they cannot wash a restricted sender's identity away.
        self._senders: ContextVar[frozenset[str] | None] = ContextVar(
            "rbac_notification_senders", default=None
        )

    @callback
    def start(self) -> None:
        """Install only when Companion has already imported its notify module."""
        if self._restore:
            return
        module = sys.modules.get(NOTIFY_MODULE)
        service_type = getattr(module, "MobileAppNotificationService", None)
        original_send = getattr(service_type, "async_send_message", None)
        original_execute = getattr(ServiceRegistry, "_execute_service", None)
        if not callable(original_send) or not callable(original_execute):
            raise HomeAssistantError(
                "Companion notification dispatch is incompatible with access control"
            )

        @wraps(original_execute)
        async def execute(registry: Any, handler: Any, call: ServiceCall) -> Any:
            if registry is not self._hass.services:
                return await original_execute(registry, handler, call)
            senders = self._senders.get() or frozenset()
            if call.context.user_id:
                senders = senders | {call.context.user_id}
            marker = self._senders.set(senders)
            try:
                return await original_execute(registry, handler, call)
            finally:
                self._senders.reset(marker)

        @wraps(original_send)
        async def send(service: Any, message: str = "", **kwargs: Any) -> None:
            if service.hass is not self._hass:
                await original_send(service, message, **kwargs)
                return
            await self._send(module, original_send, service, message, kwargs)

        for owner, name, original, wrapped in (
            (ServiceRegistry, "_execute_service", original_execute, execute),
            (service_type, "async_send_message", original_send, send),
        ):
            setattr(owner, name, wrapped)
            self._restore.append((owner, name, original, wrapped))

    @callback
    def stop(self) -> None:
        """Restore owned hooks and invalidate outstanding buttons on unload."""
        for owner, name, original, wrapped in reversed(self._restore):
            if getattr(owner, name) is wrapped:
                setattr(owner, name, original)
        self._restore.clear()
        self._pending.clear()

    async def _trusted_sender(self) -> bool:
        """Do not let a restricted notification author mint reply authority."""
        if (senders := self._senders.get()) is None:
            return False
        for user_id in senders:
            user = await self._hass.auth.async_get_user(user_id)
            if (
                user is None
                or not user.is_active
                or not self._evaluator.async_permissions(user).full_access
            ):
                return False
        return True

    async def _send(
        self,
        module: Any,
        original: Callable,
        service: Any,
        message: str,
        kwargs: dict[str, Any],
    ) -> None:
        """Give each recipient its own payload before Core selects a transport."""
        data = kwargs.get("data")
        if not isinstance(data, dict) or not ("actions" in data or "tag" in data):
            await original(service, message, **kwargs)
            return
        targets = kwargs.get("target") or module.push_registrations(self._hass).values()
        trusted = await self._trusted_sender()
        deliveries = []
        for target in targets:
            entry = self._hass.data["mobile_app"]["config_entries"][target]
            user_id = entry.data.get("user_id")
            user = await self._hass.auth.async_get_user(user_id) if user_id else None
            permissions = self._evaluator.async_permissions(user) if user else None
            if user and user.is_active and permissions.full_access:
                outgoing = data
            else:
                outgoing = self._prepare(
                    entry,
                    message,
                    data,
                    permissions if user and user.is_active else None,
                    trusted,
                )
            deliveries.append((target, outgoing))

        # Keep Core's batch behavior untouched when everyone has native access.
        if all(outgoing is data for _, outgoing in deliveries):
            await original(service, message, **kwargs)
            return
        errors = []
        for target, outgoing in deliveries:
            try:
                await original(
                    service, message, **{**kwargs, "target": [target], "data": outgoing}
                )
            except HomeAssistantError as err:
                # A local-only phone being offline must not prevent delivery to
                # the remaining recipients, just as in Core's original loop.
                errors.append(err)
        if errors:
            raise errors[0]

    @callback
    def _prepare(
        self,
        entry: Any,
        message: str,
        data: dict[str, Any],
        permissions: Permissions | None,
        trusted: bool,
    ) -> dict[str, Any]:
        """Replace permitted action identifiers with opaque, expiring receipts."""
        self._expire()
        tag = data.get("tag") if isinstance(data.get("tag"), str) else None
        if tag:
            self._pending = {
                token: reply
                for token, reply in self._pending.items()
                if (reply.entry_id, reply.tag) != (entry.entry_id, tag)
            }
        outgoing = deepcopy(data)
        actions = outgoing.get("actions")
        if not isinstance(actions, list):
            return outgoing
        outgoing["actions"] = []
        event_data = deepcopy(data)
        for field in ("actions", "action", "reply_text", "device_id"):
            event_data.pop(field, None)
        batch = token_urlsafe(24)
        for button in actions[:MAX_ACTIONS]:
            if not isinstance(button, dict):
                continue
            action = button.get("action", button.get("identifier"))
            if not isinstance(action, str) or not action:
                continue
            if action == "URI":
                outgoing["actions"].append(button)
                continue
            if (
                not trusted
                or permissions is None
                or message == "clear_notification"
                or not self._decider.decide_notification_action(
                    permissions, action
                ).allowed
            ):
                continue
            self._make_room(entry.entry_id)
            token = TOKEN_PREFIX + token_urlsafe(32)
            text_input = action == "REPLY" or button.get("behavior") == "textInput"
            self._pending[token] = _Reply(
                entry_id=entry.entry_id,
                webhook_id=entry.data["webhook_id"],
                user_id=entry.data["user_id"],
                action=action,
                batch=batch,
                tag=tag,
                expires=monotonic() + ACTION_TTL,
                event_data={
                    **event_data,
                    "action": action,
                    "device_id": entry.data.get("device_id"),
                },
                text_input=text_input,
            )
            button["action"] = token
            if "identifier" in button:
                button["identifier"] = token
            if text_input:
                # REPLY is a special client-side identifier; after replacing it
                # the equivalent behavior flag keeps the text-entry UI working.
                button["behavior"] = "textInput"
            outgoing["actions"].append(button)
        return outgoing

    @callback
    def consume(
        self, entry: Any, permissions: Permissions, payload: Any
    ) -> tuple[Decision, dict[str, Any] | None]:
        """Validate and consume a reply without trusting returned event fields."""
        refused = Decision(
            allowed=False,
            reason="notification",
            detail="no valid outstanding notification action for this registration",
        )
        self._expire()
        if not isinstance(payload, dict) or payload.get("event_type") != EVENT_ACTION:
            return refused, None
        event_data = payload.get("event_data")
        if not isinstance(event_data, dict):
            return refused, None
        token = event_data.get("action")
        reply = self._pending.get(token) if isinstance(token, str) else None
        if reply is None or (reply.entry_id, reply.webhook_id, reply.user_id) != (
            entry.entry_id,
            entry.data.get("webhook_id"),
            entry.data.get("user_id"),
        ):
            return refused, None
        decision = self._decider.decide_notification_action(permissions, reply.action)
        if not decision.allowed:
            return decision, None
        canonical = deepcopy(reply.event_data)
        if "reply_text" in event_data:
            text = event_data["reply_text"]
            if (
                not reply.text_input
                or not isinstance(text, str)
                or len(text) > MAX_REPLY_LENGTH
            ):
                return refused, None
            canonical["reply_text"] = text
        # No awaits between lookup and consuming the entire choice, so two
        # concurrent taps (including different buttons) can dispatch only once.
        self._pending = {
            key: value
            for key, value in self._pending.items()
            if value.batch != reply.batch
        }
        return decision, {"event_type": EVENT_ACTION, "event_data": canonical}

    @callback
    def _expire(self) -> None:
        now = monotonic()
        self._pending = {
            token: reply
            for token, reply in self._pending.items()
            if reply.expires > now
        }

    @callback
    def _make_room(self, entry_id: str) -> None:
        owned = [
            token
            for token, reply in self._pending.items()
            if reply.entry_id == entry_id
        ]
        if len(owned) >= MAX_PER_REGISTRATION:
            del self._pending[owned[0]]
        if len(self._pending) >= MAX_PENDING:
            del self._pending[next(iter(self._pending))]
