"""Apply a phone registration owner's policy after Core decrypts its webhook.

Core's dispatcher is shared by HTTP, websocket and cloud delivery. Inspecting
there keeps encryption and registration authentication in Core and avoids an
HTTP-only guard that another transport can bypass. This is an internal Core
interface, so its contract is covered by tests against Core's real dispatcher.
"""

import sys
from functools import partial
from http import HTTPStatus
from typing import Any

from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util.decorator import Registry

from .decide import KIND_WEBHOOK, Decider, Decision
from .denylog import Denial, DenyLog
from .filters import REGISTRY, FilterContext
from .policy import Evaluator

MODULE = "homeassistant.components.mobile_app.webhook"


class _GuardedCommands(Registry):
    """Guard lookups, including commands registered after installation."""

    def __init__(self, commands: Registry, guard: "MobileWebhookGuard") -> None:
        """Keep the registered handlers unchanged beneath the lookup guard."""
        super().__init__(commands)
        self.guard = guard

    def __getitem__(self, command: str) -> Any:
        """Wrap dispatch without copying, decrypting or logging its payload."""
        return partial(self.guard.async_handle, command, super().__getitem__(command))


class MobileWebhookGuard:
    """Bind Companion commands to the user stored on their registration."""

    def __init__(
        self,
        hass: HomeAssistant,
        evaluator: Evaluator,
        decider: Decider,
        denylog: DenyLog,
    ) -> None:
        """Create a guard without importing optional mobile app dependencies."""
        self._hass = hass
        self._evaluator = evaluator
        self._decider = decider
        self._denylog = denylog
        self._module: Any = None
        self._original: Registry | None = None
        self._commands: _GuardedCommands | None = None
        self._unsubscribe: Any = None

    @callback
    def start(self) -> None:
        """Protect an existing mobile integration and one added later."""
        self._install()
        self._unsubscribe = self._hass.bus.async_listen(
            "component_loaded", self._component_loaded
        )

    @callback
    def _component_loaded(self, event: Event) -> None:
        """Install before a newly loaded mobile integration receives commands."""
        if event.data.get("component") == "mobile_app":
            self._install()

    @callback
    def _install(self) -> None:
        """Replace only the dispatcher lookup, leaving Core's handlers intact."""
        if self._commands is not None or (module := sys.modules.get(MODULE)) is None:
            return
        commands = getattr(module, "WEBHOOK_COMMANDS", None)
        if not isinstance(commands, Registry) or not callable(
            getattr(module, "webhook_response", None)
        ):
            raise HomeAssistantError(
                "Companion webhook dispatch is incompatible with access control"
            )
        self._module = module
        self._original = commands
        self._commands = _GuardedCommands(commands, self)
        module.WEBHOOK_COMMANDS = self._commands

    @callback
    def stop(self) -> None:
        """Restore the dispatcher on unload without losing later registrations."""
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        if (
            self._commands is not None
            and self._module.WEBHOOK_COMMANDS is self._commands
            and self._original is not None
        ):
            self._original.clear()
            self._original.update(self._commands)
            self._module.WEBHOOK_COMMANDS = self._original
        self._commands = None

    async def async_handle(
        self,
        command: str,
        handler: Any,
        hass: HomeAssistant,
        entry: Any,
        payload: Any,
    ) -> Any:
        """Judge the decrypted operation before any handler can cause effects."""
        # The registry is a module global; another HA instance in the same
        # process (notably tests) must retain its own lifecycle and policy.
        if hass is not self._hass:
            return await handler(hass, entry, payload)

        user_id = entry.data.get("user_id")
        user = await hass.auth.async_get_user(user_id) if user_id else None
        if user is None or not user.is_active:
            decision = Decision(
                allowed=False,
                reason="identity",
                detail="phone registration has no active user",
            )
        else:
            permissions = self._evaluator.async_permissions(user)
            decision = self._decider.decide(permissions, KIND_WEBHOOK, command, payload)

        if not decision.allowed:
            self._denylog.async_record(
                Denial(
                    user_id=user.id if user else "",
                    user_name=user.name or "" if user else "",
                    kind=KIND_WEBHOOK,
                    name=f"mobile_app/{command}",
                    reason=decision.reason,
                    detail=decision.detail,
                    resources=decision.resources,
                )
            )
            # Do not log the webhook id, encryption key, location or payload.
            # Use Core's serializer so encrypted registrations get encrypted
            # errors too, with no internal policy diagnostic in the response.
            return self._module.webhook_response(
                {
                    "success": False,
                    "error": {"code": "unauthorized", "message": "Unauthorized"},
                },
                registration=entry.data,
                status=HTTPStatus.FORBIDDEN,
            )

        if command == "get_zones" and decision.filter_response:
            zones = [
                state.as_dict()
                for entity_id in sorted(hass.states.async_entity_ids("zone"))
                if (state := hass.states.get(entity_id)) is not None
            ]
            filtered = REGISTRY.filter_result(
                "get_states", FilterContext.for_user(hass, permissions), zones
            )
            return self._module.webhook_response(filtered, registration=entry.data)

        return await handler(hass, entry, payload)
