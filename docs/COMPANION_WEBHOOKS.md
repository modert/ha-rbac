# Companion webhook enforcement

Companion sends both telemetry and actions through its registered webhook. Core
authenticates and decrypts those messages before dispatching them. Access Control
guards that dispatcher and resolves the user from the stored registration, never
from a payload or an unrelated HTTP/WebSocket login. See the [Core mobile API](https://developers.home-assistant.io/docs/api/native-app-integration/sending-data/).

The current role is evaluated for each request. Missing or inactive owners are
refused. Active users with full access, including unassigned users under this
fork's opt-in behavior, retain Core's existing handlers.

For restricted accounts:

| Operation | Policy |
| --- | --- |
| `call_service` | Same service, target, tier and choice checks as WebSocket dashboard controls. |
| `stream_camera` | Same entity read and command checks as `camera/stream`. |
| `get_zones` | Same read gate and state/attribute filtering as the state API, before encryption. |
| `get_config` | Same command gate as `get_config`; Core returns app configuration and that registration's sensor settings. |
| `update_location`, `register_sensor`, `update_sensor_states` | Core scopes uploads to the authenticated registration. Reporting telemetry grants no general entity-control permission. |
| `update_registration`, `enable_encryption` | Core validates changes to that registration. |
| `fire_event` | Only an explicitly granted, outstanding notification button can emit `mobile_app_notification_action`; all other events are refused. |
| `scan_tag`, `conversation_process`, `render_template` | Refused: their effects or rendered output cannot be bounded safely by their payload. |
| Unknown operations | Refused until an adapter is implemented and tested. |

All restricted requests also honor explicit `mobile_app/<operation>` tier
denials. Service and camera adapters additionally honor their usual command
denials. Sensor registration does not add any entity to an RBAC role.

## Notification action replies

Restricted users need both a role grant and an outstanding button sent to their
specific phone. Add an exact action identifier to the role's command exceptions:

```json
{
  "tiers": {
    "max": "user",
    "allow": ["mobile_app/notification_action/ACK_REMINDER"],
    "deny": ["fire_event"]
  }
}
```

This grants the automation behind `ACK_REMINDER`, not arbitrary events or
general control of its entities. Review that handler's effects before granting
it, and prefer distinct action identifiers for distinct authority. A user-level
role has no reply grants by default. Like other command exceptions, an explicit
deny in any active role wins; admin-tier roles permit these commands by rank.
`mobile_app/fire_event` denies even bounded replies. A plain `fire_event` denial
continues blocking the WebSocket command without disabling this separate grant.

On an outgoing notification, the integration removes ungranted action buttons
for restricted recipients and replaces granted identifiers with random tokens.
Each token is tied to the registration and its stored user, expires after 24
hours, and can be used only once. Answering any button consumes the other choices
in that notification. Replacing or clearing its `tag` revokes the old buttons.
There are at most 64 outstanding buttons per registration and 2,048 overall;
oldest entries expire on overflow. All tokens expire on RBAC unload or Core
restart: reissue unanswered notifications afterward.

Only system service calls and active users with full RBAC access may issue
reply tokens. A restricted user's notification call cannot grant new reply
authority, even through a notify group that drops the original service context.
The integration carries the caller through nested service execution. Direct
integration calls outside a service context cannot issue tokens. Automations or
scripts carrying a restricted user's context likewise cannot issue them; keep
such approval flows on a trusted notification-sending path.

At reply time, the registration owner must still be active and their current
role must still permit the original action. The guard restores that action and
the server's original notification `data`, supplies the registration's device
ID, and discards other client-supplied event fields. Existing automation action
names need no changes. The event retains **the recipient's** user context, never
the sender's; parent-only automation identity checks still apply.

`REPLY` and `behavior: textInput` retain their text-entry UI. Only those buttons
accept `reply_text` (a string of at most 4,096 characters). Treat it as user input
in the receiving automation. `action_data` and other notification metadata come
from the stored outgoing data, not the reply; their original JSON types are
preserved rather than accepting Android's echoed or flattened representation.

Dashboard URL buttons (`action: URI`) and notifications without buttons keep
their usual navigation/delivery behavior. Unrestricted recipients keep native
action identifiers. Plaintext and encrypted webhook delivery, local push and
cloud fallback use the same capability. The modern inline `data.actions` format
is supported, including the iOS `identifier` alias. Legacy preconfigured iOS
categories, notification-received/cleared events and arbitrary events do not
receive this authority. See [Companion's action format](https://companion.home-assistant.io/docs/notifications/actionable-notifications/).

Refusals appear in the existing Denials log with kind `webhook` and an operation
name. The guard does not log webhook IDs, encryption keys or request payloads.
Errors and filtered zone responses use Core's serializer and encryption. The
admin `ha_rbac/simulate` API accepts `kind: webhook`, the short operation name
and its decrypted `payload` object; it runs the same decision engine without
executing the command. A webhook has no single derived transport tier, so that
response's `tier` is null.

For an action **policy** check, use `ha_rbac/simulate` with
`kind: notification_action` and `command: ACK_REMINDER`. It checks the same role
grant without sending anything or creating a token. A successful simulation is
not a live receipt: the webhook still requires an outstanding phone-bound token.

The dispatcher, legacy notify send method and service execution hook are internal
Core interfaces. Regression tests exercise real plaintext and encrypted
envelopes, HTTP and WebSocket delivery, Core notify groups, local/cloud push,
owner identity, caller provenance, expiry, replay, revocation and lifecycle
cleanup. Push transport is mocked; no real devices receive tests. Revalidate
these contracts on Core upgrades. Other integrations' webhooks still need their
own ownership adapter; this is not a blanket user permission model for every
webhook.
