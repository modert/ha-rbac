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
| `fire_event`, `scan_tag`, `conversation_process`, `render_template` | Refused: their effects or rendered output cannot be bounded safely by their payload. |
| Unknown operations | Refused until an adapter is implemented and tested. |

All restricted requests also honor explicit `mobile_app/<operation>` tier
denials. Service and camera adapters additionally honor their usual command
denials. Sensor registration does not add any entity to an RBAC role.

Push notification delivery and dashboard URL links are unchanged. Action replies
sent using `fire_event` are refused for restricted users, including notification
action events. Administrators should not grant blanket event authority to work
around this: specific event support needs a separate design for bounding its
effects. Unrestricted users retain their existing notification actions.

Refusals appear in the existing Denials log with kind `webhook` and an operation
name. The guard does not log webhook IDs, encryption keys or request payloads.
Errors and filtered zone responses use Core's serializer and encryption. The
admin `ha_rbac/simulate` API accepts `kind: webhook`, the short operation name
and its decrypted `payload` object; it runs the same decision engine without
executing the command. A webhook has no single derived transport tier, so that
response's `tier` is null.

The dispatcher is an internal Core interface. Regression tests exercise Core's
real plaintext and encrypted envelopes, HTTP and WebSocket delivery, owner
identity, revocation and lifecycle cleanup. Revalidate this contract on Core
upgrades. Other integrations' webhooks still need their own ownership adapter;
this is not a blanket user permission model for every webhook.
