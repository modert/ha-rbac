# Modert deployment

Based on FezVrasta/ha-rbac v0.26.0, commit 47a6807. The restricted dashboard
landing fix that used to be carried here is upstream since v0.26.0 (#74).

This fork rolls out access control per account. Accounts without an assigned
role or a per-user denial retain Home Assistant's native permissions, including
Assist and signed media URLs. Explicitly assigned accounts are filtered normally;
a missing or inactive assigned role grants nothing. The upstream server still
authenticates every request and applies its native permissions.

Household roles and dashboards live in modert/homeassistant-config. They do not
belong in this reusable integration. Logan is the first restricted account.

Companion registration is allowed after the normal tier/app checks: Core binds
the new registration to the authenticated user. Explicit command denials still
win. An embedded To-do card may subscribe to its named list when the To-do panel
is hidden; the regular entity read check still applies.

Companion webhooks now use the registration owner's current role after Core
decrypts the request. Service/camera operations reuse the decision engine,
telemetry stays registration-scoped, and zones are filtered before encryption.
Unbounded and unknown commands are refused for restricted accounts. See
`docs/COMPANION_WEBHOOKS.md` for the generic behavior and notification-action
limitations. Other integrations' webhooks still need ownership adapters; this
is not a complete audit of all custom-integration paths. Continue merging
upstream security fixes. Preserve attribution and report vulnerabilities privately.
