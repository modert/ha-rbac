# Modert deployment

Based on FezVrasta/ha-rbac v0.25.0, commit 2b58ae6.

This fork rolls out access control per account. Accounts without an assigned
role or a per-user denial retain Home Assistant's native permissions, including
Assist and signed media URLs. Explicitly assigned accounts are filtered normally;
a missing or inactive assigned role grants nothing. The upstream server still
authenticates every request and applies its native permissions.

Household roles and dashboards live in modert/homeassistant-config. They do not
belong in this reusable integration. Logan is the first restricted account.

The upstream webhook limitations remain. This release is intended to restrict
normal dashboard, search, and device controls; it is not a complete audit of all
Companion-app and custom-integration paths. Continue merging upstream security
fixes. Preserve upstream attribution and report vulnerabilities privately.
