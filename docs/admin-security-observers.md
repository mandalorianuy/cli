# Admin and Security Observers

The Admin and Security observers provide a read-only control plane for Google
Workspace administration. They never create, update, suspend, delete, sign out,
revoke, wipe, or otherwise mutate Workspace resources.

## Separate credential profile

Use a dedicated configuration directory so the observer cannot inherit the
broader scopes of an operational `gws` profile:

```bash
export GOOGLE_WORKSPACE_CLI_CONFIG_DIR="$HOME/.config/gws-admin-observer"
gws auth login --scopes \
  https://www.googleapis.com/auth/admin.reports.audit.readonly,\
https://www.googleapis.com/auth/admin.reports.usage.readonly,\
https://www.googleapis.com/auth/admin.directory.user.readonly,\
https://www.googleapis.com/auth/admin.directory.group.readonly,\
https://www.googleapis.com/auth/admin.directory.orgunit.readonly,\
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,\
https://www.googleapis.com/auth/admin.directory.domain.readonly,\
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,\
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
```

The authenticated Workspace account must also hold the corresponding delegated
administrator privileges. OAuth scopes do not grant an administrator role.

## Administration inventory

```bash
gws admin-reports +admin-observer
gws admin-reports +admin-observer --include-devices
```

The default inventory includes:

- users;
- groups;
- organizational units;
- administrator roles and role assignments;
- domains.

ChromeOS and mobile devices are opt-in because their metadata is more sensitive
and may be substantially larger.

## Security detection

```bash
gws admin-reports +security-observer
gws admin-reports +security-observer \
  --lookback-minutes 60 \
  --min-severity critical
```

The observer reads the Login, Admin, and OAuth Token audit applications. It
raises findings for:

- Google-detected suspicious or programmatic logins;
- suspicious session cookies;
- password leaks and hijacked accounts;
- suspicious successful logins;
- repeated login failures;
- 2-Step Verification disablement;
- passkey or recovery-channel removal and changes;
- administrator role assignments;
- domain-wide delegation authorization;
- Context-Aware Access changes;
- OAuth application authorization.

Output is structured JSON by default and includes `mode: "read-only"` so
automations can fail closed if the contract changes. Every finding also carries
an `eventId`, `eventTime`, `source`, and `occurrences` value. Consumers should
use `eventId` as their idempotency key when appending overlapping observer
windows to a durable store such as Google Sheets.

## Alerting boundary

These commands only produce findings. Notification delivery and remediation are
separate components:

- notification may send a finding to an approved destination;
- remediation must never run automatically from an observer finding;
- user suspension, token revocation, session termination, 2SV changes, and
  device actions require a separate credential and explicit authorization.

Google Alert Center integration is intentionally separate because its API
requires a service account with domain-wide delegation and exposes a combined
read/write OAuth scope.
