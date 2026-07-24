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
  --internal-domain example.com \
  --trusted-domain approved-partner.example \
  --min-severity critical
```

The observer reads the Login, Admin, OAuth Token, Drive, and Rules audit
applications. All five sources use the same
`admin.reports.audit.readonly` scope. It
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
- public Drive links and external ownership transfers;
- Drive sharing or email attachments sent to consumer accounts;
- Drive sharing outside configured trusted domains;
- bulk downloads, API/sync access, and deletes across unique files;
- Google ransomware sync pauses;
- DLP content matches, rule triggers, and user warnings.

Repeat `--internal-domain` for Workspace aliases and `--trusted-domain` for
approved partners. Common consumer email providers are recognized by default;
`--consumer-domain` adds organization-specific consumer domains.

The bulk detectors count unique Drive resource IDs per actor, IP address, and
originating application within the observation window. The defaults are 25
downloads, 100 API/sync accesses, and 50 deletes. Override them with
`--bulk-download-threshold`, `--bulk-api-access-threshold`, and
`--bulk-delete-threshold`. Drive download audit events do not include byte
counts, so these are unique-file thresholds rather than transfer-volume
thresholds.

Output is structured JSON by default and includes `mode: "read-only"` so
automations can fail closed if the contract changes. Every finding also carries
an `eventId`, `eventTime`, `source`, raw `eventName`, human-readable `reason`,
`occurrences`, and an allowlisted `evidence` object. Evidence can include OAuth
app/client/scopes, login suspicion and challenge metadata, Drive target and
visibility, originating application ID, and DLP rule/detector metadata. File
titles and file content are intentionally excluded. Consumers should use
`eventId` as their idempotency key when appending overlapping observer windows
to a durable store such as Google Sheets.

The report also includes:

- `telemetry`: aggregate document types, visibility states, originating
  application IDs, external target domains, and matched DLP detector names;
- `recommendations`: stable, idempotent proposals derived from the observed
  evidence.

Store recommendations separately from findings. A finding records what
happened; a recommendation records a proposed human decision. Recommended
states are `proposed`, `accepted`, `rejected`, and `implemented`. The observer
never changes a recommendation state and never applies a DLP or sharing rule.

## DLP discovery workflow

Metadata alone cannot determine whether a document contains customer records,
credentials, financial identifiers, or other sensitive content. Use the
observer telemetry to establish scope, then create audit-only DLP rules for
predefined or custom detectors. Audit-only rules write matches to the Rules
audit log without warning or blocking users. After measuring precision and
documenting false positives, a human administrator can decide whether a rule
should remain audit-only, warn users, or block an action.

## Alerting boundary

These commands only produce findings. Notification delivery and remediation are
separate components:

- notification may send a finding to an approved destination;
- remediation must never run automatically from an observer finding;
- user suspension, token revocation, session termination, 2SV changes, and
  device actions require a separate credential and explicit authorization.

Google Alert Center integration is intentionally separate because its API
requires the broad `apps.alerts` scope and should use an isolated credential
boundary. The observer already consumes Google-generated suspicious login,
session-cookie, password-leak, hijacking, and ransomware signals that are
available in the read-only Reports API.
