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
  --min-severity critical \
  --ip-intelligence
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

### IP intelligence

`--ip-intelligence` enriches each finding that has an IP address. It does not
add Google OAuth scopes and does not change the raw severity or rule selected
by the observer.

Without any additional credential, the observer:

- classifies public, private, shared, loopback, link-local, documentation,
  benchmarking, multicast, and reserved addresses locally;
- uses the official IANA IPv4/IPv6 RDAP bootstrap registries to select a
  Regional Internet Registry;
- follows one bounded RIR referral when the authoritative registry differs
  from the initial allocation;
- reports the registered network holder, network name and range, RIR, RDAP
  source URL, and registration country.

Set `GOOGLE_WORKSPACE_CLI_IPINFO_TOKEN` to add the IPinfo data available to the
token's plan. The observer first requests Core data and falls back to Lite for
country and ASN. It separately requests privacy data for explicit VPN, proxy,
Tor, relay, hosting, and service fields. Tokens are passed to the provider but
are never serialized into report output or error messages.

Every finding uses tri-state `vpn`, `proxy`, `tor`, and `relay` values:
`detected`, `not_detected`, or `unknown`. `unknown` is retained when no
qualified provider returned the specific signal. The observer never infers VPN
status from an ASN name, network owner, hosting flag, country, or repetition.

Treat the fields according to their evidence source:

- `networkOwner` is the registered organization holding the address range, not
  the person using the IP;
- `registrationCountry` is registry data and may differ from physical origin;
- `country`, `region`, `city`, coordinates, and timezone are provider
  geolocation estimates, not proof of a user's location;
- VPN/proxy/Tor results are point-in-time provider observations and should
  inform human review rather than independently prove compromise.

Enrichment is best effort and deduplicated per unique IP within a run. Provider
failures are recorded as bounded error codes inside `ipIntelligence`; they do
not suppress or discard the underlying Workspace finding. The report-level
`ipIntelligence` summary shows enabled providers and complete, partial, and
unavailable lookup counts.

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
