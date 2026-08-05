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

Add identity and control posture without changing the existing audit-finding
contract:

```bash
gws admin-reports +security-observer \
  --lookback-minutes 60 \
  --internal-domain example.com \
  --include-posture \
  --inactive-days 90
```

`--include-posture` adds three paginated Directory API GET collections: users,
administrator roles, and role assignments. It requires only
`admin.directory.user.readonly` and
`admin.directory.rolemanagement.readonly` in addition to the Reports scope.
The output detects active users without 2SV, privileged users without 2SV,
stale active accounts, and identity-state or privilege-protection differences
when Microsoft is also enabled.

If a Google posture collection fails, the observer stops without emitting a
partial posture report. The error is reduced to a stable HTTP/provider code;
the provider response body is not copied to terminal output or report data.

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

## Microsoft 365 and cross-cloud posture

Microsoft integration is opt-in. An explicitly supplied
`MICROSOFT_GRAPH_ACCESS_TOKEN` remains the highest-priority override; it is
used as-is for compatibility and certificate files are not read when it is
present. The helper does not register an Entra application, request admin
consent, refresh a refresh token, or write an access token to disk:

```bash
export MICROSOFT_GRAPH_ACCESS_TOKEN="<short-lived-read-only-token>"
gws admin-reports +security-observer \
  --lookback-minutes 60 \
  --internal-domain example.com \
  --include-posture \
  --microsoft-graph
```

For unattended runs without an explicit access token, configure certificate
client credentials with environment values that contain references, never key
bytes:

```bash
export MICROSOFT_GRAPH_TENANT_ID="00000000-0000-0000-0000-000000000000"
export MICROSOFT_GRAPH_CLIENT_ID="00000000-0000-0000-0000-000000000000"
export MICROSOFT_GRAPH_CERTIFICATE_FILE="/secure/nexa-wsso/certificate.pem"
export MICROSOFT_GRAPH_PRIVATE_KEY_FILE="/secure/nexa-wsso/private-key.pem"
# Optional, but recommended when the Entra key identifier is known:
export MICROSOFT_GRAPH_CERTIFICATE_KEY_ID="00000000-0000-0000-0000-000000000000"
# Optional SHA-1 thumbprint assertion, 40 hexadecimal characters:
export MICROSOFT_GRAPH_CERTIFICATE_THUMBPRINT="0123456789ABCDEF0123456789ABCDEF01234567"
```

The tenant and client IDs are strict hyphenated UUIDs. The certificate file
must be one PEM-encoded X.509 certificate, and the private key must be an RSA
PKCS#1 or unencrypted PKCS#8 PEM key. On Unix/macOS both files must be regular,
non-symlink files owned by the executing user. The private key must use exact
mode `0600`; the public certificate may use standard readable mode `0644`, but
neither file may be group/world writable and their parent directory must also
be owned by that user and not group/world writable. The certificate must be
currently valid, RSA, and match the private key. The optional thumbprint is
checked against the certificate. A missing, partial, malformed, mismatched,
expired, or insecure configuration fails closed with a bounded authentication
code; it never becomes disabled or clean.

The client assertion is signed in memory with RS256, has a unique `jti`, a
tenanted fixed `aud`/issuer/subject, and certificate `x5t`, `x5t#S256`, and
optional `kid` headers. The token request is always the fixed HTTPS endpoint
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with
`grant_type=client_credentials` and
`scope=https://graph.microsoft.com/.default`. Assertions, private-key bytes,
access tokens, and provider response bodies are memory-only and are not copied
to logs, errors, observer JSON, or monitor records. The response must be a
Bearer token with at least five minutes of lifetime and all seven configured
Graph application roles; otherwise the run fails closed. A session reuses the
token while it remains beyond the 60-second expiry skew; a new scheduled
process acquires a new token.

For a scheduled runner, place the two PEM files in a dedicated directory with
`0700` directory permissions, load only the variable names above from the
runner's protected environment/configuration, and keep the PEM files outside
Git. Rotate by installing the new certificate/key pair, updating the optional
key ID/thumbprint references, validating the new pair, and only then removing
the old pair. Never put the private key or an access token in command-line
arguments, `.env` committed to a repository, fixtures, receipts, or reports.

Do not reuse a write-capable operational identity. Consent and licensing are
external authority gates. Grant only the permissions for the sources that the
organization approves:

| Source | Microsoft Graph permission | Additional requirement |
|---|---|---|
| Users | `User.Read.All` | Entra role may also constrain delegated access |
| Authentication method registration | `AuditLog.Read.All` | Reports Reader, Security Reader, Security Administrator, or Global Reader for delegated access |
| Directory role assignments | `RoleManagement.Read.Directory` | Admin consent; a supported Entra reader role for delegated access |
| Conditional Access policies | `Policy.Read.All` | Supported Conditional Access/security reader role; policy availability depends on tenant licensing |
| Sign-ins and directory audits | `AuditLog.Read.All` (directory audits can additionally require `Directory.Read.All`) | Sign-in log download requires Microsoft Entra ID P1 or P2 |
| Defender alerts | `SecurityAlert.Read.All` | Defender data and supported security reader role/license |
| Defender incidents | `SecurityIncident.Read.All` | Microsoft Defender XDR availability and supported role/license |
| Secure Score | `SecurityEvents.Read.All` | Secure Score availability for the tenant |

Every Microsoft endpoint is a fixed `https://graph.microsoft.com/v1.0/` GET.
Pagination follows only HTTPS `@odata.nextLink` values on that exact host and
API version, with a 100-page safety limit. Provider error bodies are not copied
to output. Instead, each source receives an `available`, `unavailable`, or
`disabled` coverage entry and a bounded error code such as
`http_403_Authorization_RequestDenied`. An unavailable source never becomes a
clean result and makes `coverageComplete` false when Microsoft was requested.
Disabled Microsoft sources are explicit non-assurance entries when the Graph
flag is not selected; they are not interpreted as clean coverage.

The `securityPosture` object uses schema `security_intelligence_v1` and keeps
four concerns separate:

- `identityPosture`: 2SV/MFA, active state, staleness, and privileged identity
  protection;
- `controlPosture`: Conditional Access MFA coverage and explicit active-user
  exclusions;
- `crossCloudCorrelations`: exact normalized-email matches with inconsistent
  active state, privilege protection gaps, or risky access signals in both
  Google and Microsoft during the observation window;
- `signalFindings`: risky Entra sign-ins, sensitive successful directory
  changes, and high/critical Microsoft Defender alerts and incidents.

Secure Score is stored only as a snapshot metric (`currentScore`, `maxScore`,
percentage, timestamp, and user counts). It is not treated as proof that any
individual control is effective.

Every posture or signal finding has a stable control ID, raw allowlisted
evidence, and an initial human-operational analysis in Spanish. The analysis
separates conclusion, escalation reason, plausible impact, supporting and
counter-evidence, uncertainty, recommended human action, urgency, and
confidence. It never claims compromise, exfiltration, or successful
remediation from a provider severity alone.

Initial stable controls include:

- `GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV` and
  `GOOGLE.IDENTITY.USER_WITHOUT_2SV`;
- `GOOGLE.IDENTITY.STALE_ACTIVE_ACCOUNT`;
- `MSFT.IDENTITY.ADMIN_NOT_MFA_CAPABLE`,
  `MSFT.IDENTITY.ADMIN_NOT_MFA_REGISTERED`, and
  `MSFT.IDENTITY.USER_NOT_MFA_REGISTERED`;
- `MSFT.CA.NO_ENABLED_MFA_POLICY` and
  `MSFT.CA.USER_EXCLUDED_FROM_MFA`;
- `MSFT.SIGNAL.RISKY_SIGN_IN`, `MSFT.SIGNAL.DIRECTORY_CHANGE`, and the
  high-severity Defender alert/incident controls;
- `CROSS.IDENTITY.ACTIVE_STATE_MISMATCH`,
  `CROSS.IDENTITY.PRIVILEGE_PROTECTION_GAP`, and
  `CROSS.SIGNAL.MULTITENANT_SUSPICIOUS_LOGIN`.

Microsoft reference contracts: [authentication method registration](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0),
[sign-ins](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0),
[directory audits](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0),
[Conditional Access policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0),
[Defender alerts](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0),
[Defender incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0),
and [Graph Security authorization](https://learn.microsoft.com/en-us/graph/security-authorization).

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
