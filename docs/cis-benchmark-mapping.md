# CIS AWS Foundations Benchmark v5.0.0 — Triage Notes

Security Hub CSPM's CIS v5.0.0 standard runs ~40 automated controls
across IAM, Storage, Logging, Monitoring, and Networking. This document
records triage judgment for findings surfaced in this environment — not
a transcript of the raw finding list, but the analysis behind each call.

The three possible outcomes for any finding:

- **Remediate** — real issue, fix it
- **Accept (sandbox)** — would remediate in production, acceptable in a
  personal learning account
- **Accept (by design)** — intentional architecture decision, not a gap

---

## IAM controls (CIS section 1)

**Root account access keys exist**
Not applicable — no root access keys created in any account. This control
passes across all three accounts. Cross-references with GuardDuty's
`Policy:IAMUser/RootCredentialUsage` finding type — both watching the
same risk from different angles (Config checks configuration, GuardDuty
watches runtime behavior).

**MFA not enabled for console users**
Maps directly to the `mfa-enabled-for-iam-console-access` Config rule
running in this environment. If Security Hub CSPM and Config disagree on
a specific user, that's worth investigating — they use different
evaluation mechanisms (Security Hub CSPM reads IAM credential reports,
Config uses a scheduled Lambda evaluation) and a mismatch indicates one
is stale.

**IAM password policy**
In a sandbox account using IAM Identity Center (SSO) as the primary
access method, password policy controls on IAM users are lower priority
since human access doesn't go through IAM user passwords. Would
remediate in a production account with direct IAM user access.

---

## Logging controls (CIS section 2)

**CloudTrail not enabled / not multi-region**
CloudTrail is running in this environment as a GuardDuty data source.
A dedicated multi-region trail with log file validation and centralized
delivery to the security account S3 bucket is the production standard —
not configured here since this is a learning environment relying on
GuardDuty's data source enablement. Would be the first remediation item
before production use.

**CloudTrail log file validation not enabled**
Same as above — accepted for this environment, required for production.
Log file validation detects tampering with CloudTrail logs after the fact,
which is relevant when CloudTrail itself is a forensic source during an
incident..

---

## Storage controls (CIS section 3)

**S3 bucket public access**
Maps directly to the `s3-bucket-public-read-prohibited` and
`s3-bucket-public-write-prohibited` Config rules running in this
environment. Any finding here should agree with those Config rules — if
they disagree, one evaluation is stale and worth investigating.

---

## Monitoring controls (CIS section 4)

**CloudWatch alarms for root usage, unauthorized API calls, etc.**
These controls check for specific CloudWatch metric filters and alarms.
In this architecture, equivalent alerting is handled through GuardDuty
findings flowing to Security Hub CSPM and SNS, rather than raw CloudWatch
alarms. Technically non-compliant per CIS (which expects the specific
metric filter pattern), functionally covered by a more capable detection
layer. This is a reasonable tradeoff to document explicitly rather than
building CloudWatch alarms that duplicate GuardDuty coverage.

---

## Networking controls (CIS section 5)

**Default VPC security groups allow unrestricted access**
Common finding in any AWS account that hasn't explicitly hardened default
VPCs. In a learning account with no production traffic in the default VPC,
this is accepted. In production, default VPCs should either be deleted or
have their default security groups locked down — the default SG allowing
all inbound from within the SG is a lateral movement risk if instances
are ever launched into it accidentally.

---

## Notes on this triage approach

Security Hub CSPM's compliance score is a useful starting metric but
not the end goal. A score of 100% achieved by accepting all findings as
false positives is meaningless. A score of 70% with clear documented
rationale for each gap — distinguishing real issues from sandbox
limitations from intentional architecture decisions — is the actual
deliverable.

The most important column in any CIS triage is "would I remediate this
in production?" If the answer is yes and the only reason it's not fixed
here is the sandbox context, that should be explicit. Interviewers ask
about this distinction directly.
