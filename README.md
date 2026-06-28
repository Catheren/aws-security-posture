# AWS Cloud Security Posture
[![AWS](https://img.shields.io/badge/AWS-Multi--Account-FF9900?logo=amazon-aws&logoColor=white)](https://aws.amazon.com/)
[![GuardDuty](https://img.shields.io/badge/GuardDuty-Threat_Detection-red)](https://aws.amazon.com/guardduty/)
[![Security Hub](https://img.shields.io/badge/Security_Hub-CSPM-blue)](https://aws.amazon.com/security-hub/)
[![AWS Config](https://img.shields.io/badge/AWS_Config-Compliance-orange)](https://aws.amazon.com/config/)
[![Inspector](https://img.shields.io/badge/Inspector-Vulnerability_Scanning-yellow)](https://aws.amazon.com/inspector/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)

A hands-on multi-account AWS security project demonstrating the architecture,
tooling, and judgment.

Built on AWS across three workload accounts (security, prod, dev) under a
single AWS Organization. Every decision here — what to enable, where to run
it, and what to defer — reflects how a small-to-medium company would
realistically operate this stack, not a checklist of every available toggle.

---
## What this demonstrates

| Skill | Implementation |
|---|---|
| Multi-account AWS security architecture | 4-account pattern with delegated admin via AWS Organizations |
| Threat detection | GuardDuty enabled org-wide with centralized findings |
| Cloud security posture management | Security Hub CSPM with CIS AWS Foundations Benchmark v5.0.0 |
| Configuration compliance | AWS Config with custom Lambda rule + 2 managed rules |
| Vulnerability management | Amazon Inspector across EC2 and ECR in all accounts |
| Cross-account event pipeline | EventBridge forwarding all CloudTrail events to central security bus |
| SIEM-ready architecture | S3 landing zone via Kinesis Firehose for vendor-agnostic ingestion |
| Incident response | IR playbooks for credential compromise, public S3, suspicious IAM |
| Detection gap analysis | Coverage map documenting native vs custom detection decisions |

## Architecture

```
Management Account (org root)
│
│  delegates admin (GuardDuty, Security Hub, Inspector, Config)
│
└── Security Account (centralized visibility hub)
    │   GuardDuty · Security Hub CSPM · Config aggregator
    │   Inspector · EventBridge central bus · Config rules
    │   SNS alerting · S3 SIEM export bucket
    │
    ├── Prod Account (us-east-2)
    │   GuardDuty member · Config recorder · Inspector
    │   EventBridge → central bus · EC2 · S3 · IAM · RDS
    │
    └── Dev Account (us-east-2)
        GuardDuty member · Config recorder · Inspector
        EventBridge → central bus · dev workloads
```

The security account has no workloads of its own. It exists purely as a
visibility and control hub — one place to view findings, compliance posture,
and vulnerability data across every account, without needing separate
credentials for each.

---

## Repository structure

```
aws-cloud-security-engineering/
  console-walkthrough.md        Step-by-step setup guide
  docs/
    coverage-map.md             Native vs custom detection analysis
    cis-benchmark-mapping.md    CIS findings triage notes
  lambda/
    no_wildcard_iam.py          Custom Config rule evaluation logic
   playbooks/                    IR playbooks (credential compromise,
                                public S3, suspicious IAM activity)
```

---

## What was built

### Account structure and delegation

The four-account pattern (management, security, prod, dev) is the baseline
AWS recommends for any organization running multiple environments. The
management account's only job is to grant delegated administrator status
to the security account for each service — it runs no workloads and has
no long-term configuration.

One non-obvious thing: Config's delegated administrator registration is
CLI-only. GuardDuty, Security Hub, and Inspector all have a console button
for this. Config does not — it requires running
`aws organizations register-delegated-administrator` from the management
account via CloudShell. This is a product inconsistency, not a different
security model.

---

### GuardDuty

Enabled in all three accounts with the security account as delegated
administrator. Prod and dev are auto-enrolled via organization settings,
so any new account added to the org gets GuardDuty automatically.

**What it does:** behavioral threat detection. Watches CloudTrail API
calls, VPC Flow Logs, and DNS queries. Uses threat intelligence feeds
and ML baselines to flag anomalous patterns — credentials used from an
unusual location, EC2 instances making suspicious outbound connections,
IAM enumeration behavior.

**What it doesn't do:** it doesn't check software vulnerabilities on your
instances (that's Inspector), it doesn't evaluate AWS resource configuration
(that's Config and Security Hub CSPM), and it doesn't support custom
detection rules. The detection logic is a managed black box.

**Design note:** GuardDuty natively covers several patterns often cited
as requiring custom detection — impossible travel, privilege escalation
anomalies, root usage. Before building any custom rules, this project
documents exactly what GuardDuty catches versus where its gaps are.
See `docs/coverage-map.md`.

---

### AWS Config

Enabled in all three accounts. The security account runs an organization
aggregator that pulls configuration history and compliance results from
prod and dev into a single view.

**What it does:** continuous configuration compliance. Records every
change to AWS resources and evaluates them against rules — both
AWS-managed and custom. Answers questions like "has any S3 bucket been
made public since yesterday?" or "which IAM users don't have MFA?"

**Three rules running:**

| Rule | Type | Trigger |
|---|---|---|
| `s3-bucket-public-read/write-prohibited` | AWS managed | Configuration change |
| `mfa-enabled-for-iam-console-access` | AWS managed | Periodic (scheduled) |
| `no-wildcard-iam-policies` | Custom Lambda | Configuration change |

The MFA rule runs on a schedule rather than reacting to changes — because
whether a user has an MFA device attached isn't captured as a discrete
configuration change event in Config. This distinction between
change-triggered and periodic rules matters when designing compliance
coverage.

The wildcard IAM policy rule is a custom Lambda function that evaluates
every customer-managed IAM policy for statements combining `"Action": "*"`
and `"Resource": "*"`. AWS's managed rule `iam-policy-no-statements-with-admin-access`
covers the same check — the custom version is retained as a demonstration
of writing Config evaluation logic. In production, the managed rule would
be the right choice.

---

### Security Hub CSPM

Enabled in the security account with the CIS AWS Foundations Benchmark
v5.0.0 standard active.

**What it does:** two things. First, aggregates findings from GuardDuty,
Inspector, and Config into a single dashboard. Second, runs its own
compliance checks against AWS resource configurations per the enabled
standards (CIS, FSBP, PCI DSS, NIST).

**Naming note:** AWS renamed the original Security Hub to "Security Hub
CSPM" in late 2025 when they launched a separate product called "Security
Hub" — a newer correlation layer using OCSF format. For teams with existing
ASFF-based automation, Security Hub CSPM is the right choice. Both products
appear in the console under the Security Hub area, which creates confusion
worth being aware of.

The CIS benchmark triage exercise — determining which control failures are
real issues versus sandbox noise versus acceptable risk — is documented
in `docs/cis-benchmark-mapping.md`. This triage judgment is the actual
security work, not the act of enabling the standard.

---

### Amazon Inspector

Enabled across all three accounts with the security account as delegated
administrator, scanning EC2 instances and ECR container images.

**What it does:** vulnerability assessment. Compares software packages
installed on EC2 instances and container images against the CVE database.
An instance running a vulnerable OpenSSL version gets flagged here.

**How it differs from GuardDuty:** GuardDuty asks "is something bad
happening right now?" Inspector asks "does my software have known
vulnerabilities?" One watches behavior, the other watches what's installed.
Neither replaces the other.

---

### EventBridge cross-account event pipeline

EventBridge forwarding rules in prod and dev send all CloudTrail management
events to `central-security-bus` in the security account.

**What this enables:** any real-time detection or response attached to the
central bus sees events from prod and dev without needing credentials in
those accounts. A SIEM connector, detection Lambda, or automated response
function all subscribe here.

**Why forward everything:** detection context depends on the full event
stream, not just the events you anticipated when writing a filter. Filtering
at the EventBridge rule level trades detection coverage for cost savings —
any attack technique using an unfiltered API call becomes invisible to
everything downstream. At small-to-medium account activity levels the cost
difference is negligible. When volume grows, the right place to filter is
downstream in the SIEM, where detection logic can evolve without touching
infrastructure.

---

### SIEM export path

An S3 bucket in the security account serves as a vendor-agnostic landing
zone for raw CloudTrail events and security findings, delivered via Kinesis
Data Firehose from the central EventBridge bus.

**Why S3 as the landing zone:** Splunk, Microsoft Sentinel, Elastic, and
Datadog Security all support S3 ingestion natively. The SIEM gets full
event context — not a pre-filtered subset — which is what makes correlation
across accounts and services possible. Provisioning this now means
onboarding a SIEM later is a configuration change, not a pipeline redesign.

**Why not custom Lambda detections instead:** for a small-to-medium
security team, operationalizing native AWS findings through a SIEM is more
practical than maintaining bespoke detection code. Custom Lambda detection
is a pattern used by larger teams with dedicated detection engineering
functions. The architecture supports it as a future addition without
requiring a redesign.

---

## Key design decisions

**The security account is the highest-value target in this setup.** Being
the delegated administrator for every detection service means a compromised
security account doesn't just expose one workload — it exposes visibility
and configuration control across the entire organization, and potentially
the ability to turn detection off in prod and dev silently. Mitigations:
phishing-resistant MFA for any human access, short-lived credentials via
IAM Identity Center (no standing IAM users), no workloads in the account,
and GuardDuty and Config watching the security account itself.

**Dev is in scope deliberately.** Attackers who compromise developer
credentials don't stay in dev. Lateral movement from dev to prod via
assumed roles or shared secrets is a real path. Treating dev as out-of-scope
for detection creates a blind spot at exactly the entry point most likely
to be targeted.

**Native tooling before custom detections.** GuardDuty, Security Hub CSPM,
Config, and Inspector collectively cover the most common cloud attack
patterns out of the box. The right question before building any custom
detection is: does this already exist natively, and if so, what does a
custom rule actually add — gap-filling or tuning control? The coverage map
documents this analysis for the most common IAM and credential-abuse
detection patterns.

**Forward all events to the SIEM export bucket.** A SIEM is only as good
as the context it has. Pre-filtering events at the source saves cost at
the expense of detection coverage and correlation fidelity. At this scale
the cost is negligible and the coverage is worth it.

---

## Prerequisites

- AWS account with Organizations set up (management + member accounts)
- AWS CLI v2, Python 3.12
- Admin access in each account for initial setup
See `console-walkthrough.md` for the full step-by-step setup guide.
