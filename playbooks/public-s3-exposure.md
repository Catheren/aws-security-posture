# Playbook — Public S3 Exposure

## What this playbook is

A response guide for one of the most common and highest-visibility AWS
misconfigurations: an S3 bucket made publicly accessible, potentially
exposing sensitive data to the internet.

S3 public exposure has been the root cause of some of the largest data
breaches in cloud history. Unlike credential compromise (which requires
an attacker to actively steal something), public S3 exposure means data
is simply available to anyone who knows the URL — no attack required.
Automated scanners continuously probe AWS for public buckets and index
their contents within minutes of exposure.

## Why this playbook exists in this architecture

This architecture detects public S3 exposure through two complementary
controls that watch the same risk from different angles:

**AWS Config rules (preventive + detective):**
- `s3-bucket-public-read-prohibited` — flags any bucket where the ACL or
  bucket policy grants read access to `AllUsers` or `AuthenticatedUsers`
- `s3-bucket-public-write-prohibited` — same for write access
- These are change-triggered: they evaluate immediately when a bucket's
  policy or ACL changes, catching the misconfiguration within minutes

**Security Hub CSPM (compliance):**
- CIS v5.0.0 and AWS Foundational Security Best Practices both include
  S3 public access controls, so Security Hub CSPM surfaces these as
  compliance findings in addition to Config's operational findings

Both sets of findings flow to the security account and trigger SNS alerts.
This playbook describes the response.

## Why S3 public access is more dangerous than it looks

Several factors make public S3 exposure worse than a simple misconfiguration:

**Discovery is near-instant.** Automated scanners maintain lists of known
S3 bucket naming patterns and continuously probe them. A bucket exposed for
10 minutes may already have been discovered and its contents indexed.

**No authentication required.** Unlike a compromised IAM credential (where
the attacker needs to know what to access), a public bucket is browseable.
Attackers can list all objects and selectively download anything interesting.

**Data classification is often wrong.** Buckets containing "non-sensitive"
data frequently contain more than their owners realize — logs with internal
IP addresses, backups with customer data, configuration files with secrets,
or code with hardcoded credentials.

**Legal and compliance implications.** Depending on what data was exposed
and for how long, there may be regulatory notification requirements
(GDPR, HIPAA, state breach notification laws). The clock starts when you
knew or should have known about the exposure.

---

## Trigger

AWS Config rule `s3-bucket-public-read-prohibited` or
`s3-bucket-public-write-prohibited` reporting NON_COMPLIANT.

Or Security Hub CSPM surfacing an S3 public access finding.

Or a report from an external researcher, partner, or automated tool
(GuardDuty doesn't directly detect public S3 configuration but does
flag suspicious access patterns to public buckets).

---

## Immediate containment (first 15 minutes)

**Goal:** make the bucket private. This is the one case where containment
takes priority over investigation — every minute the bucket is public
increases exposure risk.

1. **Identify the bucket** — the Config finding includes the bucket name
   and the account it's in. Note the exact time Config flagged it as
   NON_COMPLIANT (this is the earliest confirmed exposure time — the
   actual exposure may have started earlier if Config had a delay).

2. **Enable S3 Block Public Access** — S3 console → the bucket →
   Permissions tab → Block public access (bucket settings) → Edit →
   enable all four settings:
   - Block public access to buckets and objects granted through new
     access control lists (ACLs)
   - Block public access to buckets and objects granted through any
     access control lists (ACLs)
   - Block public access to buckets and objects granted through new
     public bucket or access point policies
   - Block public access to buckets and objects granted through any
     public bucket or access point policies

   These four settings override any bucket policy or ACL granting public
   access and take effect immediately. This is the fastest path to
   containment — faster than editing the bucket policy directly.

3. **Do not delete the bucket or its contents** — the contents are evidence.
   You need them to determine what was exposed. Deletion before investigation
   also destroys your ability to assess breach notification requirements.

4. **Verify the fix** — after enabling Block Public Access, attempt to
   access an object in the bucket from an incognito browser window (not
   signed into AWS). You should receive an Access Denied error. Config
   should show COMPLIANT within a few minutes.

---

## Investigation

Build a timeline of the exposure:

**When was the bucket made public?**
Check CloudTrail for the API call that changed the bucket's access:
- `PutBucketAcl` — changed the bucket's ACL to grant public access
- `PutBucketPolicy` — added or modified a bucket policy granting public access
- `DeletePublicAccessBlock` — removed the Block Public Access settings

The CloudTrail event includes who made the call (userIdentity), from where
(sourceIPAddress), and when (eventTime). This establishes when the exposure
started and who is responsible.

**Was this intentional?**
Some buckets are legitimately public — static website hosting, public
software downloads, open data sets. Confirm with the bucket owner whether
this was intentional before treating it as an incident. If intentional,
document it as an accepted exception with business justification rather
than remediating it.

**What data is in the bucket?**
Review the bucket's contents and classify them. Look specifically for:
- Files containing customer data (names, emails, payment info, health data)
- Credentials or API keys (even in filenames — attackers look for
  `credentials.json`, `config.yml`, `.env`)
- Internal configuration or architecture information
- Database backups or exports
- Application logs (which often contain more data than intended)

**Was the data accessed while public?**
Enable S3 server access logging (if not already on) and check the logs
for the exposure window. Look for `REST.GET.OBJECT` requests from IP
addresses that don't belong to your organization. CloudTrail data events
(if enabled for this bucket) provide even more detail.

Note: the absence of access logs doesn't mean no access occurred. If
S3 server access logging wasn't enabled before the exposure, you may
not be able to confirm whether the data was accessed. This uncertainty
itself needs to be documented and factors into breach notification decisions.

**How long was it public?**
Calculate: time of remediation minus time of exposure (from CloudTrail).
This is the exposure window and is required for breach notification
assessment.

---

## Remediation

- Confirm Block Public Access is enabled and Config shows COMPLIANT
- If the exposure was caused by a bucket policy or ACL rather than a
  missing Block Public Access setting, review and clean up those too —
  Block Public Access overrides them, but leaving misconfigured policies
  in place is a latent risk if Block Public Access is ever disabled
- Assess breach notification requirements based on:
  - What data was in the bucket
  - Whether you can confirm it was or wasn't accessed
  - The exposure duration
  - Applicable regulations (GDPR: 72 hours; HIPAA: 60 days; state laws vary)
- Review who has `s3:DeletePublicAccessBlock` and `s3:PutBucketPolicy`
  permissions — these are the actions that enabled the exposure
- Enable S3 server access logging on all buckets if not already on —
  you can't investigate what you can't see

---

## Lessons learned

Document:
- What data was exposed and its classification
- The exposure window (when → when)
- Whether access during the exposure window can be confirmed or ruled out
- Root cause (who made the change, what process led to it)
- Whether breach notification is required and to whom
- What preventive control (S3 Block Public Access at the account or
  organization level, SCP preventing DeletePublicAccessBlock) would have
  prevented this

---

## Notes

**Q: What's the difference between S3 Block Public Access settings and a
bucket policy?**
A bucket policy is explicit access control you write. S3 Block Public
Access is an override layer that sits above bucket policies and ACLs —
when enabled, it prevents any bucket policy or ACL from granting public
access, regardless of what the policy says. This is why enabling Block
Public Access is the fastest containment action: it overrides everything
without requiring you to find and edit the specific policy that was
misconfigured.

**Q: Why does this architecture use two separate controls for the same risk?**
Config rules are operational — they fire immediately when a bucket changes
and report compliance status per resource. Security Hub CSPM standards are
compliance-oriented — they aggregate across accounts and show a compliance
score against a framework. Both are useful for different audiences: Config
for the security team's day-to-day monitoring, Security Hub CSPM for
compliance reporting and posture tracking over time.

**Q: What's the difference between a public bucket that was accessed and
one that wasn't?**
Legally and reputationally, it matters whether data was actually exfiltrated
versus merely exposed. In practice, you often can't prove negative — the
absence of access logs (especially if logging wasn't enabled) means you
can't confirm no access occurred, and regulators generally treat "we don't
know" conservatively. This is why enabling S3 server access logging on all
buckets from the start matters — it's the difference between "no access
occurred" and "we have no way to know."
