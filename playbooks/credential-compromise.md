# Playbook — Credential Compromise

## What this playbook is

A structured response guide for the most common and highest-impact AWS
security incident: a set of IAM credentials (access key, console password,
or temporary session token) being used by someone other than their intended
owner.

Credential compromise is the entry point for the majority of AWS cloud
breaches. Attackers obtain credentials through phishing, exposed keys in
public GitHub repos, leaked environment variables, compromised developer
laptops, or purchasing them from credential markets. Once they have valid
credentials, they move fast — enumeration, privilege escalation, and data
access typically happen within minutes of first use.

## Why this playbook exists in this architecture

This architecture detects credential compromise primarily through GuardDuty,
which watches CloudTrail API calls and flags anomalous patterns:

- `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` — login from an
  unusual geographic location
- `CredentialAccess:IAMUser/AnomalousBehavior` — API call patterns
  inconsistent with the principal's baseline behavior
- `Discovery:IAMUser/AnomalousBehavior` — enumeration behavior (listing
  resources, reading configs) inconsistent with normal usage

These findings flow through the central EventBridge bus to SNS, triggering
an alert. This playbook describes what happens after that alert fires.

## What "compromised credential" actually means.

A credential is considered compromised when there is reasonable evidence it
is being used by an unauthorized party. This includes:

- API calls from geographic locations inconsistent with the user's location
- API calls at times inconsistent with the user's normal working hours
- API call patterns (enumeration, privilege escalation attempts) inconsistent
  with the user's role
- The user themselves reporting their credentials as stolen or exposed

A credential is NOT automatically compromised just because:
- GuardDuty fired a finding (findings require investigation, not automatic
  revocation — false positives are common, especially for users who travel
  or use VPNs)
- The credential was used from an AWS region the user doesn't normally use
  (developers testing in new regions is legitimate)

The first step is always investigation, not immediate revocation.

---

## Trigger

GuardDuty findings:
- `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`
- `CredentialAccess:IAMUser/AnomalousBehavior`
- `UnauthorizedAccess:IAMUser/MaliciousIPCaller`

Or direct report from a user that their credentials were exposed (e.g.
accidentally committed to a public GitHub repo).

---

## Immediate containment (first 15 minutes)

**Goal:** stop the bleeding without destroying evidence.

1. **Identify the principal** — which IAM user, role, or access key is
   involved. Check the GuardDuty finding's `userIdentity` field. Note
   whether it's a long-term access key (user) or a temporary credential
   (assumed role session).

2. **Preserve evidence first** — before taking any action, export the
   CloudTrail event history for this principal for the 24 hours preceding
   the alert. Taking containment action first can make the timeline harder
   to reconstruct and may destroy evidence needed for a post-incident review.

3. **Disable the access key** — IAM console → Users → the user → Security
   credentials tab → disable the active access key. Disable, not delete —
   deleting removes it from the audit trail. The key can be deleted after
   the investigation is complete.

4. **Revoke active sessions** — disabling the key stops future use but
   doesn't invalidate existing sessions that were authenticated with that
   key. Attach an explicit deny policy to the IAM user to invalidate all
   sessions issued before the compromise time:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Deny",
       "Action": "*",
       "Resource": "*",
       "Condition": {
         "DateLessThan": {
           "aws:TokenIssueTime": "<ISO8601_timestamp_of_compromise>"
         }
       }
     }]
   }
   ```
  
   This works because AWS evaluates this condition against the time the
   session token was issued. Any session started before the compromise
   timestamp will be denied on all subsequent API calls, even if the
   session would normally still be valid.

      ### Understanding the session revocation policy

  When an attacker authenticates using a compromised access key, AWS issues
  them a temporary session token. That session token is independent of the
  access key that created it — disabling the access key stops new
  authentication attempts but does nothing to the session tokens already
  issued. Those remain valid and fully functional until they naturally
  expire, which can be up to 12 hours later.

  This is the gap the explicit deny policy closes.

  **How the policy works**

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2024-01-15T10:00:00Z"
        }
      }
    }]
  }
  ```

  AWS evaluates this condition on every API request the session makes. If
  the session token was issued before the timestamp in the policy, the
  request is denied — regardless of what permissions the user's policies
  normally grant. AWS's IAM evaluation logic applies explicit Deny
  statements before any Allow, so this overrides everything instantly.

  Attach this as an inline policy directly on the compromised IAM user.
  It takes effect immediately with no delay.

  **Choosing the right timestamp**

  The timestamp is in ISO8601 UTC format: `YYYY-MM-DDTHH:MM:SSZ`

  Two scenarios:

  *You know when the compromise happened:*
  Set the timestamp to the time of the first suspicious CloudTrail event.
  Find this in CloudTrail → Event history → filter by the compromised user
  → look at the earliest suspicious event's timestamp. For example, if the
  first anomalous API call was at 9am: `2024-01-15T09:00:00Z`. This revokes
  the attacker's sessions while being surgical about what it affects.

  *You don't know when it happened (most common):*
  Set the timestamp to right now — the current UTC time. This revokes every
  active session for this user, including any legitimate sessions the real
  user has open. That is acceptable during active containment. The legitimate
  user gets fresh credentials once the incident is resolved.

  To get the current UTC time in the exact format AWS expects, run this in
  CloudShell:

  ```bash
  date -u +"%Y-%m-%dT%H:%M:%SZ"
  ```

  Copy the output directly into the policy.

  **Cleanup after containment**

  This policy stays attached to the user permanently until you remove it.
  Once the incident is resolved and fresh credentials have been issued,
  detach the inline policy — otherwise it will continue denying sessions
  indefinitely. Leaving it attached after recovery is a common oversight
  that causes "my credentials stopped working again" reports from the
  legitimate user days later.


5. **Notify the user** — confirm with the legitimate owner whether the
   activity was theirs. Sometimes GuardDuty fires on legitimate use (VPN,
   travel, testing in a new region). Containment before confirmation wastes
   time if it's a false positive, but notifying the user also helps confirm
   the compromise if they weren't aware.

---

## Investigation

Work through CloudTrail event history for the compromised principal,
building a timeline of every action taken:

- What was the first API call after the suspected compromise time? Attackers
  almost always start with `sts:GetCallerIdentity` — confirming the
  credential works and identifying the account.

- Did they enumerate resources? Look for bursts of List/Describe calls
  across services (ListBuckets, DescribeInstances, ListRoles, GetAccountSummary).
  Enumeration typically happens in the first few minutes.

- Did they attempt to escalate privileges? Look for IAM write calls:
  `AttachUserPolicy`, `PutUserPolicy`, `CreateAccessKey`, `AddUserToGroup`,
  `PassRole`. These indicate the attacker found the initial access insufficient
  and tried to expand it.

- Did they assume any roles? `AssumeRole` calls indicate lateral movement
  attempts — the attacker is trying to access other principals' permissions.
  Check what roles were assumed and what those roles can do.

- Did they access data? S3 `GetObject` calls, RDS connection attempts,
  Secrets Manager `GetSecretValue`. This is what determines whether a
  credential compromise becomes a data breach.

- Did they create persistence? New IAM users, new access keys on existing
  users, new roles with permissive trust policies. Attackers who intend to
  return create backdoors before they leave.

- How did the credential leave the environment? Git history, environment
  variables, CI/CD pipeline logs, developer laptop compromise. Understanding
  the vector prevents recurrence.

---

## Remediation

- Issue a new credential to the legitimate user once the investigation
  is complete and the vector is understood
- Review and tighten the compromised principal's IAM permissions —
  credential compromise often reveals over-provisioned access
- If the credential was exposed in code, rotate all secrets in the same
  codebase (treat every secret in a compromised repo as compromised)
- Remove any persistence mechanisms the attacker created (new users,
  new keys, new roles)
- Enable MFA if not already enforced on this principal

---

## Lessons learned

Document within 48 hours while details are fresh:

- What was the full attacker timeline? (first access → enumeration →
  escalation → data access → persistence)
- What was the detection timeline? (when did GuardDuty fire vs. when
  did the compromise actually start)
- What was the containment timeline? (alert → investigation → revocation)
- What did the attacker successfully access or modify?
- What was the root cause? (how did the credential get out)
- What control would have prevented this or caught it earlier?

---

## Notes

**Q: Why disable the key instead of deleting it?**
Deletion removes the key from IAM's API — you can no longer look it up,
confirm which services were using it, or reference it in audit logs. The
disabled key still appears in the audit trail and can be re-enabled if the
investigation reveals it was a false alarm. Delete only after the
investigation closes.

**Q: What's the difference between disabling a key and revoking sessions?**
Disabling the key prevents new authentications using that key. But AWS
issues temporary session tokens (STS) that are valid for up to 12 hours
after authentication. A session authenticated at 9am with a key you disable
at 10am is still valid until it expires — the attacker can keep using it.
The explicit deny policy with DateLessThan on aws:TokenIssueTime invalidates
those existing sessions immediately, without waiting for them to expire.

**Q: How long does GuardDuty take to fire after a compromise?**
GuardDuty operates in near real-time for most finding types — typically
within minutes of the anomalous activity. However, anomaly-based findings
(AnomalousBehavior) require GuardDuty to have established a behavioral
baseline for that principal first, which takes about two weeks of observed
normal activity. A brand new IAM user has no baseline, so GuardDuty may
not flag their activity as anomalous even if it looks suspicious.
