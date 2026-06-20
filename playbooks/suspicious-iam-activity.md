# Playbook — Suspicious IAM Activity

## What this playbook is

A response guide for IAM changes that indicate an attacker (or a
misconfigured automation) is attempting to escalate privileges, create
persistence, or otherwise manipulate the identity and access control layer
of your AWS environment.

IAM is the most important attack surface in AWS. Unlike infrastructure
attacks (exploiting an EC2 vulnerability, accessing a misconfigured S3
bucket), IAM attacks target the permission system itself — meaning a
successful IAM attack can grant access to everything else. Attackers who
gain initial access to AWS almost always move immediately to IAM to either
escalate their permissions or create a backdoor before they're detected.

## Why this playbook exists in this architecture

This architecture detects suspicious IAM activity through two layers:

**GuardDuty (behavioral detection):**
- `PrivilegeEscalation:IAMUser/AnomalousBehavior` — IAM write actions
  that are anomalous relative to this principal's baseline behavior
- `Persistence:IAMUser/AnomalousBehavior` — IAM changes that suggest
  the attacker is trying to maintain access (creating new users, new keys,
  new roles with permissive trust policies)

**AWS Config (configuration compliance):**
- The `no-wildcard-iam-policies` custom rule catches the result of
  successful privilege escalation — a policy with `Action:"*"` and
  `Resource:"*"` that someone attached or created
- The `mfa-enabled-for-iam-console-access` rule catches a common
  persistence tactic: creating new IAM users without MFA enforcement

These findings flow to the security account via the central EventBridge bus
and trigger SNS alerts. This playbook describes the response.

## Why IAM attacks are different from other incident types

**The attacker is targeting your control plane, not your data.**
IAM attacks are fundamentally different from data exfiltration or malware.
The attacker isn't trying to read your S3 buckets directly — they're trying
to grant themselves permission to read everything. Containing the attack
means reverting the IAM changes, not just isolating a compromised resource.

**The blast radius is determined by what the modified policy grants.**
A credential compromise where the attacker reads a single S3 object is
bad. A credential compromise where the attacker attaches `AdministratorAccess`
to a role they control is potentially catastrophic — they now have
unrestricted access to the entire account for as long as that policy stays
attached.

**Privilege escalation paths are numerous and subtle.**
AWS has documented dozens of privilege escalation paths — ways to use
a limited set of IAM permissions to ultimately grant yourself broader
access. Common examples:
- `iam:PutUserPolicy` on your own user — attach an inline policy granting
  yourself whatever you want
- `iam:AttachUserPolicy` + a wildcard managed policy
- `iam:CreatePolicyVersion` — create a new version of an existing policy
  with escalated permissions and set it as default
- `iam:PassRole` + `ec2:RunInstances` — launch an EC2 instance with a
  high-privilege role, then use that instance to perform privileged actions
- `sts:AssumeRole` on a role with a permissive trust policy

Understanding these paths matters when investigating — you need to think
like the attacker to identify what they were trying to achieve.

**Persistence is often the real goal.**
Many IAM attacks aren't about immediate access — they're about ensuring
continued access after the initial breach is discovered and the compromised
credential is revoked. Common persistence mechanisms:
- Creating a new IAM user with their own access key
- Adding an access key to an existing low-profile IAM user
- Creating a role with a trust policy that trusts an external account
  (the attacker's own AWS account)
- Modifying a Lambda function's execution role to give it broader permissions

---

## Trigger

GuardDuty findings:
- `PrivilegeEscalation:IAMUser/AnomalousBehavior`
- `Persistence:IAMUser/AnomalousBehavior`

AWS Config findings:
- `no-wildcard-iam-policies` showing NON_COMPLIANT on a recently modified
  policy

Or direct observation in CloudTrail of IAM write calls from an unexpected
principal, particularly:
- `iam:AttachUserPolicy` / `iam:DetachUserPolicy`
- `iam:PutUserPolicy` / `iam:DeleteUserPolicy`
- `iam:AttachRolePolicy` / `iam:PutRolePolicy`
- `iam:CreatePolicyVersion` with `SetAsDefault: true`
- `iam:CreateUser` / `iam:CreateAccessKey`
- `iam:UpdateAssumeRolePolicy` (modifying a role's trust policy)

---

## Immediate containment (first 15 minutes)

**Goal:** understand what changed before reverting it. Reverting without
understanding what changed risks missing additional changes made in the
same window, or reverting something legitimate.

1. **Identify what changed and who changed it.**
   Check CloudTrail for the specific IAM write calls that triggered the
   alert. The event includes:
   - `userIdentity.arn` — who made the change
   - `requestParameters` — exactly what was changed (which policy, which
     user, which role)
   - `eventTime` — when it happened
   - `sourceIPAddress` — where the call came from

2. **Assess the change's scope.**
   What permissions did the change grant or modify? A change attaching
   a read-only S3 policy is very different from one attaching
   AdministratorAccess. Look at the specific policy content, not just
   the fact that a policy was attached.

3. **Check whether the legitimate owner made the change.**
   Not all IAM changes are attacks. A developer may have legitimately
   added a policy to their own user. Confirm with the identity in
   question before treating this as an incident — but don't delay
   containment waiting for a response if the change looks clearly malicious.

4. **Revert the change.**
   - If a policy was attached: `iam:DetachUserPolicy` or
     `iam:DetachRolePolicy`
   - If an inline policy was added: `iam:DeleteUserPolicy` or
     `iam:DeleteRolePolicy`
   - If a policy version was changed: set the previous version as default
     via `iam:SetDefaultPolicyVersion`, then delete the new version
   - If a new user was created: disable their access key immediately,
     then investigate before deleting (the account may hold evidence)
   - If a trust policy was modified: restore the previous version

   Do not delete evidence. Disable, detach, or revert — don't destroy.

5. **If privilege escalation is confirmed:**
   Treat the actor's credentials as compromised and follow the credential
   compromise playbook in parallel. The IAM change was likely made using
   a compromised credential — disabling that credential is equally urgent.

6. **Check for additional changes in the same window.**
   Attackers rarely make a single IAM change. Search CloudTrail for all
   IAM write events in the same 30-minute window around the alert time,
   particularly from the same source IP or the same principal. Reverting
   only the change that triggered the alert while missing three others is
   worse than a slow response.

---

## Investigation

Build a complete picture of what the attacker attempted and achieved:

- What was the first API call from this principal in the attack window?
  (Usually `sts:GetCallerIdentity` to confirm the credential works)
- What reconnaissance preceded the IAM changes?
  (ListRoles, GetAccountSummary, ListPolicies, ListAttachedUserPolicies)
- What was the full sequence of IAM changes made?
- Did the attacker use the new permissions before they were revoked?
  (Check for API calls made after the IAM change and before containment)
- Did the attacker create any persistence mechanisms beyond the initial
  IAM change?
- Which privilege escalation path did they use (or attempt to use)?
  Understanding this informs what preventive controls would have blocked it.

---

## Remediation

- Revert all unauthorized IAM changes (see containment step 4)
- Audit all IAM changes in a broader window around the incident —
  some may not have triggered alerts
- Review who holds the high-risk IAM permissions that enabled this:
  `iam:PutUserPolicy`, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`,
  `iam:PassRole`, `iam:UpdateAssumeRolePolicy`. These should be held by
  the minimum number of principals, ideally requiring MFA for use
- Consider adding an SCP (Service Control Policy) at the Organizations
  level to prevent detaching mandatory guardrail policies — SCPs can't
  be bypassed by even account-level administrators
- Enable IAM Access Analyzer to continuously flag any policies that
  grant unintended cross-account or external access

---

## Lessons learned

Document:
- The complete attack sequence (what they did, in order, with timestamps)
- The detection timeline (when GuardDuty/Config fired vs. when the
  attack actually started)
- The containment timeline (alert → investigation → revocation)
- Whether the attacker successfully used the elevated permissions before
  containment
- Which privilege escalation path was used
- What preventive control (SCP, permission boundary, least-privilege IAM
  policy) would have blocked the escalation path entirely

---

## Notes

**Q: What's the difference between privilege escalation and lateral movement
in AWS?**
Privilege escalation is gaining more permissions within the same identity
context (making your current credentials more powerful). Lateral movement
is moving to a different identity context (assuming a different role,
using a different set of credentials). They're related but distinct:
an attacker might escalate privileges to gain `sts:AssumeRole` on a
high-privilege role, then use lateral movement to operate as that role.
AssumeRole chains are a common combination of both.

**Q: Why can't you just use an SCP to prevent all IAM changes?**
SCPs are a powerful guardrail but you still need someone to be able to
manage IAM legitimately — create users for new team members, update
policies as services evolve, manage roles for automation. The goal of
SCPs for IAM isn't to prevent all changes, it's to prevent specific
dangerous patterns: detaching guardrail policies, creating new admin
users, modifying trust policies to trust external accounts. Well-scoped
SCPs with specific deny conditions are more effective than blanket
restrictions that your own team will need workarounds for.

**Q: How does GuardDuty's `PrivilegeEscalation:IAMUser/AnomalousBehavior`
compare to a deterministic detection rule?**
GuardDuty's detection is ML-based and anomaly-driven — it fires when IAM
write actions are unusual relative to a principal's established baseline.
This means it won't fire on day one for a new IAM user (no baseline yet),
and it may not fire if an attacker operates slowly and gradually over
weeks (staying within the baseline). A deterministic rule — "any
`iam:AttachUserPolicy` call where the actor and target are the same
principal" — fires regardless of history or timing. Both approaches have
value; they catch different things, and the coverage map in this repo
documents how they complement each other.
