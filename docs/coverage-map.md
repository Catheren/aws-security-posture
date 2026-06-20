# Native vs Custom Detection Coverage Map

This document records the analysis behind the decision to rely on native
AWS detection tooling rather than building custom detection rules. The
question asked for each potential detection: does GuardDuty already cover
this, and if so, what would a custom rule actually add?

This analysis was completed by generating GuardDuty sample findings and
reviewing the actual finding types, data fields, and coverage scope for
each pattern.

---

## Coverage analysis

### Impossible travel

**GuardDuty finding:** `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`

**Does it cover this?** Yes — GuardDuty flags console logins from
anomalous locations using its own ML model trained on per-principal
baseline behavior.

**What a custom rule would add:** tunable distance/time thresholds,
explicit VPN exit node suppression, and visibility into why it fired
(the GuardDuty finding doesn't expose the underlying calculation). For
most environments, GuardDuty's native coverage is sufficient. A custom
rule makes sense when you need deterministic thresholds or fine-grained
suppression for known-good locations.

**Decision:** rely on GuardDuty native coverage. Document suppression
logic for known VPN exit nodes in the triage notes if false positives
emerge.

---

### Suspicious AssumeRole chains

**GuardDuty finding:** none — no dedicated finding type for multi-hop
role chains exists in GuardDuty.

**Does it cover this?** No — GuardDuty evaluates individual API calls
and per-principal behavioral baselines. It has no concept of a
multi-hop role chain across a session (role A → role B → role C).

**What a custom rule would add:** genuine new detection. Multi-hop
AssumeRole chains are a real lateral movement pattern invisible to
per-event analysis but visible when correlating a sequence of events
over a time window.

**Decision:** genuine gap in GuardDuty coverage. In a mature environment
this would be implemented as a SIEM detection rule correlating AssumeRole
events per principal over a rolling 1-hour window. The SIEM export bucket
in this architecture is provisioned specifically to enable this.

---

### Privilege escalation

**GuardDuty finding:** `PrivilegeEscalation:IAMUser/AnomalousBehavior`

**Does it cover this?** Partially — GuardDuty flags privilege escalation
when the behavior is anomalous relative to the principal's ML baseline.
It won't fire on day one for a new IAM user with no history.

**What a custom rule would add:** deterministic coverage — a rule that
fires on any `iam:AttachUserPolicy` or `iam:PutUserPolicy` call where
the actor and target are the same principal, regardless of whether
GuardDuty's ML model considers it anomalous. This eliminates the
baseline-dependency blind spot.

**Decision:** GuardDuty covers the majority of cases. The Config rule
`no-wildcard-iam-policies` provides a complementary preventive control
by catching over-permissive policies before they can be exploited. A
deterministic privilege escalation detection rule is a good candidate
for the SIEM.

---

### Unusual API call volume spikes

**GuardDuty finding:** `Discovery:IAMUser/AnomalousBehavior`,
`Recon:IAMUser/MaliciousIPCaller`, and related recon finding types.

**Does it cover this?** Partially — GuardDuty covers specific
enumeration API patterns (ListBuckets, DescribeInstances, ListRoles)
against known-bad IP reputation and behavioral baselines. It does not
cover general volume anomalies across all API types for any principal.

**What a custom rule would add:** broader coverage — a rule counting
total API call volume per principal per time window catches novel
reconnaissance patterns that don't match GuardDuty's specific recon
signatures, and catches automated credential abuse regardless of which
APIs are being called.

**Decision:** genuine partial gap. Good candidate for a SIEM detection
rule. The full CloudTrail event stream flowing to the SIEM export bucket
provides the data needed for this.

---

### Root account usage

**GuardDuty finding:** `Policy:IAMUser/RootCredentialUsage`

**Does it cover this?** Yes — GuardDuty alerts on any root account API
call or console login without exception.

**What a custom rule would add:** primarily routing and severity tagging
control. The detection itself is not a gap — any root usage fires. A
custom rule would allow custom severity assignment (e.g. always CRITICAL
regardless of GuardDuty's severity scoring) and routing to a specific
on-call channel.

**Decision:** GuardDuty native coverage is sufficient for detection.
Severity routing can be handled in the SIEM or via Security Hub CSPM
automation rules without building a custom detector.

---

## Summary

| Detection | GuardDuty covers it? | Gap type | Recommended approach |
|---|---|---|---|
| Impossible travel | Yes (ML-based) | Tuning control only | Rely on GuardDuty, suppress known VPN exits |
| AssumeRole chains | No | Genuine gap | SIEM detection rule on full event stream |
| Privilege escalation | Partially (ML-based) | Determinism gap | SIEM rule + Config preventive control |
| API volume spikes | Partially (specific patterns) | Partial gap | SIEM detection rule on full event stream |
| Root usage | Yes | Routing/severity only | Rely on GuardDuty, route via SIEM |

The SIEM export bucket provisioned in this architecture is the foundation
for closing the two genuine gaps (AssumeRole chains, general API spikes)
without building and maintaining bespoke Lambda detection code.
