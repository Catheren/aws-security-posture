"""
AWS Config Custom Rule — No Wildcard IAM Policies
==================================================

WHAT THIS IS
------------
This is an AWS Lambda function that serves as the evaluation logic for a
custom AWS Config rule. AWS Config invokes this function whenever a
customer-managed IAM policy is created or modified in the account.

The function checks whether the policy contains a statement that grants
both Action "*" and Resource "*" simultaneously — meaning unrestricted
access to every AWS action on every resource in the account. If found,
the policy is marked NON_COMPLIANT in Config.

WHY IT EXISTS
-------------
IAM policies with Action "*" and Resource "*" are one of the most common
misconfigurations in AWS environments. They hand out root-equivalent
permissions to whatever principal the policy is attached to, defeating
the entire purpose of IAM. Common causes:
  - Developers copying example policies from documentation and not
    scoping them down
  - Break-glass policies that were never removed after an incident
  - Automated tooling creating overly broad policies for convenience

AWS Config has a managed rule — iam-policy-no-statements-with-admin-access
— that catches exactly this pattern. This custom version exists as a
deliberate learning artifact: to demonstrate how Config's custom rule
mechanism works — how Lambda evaluation logic is written, how the
invocation event is structured, and how compliance results are reported
back to Config.

In a production environment, the managed rule is the right choice. AWS
maintains it, it requires no Lambda function to deploy or operate, and it
covers the same check without adding code you have to support. The custom
rule is retained here because understanding how to write one matters more
for interview preparation than the rule itself.


HOW AWS CONFIG CUSTOM RULES WORK
---------------------------------
Config doesn't evaluate resources itself when using a custom rule. Instead:

1. A resource change occurs (someone creates or modifies an IAM policy)
2. Config detects the change and records it
3. Config invokes this Lambda function, passing an event containing:
   - invokingEvent: the ConfigurationItem for the changed resource
     (includes the resource's ARN, type, and configuration details)
   - resultToken: a one-time token tying this invocation to this
     specific evaluation request
4. This function performs its own evaluation logic (checking the policy
   document for wildcard statements)
5. This function calls config.put_evaluations() with the result:
   COMPLIANT or NON_COMPLIANT, plus an annotation explaining why
6. Config records that result and displays it on the rule's page

The resultToken in steps 3 and 5 is important — it's how Config matches
your evaluation response to the original request. Without it, Config
doesn't know which rule invocation your response belongs to.

TRIGGER TYPE
------------
This rule uses ConfigurationItemChangeNotification as its trigger — it
only fires when an AWS::IAM::Policy resource actually changes, not on a
schedule. Compare this to the mfa-enabled-for-iam-console-access rule,
which runs periodically because MFA device status isn't captured as a
discrete configuration change event. Using a change-triggered rule for
something that needs periodic evaluation means you'd only catch it when
something else on the resource changes, creating gaps. Choosing the right
trigger type for the thing being checked is a real design decision.

PERMISSIONS REQUIRED
--------------------
The Lambda execution role needs:
  - config:PutEvaluations — to report compliance results back to Config
  - iam:GetPolicy — to fetch policy metadata (specifically the active
    version ID)
  - iam:GetPolicyVersion — to fetch the actual policy document for the
    active version
  - iam:ListPolicyVersions — to enumerate available versions
  - AWSLambdaBasicExecutionRole — to write logs to CloudWatch

These are intentionally narrow. The function cannot modify IAM policies,
cannot access other AWS services, and cannot read any resource other than
the specific policy being evaluated. This is least-privilege applied to
detection tooling itself — a detection function with overly broad
permissions is itself a security risk if compromised or buggy.

NOTES
---------------
Q: Why build a custom rule when the managed rule does the same thing?
A: In production you wouldn't — the managed rule is simpler, maintained
   by AWS, and requires no Lambda code to operate. This custom version
   exists as a learning artifact to demonstrate how Config's custom rule
   mechanism works end to end. Understanding the mechanics (invocation
   event structure, resultToken, put_evaluations call) is more valuable
   for a security engineering role than the rule's output itself.

Q: What's the difference between change-triggered and periodic Config rules?
A: Change-triggered rules (like this one) evaluate a resource immediately
   when it changes. Periodic rules run on a schedule regardless of changes.
   Periodic rules exist for checks where the relevant data isn't captured
   as a configuration change event — MFA device status is the classic
   example. The mfa-enabled-for-iam-console-access rule in this project
   is periodic for exactly this reason.

Q: What happens if the Lambda function fails or times out?
A: Config retries the invocation. If it consistently fails, the rule shows
   as ERROR rather than COMPLIANT or NON_COMPLIANT. CloudWatch Logs (the
   log group /aws/lambda/config-no-wildcard-iam-policies) is where you'd
   look to debug failures. This is also why Lambda timeout and error
   handling matter even for simple functions — a silent failure here means
   a policy that should be NON_COMPLIANT shows no status at all.

Q: Why does this only check customer-managed policies, not AWS-managed ones?
A: AWS-managed policies (like AdministratorAccess) are maintained by AWS
   and can't be modified. Config's scope for this rule is set to
   AWS::IAM::Policy, which only includes customer-managed policies.
   AWS-managed policies appear under a different resource type. More
   importantly, even AdministratorAccess granting Action "*" is
   intentional by design — what we're looking for is unexpected wildcard
   grants in policies your team created, not AWS-maintained ones.

Q: What's the difference between the managed rule and this custom one
   beyond deployment method?
A: Functionally, none — both check for Allow statements combining
   Action "*" and Resource "*" in customer-managed policies. The managed
   rule is a black box (you can't see or modify its logic). The custom
   rule is transparent — you can see exactly what it checks, add logging,
   adjust the logic (e.g. flag Action "*" even without Resource "*"), and
   extend it. That flexibility is the only production reason to prefer a
   custom rule over the managed one for this specific check.
"""

import json
import boto3

config = boto3.client("config")
iam = boto3.client("iam")


def lambda_handler(event, context):
    """
    Entry point invoked by AWS Config when an IAM policy changes.

    The event contains two key fields:
      - invokingEvent: JSON string describing the changed resource
      - resultToken: opaque token returned to Config with the evaluation
        result — must be passed back in put_evaluations() so Config can
        match this response to the original invocation request
    """
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]

    policy_arn = configuration_item["ARN"]
    compliance_type = "COMPLIANT"
    annotation = "No statement grants both Action '*' and Resource '*'."

    if _has_wildcard_statement(policy_arn):
        compliance_type = "NON_COMPLIANT"
        annotation = "Policy contains a statement with Action '*' and Resource '*'."

    # Report the evaluation result back to Config.
    # Without this call, Config never learns the outcome and the rule
    # stays in an evaluating state indefinitely.
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": configuration_item["resourceType"],
                "ComplianceResourceId": configuration_item["resourceId"],
                "ComplianceType": compliance_type,
                "Annotation": annotation,
                # OrderingTimestamp tells Config when this resource state was
                # observed — using the capture time from the configuration
                # item ensures the evaluation is anchored to the actual
                # change time, not the Lambda invocation time (which could
                # be slightly later due to invocation delay).
                "OrderingTimestamp": configuration_item["configurationItemCaptureTime"],
            }
        ],
        ResultToken=event["resultToken"],
    )


def _has_wildcard_statement(policy_arn):
    """
    Fetches the active version of the IAM policy and checks whether any
    Allow statement grants both Action '*' and Resource '*'.

    IAM policies can have multiple versions (up to 5). Config tells us the
    policy ARN but not which version to check. We fetch the policy metadata
    first to find the default (active) version, then fetch that version's
    document.

    Returns True if a wildcard statement is found, False otherwise.
    """
    # Step 1: get policy metadata to find the active version ID
    # e.g. DefaultVersionId might be "v1", "v2", etc.
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = policy["DefaultVersionId"]

    # Step 2: fetch the actual policy document for the active version
    policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    document = policy_version["PolicyVersion"]["Document"]

    # Step 3: check each statement
    # The Statement field can be either a list of statements or a single
    # statement dict — normalize to a list to handle both cases.
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        # Only check Allow statements — Deny statements granting "*" are
        # actually good (explicit denies override everything in AWS IAM),
        # so flagging them would produce false positives.
        if statement.get("Effect") != "Allow":
            continue

        # Action and Resource can each be a string or a list of strings.
        # Normalize both to lists for consistent comparison.
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # The dangerous combination: unrestricted action on every resource.
        # Either wildcard alone is not automatically dangerous:
        #   - Action "*" on a specific resource ARN is limited by that ARN
        #   - s3:* on Resource "*" is broad but scoped to S3 actions only
        # Both together removes all constraints — root-equivalent access.
        if "*" in actions and "*" in resources:
            return True

    return False