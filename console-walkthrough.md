# Console Setup Walkthrough

Step-by-step guide for setting up the multi-account AWS security
architecture described in this repo. All steps use the AWS console
(CloudShell where CLI is required). No local tooling needed beyond
AWS account access.

Console menu paths shift between AWS console releases — if a label
doesn't match exactly, use the search bar at the top of any page.

---

## Account roles

- **Management account** — AWS Organizations root. Visit only to grant
  delegation. No long-term configuration lives here.
- **Security account** — delegated administrator for all services. Where
  you spend most of your time post-setup.
- **Prod and Dev accounts** — where workloads live. Each runs local
  GuardDuty, Config, and Inspector instances that report to the security
  account.

**Order matters:** set up Config first, since Security Hub CSPM compliance
checks depend on Config already recording.

**Region consistency:** all services must be in the same region across all
accounts. This setup uses us-east-2 throughout. The console region selector
(top right) must match in every account before creating any resource.

---

## 1. AWS Config

### 1a. Management account — register Security as delegated administrator

Config's delegated administrator registration is CLI-only. Unlike
GuardDuty, Security Hub, and Inspector — which all have a Delegated
administrator field in the console — Config requires running these
commands from the management account's CloudShell (top nav bar, `>_` icon):

```bash
# Enable trusted access for Config with Organizations
aws organizations enable-aws-service-access \
  --service-principal=config-multiaccountsetup.amazonaws.com
aws organizations enable-aws-service-access \
  --service-principal=config.amazonaws.com

# Register the security account as Config's delegated administrator
aws organizations register-delegated-administrator \
  --service-principal=config-multiaccountsetup.amazonaws.com \
  --account-id <SECURITY_ACCOUNT_ID>

aws organizations register-delegated-administrator \
  --service-principal=config.amazonaws.com \
  --account-id <SECURITY_ACCOUNT_ID>

# Verify — should show security account with "Status": "ACTIVE"
aws organizations list-delegated-administrators \
  --service-principal=config.amazonaws.com
```

No output from the first four commands means success. Do not proceed to
the aggregator step until the verify command shows ACTIVE.

### 1b. Security, Prod, and Dev accounts — enable the recorder in each

Repeat in each of the three accounts:

1. Config console → Get started
2. Resource types to record: **Record all resources supported in this
   region** → check **Include global resources (e.g., AWS IAM resources)**

   > This checkbox is critical. Without it, Config records EC2, S3, etc.
   > but never records IAM resources. The wildcard IAM policy rule and
   > several CIS controls depend on IAM being recorded. If IAM queries
   > return no results later, this is the cause.

3. Amazon S3 bucket: Create a bucket (Config names it automatically)
4. AWS Config service role: **Use a service-linked role**
5. Rules: add `s3-bucket-public-read-prohibited`,
   `s3-bucket-public-write-prohibited`, `mfa-enabled-for-iam-console-access`
6. Confirm

### 1c. Security account — create the organization aggregator

First, create an IAM role for the aggregator — the console's auto-create
option is unreliable and produces the error
`Value null at 'organizationAggregationSource.roleArn' failed to satisfy constraint`.
Create it explicitly via CloudShell in the security account:

```bash
aws iam create-role --role-name OrgConfigAggregatorRole \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"Service":"config.amazonaws.com"},
      "Action":"sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name OrgConfigAggregatorRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations
```

Then in the Config console:

1. Aggregators → Create aggregator
2. Name: `org-aggregator`
3. Source accounts: **Add my organization**
4. IAM role: choose **OrgConfigAggregatorRole** from the dropdown
   (do not use the auto-create option)
5. Select your region → Create aggregator

### 1d. Verify the aggregator is working

In the Config console (security account) → Advanced queries → select
`org-aggregator` as the data source → run:

```sql
SELECT accountId, COUNT(*)
WHERE resourceType = 'AWS::S3::Bucket'
GROUP BY accountId
```

All three account IDs should appear. If IAM resources are missing, go
back to step 1b and confirm "Include global resources" is checked in
each account's recorder settings.

### 1e. Custom rule — no wildcard IAM policies

1. Lambda console → Create function → Author from scratch
   - Name: `config-no-wildcard-iam-policies`
   - Runtime: Python 3.12
   - Create function

2. In the Code tab, paste the contents of `lambda/no_wildcard_iam.py`
   → Deploy

3. Configuration → Permissions → click the execution role → attach:
   - Managed policy: `AWSLambdaBasicExecutionRole`
   - Inline policy:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Allow",
         "Action": [
           "config:PutEvaluations",
           "iam:GetPolicy",
           "iam:GetPolicyVersion",
           "iam:ListPolicyVersions"
         ],
         "Resource": "*"
       }]
     }
     ```

4. Config console → Rules → Add rule → Create custom rule
   - Trigger type: AWS Lambda function → select the function
   - Trigger: Configuration changes
   - Scope: resource type `AWS::IAM::Policy`
   - Save (console auto-grants Config permission to invoke the Lambda)

5. Test: create a throwaway IAM policy with `"Action":"*","Resource":"*"`.
   Wait a few minutes (or use the Re-evaluate button on the rule).
   Confirm it shows NON_COMPLIANT. Delete the test policy.

---

## 2. GuardDuty

### 2a. Management account

GuardDuty console → Settings → Delegated administrator → enter Security
account's 12-digit ID → Delegate.

### 2b. Security account

1. GuardDuty should already be enabled (delegation auto-enables it)
2. Left nav → Accounts → a banner appears to enable organization
   auto-enrollment → click Enable → set to **All**
3. Accounts page should show prod and dev as member accounts within a
   few minutes
4. Settings → Generate sample findings → review finding types in the
   Findings page, particularly:
   - `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`
   - `PrivilegeEscalation:IAMUser/AnomalousBehavior`
   - `Policy:IAMUser/RootCredentialUsage`

---

## 3. Security Hub CSPM

> Note: AWS now has two products in the Security Hub console area —
> "Security Hub" (new, OCSF format) and "Security Hub CSPM" (original,
> ASFF format). Use **Security Hub CSPM** for this setup.

### 3a. Management account

Security Hub CSPM console → Delegated administrator → Configure → enter
Security account's ID → Delegate.

### 3b. Security account

1. Enable Security Hub CSPM
2. Security standards → enable **CIS AWS Foundations Benchmark v5.0.0**
3. Use central configuration to push the standard to prod and dev in
   one action rather than enabling it separately in each account
4. Findings → filter by Product name = GuardDuty to confirm GuardDuty
   findings are flowing in
5. Allow up to a few hours for CIS controls to populate findings on
   initial enablement

---

## 4. Inspector

### 4a. Management account

Inspector console → General settings → Delegated administrator → enter
Security account's 12-digit ID → Delegate → confirm.

### 4b. Security account

Account management → Accounts tab → select prod and dev → Activate →
enable EC2 and ECR scanning.

---

## 5. EventBridge cross-account pipeline

### 5a. Security account — create the central event bus

1. EventBridge console → Event buses → Create event bus
   - Name: `central-security-bus`
   - Create

2. Click `central-security-bus` → Permissions tab → add resource policy:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Sid": "AllowProdAndDev",
       "Effect": "Allow",
       "Principal": {
         "AWS": [
           "arn:aws:iam::<PROD_ACCOUNT_ID>:root",
           "arn:aws:iam::<DEV_ACCOUNT_ID>:root"
         ]
       },
       "Action": "events:PutEvents",
       "Resource": "arn:aws:events:us-east-2:<SECURITY_ACCOUNT_ID>:event-bus/central-security-bus"
     }]
   }
   ```

   > Use the prod and dev account IDs here, not the management account ID.
   > A common mistake is pasting the management account ID — events from
   > prod will be silently rejected if so.

3. Enable logging on the central bus for visibility into what's arriving:
   Event buses → `central-security-bus` → Logging → enable → Trace level
   → log group `/aws/events/central-security-bus`

### 5b. Prod and Dev accounts — create forwarding rules

Repeat in both accounts:

1. EventBridge console → Rules → Create rule
   - Name: `forward-to-security`
   - Event bus: **default**
   - Rule type: Rule with an event pattern
   - Event pattern:
     ```json
     {
       "source": [{"prefix": ""}]
     }
     ```
   - Target: EventBridge event bus → Event bus in a different account
   - Event bus ARN: paste the `central-security-bus` ARN from the
     security account
   - IAM role: Create a new role for this specific resource (auto-created)
   - Create

   > The event pattern `{"source":[{"prefix":""}]}` matches all events.
   > An empty object `{}` is not valid in the EventBridge console even
   > though it works in the API.

### 5c. Verify the pipeline

From prod account CloudShell:
```bash
aws events put-events --entries '[{
  "Source": "manual.test",
  "DetailType": "TestEvent",
  "Detail": "{\"message\": \"pipeline test\"}",
  "EventBusName": "arn:aws:events:us-east-2:<SECURITY_ACCOUNT_ID>:event-bus/central-security-bus"
}]'
```

`FailedEntryCount: 0` confirms the event was accepted. Check
CloudWatch → Log groups → `/aws/events/central-security-bus` to confirm
it actually arrived and a rule matched it.

---

## 6. SNS alerting

### 6a. Security account

1. SNS console → Topics → Create topic → Standard → name `security-alerts`
2. Create subscription → Protocol: Email → your email address
3. Confirm the subscription from the email that arrives
   (check spam — AWS SNS emails frequently land there)

   > The SNS subscription confirmation email goes to spam more often than
   > not on first use. Check before assuming it failed.

4. Add SNS topic access policy to allow EventBridge to publish:
   SNS → Topics → `security-alerts` → Access policy → edit → add this
   statement to the existing policy:
   ```json
   {
     "Sid": "AllowEventBridgePublish",
     "Effect": "Allow",
     "Principal": {
       "Service": "events.amazonaws.com"
     },
     "Action": "SNS:Publish",
     "Resource": "arn:aws:sns:us-east-2:<SECURITY_ACCOUNT_ID>:security-alerts"
   }
   ```

   > By default, SNS topics only allow IAM principals from the same account
   > to publish. `events.amazonaws.com` acts as a service principal, not
   > an IAM principal — so the default policy's `AWS:SourceOwner` condition
   > silently rejects EventBridge even though it's in the same account.
   > This statement is required.

5. EventBridge → Event buses → `central-security-bus` → Rules →
   Create rule → match all events → target: SNS topic → `security-alerts`

6. Run the `put-events` test from step 5c again — you should receive an
   email within 60 seconds confirming the full pipeline works end to end.

---

## 7. SIEM export bucket

Security account:

1. S3 console → Create bucket → name `siem-export-<SECURITY_ACCOUNT_ID>`
   → Block all public access → Create

2. Kinesis Data Firehose console → Create delivery stream
   - Source: Direct PUT
   - Destination: Amazon S3 → select the bucket above
   - Name: `security-events-to-siem`
   - Create

3. EventBridge → Event buses → `central-security-bus` → Rules →
   Create rule → match all events → target: Firehose delivery stream →
   select `security-events-to-siem`

Any SIEM (Splunk, Sentinel, Elastic, Datadog) can ingest from this S3
bucket using its native S3 connector. No pipeline redesign required when
onboarding a SIEM later.

---

## Known gotchas

| Issue | Cause | Fix |
|---|---|---|
| Config aggregator creation fails with `roleArn must not be null` | Console auto-create role option is unreliable | Create `OrgConfigAggregatorRole` manually via CLI first |
| Config aggregator shows no IAM resources | "Include global resources" not checked in recorder settings | Re-check recorder settings in each account |
| EventBridge forwarding rule creation fails | No IAM role attached (required since March 2023) | Let the console auto-create the role on rule creation |
| Events arrive at central bus but no SNS email | EventBridge service principal rejected by SNS default policy | Add explicit `events.amazonaws.com` statement to SNS access policy |
| SNS subscription confirmation email missing | Went to spam | Check spam folder |
| EventBridge rule not matching events | Event pattern set to `{"account":["<security_account_id>"]}` instead of matching all accounts | Change pattern to `{"source":[{"prefix":""}]}` |
| Config delegated admin fails with permission error | CLI commands not run from management account | Re-run from management account CloudShell |
