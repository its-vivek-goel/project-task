# IAM Permission Boundary Policy — Design Document

## Overview

This Permission Boundary is designed to be attached to **every new IAM role** created via the IAM Deployer. It acts as a **maximum ceiling** on what the role can do, regardless of what identity-based policies (e.g., PowerUserAccess) are attached to it.

**Key principle:** `Effective Permissions = Identity Policy ∩ Permission Boundary`. An explicit `Deny` in the boundary **cannot** be overridden by any identity or resource-based policy.

---

## AWS Managed Policy Size Limit

> **Important:** AWS managed policies have a **6,144 character limit** (after whitespace removal). The policy provided is within this limit. If you need to add more deny actions, consider splitting into multiple policies or using compact action patterns (e.g., `iam:Create*`).

---

## Category Breakdown

### 1. IAM Privilege Escalation Prevention (`DenyIAMPrivilegeEscalation`)

**Risk: CRITICAL** — This is the #1 attack vector in AWS.

| Action | Why Deny |
|--------|----------|
| `iam:CreateUser/Role/Group/Policy` | Prevent creating new principals or policies to escalate |
| `iam:CreatePolicyVersion` | Attacker can create a new version of an existing policy with admin privileges |
| `iam:SetDefaultPolicyVersion` | Attacker can revert a policy to a previous, more permissive version |
| `iam:AttachUserPolicy/RolePolicy/GroupPolicy` | Prevent attaching admin policies to self or others |
| `iam:PutUserPolicy/RolePolicy/GroupPolicy` | Prevent inline policy injection |
| `iam:UpdateAssumeRolePolicy` | Prevent modifying trust policies to allow unauthorized role assumption |
| `iam:CreateLoginProfile/UpdateLoginProfile` | Prevent creating console passwords for other users |
| `iam:CreateAccessKey` | Prevent creating long-lived credentials for other users |
| `iam:AddUserToGroup` | Prevent adding self to admin groups |
| `iam:DeactivateMFADevice` | Prevent disabling MFA on privileged accounts |
| `iam:Delete*` (users, roles, policies) | Prevent deleting IAM entities to cause disruption |

**PowerUser Impact:** None. PowerUserAccess already denies most `iam:*` actions. This boundary ensures even if a broader policy is attached, escalation is still blocked.

---

### 2. Permission Boundary Self-Protection (`DenyPermissionBoundaryTampering`)

**Risk: CRITICAL**

| Action | Why Deny |
|--------|----------|
| `iam:DeleteUserPermissionsBoundary` | Prevent removing the boundary from users |
| `iam:DeleteRolePermissionsBoundary` | Prevent removing the boundary from roles |
| `iam:PutUserPermissionsBoundary` | Prevent replacing with a more permissive boundary |
| `iam:PutRolePermissionsBoundary` | Same as above |

**PowerUser Impact:** None. This is purely a safety mechanism.

---

### 3. Identity Provider Manipulation (`DenyIdentityProviderManipulation`)

**Risk: HIGH**

| Action | Why Deny |
|--------|----------|
| `iam:CreateSAMLProvider` | Prevent introducing rogue federation |
| `iam:CreateOpenIDConnectProvider` | Prevent introducing rogue OIDC federation |
| `iam:Delete/Update*Provider` | Prevent tampering with existing federation |

**PowerUser Impact:** None. IdP management should be centralized.

---

### 4. Security Services Tampering (`DenySecurityServicesTampering`)

**Risk: CRITICAL** — Disabling monitoring = blind spot for attackers.

| Service | Denied Actions | Why |
|---------|---------------|-----|
| **CloudTrail** | DeleteTrail, StopLogging, UpdateTrail, PutEventSelectors | Prevents audit log tampering |
| **GuardDuty** | DeleteDetector, DisassociateFrom*, UpdateDetector, StopMonitoring* | Prevents threat detection disabling |
| **AWS Config** | DeleteConfigRule, DeleteConfigurationRecorder, StopConfigurationRecorder | Prevents compliance monitoring disabling |
| **Access Analyzer** | DeleteAnalyzer | Prevents external access analysis disabling |
| **Security Hub** | DisableSecurityHub, BatchDisableStandards | Prevents security posture dashboard disabling |
| **Inspector** | Disable | Prevents vulnerability scanning disabling |
| **Detective** | DeleteGraph | Prevents security investigation graph deletion |

**PowerUser Impact:** None. Users don't need to manage security infrastructure.

---

### 5. Data Exfiltration Prevention (`DenyDataExfiltration`)

**Risk: HIGH**

| Action | Why Deny |
|--------|----------|
| `s3:PutBucketPolicy` | Prevent making buckets publicly accessible via bucket policies |
| `s3:PutBucketAcl` | Prevent making buckets publicly accessible via ACLs |
| `s3:PutObjectAcl` | Prevent making individual objects public |
| `s3:PutBucketPublicAccessBlock` | Prevent disabling the S3 public access block |
| `s3:PutAccountPublicAccessBlock` | Prevent disabling the account-level S3 public access block |
| `ec2:ModifySnapshotAttribute` | Prevent sharing EBS snapshots externally |
| `ec2:ModifyImageAttribute` | Prevent making AMIs public |
| `rds:ModifyDBSnapshotAttribute` | Prevent sharing RDS snapshots externally |
| `rds:ModifyDBClusterSnapshotAttribute` | Same for Aurora cluster snapshots |
| `ram:CreateResourceShare` | Prevent sharing resources externally via RAM |
| `ram:UpdateResourceShare` | Prevent modifying existing RAM shares |
| `ram:AcceptResourceShareInvitation` | Prevent accepting external resource shares |

**PowerUser Impact: MEDIUM** — Users won't be able to:
- Modify S3 bucket policies (use a separate controlled process/pipeline for this)
- Share snapshots (should go through a review process anyway)
- *Workaround:* If your teams need `s3:PutBucketPolicy`, add a condition to only allow it when `s3:x-amz-acl` is NOT `public-read` or `public-read-write`, or use an SCP at the org level instead.

---

### 6. Account & Organization Actions (`DenyAccountAndOrgActions`)

**Risk: HIGH**

| Action | Why Deny |
|--------|----------|
| `organizations:*` | Prevent any org-level changes |
| `account:*` | Prevent account settings changes (e.g., alternate contacts, regions) |
| `aws-portal:*` | Prevent billing portal access |
| `billing:*` | Prevent billing modifications |
| `ce:*` | Prevent Cost Explorer manipulation |
| `cur:*` | Prevent Cost & Usage Report changes |
| `purchase-orders:*` | Prevent purchase order creation |
| `budgets:ModifyBudget/DeleteBudget` | Prevent removing budget alerts |

**PowerUser Impact:** None. PowerUserAccess already denies `organizations:*` and `account:*`.

---

### 7. Network Security (`DenyNetworkSecurityTampering`)

**Risk: HIGH**

| Action | Why Deny |
|--------|----------|
| `ec2:CreateVpcPeeringConnection` | Prevent unauthorized network interconnections |
| `ec2:AcceptVpcPeeringConnection` | Prevent accepting rogue peering requests |
| `ec2:CreateTransitGateway*` | Prevent unauthorized transit gateway creation |
| `ec2:CreateCustomerGateway` | Prevent rogue site-to-site VPN endpoints |
| `ec2:CreateVpnConnection/Gateway` | Prevent unauthorized VPN tunnels |
| `ec2:DeleteFlowLogs` | Prevent deleting network flow logs |
| `directconnect:*` | Prevent Direct Connect manipulation |
| `globalaccelerator:Create*/Update*` | Prevent creating public-facing accelerators |

**PowerUser Impact: LOW** — Users can still create VPCs, subnets, security groups, and manage their normal networking. Only cross-network and external-connectivity actions are blocked.

---

### 8. Encryption / KMS Protection (`DenyEncryptionTampering`)

**Risk: HIGH**

| Action | Why Deny |
|--------|----------|
| `kms:DisableKey` | Prevent disabling encryption keys (causes data loss) |
| `kms:ScheduleKeyDeletion` | Prevent scheduling key deletion |
| `kms:PutKeyPolicy` | Prevent modifying key policies to grant external access |
| `kms:RevokeGrant` | Prevent revoking grants (can break services) |
| `kms:DisableKeyRotation` | Prevent disabling automatic key rotation |
| `kms:CreateGrant` | Prevent granting key access to unauthorized principals |

**PowerUser Impact: LOW-MEDIUM** — Users can still use `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`, etc. The `kms:CreateGrant` denial may impact some service integrations (EBS, RDS). See "Tuning" section below.

---

### 9. Logging Tampering (`DenyLoggingTampering`)

**Risk: MEDIUM-HIGH**

| Action | Why Deny |
|--------|----------|
| `logs:DeleteLogGroup` | Prevent deleting CloudWatch log groups |
| `logs:DeleteLogStream` | Prevent deleting log streams |
| `logs:PutRetentionPolicy` | Prevent reducing log retention periods |
| `logs:DeleteRetentionPolicy` | Prevent removing retention policies |
| `logs:AssociateKmsKey` | Prevent changing log group encryption |
| `logs:DisassociateKmsKey` | Prevent removing encryption from logs |

**PowerUser Impact: MEDIUM** — Users can still `CreateLogGroup`, `CreateLogStream`, `PutLogEvents`, `DescribeLogGroups`, etc. If users need to manage log retention, consider allowing `logs:PutRetentionPolicy` with a condition that enforces a minimum retention period.

---

### 10. SSO & Directory (`DenySSOAndDirectoryManipulation`)

**Risk: HIGH**

All `sso:*`, `sso-admin:*`, and `ds:*` (Directory Service) actions are denied.

**PowerUser Impact:** None. SSO and directory management should be centralized with dedicated admin roles.

---

### 11. Domain Hijacking (`DenyDomainHijacking`)

**Risk: MEDIUM**

| Action | Why Deny |
|--------|----------|
| `route53domains:TransferDomain` | Prevent transferring domains out |
| `route53domains:DeleteDomain` | Prevent deleting registered domains |
| `route53domains:DisableDomainTransferLock` | Prevent unlocking domains for transfer |
| `route53domains:TransferDomainToAnotherAwsAccount` | Prevent cross-account domain transfer |

**PowerUser Impact:** None. DNS record management (`route53:*`) is not blocked, only domain registration actions.

---

### 12. Secrets & Parameter Store (`DenySecretsAndCredentialAbuse`)

**Risk: MEDIUM**

| Action | Why Deny |
|--------|----------|
| `secretsmanager:DeleteSecret` | Prevent deleting secrets |
| `secretsmanager:PutResourcePolicy` | Prevent making secrets cross-account accessible |
| `ssm:DeleteParameter(s)` | Prevent deleting SSM parameters |
| `ssm:PutParameter` | Prevent overwriting SSM parameters |

**PowerUser Impact: MEDIUM-HIGH** — The `ssm:PutParameter` denial will prevent users from creating/updating SSM parameters. **If your teams need this, remove `ssm:PutParameter` from the deny list** or scope it to specific parameter path prefixes using conditions.

---

### 13. Marketplace (`DenyMarketplaceAndSupport`)

**Risk: LOW-MEDIUM**

Prevents subscribing to paid AWS Marketplace products and managing marketplace listings.

**PowerUser Impact:** None.

---

## Tuning Recommendations

### Actions You Might Need to Allow Back (Based on Team Needs)

| Action | When to Allow | Condition to Add |
|--------|--------------|-----------------|
| `s3:PutBucketPolicy` | Teams manage their own bucket policies | Add condition: `"s3:x-amz-acl": {"StringNotEquals": ["public-read", "public-read-write"]}` |
| `ssm:PutParameter` | Teams store app config in Parameter Store | Scope with `Resource` to specific paths like `arn:aws:ssm:*:*:parameter/app/*` |
| `kms:CreateGrant` | EBS encryption, RDS, or other service integrations | Add condition: `"kms:ViaService": "ec2.*.amazonaws.com"` |
| `logs:PutRetentionPolicy` | Teams manage their own log retention | Add condition with minimum retention value |
| `ec2:CreateVpcPeeringConnection` | Teams need to set up peering | Require approval tags or specific VPC IDs |

### Additional Deny Actions to Consider

| Action | Why |
|--------|-----|
| `sts:AssumeRole` with cross-account condition | Prevent assuming roles in other accounts |
| `ec2:RunInstances` with instance type condition | Prevent launching expensive instance types (p4d, p5, etc.) |
| `lambda:AddPermission` | Prevent making Lambda functions publicly invocable |
| `sns:AddPermission` | Prevent making SNS topics publicly accessible |
| `sqs:AddPermission` | Prevent making SQS queues publicly accessible |
| `ecr:SetRepositoryPolicy` | Prevent making ECR repos cross-account accessible |
| `iam:PassRole` with condition | Only allow passing roles to specific services |
| `sts:GetFederationToken` | Prevent creating federated sessions |
| Region restriction condition | Restrict to approved regions only |

### Region Lock (Optional Add-On)

Add this condition to the Allow statement to restrict operations to approved regions:

```json
{
  "Sid": "RegionRestriction",
  "Effect": "Deny",
  "NotAction": [
    "iam:*",
    "sts:*",
    "s3:*",
    "cloudfront:*",
    "route53:*",
    "support:*",
    "budgets:*",
    "waf:*",
    "wafv2:*",
    "cloudwatch:*",
    "logs:*"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": [
        "us-east-1",
        "us-west-2",
        "eu-west-1"
      ]
    }
  }
}
```

---

## Deployment Strategy

1. **Create as a Customer Managed Policy** in each account
2. **Enforce via SCP** that all `iam:CreateRole` calls must include this permission boundary:
   ```json
   {
     "Sid": "EnforcePermissionBoundary",
     "Effect": "Deny",
     "Action": ["iam:CreateRole", "iam:CreateUser"],
     "Resource": "*",
     "Condition": {
       "StringNotLike": {
         "iam:PermissionsBoundary": "arn:aws:iam::*:policy/IAMDeployerPermissionBoundary"
       }
     }
   }
   ```
3. **Attach in your IAM Deployer** automation when creating roles
4. **Monitor** with CloudTrail for any `AccessDenied` events from the boundary to detect false positives

---

## Compatibility with PowerUserAccess

| Feature | Works? | Notes |
|---------|--------|-------|
| EC2 (launch, manage instances) | Yes | No restrictions on normal EC2 operations |
| S3 (read, write, create buckets) | Yes | Only bucket policy/ACL changes blocked |
| Lambda (create, deploy, invoke) | Yes | Fully functional |
| RDS / DynamoDB | Yes | Only snapshot sharing blocked |
| ECS / EKS | Yes | Fully functional |
| CloudFormation | Yes | Works except actions that would violate denied permissions |
| CodeBuild / CodePipeline | Yes | Fully functional |
| SNS / SQS | Yes | Fully functional |
| CloudWatch (metrics, alarms) | Yes | Only log deletion/retention blocked |
| API Gateway | Yes | Fully functional |
| Step Functions | Yes | Fully functional |
| Secrets Manager (read/create) | Yes | Only delete/policy changes blocked |
