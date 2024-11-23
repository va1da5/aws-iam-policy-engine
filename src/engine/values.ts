export enum ConditionSetOperator {
  None,
  ForAllValues,
  ForAnyValue,
}

export enum PolicyType {
  Identity = "IDENTITY_POLICY",
  Resource = "RESOURCE_POLICY",
  Trust = "TRUST_POLICY", // RESOURCE_POLICY -> AWS::IAM::AssumeRolePolicyDocument
  ServiceControl = "SERVICE_CONTROL_POLICY",
}

export const policyTypeMap: Record<PolicyType, string> = {
  [PolicyType.Identity]: "Identity Policy",
  [PolicyType.Resource]: "Resource-based Policy",
  [PolicyType.Trust]: "Trust Policy",
  [PolicyType.ServiceControl]: "Service Control Policy",
};

export const validPolicyVersions = ["2012-10-17", "2008-10-17"];

export const requiredPolicyElements = ["Version", "Statement"];

export const validStatementElements = [
  "Sid",
  "Effect",
  "Principal",
  "NotPrincipal",
  "Action",
  "NotAction",
  "Resource",
  "NotResource",
  "Condition",
];

export const validEffectValues = ["Allow", "Deny"];

export const mutuallyExclusiveElements = [
  ["Principal", "NotPrincipal"],
  ["Resource", "NotResource"],
  ["Action", "NotAction"],
];

export const validPartitions = ["*", "aws", "aws-cn", "aws-us-gov"];

export const awsAccountIdRegex = /^\d{12}$/;
export const awsRootAccountRegex = /^arn:.*?:\d{12}:root$/;
export const awsIdentityIdRegex = /^[\w]{16,128}$/;
