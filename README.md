# AWS IAM Policy Engine Simulator

An attempt to simulate the AWS IAM policy decision engine primarily for learning purposes. This is a work in progress...

## TODOs

- [x] Principle/NotPrinciple
- [ ] Add Null condition
- [ ] Support for multiple context values
- [ ] Support for variables in policies

## AWS IAM Policies

- **Identity Policies**: These are policies that are attached to IAM (Identity and Access Management) identities, such as users, groups, or roles. Identity policies define what actions an identity can perform on which resources. For example, an identity policy might allow a user to read objects from an S3 bucket or launch EC2 instances.

- **Resource-Based Policies**: These are policies that are attached directly to AWS resources such as S3 buckets, SQS queues, or SNS topics. They define what actions can be performed on the resource and who (which AWS accounts, IAM users, or roles) is allowed to perform those actions. Resource-based policies are used to grant cross-account access and to specify permissions for the resource itself.

- **Trust Policies**: These are policies associated with IAM roles. A trust policy specifies which entities (users, roles, or AWS services) are allowed to assume the role. Essentially, it defines the trust relationship between the role and the entities that can assume it. Trust policies are crucial for enabling roles to be assumed by users or services from the same or different AWS accounts.

- **Session Policies**: These are temporary policies that can be applied when assuming a role or when using AWS STS (Security Token Service). Session policies allow you to further restrict the permissions granted by the identity policy for the duration of the session. They are useful for providing temporary, limited permissions without modifying the identity policy itself.

- **Service Control Policies (SCPs)**: SCPs are a feature of AWS Organizations and are used to manage permissions across multiple AWS accounts within an organization. SCPs allow you to set permission guardrails for accounts, which can restrict the maximum permissions that can be granted to IAM identities within those accounts. SCPs do not grant permissions by themselves; they only define what is allowed or denied at the organizational level.

- **Permission Boundary Policies**: These are a specific type of policy that defines the maximum permissions that an IAM role can have. A permission boundary acts as a guardrail, limiting the permissions that can be granted to the role, even if the identity policies attached to that role would allow broader permissions. Permission boundaries are particularly useful in scenarios where you want to delegate permission management while ensuring that certain limits are enforced.

## References

- [Why AWS IAM is so hard to use](https://www.effectiveiam.com/why-aws-iam-is-so-hard-to-use)
- [Policy summary (list of services)](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_understand-policy-summary.html)
- [IAM JSON policy element reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html)
- [Actions, resources, and condition keys for AWS services](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html)
- [IAM JSON policy elements: Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Numeric)
- [Actions, resources, and condition keys for AWS services](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html)
- [Example IAM identity-based policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html)
- [ARN Structure](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html)
- [AWS Service to prefix mapping table](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation-action-last-accessed-support.html)
- [Identity-based policies vs Resource-based policies](https://www.reddit.com/r/aws/comments/18xjw7x/identitybased_policies_vs_resourcebased_policies/)
- [Grammar of the IAM JSON policy language](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html)
- [How to use trust policies with IAM roles](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/)
