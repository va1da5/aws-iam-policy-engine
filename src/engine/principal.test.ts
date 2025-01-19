import { describe, test, expect } from "vitest";

import { IAMPolicyEngine } from "./index";
import { PolicyType } from "./values";

describe("Test policy principal functionality", () => {
  test("Principal in identity-based policy", () => {
    expect(() => {
      new IAMPolicyEngine(
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "Enable IAM User Permissions",
              Effect: "Allow",
              Principal: {
                AWS: "arn:aws:iam::111122223333:root",
              },
              Action: "kms:*",
              Resource: "*",
            },
          ],
        },
        PolicyType.Identity,
      );
    }).toThrowError(
      /^Invalid statement 0 format: Principal and NotPrincipal elements are not allowed$/,
    );

    expect(() => {
      new IAMPolicyEngine(
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "Enable IAM User Permissions",
              Effect: "Allow",
              NotPrincipal: {
                AWS: "arn:aws:iam::111122223333:root",
              },
              Action: "kms:*",
              Resource: "*",
            },
          ],
        },
        PolicyType.Identity,
      );
    }).toThrowError(
      /^Invalid statement 0 format: Principal and NotPrincipal elements are not allowed$/,
    );
  });

  test("Wildcard principal wildcard", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "Enable IAM User Permissions",
            Effect: "Allow",
            Principal: "*",
            Action: "kms:*",
            Resource: "*",
          },
        ],
      },
      PolicyType.Resource,
    );

    expect(
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/181e8f25-b5ad-4c02-ac2d-fcbbd2d22f1b",
        principal: { AWS: "arn:aws:iam::123456789012:user/alice" },
      }),
    ).toBeTruthy();
  });

  test("Wildcard principal wildcard", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "Enable IAM User Permissions",
            Effect: "Allow",
            Principal: {
              AWS: "*",
            },
            Action: "kms:*",
            Resource: "*",
          },
        ],
      },
      PolicyType.Resource,
    );

    expect(
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/181e8f25-b5ad-4c02-ac2d-fcbbd2d22f1b",
        principal: { AWS: "arn:aws:iam::123456789012:user/alice" },
      }),
    ).toBeTruthy();
  });

  test("Wildcard in principal definition", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "Enable IAM User Permissions",
            Effect: "Allow",
            Principal: {
              AWS: "rn:aws:iam::123456789012:user/*",
            },
            Action: "kms:*",
            Resource: "*",
          },
        ],
      },
      PolicyType.Resource,
    );

    expect(() => {
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/181e8f25-b5ad-4c02-ac2d-fcbbd2d22f1b",
        principal: { AWS: "arn:aws:iam::123456789012:user/alice" },
      });
    }).toThrowError(
      "Unsupported Wildcard In Principal: Wildcards (*, ?) are not supported with the principal key AWS. Replace the wildcard with a valid principal value.",
    );
  });

  test("Incorrect data type", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "Enable IAM User Permissions",
            Effect: "Allow",
            Principal: {
              // @ts-expect-error Type 'null' is not assignable to type 'string | string[] | undefined'.
              AWS: null,
            },
            Action: "kms:*",
            Resource: "*",
          },
        ],
      },
      PolicyType.Resource,
    );

    expect(() => {
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/181e8f25-b5ad-4c02-ac2d-fcbbd2d22f1b",
        principal: { AWS: "arn:aws:iam::123456789012:user/alice" },
      });
    }).toThrowError(
      "Data Type Mismatch: The text does not match the expected JSON data type String or String Array.",
    );
  });

  test("Simple AWS KMS policy", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "Enable IAM User Permissions",
            Effect: "Allow",
            Principal: {
              AWS: "arn:aws:iam::111122223333:root",
            },
            Action: "kms:*",
            Resource: "*",
          },
        ],
      },
      PolicyType.Resource,
    );

    expect(
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/181e8f25-b5ad-4c02-ac2d-fcbbd2d22f1b",
        principal: { AWS: "arn:aws:iam::111122223333:user/alice" },
      }),
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/e1ba06a7-3bb5-4199-8551-265e9e63f634",
        principal: { AWS: "arn:aws:iam::111122223333:user/bob" },
      }),
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/e1ba06a7-3bb5-4199-8551-265e9e63f634",
        principal: { AWS: "arn:aws:iam::123456789012:user/john" },
      }),
    ).toBeFalsy();
  });

  test("Simple AWS KMS policy with only account ID", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "Enable IAM User Permissions",
            Effect: "Allow",
            Principal: {
              AWS: "111122223333",
            },
            Action: "kms:*",
            Resource: "*",
          },
        ],
      },
      PolicyType.Resource,
    );

    expect(
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/181e8f25-b5ad-4c02-ac2d-fcbbd2d22f1b",
        principal: { AWS: "arn:aws:iam::111122223333:user/alice" },
      }),
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/e1ba06a7-3bb5-4199-8551-265e9e63f634",
        principal: { AWS: "arn:aws:iam::123456789012:user/john" },
      }),
    ).toBeFalsy();
  });

  test("IAM role principals", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "Allow use of the key",
            Effect: "Allow",
            Principal: {
              AWS: [
                "arn:aws:iam::111122223333:role/admin",
                "arn:aws:iam::111122223333:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS",
              ],
            },
            Action: [
              "kms:Encrypt",
              "kms:Decrypt",
              "kms:ReEncrypt*",
              "kms:GenerateDataKey*",
              "kms:DescribeKey",
            ],
            Resource: "*",
          },
        ],
      },
      PolicyType.Resource,
    );

    expect(
      policy.evaluate({
        action: "kms:DescribeKey",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/181e8f25-b5ad-4c02-ac2d-fcbbd2d22f1b",
        principal: { AWS: "arn:aws:iam::111122223333:role/admin" },
      }),
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "kms:Decrypt",
        resource:
          "arn:aws:kms:us-east-1:111122223333:key/181e8f25-b5ad-4c02-ac2d-fcbbd2d22f1b",
        principal: { AWS: "arn:aws:iam::111122223333:role/devops" },
      }),
    ).toBeFalsy();
  });

  test("Trust policy", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: {
              Service: "eks.amazonaws.com",
            },
            Action: "sts:AssumeRole",
          },
        ],
      },
      PolicyType.Trust,
    );

    expect(
      policy.evaluate({
        action: "sts:AssumeRole",
        resource:
          "arn:aws:iam::111122223333:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS",
        principal: { Service: "eks.amazonaws.com" },
      }),
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "sts:AssumeRole",
        resource:
          "arn:aws:iam::111122223333:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS",
        principal: { Service: "ec2.amazonaws.com" },
      }),
    ).toBeFalsy();
  });

  test("Trust NoPrincipal", () => {
    const policy = new IAMPolicyEngine(
      {
        Version: "2012-10-17",
        Id: "Policy1571158084375",
        Statement: [
          {
            Sid: "BroadAll",
            Effect: "Allow",
            Action: "s3:*",
            Principal: "*",
            Resource: ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"],
          },
          {
            Sid: "denyMostPrincipals",
            Effect: "Deny",
            NotPrincipal: {
              AWS: [
                "arn:aws:iam::111122223333:role/MyRole",
                "arn:aws:iam::111122223333:user/MyUser",
              ],
            },
            Action: "s3:*",
            Resource: "*",
          },
        ],
      },
      PolicyType.Resource,
    );

    expect(
      policy.evaluate({
        action: "s3:GetObject",
        resource: "arn:aws:s3:::bucket/test.jpg",
        principal: { AWS: "arn:aws:iam::111122223333:role/MyRole" },
      }),
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "sts:GetObject",
        resource: "arn:aws:s3::111122223333:bucket/test.jpg",
        principal: { AWS: "arn:aws:iam::111122223333:role/SomeOtherRole" },
      }),
    ).toBeFalsy();
  });
});
