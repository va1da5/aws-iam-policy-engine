import { describe, test, expect } from "vitest";

import { IAMPolicyEngine } from "./index";

describe("Test policy functionality", () => {
  test("Simple policy", () => {
    const policy = new IAMPolicyEngine({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "ExampleStatementID",
          Effect: "Allow",
          Action: "s3:ListAllMyBuckets",
          Resource: "arn:aws:s3:::amzn-s3-demo-bucket-production/*",
        },
      ],
    });

    expect(
      policy.evaluate({
        action: "s3:ListAllMyBuckets",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-production/test.jpg",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "s3:ListAllMyBuckets",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-production/robots.txt",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "s3:ListBucket",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-production/test.jpg",
      })
    ).toBeFalsy();

    expect(
      policy.evaluate({
        action: "s3:ListAllMyBuckets",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-test/test.jpg",
      })
    ).toBeFalsy();
  });

  test("Allows access based on date and time", () => {
    const policy = new IAMPolicyEngine({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "ExampleStatementID",
          Effect: "Allow",
          Action: ["s3:*", "ec2:*"],
          Resource: "*",
          Condition: {
            DateGreaterThan: { "aws:CurrentTime": "2020-04-01T00:00:00Z" },
            DateLessThan: { "aws:CurrentTime": "2020-06-30T23:59:59Z" },
          },
        },
      ],
    });

    expect(
      policy.evaluate({
        action: "s3:ListAllMyBuckets",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-test/test.jpg",
        "aws:CurrentTime": "2020-04-02T00:00:00Z",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "ec2:DeleteBucket",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-test/test.jpg",
        "aws:CurrentTime": "2020-07-01T00:00:00Z",
      })
    ).toBeFalsy();
  });

  test("Deny access to specific department", () => {
    const policy = new IAMPolicyEngine({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "FullAccessForDevelopers",
          Effect: "Allow",
          Action: ["*"],
          Resource: "*",
        },
        {
          Sid: "DenyHR",
          Effect: "Deny",
          Action: ["ec2:*", "s3:*"],
          Resource: "*",
          Condition: {
            StringEquals: {
              "aws:PrincipalTag/department": "hr",
            },
          },
        },
      ],
    });

    expect(
      policy.evaluate({
        action: "s3:ListAllMyBuckets",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-test/test.jpg",
        "aws:PrincipalTag/department": "development",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "s3:ListAllMyBuckets",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-test/test.jpg",
        "aws:PrincipalTag/department": "engineering",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "s3:ListAllMyBuckets",
        resource: "arn:aws:s3:::amzn-s3-demo-bucket-test/test.jpg",
        "aws:PrincipalTag/department": "hr",
      })
    ).toBeFalsy();
  });

  test("Limit access to specific IP range", () => {
    const policy = new IAMPolicyEngine({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: ["s3:ListBucket", "s3:GetObject", "s3:PutObject"],
          Resource: [
            "arn:aws:s3:::example-bucket",
            "arn:aws:s3:::example-bucket/*",
          ],
        },
        {
          Effect: "Deny",
          Action: ["s3:GetObject", "s3:PutObject"],
          Resource: "arn:aws:s3:::example-bucket/*",
          Condition: {
            IpAddressIfExists: {
              "aws:SourceIp": "203.0.113.0/24",
            },
          },
        },
      ],
    });

    expect(
      policy.evaluate({
        action: "s3:ListBucket",
        resource: "arn:aws:s3:::example-bucket",
        "aws:SourceIp": "18.20.50.10",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "s3:GetObject",
        resource: "arn:aws:s3:::example-bucket/test.jpg",
        "aws:SourceIp": "118.0.100.10",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "s3:PutObject",
        resource: "arn:aws:s3:::example-bucket/test.jpg",
        "aws:SourceIp": "203.0.113.50",
      })
    ).toBeFalsy();

    expect(
      policy.evaluate({
        action: "s3:PutObject",
        resource: "arn:aws:s3:::example-bucket/test.jpg",
      })
    ).toBeFalsy();

    expect(
      policy.evaluate({
        action: "s3:DeleteBucket",
        resource: "arn:aws:s3:::example-bucket",
        "aws:SourceIp": "18.20.50.10",
      })
    ).toBeFalsy();
  });
});

describe("Allow access to specific region only", () => {
  const policy = new IAMPolicyEngine({
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "EnableDisableHongKong",
        Effect: "Allow",
        Action: ["account:EnableRegion", "account:DisableRegion"],
        Resource: "*",
        Condition: {
          StringEquals: { "account:TargetRegion": "us-east-1" },
        },
      },
      {
        Sid: "ViewConsole",
        Effect: "Allow",
        Action: ["account:ListRegions"],
        Resource: "*",
      },
    ],
  });

  test("Valid", () => {
    expect(
      policy.evaluate({
        action: "account:DisableRegion",
        resource: "arn:aws:account:us-east-1:123456789012:account",
        "account:TargetRegion": "us-east-1",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "account:EnableRegion",
        resource: "arn:aws:account:us-east-1:123456789012:account",
        "account:TargetRegion": "us-east-1",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "account:ListRegions",
        resource: "arn:aws:account:us-east-1:123456789012:account",
        "account:TargetRegion": "us-east-1",
      })
    ).toBeTruthy();

    expect(
      policy.evaluate({
        action: "account:ListRegions",
        resource: "arn:aws:account:us-east-1:123456789012:account",
        "account:TargetRegion": "us-west-1",
      })
    ).toBeTruthy();
  });

  test("Invalid", () => {
    expect(
      policy.evaluate({
        action: "account:DisableRegion",
        resource: "arn:aws:account:us-east-1:123456789012:account",
        "account:TargetRegion": "us-west-1",
      })
    ).toBeFalsy();

    expect(
      policy.evaluate({
        action: "account:EnableRegion",
        resource: "arn:aws:account:us-east-1:123456789012:account",
        "account:TargetRegion": "us-west-1",
      })
    ).toBeFalsy();
  });
});
