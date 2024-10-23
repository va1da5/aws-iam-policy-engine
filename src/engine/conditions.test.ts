import { describe, test, expect } from "vitest";

import { IAMPolicyEngine } from "./index";

describe("Test Conditions", () => {
  const engine = new IAMPolicyEngine({ Version: "2012-10-17", Statement: [] });

  test("Condition StringEquals matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "iamuser-admin",
        },
        {
          StringEquals: {
            "aws:PrincipalTag/job-category": "iamuser-admin",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition StringEquals does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "s3-admin",
        },
        {
          StringEquals: {
            "aws:PrincipalTag/job-category": "iamuser-admin",
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition StringEquals matches arrya", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "iamuser-admin",
        },
        {
          StringEquals: {
            "aws:PrincipalTag/job-category": ["ec2-user", "iamuser-admin"],
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition StringEquals matches multiple context", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "iamuser-admin",
          "aws:PrincipalTag/department": "devops",
        },
        {
          StringEquals: {
            "aws:PrincipalTag/job-category": ["ec2-user", "iamuser-admin"],
            "aws:PrincipalTag/department": ["devops", "kubernetes"],
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition StringEquals does not matches missing context data", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "",
          "aws:PrincipalTag/department": "devops",
        },
        {
          StringEquals: {
            "aws:PrincipalTag/job-category": ["ec2-user", "iamuser-admin"],
            "aws:PrincipalTag/department": ["devops", "kubernetes"],
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition StringEquals does not match multiple context", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "iamuser-admin",
          "aws:PrincipalTag/department": "database",
        },
        {
          StringEquals: {
            "aws:PrincipalTag/job-category": ["ec2-user", "iamuser-admin"],
            "aws:PrincipalTag/department": ["devops", "kubernetes"],
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition StringNotEquals matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/department": "database",
        },
        {
          StringNotEquals: {
            "aws:PrincipalTag/department": ["devops", "kubernetes"],
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition StringNotEquals does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/department": "database",
        },
        {
          StringNotEquals: {
            "aws:PrincipalTag/department": ["devops", "database"],
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition StringEqualsIgnoreCase matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/department": "Database",
        },
        {
          StringEqualsIgnoreCase: {
            "aws:PrincipalTag/department": ["devops", "database"],
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition StringEqualsIgnoreCase does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/department": "HR",
        },
        {
          StringEqualsIgnoreCase: {
            "aws:PrincipalTag/department": ["devops", "backend"],
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition StringNotEqualsIgnoreCase matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/department": "HR",
        },
        {
          StringNotEqualsIgnoreCase: {
            "aws:PrincipalTag/department": ["devops", "backend"],
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition StringNotEqualsIgnoreCase does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/department": "HR",
        },
        {
          StringNotEqualsIgnoreCase: {
            "aws:PrincipalTag/department": ["devops", "hr"],
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition StringLike matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "iam-admin",
        },
        {
          StringLike: {
            "aws:PrincipalTag/job-category": ["*-admin", "*-user"],
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition StringLike does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "lambda-developer",
        },
        {
          StringLike: {
            "aws:PrincipalTag/job-category": ["*-admin", "*-user"],
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition StringNotLike matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "iam-admin",
        },
        {
          StringNotLike: {
            "aws:PrincipalTag/job-category": ["*-developer", "*-user"],
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition StringNotLike does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/job-category": "lambda-developer",
        },
        {
          StringNotLike: {
            "aws:PrincipalTag/job-category": ["*-developer", "*-user"],
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition ArnLike matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-west-2:111122223333:trail/finance",
        },
        {
          ArnLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:*:111122223333:trail/*",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition ArnLike matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-west-2:111122223333:trail/finance",
        },
        {
          ArnLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:*:111122223333:trail/*",
          },
        }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-west-2:111122223333:trail/finance",
        },
        {
          ArnLike: {
            "aws:SourceArn": "arn:aws:cloudtrail::111122223333:trail/*",
          },
        }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-west-2:111122223333:trail/finance",
        },
        {
          ArnLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:::trail/*",
          },
        }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-west-2:111122223333:trail/finance",
        },
        {
          ArnLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:::*",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition ArnLike does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-east-2:444455556666:user/111122223333:trail/finance",
        },
        {
          ArnLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:*:111122223333:trail/*",
          },
        }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-east-2:444455556666:user/111122223333:trail/finance",
        },
        {
          ArnLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:::",
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition ArnNotLike matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-west-2:123456789012:trail/finance",
        },
        {
          ArnNotLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:*:111122223333:trail/*",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition ArnNotLike does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceArn":
            "arn:aws:cloudtrail:us-east-2:111122223333:trail/finance",
        },
        {
          ArnNotLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:*:111122223333:trail/*",
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition NumericEquals matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "s3:max-keys": "10",
        },
        {
          NumericEquals: {
            "s3:max-keys": "10",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition NumericEquals does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "s3:max-keys": "10",
        },
        {
          NumericEquals: {
            "s3:max-keys": "5",
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition NumericNotEquals matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "s3:max-keys": "5",
        },
        {
          NumericNotEquals: {
            "s3:max-keys": "10",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition NumericNotEquals does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "s3:max-keys": "10",
        },
        {
          NumericNotEquals: {
            "s3:max-keys": "10",
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition NumericLessThan matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "s3:max-keys": "9",
        },
        {
          NumericLessThan: {
            "s3:max-keys": "10",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition NumericLessThanEquals matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "s3:max-keys": "10",
        },
        {
          NumericLessThanEquals: {
            "s3:max-keys": "10",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition NumericGreaterThan matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "s3:max-keys": "11",
        },
        {
          NumericGreaterThan: {
            "s3:max-keys": "10",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition NumericGreaterThanEquals matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "s3:max-keys": "10",
        },
        {
          NumericGreaterThanEquals: {
            "s3:max-keys": "10",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition Bool matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SecureTransport": "true",
        },
        {
          Bool: {
            "aws:SecureTransport": "true",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition Bool does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SecureTransport": "",
        },
        {
          Bool: {
            "aws:SecureTransport": "true",
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition Date matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-01T00:00:01Z",
        },
        { DateEquals: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2021-01-01T00:00:01Z",
        },
        { DateNotEquals: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2019-01-01T00:00:01Z",
        },
        { DateLessThan: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-01T00:00:01Z",
        },
        { DateLessThanEquals: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-01T00:00:02Z",
        },
        { DateGreaterThan: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-01T00:00:02Z",
        },
        {
          DateGreaterThanEquals: {
            "aws:TokenIssueTime": "2020-01-01T00:00:02Z",
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition Date does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-01T00:00:02Z",
        },
        { DateEquals: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-01T00:00:01Z",
        },
        { DateNotEquals: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-02T00:00:01Z",
        },
        { DateLessThan: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-01T00:00:02Z",
        },
        { DateLessThanEquals: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2020-01-01T00:00:00Z",
        },
        { DateGreaterThan: { "aws:TokenIssueTime": "2020-01-01T00:00:01Z" } }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:TokenIssueTime": "2019-01-01T00:00:02Z",
        },
        {
          DateGreaterThanEquals: {
            "aws:TokenIssueTime": "2020-01-01T00:00:02Z",
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition IpAddress matches", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "203.0.113.2",
        },
        { IpAddress: { "aws:SourceIp": "203.0.113.0/24" } }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "203.0.113.13",
        },
        {
          IpAddress: {
            "aws:SourceIp": ["203.0.113.12", "203.0.113.13", "203.0.113.14"],
          },
        }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "203.0.113.13",
        },
        {
          IpAddress: {
            "aws:SourceIp": "203.0.113.13",
          },
        }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "2001:DB8:1234:5678::100",
        },
        {
          IpAddress: {
            "aws:SourceIp": ["203.0.113.0/24", "2001:DB8:1234:5678::/64"],
          },
        }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "2002:DB8:1234:5678::100",
        },
        {
          NotIpAddress: {
            "aws:SourceIp": ["203.0.113.0/24", "2001:DB8:1234:5678::/64"],
          },
        }
      )
    ).toBeTruthy();
  });

  test("Condition IpAddress does not match", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "172.0.113.2",
        },
        { IpAddress: { "aws:SourceIp": "203.0.113.0/24" } }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "203.0.113.50",
        },
        {
          IpAddress: {
            "aws:SourceIp": ["203.0.113.12", "203.0.113.13", "203.0.113.14"],
          },
        }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "2002:DB8:1234:5678::100",
        },
        {
          IpAddress: {
            "aws:SourceIp": ["203.0.113.0/24", "2001:DB8:1234:5678::/64"],
          },
        }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "2001:DB8:1234:5678::100",
        },
        {
          NotIpAddress: {
            "aws:SourceIp": ["203.0.113.0/24", "2001:DB8:1234:5678::/64"],
          },
        }
      )
    ).toBeFalsy();
  });

  test("Condition ...IfExists testing", () => {
    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "203.0.113.2",
        },
        { IpAddressIfExists: { "aws:SourceIp": "203.0.113.0/24" } }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "203.0.113.2",
        },
        { IpAddressIfExists: { "aws:TargetIp": "203.0.113.0/24" } }
      )
    ).toBeTruthy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:SourceIp": "203.0.113.2",
        },
        { IpAddressIfExists: { "aws:SourceIp": "103.0.113.0/24" } }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/department": "database",
        },
        {
          StringNotEqualsIfExists: {
            "aws:PrincipalTag/department": "database",
          },
        }
      )
    ).toBeFalsy();

    expect(
      engine.conditionMatches(
        {
          action: "",
          resource: "",
          "aws:PrincipalTag/department": "database",
        },
        {
          StringNotEqualsIfExists: {
            "aws:PrincipalTag/unit": "developers",
          },
        }
      )
    ).toBeTruthy();
  });
});
