import { describe, test, expect } from "vitest";

import { IAMPolicyEngine } from "./index";

describe("Test policy variables functionality", () => {
  test("Extract variables", () => {
    const policy = new IAMPolicyEngine({
      Version: "2012-10-17",
      Statement: [],
    });

    const testString =
      "aaa ${test} arn:aws:sqs:us-east-2::${aws:PrincipalTag/team}-queue ${demo}} ";

    expect(policy.getPolicyVariables(testString)).toEqual([
      "test",
      "aws:PrincipalTag/team",
      "demo",
    ]);
  });

  test("Use policy variables", () => {
    const policy = new IAMPolicyEngine({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: ["s3:ListBucket"],
          Resource: ["arn:aws:s3:::amzn-s3-demo-bucket/${aws:username}"],
          Condition: {
            StringLike: { "s3:prefix": ["${aws:PrincipalTag/team}/*"] },
          },
        },
      ],
    });

    expect(
      policy.applyVariables(policy.policy.Statement, {
        action: "",
        "aws:username": "admin",
        "aws:PrincipalTag/team": "developers",
      })
    ).toMatchObject([
      {
        Effect: "Allow",
        Action: ["s3:ListBucket"],
        Resource: ["arn:aws:s3:::amzn-s3-demo-bucket/admin"],
        Condition: {
          StringLike: { "s3:prefix": ["developers/*"] },
        },
      },
    ]);
  });
});
