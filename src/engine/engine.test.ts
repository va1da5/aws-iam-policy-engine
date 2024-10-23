import { describe, test, expect } from "vitest";

import { IAMPolicyEngine } from "./index";

describe("Test wildcard functionality", () => {
  const engine = new IAMPolicyEngine({ Version: "2012-10-17", Statement: [] });

  test("Action match single wildcard", () => {
    expect(engine.wildcardMatch("iam:Get*", "iam:GetAccessKeyId")).toBeTruthy();
  });

  test("Match multiple wildcards", () => {
    expect(
      engine.wildcardMatch("iam:*AccessKey*", "iam:GetAccessKeyId")
    ).toBeTruthy();
  });

  test("Match all", () => {
    expect(engine.wildcardMatch("*", "iam:GetAccessKeyId")).toBeTruthy();
  });

  test("Match service", () => {
    expect(engine.wildcardMatch("iam:*", "iam:PutAccessKey")).toBeTruthy();
  });

  test("Does not match wildcard", () => {
    expect(
      engine.wildcardMatch("iam:GetAccessKey*", "iam:PutAccessKeyId")
    ).toBeFalsy();
  });

  test("Wildcard ARN as string", () => {
    expect(
      engine.wildcardMatch(
        "arn:aws:cloudtrail:*:111122223333:trail/*",
        "arn:aws:cloudtrail:us-east-2:444455556666:user/111122223333:trail/finance"
      )
    ).toBeFalsy();
  });
});

describe("Test Resources", () => {
  const engine = new IAMPolicyEngine({ Version: "2012-10-17", Statement: [] });

  test("Resource match global wildcard", () => {
    expect(
      engine.resourceMatches(
        "arn:aws:s3:::amzn-s3-demo-bucket-production/test.jpg",
        "*"
      )
    ).toBeTruthy();
  });

  test("Resource match file wildcard", () => {
    expect(
      engine.resourceMatches(
        "arn:aws:s3:::amzn-s3-demo-bucket-production/test.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket-production/*"
      )
    ).toBeTruthy();
  });

  test("Resource match multiple file wildcards", () => {
    expect(
      engine.resourceMatches(
        "arn:aws:s3:::amzn-s3-demo-bucket-production/test/account.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket-production/*/*.jpg"
      )
    ).toBeTruthy();
  });

  test("Resource match region wildcard", () => {
    expect(
      engine.resourceMatches(
        "arn:aws:s3:us-east-1::amzn-s3-demo-bucket-production/test.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket-production/*"
      )
    ).toBeTruthy();
  });

  test("Resource match account wildcard", () => {
    expect(
      engine.resourceMatches(
        "arn:aws:s3:us-east-1:123456789012:amzn-s3-demo-bucket-production/test.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket-production/*"
      )
    ).toBeTruthy();
  });

  test("Resource match account wildcard array", () => {
    expect(
      engine.resourceMatches(
        "arn:aws:s3:us-east-1:123456789012:amzn-s3-demo-bucket-production/test.jpg",
        [
          "arn:aws:s3:::amzn-s3-demo-bucket-test/*",
          "arn:aws:s3:::amzn-s3-demo-bucket-production/*",
        ]
      )
    ).toBeTruthy();
  });

  test("Resource does not match account wildcard array", () => {
    expect(
      engine.resourceMatches(
        "arn:aws:s3:us-east-1:123456789012:amzn-s3-demo-bucket-production/test.jpg",
        [
          "arn:aws:s3:::amzn-s3-demo-bucket-test/*.jpg",
          "arn:aws:s3:::amzn-s3-demo-bucket-uat/*.gif",
        ]
      )
    ).toBeFalsy();
  });
});

describe("Test Actions", () => {
  const engine = new IAMPolicyEngine({ Version: "2012-10-17", Statement: [] });

  test("Action match global wildcard", () => {
    expect(engine.actionMatches("sqs:SendMessage", "*")).toBeTruthy();
  });

  test("Action match service wildcard", () => {
    expect(engine.actionMatches("sqs:SendMessage", "sqs:*")).toBeTruthy();
  });

  test("Action match service action wildcard", () => {
    expect(engine.actionMatches("s3:GetObject", "s3:Get*")).toBeTruthy();
  });

  test("Action match service action multiple wildcard", () => {
    expect(
      engine.actionMatches("iam:DeleteAccessKey", "iam:*AccessKey*")
    ).toBeTruthy();
  });

  test("Action match service action multiple wildcard array", () => {
    expect(
      engine.actionMatches("iam:DeleteAccessKey", ["iam:*AccessKey*"])
    ).toBeTruthy();
  });

  test("Action does not match service action wildcard array", () => {
    expect(
      engine.actionMatches("iam:DeleteAccessKey", ["s3:*", "sqs:*"])
    ).toBeFalsy();
  });

  test("Action match service action wildcard array", () => {
    expect(
      engine.actionMatches("iam:DeleteAccessKey", ["s3:*", "iam:*", "sqs:*"])
    ).toBeTruthy();
  });
});
