import { Policy, PolicyType, RequestContext } from "./engine/types";

export type TestCase = {
  context: RequestContext;
  allow: boolean;
};

export type Exercise = {
  name: string;
  description: string;
  policyType: PolicyType;
  initialPolicy: Policy | { [key: string]: unknown };
  testCases: TestCase[];
  values: { [variableName: string]: string[] };
  solution: Policy;
};
