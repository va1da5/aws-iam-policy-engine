import { hasValue, isString, parseBool } from "@/utils/genetic";
import {
  Action,
  Condition,
  Policy,
  PolicyType,
  Principal,
  RequestContext,
  Resource,
} from "./types";
import ipRangeCheck from "ip-range-check";

export class IAMPolicyEngine {
  policy: Policy;
  type: PolicyType;

  constructor(policy: Policy, policyType: PolicyType = "identity-based") {
    this.policy = policy;
    this.type = policyType;
    this.validate();
  }

  validate() {
    if (
      ["Version", "Statement"]
        .map((item) => !Object.keys(this.policy).includes(item))
        .some((missing) => missing)
    )
      throw new Error("Invalid policy format");

    this.policy.Statement.map((statement, index) => {
      const errorMsg = `Invalid statement ${index} format`;

      const statementElements = Object.keys(statement);

      switch (this.type) {
        case "identity-based": {
          if (
            !statementElements.includes("Resource") &&
            !statementElements.includes("NotResource")
          )
            throw new Error(`${errorMsg}: Resource or NotResource is required`);

          if (statementElements.includes("Principal"))
            throw new Error(`${errorMsg}: Principal not allowed`);
          break;
        }

        case "resource-based": {
          if (
            !statementElements.includes("Principal") &&
            !statementElements.includes("NotPrincipal")
          )
            throw new Error(
              `${errorMsg}: Principal or NotPrincipal is required`
            );

          break;
        }

        case "trust": {
          if (!statementElements.includes("Principal"))
            throw new Error(`${errorMsg}: Principal is required`);

          if (statementElements.includes("Resource"))
            throw new Error(`${errorMsg}: Resource is not allowed`);
          break;
        }
      }

      ["Effect", "Action"].forEach((element) => {
        if (!statementElements.includes(element))
          throw new Error(`Invalid statement ${index}: ${element} is required`);
      });

      if (!["Allow", "Deny"].includes(statement.Effect))
        throw new Error(
          `Invalid statement ${index} format: incorrect Effect definition ${statement.Effect}`
        );
    });
  }

  // Main method to evaluate access
  evaluate(requestContext: RequestContext) {
    const statements = this.policy.Statement;

    let isAllowed = false;

    for (const statement of statements) {
      const { Effect, ...elements } = statement;

      const outcome = Object.keys(elements).map((element) => {
        switch (element) {
          case "Sid": {
            return true;
          }

          case "Action": {
            return this.actionMatches(
              requestContext["action"],
              statement[element]
            );
          }
          case "NotAction": {
            return this.actionMatches(
              requestContext["action"],
              statement[element] as Action
            );
          }
          case "Resource": {
            if (!requestContext["resource"]) return false;
            return this.resourceMatches(
              requestContext["resource"],
              statement[element] as Resource
            );
          }

          case "NotResource": {
            if (!requestContext["resource"]) return false;
            return !this.resourceMatches(
              requestContext["resource"] as string,
              statement[element] as Resource
            );
          }

          case "Condition": {
            return this.conditionMatches(
              requestContext,
              statement[element] as Condition
            );
          }

          case "Principal": {
            return this.principalMatches(
              requestContext,
              statement[element] as Principal
            );
          }

          case "NotPrincipal": {
            return !this.principalMatches(
              requestContext,
              statement[element] as Principal
            );
          }

          default: {
            throw new Error(`Unsupported statement element: ${element}`);
          }
        }
      });

      if (outcome.every((match) => match) && Effect == "Deny") return false;

      if (outcome.every((match) => match) && Effect == "Allow")
        isAllowed = true;
    }

    return isAllowed;
  }

  // Check if action matches
  actionMatches(action: string, actions: Action) {
    if (isString(actions)) return this.wildcardMatch(actions, action);

    return actions.some((pattern) => {
      return this.wildcardMatch(pattern, action);
    });
  }

  // Check if resource matches
  resourceMatches(resource: string, resources: Resource) {
    if (isString(resources))
      return this.wildcardMatch(this.arnWildcards(resources), resource);

    return resources.some((r) => {
      return this.wildcardMatch(this.arnWildcards(r), resource);
    });
  }

  conditionMatches(context: RequestContext, condition: Condition) {
    if (!condition) return true;

    return Object.keys(condition)
      .map((key) => {
        // capture if key ends with ..IfExists, remove it from key and pass flag indicating it to each handler
        let operator = key;
        const isIfExists = key.endsWith("IfExists");
        if (isIfExists) operator = key.replace("IfExists", "");

        switch (operator) {
          case "StringEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => value === conditionValue,
              isIfExists
            );
          }

          case "StringNotEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => value !== conditionValue,
              isIfExists,
              true
            );
          }

          case "StringEqualsIgnoreCase": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.toLocaleLowerCase() ===
                conditionValue.toLocaleLowerCase(),
              isIfExists
            );
          }

          case "StringNotEqualsIgnoreCase": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.toLocaleLowerCase() !==
                conditionValue.toLocaleLowerCase(),
              isIfExists,
              true
            );
          }

          case "StringLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                this.wildcardMatch(conditionValue, value),
              isIfExists
            );
          }

          case "StringNotLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                !this.wildcardMatch(conditionValue, value),
              isIfExists,
              true
            );
          }

          case "ArnLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => this.arnMatch(conditionValue, value),
              isIfExists
            );
          }

          case "ArnEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => this.arnMatch(conditionValue, value),
              isIfExists
            );
          }

          case "ArnNotLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => !this.arnMatch(conditionValue, value),
              isIfExists,
              true
            );
          }

          case "ArnNotEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => !this.arnMatch(conditionValue, value),
              isIfExists,
              true
            );
          }

          case "NumericEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value === conditionValue,
              isIfExists
            );
          }

          case "NumericNotEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value !== conditionValue,
              isIfExists
            );
          }

          case "NumericLessThan": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value < conditionValue,
              isIfExists
            );
          }

          case "NumericLessThanEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value <= conditionValue,
              isIfExists
            );
          }

          case "NumericGreaterThan": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value > conditionValue,
              isIfExists
            );
          }

          case "NumericGreaterThanEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value >= conditionValue,
              isIfExists
            );
          }

          case "Bool": {
            return this.checkBoolCondition(condition[key], context, isIfExists);
          }

          case "DateEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.getTime() === conditionValue.getTime(),
              isIfExists
            );
          }

          case "DateNotEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.getTime() !== conditionValue.getTime(),
              isIfExists
            );
          }

          case "DateLessThan": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value < conditionValue,
              isIfExists
            );
          }

          case "DateLessThanEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value <= conditionValue,
              isIfExists
            );
          }

          case "DateGreaterThan": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value > conditionValue,
              isIfExists
            );
          }

          case "DateGreaterThanEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value >= conditionValue,
              isIfExists
            );
          }

          case "IpAddress": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => ipRangeCheck(value, conditionValue),
              isIfExists
            );
          }

          case "NotIpAddress": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => !ipRangeCheck(value, conditionValue),
              isIfExists,
              true
            );
          }

          case "Null": {
            return this.checkNullCondition(condition[key], context);
          }

          default: {
            throw new Error(`Unsupported condition: ${key}`);
          }
        }
      })
      .every((success) => success);
  }

  principalMatches(context: RequestContext, principal: Principal) {
    if (!context.principal) return false;

    if (principal == "*") return true;

    if (typeof principal !== "object")
      throw new Error("Principal must be an object");

    return Object.keys(principal)
      .map((principalName: string) => {
        switch (principalName) {
          case "AWS": {
            if (!principal.AWS) return true;
            if (!context.principal || !context.principal[principalName])
              return false;

            if (principal[principalName] == "*") return true;

            return this.checkAWSPrincipal(
              principal.AWS,
              context.principal[principalName] as string
            );
          }

          default: {
            if (!context.principal || !context.principal[principalName])
              return false;
            if (!principal[principalName]) return false;

            return this.strictStringsMatch(
              principal[principalName] as string | string[],
              context.principal[principalName]
            );
          }
        }
      })
      .every((result) => result);
  }

  checkStringCondition(
    condition: { [key: string]: string | string[] },
    context: RequestContext,
    comparator: (condition: string, contextValue: string) => boolean,
    isIfExists: boolean,
    isNegation: boolean = false
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        const value = condition[contextKey];

        if (isIfExists && !context[contextKey]) return true;

        if (isString(value))
          return comparator(value, context[contextKey] as string);

        if (isNegation)
          return value
            .map((item) => comparator(item, context[contextKey] as string))
            .every((result) => result);

        return value
          .map((item) => comparator(item, context[contextKey] as string))
          .some((result) => result);
      })
      .every((result) => result);
  }

  checkNumericCondition(
    condition: { [key: string]: string | string[] },
    context: RequestContext,
    comparator: (condition: number, contextNumber: number) => boolean,
    isIfExists: boolean
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        if (isIfExists && !context[contextKey]) return true;

        return comparator(
          parseInt(condition[contextKey] as string),
          parseInt(context[contextKey] as string)
        );
      })
      .every((result) => result);
  }

  // Boolean matching
  checkBoolCondition(
    condition: { [key: string]: string | string[] },
    context: RequestContext,
    isIfExists: boolean
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        if (isIfExists && !context[contextKey]) return true;

        return (
          parseBool(condition[contextKey]) === parseBool(context[contextKey])
        );
      })
      .every((result) => result);
  }

  checkDateCondition(
    condition: { [key: string]: string | string[] },
    context: RequestContext,
    comparator: (condition: Date, contextValue: Date) => boolean,
    isIfExists: boolean
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        if (isIfExists && !context[contextKey]) return true;

        return comparator(
          new Date(condition[contextKey] as string),
          new Date(context[contextKey] as string)
        );
      })
      .every((result) => result);
  }

  checkNullCondition(
    condition: { [key: string]: string | string[] },
    context: RequestContext
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        const isExpected = parseBool(condition[contextKey]);
        const isPresent =
          contextKey in context && hasValue(context[contextKey]);

        console.log(`expected: ${isExpected} == ${contextKey}=${isPresent}`);
        return isExpected == isPresent;
      })
      .every((result) => result);
  }

  checkAWSPrincipal(
    allowedPrincipals: string | string[],
    requestPrincipal: string
  ) {
    const check = (allowedPrincipal: string, requestPrincipal: string) => {
      // AWS account principals: only Account ID set in policy
      if (!allowedPrincipal.includes(":"))
        return allowedPrincipal === this.getAccountId(requestPrincipal);

      // AWS account principals: full ARN
      if (allowedPrincipal.includes(":") && !allowedPrincipal.includes("/"))
        return (
          this.getAccountId(allowedPrincipal) ===
          this.getAccountId(requestPrincipal)
        );

      // IAM role/user principals
      if (allowedPrincipal.includes(":") && allowedPrincipal.includes("/"))
        return allowedPrincipal === requestPrincipal;
    };

    // Single entry defined
    if (isString(allowedPrincipals))
      return check(allowedPrincipals, requestPrincipal);

    // Multiple Principals defined
    return allowedPrincipals
      .map((principal) => check(principal, requestPrincipal))
      .some((result) => result);
  }

  arnWildcards(arn: string) {
    return arn
      .split(":")
      .map((part) => (part === "" ? "*" : part))
      .join(":");
  }

  arnMatch(pattern: string, str: string) {
    const patternParts = pattern.split(":");
    const strParts = str.split(":");

    if (patternParts.length !== strParts.length) {
      return false;
    }

    return patternParts
      .map((part, index) => {
        // If the pattern part is empty, it matches any value
        if (!part.length && index !== patternParts.length - 1) return true;
        if (part === "*" && strParts[index].length > 0) return true;

        return this.wildcardMatch(part, strParts[index]);
      })
      .every((result) => result);
  }

  wildcardMatch(pattern: string, str: string) {
    const regex = new RegExp(
      "^" +
        pattern
          .replace(/\?/g, ".") // Replace '?' with '.' (any single character)
          .replace(/\*/g, ".*?") + // Replace '*' with '.*' (any combination of characters)
        "$" // Ensure the whole string matches
    );

    return regex.test(str);
  }

  strictStringsMatch(pattern: string | string[], str: string | string[]) {
    if (isString(pattern)) return pattern === str;
    if (isString(str)) return pattern.includes(str);

    throw new Error("Unsupported array combination");
  }

  getAccountId(arn: string) {
    const parts = arn.split(":");
    if (parts.length < 5) throw new Error(`Invalid ARN: ${arn}`);
    return parts[4];
  }
}
