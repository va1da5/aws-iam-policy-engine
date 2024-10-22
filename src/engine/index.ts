import { isString, parseBool } from "@/utils/genetic";
import { Action, AWSContext, Condition, Policy, Resource } from "./types";
import ipRangeCheck from "ip-range-check";

export class IAMPolicyEngine {
  policy: Policy;

  constructor(policy: Policy) {
    this.policy = policy;
  }

  // Main method to evaluate access
  evaluate({ action, resource }: { action: string; resource: string }) {
    const statements = this.policy.Statement;

    let isAllowed = false;

    for (const statement of statements) {
      const { Effect, Action, Resource } = statement; //Condition

      // Check if the action matches
      const actionMatches = this.actionMatches(action, Action);
      // Check if the resource matches
      const resourceMatches = this.resourceMatches(resource, Resource);
      // Check if the conditions are satisfied
      //   const conditionsSatisfied = this.checkConditions(Condition, sourceIp);

      if (actionMatches && resourceMatches) {
        // && conditionsSatisfied
        if (Effect === "Allow") {
          isAllowed = true;
        } else if (Effect === "Deny") {
          return false; // Deny takes precedence
        }
      }
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

  conditionMatches(context: AWSContext, condition: Condition) {
    if (!condition) return true;

    return Object.keys(condition)
      .map((key) => {
        switch (key) {
          case "StringEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => value === conditionValue
            );
          }

          case "StringNotEquals": {
            return !this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => value === conditionValue
            );
          }

          case "StringEqualsIgnoreCase": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.toLocaleLowerCase() === conditionValue.toLocaleLowerCase()
            );
          }

          case "StringNotEqualsIgnoreCase": {
            return !this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.toLocaleLowerCase() === conditionValue.toLocaleLowerCase()
            );
          }

          case "StringLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                this.wildcardMatch(conditionValue, value)
            );
          }

          case "StringNotLike": {
            return !this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                this.wildcardMatch(conditionValue, value)
            );
          }

          case "ArnLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => this.arnMatch(conditionValue, value)
            );
          }

          case "ArnEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => this.arnMatch(conditionValue, value)
            );
          }

          case "ArnNotLike": {
            return !this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => this.arnMatch(conditionValue, value)
            );
          }

          case "ArnNotEquals": {
            return !this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => this.arnMatch(conditionValue, value)
            );
          }

          case "NumericEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value === conditionValue
            );
          }

          case "NumericNotEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value !== conditionValue
            );
          }

          case "NumericLessThan": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value < conditionValue
            );
          }

          case "NumericLessThanEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value <= conditionValue
            );
          }

          case "NumericGreaterThan": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value > conditionValue
            );
          }

          case "NumericGreaterThanEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value >= conditionValue
            );
          }

          case "Bool": {
            return this.checkBoolCondition(condition[key], context);
          }

          case "DateEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.getTime() === conditionValue.getTime()
            );
          }

          case "DateNotEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.getTime() !== conditionValue.getTime()
            );
          }

          case "DateLessThan": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value < conditionValue
            );
          }

          case "DateLessThanEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value <= conditionValue
            );
          }

          case "DateGreaterThan": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value > conditionValue
            );
          }

          case "DateGreaterThanEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value >= conditionValue
            );
          }

          case "IpAddress": {
            return this.checkIpAddressCondition(condition[key], context);
          }

          case "NotIpAddress": {
            return !this.checkIpAddressCondition(condition[key], context);
          }

          default: {
            throw new Error(`Unsupported condition: ${key}`);
          }
        }
      })
      .every((success) => success);
  }

  checkStringCondition(
    condition: { [key: string]: string | string[] },
    context: AWSContext,
    comparator: (condition: string, contextValue: string) => boolean
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        let isAllowed = false;
        const value = condition[contextKey];

        if (isString(value)) {
          if (comparator(value, context[contextKey] as string)) {
            isAllowed = true;
          }
        } else {
          for (const item of value) {
            if (comparator(item, context[contextKey] as string)) {
              isAllowed = true;
              break;
            }
          }
        }

        return isAllowed;
      })
      .every((result) => result);
  }

  checkNumericCondition(
    condition: { [key: string]: string | string[] },
    context: AWSContext,
    comparator: (condition: number, contextNumber: number) => boolean
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
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
    context: AWSContext
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        return (
          parseBool(condition[contextKey]) === parseBool(context[contextKey])
        );
      })
      .every((result) => result);
  }

  checkDateCondition(
    condition: { [key: string]: string | string[] },
    context: AWSContext,
    comparator: (condition: Date, contextValue: Date) => boolean
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        return comparator(
          new Date(condition[contextKey] as string),
          new Date(context[contextKey] as string)
        );
      })
      .every((result) => result);
  }

  checkIpAddressCondition(
    condition: { [key: string]: string | string[] },
    context: AWSContext
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        let isAllowed = false;
        const value = condition[contextKey];

        if (isString(value)) {
          if (ipRangeCheck(context[contextKey] as string, value)) {
            isAllowed = true;
          }
        } else {
          for (const item of value) {
            if (ipRangeCheck(context[contextKey] as string, item)) {
              isAllowed = true;
              break;
            }
          }
        }

        return isAllowed;
      })
      .every((result) => result);
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
    // Convert the pattern into a regular expression
    const regex = new RegExp(
      "^" +
        pattern
          .replace(/\?/g, ".") // Replace '?' with '.' (any single character)
          .replace(/\*/g, ".*?") + // Replace '*' with '.*' (any combination of characters)
        "$" // Ensure the whole string matches
    );

    return regex.test(str);
  }
}
