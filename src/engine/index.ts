import { isString, parseBool } from "@/utils/genetic";
import { Action, AWSContext, Condition, Policy, Resource } from "./types";

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
            return this.checkStringEqualsCondition(condition[key], context);
          }
          case "StringNotEquals": {
            return !this.checkStringEqualsCondition(condition[key], context);
          }
          case "StringEqualsIgnoreCase": {
            return this.checkStringEqualsIgnoreCaseCondition(
              condition[key],
              context
            );
          }
          case "StringNotEqualsIgnoreCase": {
            return !this.checkStringEqualsIgnoreCaseCondition(
              condition[key],
              context
            );
          }
          case "StringLike": {
            return this.checkStringLikeCondition(condition[key], context);
          }
          case "StringNotLike": {
            return !this.checkStringLikeCondition(condition[key], context);
          }

          case "ArnLike": {
            return this.checkArnLikeCondition(condition[key], context);
          }

          case "ArnEquals": {
            return this.checkArnLikeCondition(condition[key], context);
          }

          case "ArnNotLike": {
            return !this.checkArnLikeCondition(condition[key], context);
          }

          case "ArnNotEquals": {
            return !this.checkArnLikeCondition(condition[key], context);
          }

          case "NumericEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (condition, value) => value === condition
            );
          }

          case "NumericNotEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (condition, value) => value !== condition
            );
          }

          case "NumericLessThan": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (condition, value) => value < condition
            );
          }

          case "NumericLessThanEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (condition, value) => value <= condition
            );
          }

          case "NumericGreaterThan": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (condition, value) => value > condition
            );
          }

          case "NumericGreaterThanEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (condition, value) => value >= condition
            );
          }

          case "Bool": {
            return this.checkBoolCondition(condition[key], context);
          }

          default: {
            throw new Error(`Unsupported condition: ${key}`);
          }
        }
      })
      .every((success) => success);
  }

  // TODO: Refactor to extract logic and migrate to switch clause
  // Exact matching, case sensitive
  checkStringEqualsCondition(
    condition: { [key: string]: string | string[] },
    context: AWSContext
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        let isAllowed = false;
        const value = condition[contextKey];

        if (isString(value)) {
          if (value === context[contextKey]) {
            isAllowed = true;
          }
        } else {
          for (const item of value) {
            if (item === context[contextKey]) {
              isAllowed = true;
              break;
            }
          }
        }

        return isAllowed;
      })
      .every((result) => result);
  }

  // Exact matching, ignoring case
  checkStringEqualsIgnoreCaseCondition(
    condition: { [key: string]: string | string[] },
    context: AWSContext
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        let isAllowed = false;
        const value = condition[contextKey];

        if (isString(value)) {
          if (
            value.toLocaleLowerCase() ===
            (context[contextKey] as string).toLocaleLowerCase()
          ) {
            isAllowed = true;
          }
        } else {
          for (const item of value) {
            if (
              item.toLocaleLowerCase() ===
              (context[contextKey] as string).toLocaleLowerCase()
            ) {
              isAllowed = true;
              break;
            }
          }
        }

        return isAllowed;
      })
      .every((result) => result);
  }

  // Case-sensitive matching. The values can include multi-character match wildcards (*)
  // and single-character match wildcards (?) anywhere in the string. You must specify
  // wildcards to achieve partial string matches.
  checkStringLikeCondition(
    condition: { [key: string]: string | string[] },
    context: AWSContext
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        let isAllowed = false;
        const value = condition[contextKey];

        if (isString(value)) {
          if (this.wildcardMatch(value, context[contextKey] as string)) {
            isAllowed = true;
          }
        } else {
          for (const item of value) {
            if (this.wildcardMatch(item, context[contextKey] as string)) {
              isAllowed = true;
              break;
            }
          }
        }

        return isAllowed;
      })
      .every((result) => result);
  }

  // Case-sensitive matching of the ARN. Each of the six colon-delimited components
  // of the ARN is checked separately and each can include multi-character match wildcards (*)
  // or single-character match wildcards (?). The ArnEquals and ArnLike condition operators behave identically.
  checkArnLikeCondition(
    condition: { [key: string]: string | string[] },
    context: AWSContext
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        let isAllowed = false;
        const value = condition[contextKey];

        if (isString(value)) {
          if (
            this.wildcardMatch(
              this.arnWildcards(value),
              context[contextKey] as string
            )
          ) {
            isAllowed = true;
          }
        } else {
          for (const item of value) {
            if (
              this.wildcardMatch(
                this.arnWildcards(item),
                context[contextKey] as string
              )
            ) {
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
    comparator: (contextNumber: number, condition: number) => boolean
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

  arnWildcards(arn: string) {
    return arn
      .split(":")
      .map((part) => (part === "" ? "*" : part))
      .join(":");
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
