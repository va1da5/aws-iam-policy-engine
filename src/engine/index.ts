import {
  hasValue,
  intersection,
  isArray,
  isObject,
  isString,
  parseBool,
} from "./utils";
import {
  Action,
  Condition,
  Policy,
  Principal,
  RequestContext,
  Resource,
  Statement,
} from "./types";
import ipRangeCheck from "ip-range-check";
import {
  awsAccountIdRegex,
  awsIdentityIdRegex,
  awsRootAccountRegex,
  ConditionSetOperator,
  mutuallyExclusiveElements,
  PolicyType,
  requiredPolicyElements,
  validEffectValues,
  validPartitions,
  validPolicyVersions,
  validStatementElements,
} from "./values";
import { getErrorMessage } from "./utils";

export class IAMPolicyEngine {
  policy: Policy;
  type: PolicyType;

  constructor(policy: Policy, policyType: PolicyType = PolicyType.Identity) {
    this.policy = policy;
    this.type = policyType;
    this.validate();
  }

  validate() {
    requiredPolicyElements.forEach((value) => {
      if (!Object.keys(this.policy).includes(value))
        throw new Error(`Invalid policy format: '${value}' element is missing`);
    });

    if (!validPolicyVersions.includes(this.policy.Version))
      throw new Error(
        `Incorrect policy version. Allowed: ${validPolicyVersions.join(", ")}`,
      );

    if (!this.policy.Statement.length)
      throw new Error("Policy must have at least one statement");

    this.policy.Statement.forEach((statement, index) => {
      const errorMsg = `Invalid statement ${index} format`;

      const statementElements = Object.keys(statement);

      statementElements.forEach((element) => {
        if (!validStatementElements.includes(element))
          throw new Error(
            `${errorMsg}: Unsupported statement element '${element}'`,
          );
      });

      if (!statementElements.includes("Effect"))
        throw new Error(`${errorMsg}: Effect element is required`);

      if (
        !["Action", "NotAction"].filter((element) =>
          statementElements.includes(element),
        ).length
      )
        throw new Error(
          "Missing Action: Add an Action or NotAction element to the policy statement",
        );

      switch (this.type) {
        case PolicyType.Identity: {
          if (
            !intersection(statementElements, ["Resource", "NotResource"]).length
          )
            throw new Error(
              `${errorMsg}: Resource or NotResource element is required`,
            );

          if (
            intersection(statementElements, ["Principal", "NotPrincipal"])
              .length
          )
            throw new Error(
              `${errorMsg}: Principal and NotPrincipal elements are not allowed`,
            );
          break;
        }

        case PolicyType.Resource: {
          if (
            !intersection(statementElements, ["Principal", "NotPrincipal"])
              .length
          )
            throw new Error(
              `${errorMsg}: Principal or NotPrincipal element is required`,
            );

          break;
        }

        case PolicyType.Trust: {
          if (!statementElements.includes("Principal"))
            throw new Error(`${errorMsg}: Principal element is required`);

          if (
            intersection(statementElements, ["Resource", "NotResource"]).length
          )
            throw new Error(
              `${errorMsg}: Resource and NotResource elements are not allowed`,
            );
          break;
        }
      }

      mutuallyExclusiveElements.forEach((elements) => {
        if (intersection(statementElements, elements).length == elements.length)
          throw new Error(
            `${errorMsg}: ${elements.join(" and ")} are mutually exclusive`,
          );
      });

      if (!validEffectValues.includes(statement.Effect))
        throw new Error(
          `${errorMsg}: incorrect Effect definition '${statement.Effect}'`,
        );

      ["Action", "NotAction", "Resource", "NotResource"].forEach((element) => {
        if (!statementElements.includes(element)) return;

        if (!this.validValue(statement[element as keyof Statement]))
          throw new Error(`${errorMsg}: incorrect ${element} definition`);
      });

      ["Resource", "NotResource"].forEach((element) => {
        if (!statementElements.includes(element)) return;

        const value = statement[element as keyof Statement];

        if (!value) return;

        try {
          if (isString(value)) return this.validateArn(value);
          if (isArray(value)) return value.forEach(this.validateArn);
        } catch (error) {
          throw new Error(
            `${errorMsg}: incorrect ${element} definition. ${getErrorMessage(error)}`,
          );
        }
      });
    });
  }

  validValue(value: unknown): boolean {
    if (!hasValue(value)) return false;
    if (isString(value)) return value.length > 0;
    if (isArray(value))
      return value
        .map((v: unknown) => this.validValue(v))
        .every((valid) => valid);
    if (isObject(value)) {
      return Object.keys(value)
        .map((k) => this.validValue(value[k as keyof typeof value]))
        .every((valid) => valid);
    }
    return false;
  }

  evaluate(requestContext: RequestContext) {
    const statements = this.applyVariables(
      this.policy.Statement,
      requestContext,
    );

    const results = statements.map((statement) => {
      const { Effect, Condition, ...elements } = statement;

      const outcome = Object.keys(elements).map((element) => {
        switch (element) {
          case "Sid": {
            return true;
          }

          case "Action": {
            return this.actionMatches(
              requestContext["action"],
              statement[element] as Action,
            );
          }

          case "NotAction": {
            return !this.actionMatches(
              requestContext["action"],
              statement[element] as Action,
            );
          }

          case "Resource": {
            if (!requestContext["resource"]) return false;
            return this.resourceMatches(
              requestContext["resource"],
              statement[element] as Resource,
            );
          }

          case "NotResource": {
            if (!requestContext["resource"]) return false;
            return !this.resourceMatches(
              requestContext["resource"] as string,
              statement[element] as Resource,
            );
          }

          // TODO: handle dead code
          case "Condition": {
            return this.conditionMatches(
              requestContext,
              statement[element] as Condition,
            );
          }

          case "Principal": {
            return this.principalMatches(
              requestContext,
              statement[element] as Principal,
            );
          }

          case "NotPrincipal": {
            return !this.principalMatches(
              requestContext,
              statement[element] as Principal,
            );
          }

          default: {
            throw new Error(`Unsupported statement element: ${element}`);
          }
        }
      });

      // only evaluate conditions when the rest of the parameters match
      if (outcome.every((match) => match) && isObject(Condition)) {
        outcome.push(
          this.conditionMatches(requestContext, Condition as Condition),
        );
      }

      if (outcome.every((match) => match) && Effect == "Deny") return false;

      if (outcome.every((match) => match) && Effect == "Allow") return true;

      return;
    });

    // explicit deny
    if (results.includes(false)) return false;

    // allow
    if (results.includes(true)) return true;

    // implicit deny
    return;
  }

  applyVariables(
    statements: Statement[],
    context: RequestContext,
  ): Statement[] {
    let json = JSON.stringify(statements);

    if (!json.includes("${")) return statements;

    for (const variable of this.getPolicyVariables(json)) {
      const contextValue = context[variable];
      if (!hasValue(contextValue))
        throw new Error(`Context key ${variable} is required by the policy`);

      if (!isString(contextValue))
        throw new Error(
          `Context key ${variable} must be a string value as per policy variable requirement`,
        );

      json = json.replace(
        new RegExp(`\\$\\{${variable}\\}`, "g"),
        contextValue,
      );
    }
    return JSON.parse(json);
  }

  getPolicyVariables(json: string) {
    const regex = /\$\{([^}]+)\}/g;
    const matches = [];
    let match;

    while ((match = regex.exec(json)) !== null) {
      matches.push(match[1]);
    }
    return matches;
  }

  actionMatches(contextAction: string, actions: Action): boolean {
    if (isArray(actions))
      return actions.some((action) => {
        return this.actionMatches(contextAction, action);
      });

    if (actions === "*") return true;

    if (!actions.includes(":"))
      throw new Error(`Invalid Action: The action ${actions} does not exist.`);

    const [service, action] = actions.split(":");

    if (service.includes("*"))
      throw new Error(
        `Invalid Service In Action: The service ${service} specified in the action does not exist`,
      );

    if (!action.length)
      throw new Error(`Invalid Action: The action ${actions} does not exist.`);

    return this.wildcardMatch(actions, contextAction);
  }

  resourceMatches(resource: string, resources: Resource): boolean {
    if (isArray(resources))
      return resources.some((r) => {
        return this.resourceMatches(resource, r);
      });

    if (isString(resources)) {
      if (!resources.length) return false;
      if (resources == "*") return true;
      return this.arnMatch(resources, resource);
    }

    throw new Error("Unsupported resource type");
  }

  conditionMatches(context: RequestContext, condition: Condition) {
    if (!isObject(condition))
      throw new Error(
        "Data Type Mismatch: The text does not match the expected JSON data type Object",
      );

    return Object.keys(condition)
      .map((key) => {
        let operator = key;
        let setOperator = ConditionSetOperator.None;
        const isIfExists = key.endsWith("IfExists");

        if (key.startsWith("ForAllValues:"))
          setOperator = ConditionSetOperator.ForAllValues;

        if (key.startsWith("ForAnyValue:"))
          setOperator = ConditionSetOperator.ForAnyValue;

        operator = operator
          .replace("IfExists", "")
          .replace("ForAllValues:", "")
          .replace("ForAnyValue:", "");

        switch (operator) {
          case "StringEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => value === conditionValue,
              setOperator,
              isIfExists,
            );
          }

          case "StringNotEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => value !== conditionValue,
              setOperator,
              isIfExists,
              true,
            );
          }

          case "StringEqualsIgnoreCase": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.toLocaleLowerCase() ===
                conditionValue.toLocaleLowerCase(),
              setOperator,
              isIfExists,
            );
          }

          case "StringNotEqualsIgnoreCase": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.toLocaleLowerCase() !==
                conditionValue.toLocaleLowerCase(),
              setOperator,
              isIfExists,
              true,
            );
          }

          case "StringLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                this.wildcardMatch(conditionValue, value),
              setOperator,
              isIfExists,
            );
          }

          case "StringNotLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                !this.wildcardMatch(conditionValue, value),
              setOperator,
              isIfExists,
              true,
            );
          }

          case "ArnLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => this.arnMatch(conditionValue, value),
              setOperator,
              isIfExists,
            );
          }

          case "ArnEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => this.arnMatch(conditionValue, value),
              setOperator,
              isIfExists,
            );
          }

          case "ArnNotLike": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => !this.arnMatch(conditionValue, value),
              setOperator,
              isIfExists,
              true,
            );
          }

          case "ArnNotEquals": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => !this.arnMatch(conditionValue, value),
              setOperator,
              isIfExists,
              true,
            );
          }

          case "NumericEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value === conditionValue,
              isIfExists,
            );
          }

          case "NumericNotEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value !== conditionValue,
              isIfExists,
            );
          }

          case "NumericLessThan": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value < conditionValue,
              isIfExists,
            );
          }

          case "NumericLessThanEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value <= conditionValue,
              isIfExists,
            );
          }

          case "NumericGreaterThan": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value > conditionValue,
              isIfExists,
            );
          }

          case "NumericGreaterThanEquals": {
            return this.checkNumericCondition(
              condition[key],
              context,
              (conditionValue, value) => value >= conditionValue,
              isIfExists,
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
              isIfExists,
            );
          }

          case "DateNotEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) =>
                value.getTime() !== conditionValue.getTime(),
              isIfExists,
            );
          }

          case "DateLessThan": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value < conditionValue,
              isIfExists,
            );
          }

          case "DateLessThanEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value <= conditionValue,
              isIfExists,
            );
          }

          case "DateGreaterThan": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value > conditionValue,
              isIfExists,
            );
          }

          case "DateGreaterThanEquals": {
            return this.checkDateCondition(
              condition[key],
              context,
              (conditionValue, value) => value >= conditionValue,
              isIfExists,
            );
          }

          case "IpAddress": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => ipRangeCheck(value, conditionValue),
              setOperator,
              isIfExists,
            );
          }

          case "NotIpAddress": {
            return this.checkStringCondition(
              condition[key],
              context,
              (conditionValue, value) => !ipRangeCheck(value, conditionValue),
              setOperator,
              isIfExists,
              true,
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
            if (!isString(principal.AWS) && !isArray(principal.AWS))
              throw new Error(
                "Data Type Mismatch: The text does not match the expected JSON data type String or String Array.",
              );

            if (!context.principal || !context.principal[principalName])
              return false;

            if (principal[principalName] == "*") return true;

            return this.checkAWSPrincipal(
              principal.AWS,
              context.principal[principalName] as string,
            );
          }

          default: {
            if (!context.principal || !context.principal[principalName])
              return false;
            if (!principal[principalName]) return false;

            return this.strictStringsMatch(
              principal[principalName] as string | string[],
              context.principal[principalName],
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
    setOperator: ConditionSetOperator = ConditionSetOperator.None,
    isIfExists: boolean,
    isNegation: boolean = false,
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        const conditionValue = condition[contextKey];

        if (isIfExists && !context[contextKey]) return true;

        if (setOperator == ConditionSetOperator.None) {
          if (!isString(context[contextKey])) {
            throw new Error(
              `${contextKey} context key is undefined or contains invalid value`,
            );
          }

          if (isString(conditionValue))
            return comparator(conditionValue, context[contextKey] as string);

          if (isNegation)
            return conditionValue
              .map((item) => comparator(item, context[contextKey] as string))
              .every((result) => result);

          return conditionValue
            .map((item) => comparator(item, context[contextKey] as string))
            .some((result) => result);
        }

        if (!context[contextKey]) return true;
        if (context[contextKey]?.length == 0) return true;

        if (isString(context[contextKey]))
          throw new Error(
            `${contextKey} context key must be an array of values`,
          );

        const results = (context[contextKey] as string[]).map(
          (contextValue) => {
            return (
              (conditionValue as string[])
                .map((item) => comparator(item, contextValue))
                .filter((valid) => (isNegation ? !valid : valid)).length > 0
            );
          },
        );

        if (setOperator == ConditionSetOperator.ForAllValues) {
          if (isNegation) return results.every((results) => !results);

          return results.every((result) => result);
        }

        if (setOperator == ConditionSetOperator.ForAnyValue) {
          if (isNegation) return results.some((results) => !results);

          return results.some((result) => result);
        }

        throw new Error(`Unsupported set operator: ${setOperator}`);
      })
      .every((result) => result);
  }

  checkNumericCondition(
    condition: { [key: string]: string | string[] },
    context: RequestContext,
    comparator: (condition: number, contextNumber: number) => boolean,
    isIfExists: boolean,
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        if (isIfExists && !context[contextKey]) return true;

        return comparator(
          parseInt(condition[contextKey] as string),
          parseInt(context[contextKey] as string),
        );
      })
      .every((result) => result);
  }

  checkBoolCondition(
    condition: { [key: string]: string | string[] },
    context: RequestContext,
    isIfExists: boolean,
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
    isIfExists: boolean,
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        if (isIfExists && !context[contextKey]) return true;

        return comparator(
          new Date(condition[contextKey] as string),
          new Date(context[contextKey] as string),
        );
      })
      .every((result) => result);
  }

  checkNullCondition(
    condition: { [key: string]: string | string[] },
    context: RequestContext,
  ) {
    return Object.keys(condition)
      .map((contextKey) => {
        const isNull = parseBool(condition[contextKey]);

        const isDefined =
          contextKey in context &&
          hasValue(context[contextKey]) &&
          (context[contextKey] as string | string[]).length > 0;

        return !isNull == isDefined;
      })
      .every((result) => result);
  }

  checkAWSPrincipal(
    allowedPrincipals: string | string[],
    requestPrincipal: string,
  ): boolean {
    if (isArray(allowedPrincipals))
      return allowedPrincipals
        .map((principal) => this.checkAWSPrincipal(principal, requestPrincipal))
        .some((result) => result);

    if (!isString(allowedPrincipals))
      throw new Error(
        "Data Type Mismatch: The text does not match the expected JSON data type String or String Array.",
      );

    const allowedPrincipal = allowedPrincipals as string;

    if (allowedPrincipal.length > 1 && allowedPrincipal.includes("*"))
      throw new Error(
        "Unsupported Wildcard In Principal: Wildcards (*, ?) are not supported with the principal key AWS. Replace the wildcard with a valid principal value.",
      );

    // AWS account principals: only Account ID set in policy
    if (awsAccountIdRegex.test(allowedPrincipal))
      return allowedPrincipal === this.getAccountId(requestPrincipal);

    if (awsIdentityIdRegex.test(allowedPrincipal))
      return allowedPrincipal === requestPrincipal;

    if (awsRootAccountRegex.test(allowedPrincipal))
      // AWS account principals: full ARN
      return (
        this.getAccountId(allowedPrincipal) ===
        this.getAccountId(requestPrincipal)
      );

    // IAM role/user principals
    if (allowedPrincipal.includes(":") && allowedPrincipal.includes("/"))
      return allowedPrincipal === requestPrincipal;

    throw new Error(`Unsupported Principal: ${allowedPrincipal}`);
  }

  arnWildcards(arn: string) {
    return arn
      .split(":")
      .map((part) => (part === "" ? "*" : part))
      .join(":");
  }

  validateArn(arn: string) {
    if (arn == "*") return true;

    // prevent split of AWS variables
    arn = arn.replace(/\$\{([^}]+)\}/g, "${variable-placeholder}");
    const parts = arn.split(":");

    if (parts.length != 6) throw new Error(`Invalid ARN: "${arn}"`);

    const [prefix, partition, service, region, accountId, resource] = parts;

    if (prefix != "arn") throw new Error(`Invalid ARN: "${arn}"`);

    if (!validPartitions.includes(partition))
      throw new Error(
        `Invalid ARN partition "${partition}". Supported values ${validPartitions.join(", ")}.`,
      );

    if (!service.length || service != service.toLowerCase()) {
      throw new Error(`Invalid ARN service: "${service}"`);
    }

    if (region != region.toLocaleLowerCase())
      throw new Error(`Invalid ARN region: ${region}`);

    if (accountId.length && accountId != "*" && !/\d{12}/.test(accountId))
      throw new Error(`Invalid ARN account ID: "${accountId}"`);

    if (!resource.length) throw new Error(`Empty ARN resource part`);
  }

  arnMatch(pattern: string, str: string) {
    if (pattern == "*") return true;

    const patternParts = pattern.split(":");
    const strParts = str.split(":");

    if (patternParts.length !== strParts.length) {
      return false;
    }

    return patternParts
      .map((part, index) => {
        // If the part is empty and is either region or account ID and is empty
        if (!part.length && [3, 4].includes(index)) return true;
        if (part === "*" && strParts[index].length > 0) return true;
        return this.wildcardMatch(part, strParts[index], true);
      })
      .every((result) => result);
  }

  wildcardMatch(pattern: string, str: string, caseSensitive: boolean = false) {
    const regex = new RegExp(
      "^" +
        pattern
          .replace(/\?/g, ".") // Replace '?' with '.' (any single character)
          .replace(/\*/g, ".*?") + // Replace '*' with '.*' (any combination of characters)
        "$", // Ensure the whole string matches
      caseSensitive ? undefined : "i",
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
