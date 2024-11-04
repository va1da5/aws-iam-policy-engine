export function isString(variable: unknown) {
  return typeof variable === "string";
}

export function isArray(variable: unknown) {
  return Array.isArray(variable);
}

export function isObject(variable: unknown) {
  return typeof variable === "object" && variable !== null;
}

export function isBoolean(variable: unknown) {
  return typeof variable === "boolean";
}

export function isNumber(variable: unknown) {
  return typeof variable === "number";
}

export function isUndefined(variable: unknown) {
  return typeof variable === "undefined";
}

export function isNull(variable: unknown) {
  return variable === null;
}

export function parseBool(variable: unknown) {
  if (isString(variable)) {
    return variable.toLowerCase() === "true";
  }

  return !!variable;
}

export function hasValue(variable: unknown) {
  return !isUndefined(variable) && !isNull(variable);
}

export function intersection<T>(arr1: T[], arr2: T[]) {
  return arr1.filter((value) => arr2.includes(value));
}

export function getErrorMessage(error: unknown) {
  if (error instanceof Error) return error.message;
  return String(error);
}
