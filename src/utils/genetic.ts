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
