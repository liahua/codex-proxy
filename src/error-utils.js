function serializeUnknown(value, seen) {
  if (value instanceof Error) {
    if (seen.has(value)) {
      return { message: value.message, circular: true };
    }
    seen.add(value);
    const serialized = {
      name: value.name,
      message: value.message
    };
    if (value.stack) {
      serialized.stack = value.stack;
    }
    for (const key of ["code", "errno", "syscall", "address", "port", "type"]) {
      if (value[key] !== undefined) {
        serialized[key] = value[key];
      }
    }
    if ("cause" in value && value.cause !== undefined) {
      serialized.cause = serializeUnknown(value.cause, seen);
    }
    for (const [key, nested] of Object.entries(value)) {
      if (serialized[key] !== undefined) {
        continue;
      }
      serialized[key] = serializeUnknown(nested, seen);
    }
    return serialized;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => serializeUnknown(entry, seen));
  }
  if (value && typeof value === "object") {
    if (seen.has(value)) {
      return "[Circular]";
    }
    seen.add(value);
    return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, serializeUnknown(nested, seen)]));
  }
  return value;
}

export function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

export function serializeError(error) {
  return serializeUnknown(error, new WeakSet());
}

export function logError(prefix, context, error) {
  console.error(prefix, {
    ...context,
    error: serializeError(error)
  });
}
