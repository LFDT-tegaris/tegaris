type JsonValue =
  null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

const isPlainObject = (value: object) => {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

export const immutableJsonCopy = <T>(value: T): T => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite JSON number');
    if (!Number.isSafeInteger(value)) throw new Error('non-canonical JSON number');
    return value;
  }
  if (!value || typeof value !== 'object') throw new Error('non-JSON value');
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    const length = lengthDescriptor?.value;
    if (
      !lengthDescriptor ||
      !('value' in lengthDescriptor) ||
      !Number.isSafeInteger(length) ||
      length < 0 ||
      keys.length !== length + 1
    )
      throw new Error('non-JSON array property');
    const items: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor))
        throw new Error('non-JSON array property');
      items.push(descriptor.value);
    }
    if (
      keys.some(
        (key) => typeof key !== 'string' || (key !== 'length' && !/^(0|[1-9][0-9]*)$/.test(key)),
      )
    )
      throw new Error('non-JSON array property');
    return Object.freeze(items.map(immutableJsonCopy)) as T;
  }
  if (!isPlainObject(value)) throw new Error('non-plain JSON object');
  const keys = Reflect.ownKeys(value);
  const entries = keys.map((key) => {
    if (typeof key !== 'string') throw new Error('non-JSON object property');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor))
      throw new Error('non-JSON object property');
    return [key, descriptor.value] as const;
  });
  const copy = {} as Record<string, JsonValue>;
  for (const [key, entry] of entries)
    Object.defineProperty(copy, key, {
      value: immutableJsonCopy(entry),
      enumerable: true,
      configurable: false,
      writable: false,
    });
  return Object.freeze(copy) as T;
};
