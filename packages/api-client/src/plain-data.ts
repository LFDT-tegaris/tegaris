const scalar = (value: unknown): value is null | boolean | number | string =>
  value === null ||
  typeof value === 'boolean' ||
  typeof value === 'string' ||
  (typeof value === 'number' && Number.isFinite(value));

export const immutablePlainCopy = <T>(value: T): T => {
  if (scalar(value)) return value;
  if (!value || typeof value !== 'object') throw new Error('non-plain response');
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== value.length + 1 ||
      !keys.includes('length') ||
      !keys.every((key) => key === 'length' || (typeof key === 'string' && /^\d+$/.test(key)))
    )
      throw new Error('non-plain response');
    const result = value.map((_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor))
        throw new Error('non-plain response');
      return immutablePlainCopy(descriptor.value);
    });
    return Object.freeze(result) as T;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error('non-plain response');
  const result = {} as Record<PropertyKey, unknown>;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('non-plain response');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor))
      throw new Error('non-plain response');
    Object.defineProperty(result, key, {
      value: immutablePlainCopy(descriptor.value),
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(result) as T;
};
