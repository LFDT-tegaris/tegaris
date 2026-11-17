import { types } from 'node:util';

const reject = (boundary: string): never => {
  throw new Error(`invalid ${boundary}`);
};

export const requireExactOwnData = (
  value: unknown,
  names: readonly string[],
  boundary: string,
): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value))
    return reject(boundary);
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== names.length ||
    keys.some((key) => typeof key !== 'string' || !names.includes(key))
  )
    return reject(boundary);
  const admitted = Object.create(null) as Record<string, unknown>;
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return reject(boundary);
    admitted[name] = descriptor.value;
  }
  return admitted;
};

export const copyExactUint8Array = (value: unknown, boundary: string): Buffer => {
  if (
    !value ||
    typeof value !== 'object' ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype ||
    !(value instanceof Uint8Array) ||
    value.byteLength === 0
  )
    return reject(boundary);
  return Buffer.from(value);
};
