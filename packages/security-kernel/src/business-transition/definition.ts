import { createHash } from 'node:crypto';

/** pc.control.definition-json.v1: canonical bytes of a trusted product definition. */
export function canonicalDefinitionJson(value: unknown): string {
  function encode(item: unknown, depth: number): string {
    if (depth > 32) throw new Error('Definition nesting limit exceeded');
    if (item === null || typeof item === 'boolean') return JSON.stringify(item);
    if (typeof item === 'string') {
      if (item.normalize('NFC') !== item || Buffer.from(item).toString('utf8') !== item)
        throw new Error('Definition string must be valid NFC Unicode');
      return JSON.stringify(item);
    }
    if (typeof item === 'number') {
      if (!Number.isSafeInteger(item) || Object.is(item, -0))
        throw new Error('Definition number must be a safe integer');
      return String(item);
    }
    if (Array.isArray(item)) {
      for (let index = 0; index < item.length; index++)
        if (!Object.hasOwn(item, index)) throw new Error('Definition array contains a hole');
      return `[${item.map((child) => encode(child, depth + 1)).join(',')}]`;
    }
    if (
      typeof item !== 'object' ||
      item === null ||
      Object.getPrototypeOf(item) !== Object.prototype
    )
      throw new Error('Definition must contain only JSON values');
    return `{${Object.keys(item)
      .sort()
      .map(
        (key) =>
          `${encode(key, depth + 1)}:${encode((item as Record<string, unknown>)[key], depth + 1)}`,
      )
      .join(',')}}`;
  }
  return encode(value, 0);
}

export function definitionDigest(value: Readonly<Record<string, unknown>>): Buffer {
  const preimage = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== 'definitionDigest' && key !== 'signature'),
  );
  return createHash('sha256').update(canonicalDefinitionJson(preimage), 'utf8').digest();
}
