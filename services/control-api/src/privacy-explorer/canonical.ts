import { createHash } from 'node:crypto';

const compare = (left: string, right: string) => (left < right ? -1 : left > right ? 1 : 0);

export const canonicalJson = (value: unknown): string => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string')
    return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite scalar');
    if (!Number.isSafeInteger(value)) throw new Error('non-canonical numeric scalar');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!value || typeof value !== 'object') throw new Error('unsupported canonical value');
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort(compare)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
};

export const sha256CanonicalJson = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
