import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { ContractError } from './errors.js';
import { canonicalJson } from './canonical-json.js';
export { canonicalJson } from './canonical-json.js';

const policyCore = fileURLToPath(
  new URL('../../../../target/debug/openpc-policy-evaluator', import.meta.url),
);

function policyCoreValue(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return Array.from(value);
  if (Array.isArray(value)) return value.map(policyCoreValue);
  if (value !== null && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        policyCoreValue(item),
      ]),
    );
  return value;
}

export interface PcCbor1Value {
  readonly bytes: Buffer;
  readonly digest: Buffer;
}

/** The sole semantic identity path delegates to the shared Rust PC-CBOR-1 core. */
export function pcCbor1(value: unknown): PcCbor1Value {
  const executable = process.env.OPENPC_POLICY_CORE_BIN ?? policyCore;
  if (!existsSync(executable))
    throw new ContractError('PC-POLICY-2003', 'shared policy digest core is unavailable');
  const output = JSON.parse(
    execFileSync(executable, [], {
      encoding: 'utf8',
      input: JSON.stringify({ command: 'DIGEST', value: policyCoreValue(value) }),
      timeout: 10_000,
      windowsHide: true,
    }),
  ) as { identity?: string; digest?: string; bytes?: string };
  if (
    output.identity !== 'PC-CBOR-1' ||
    !output.digest?.match(/^[0-9a-f]{64}$/) ||
    !output.bytes?.match(/^(?:[0-9a-f]{2})+$/)
  )
    throw new ContractError('PC-POLICY-2003', 'unexpected policy digest identity');
  return {
    bytes: Buffer.from(output.bytes, 'hex'),
    digest: Buffer.from(output.digest, 'hex'),
  };
}

export function pcCbor1Digest(value: unknown): string {
  return pcCbor1(value).digest.toString('hex');
}

export function sha256(value: unknown): string {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array)
    return createHash('sha256').update(value).digest('hex');
  return createHash('sha256')
    .update(typeof value === 'string' ? value : canonicalJson(value))
    .digest('hex');
}
