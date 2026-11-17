import { createHash } from 'node:crypto';
import { pcCbor1 } from './digest.js';

const identity = 'PC-POLICY-EVALUATOR-1/PC-CBOR-1';
const denial = 'TYPED_RPC_POLICY_DENY';

/** A completed restrictive prediction is still DENIED. Only evaluator-owned
 * explicit RPC denial with complete remaining contributions can support release. */
export function isReleaseSimulation(input: {
  truthState: unknown;
  authorityLabel: unknown;
  resultDocument?: unknown;
  inputDigest?: Buffer;
  resultDigest?: Buffer;
}): boolean {
  if (input.authorityLabel !== 'SIMULATION_ONLY') return false;
  if (input.truthState === 'SUCCESS') return true;
  const result = input.resultDocument;
  if (
    input.truthState !== 'DENIED' ||
    !result ||
    typeof result !== 'object' ||
    Array.isArray(result)
  )
    return false;
  const row = result as Record<string, unknown>;
  if (
    row.evaluatorIdentity !== identity ||
    row.truthState !== 'DENIED' ||
    !['permissions', 'obligations', 'conflicts'].every(
      (key) => Array.isArray(row[key]) && row[key].length === 0,
    ) ||
    !Array.isArray(row.explanationCodes) ||
    row.explanationCodes.length !== 1 ||
    row.explanationCodes[0] !== denial ||
    !Buffer.isBuffer(input.inputDigest) ||
    !Buffer.isBuffer(input.resultDigest) ||
    row.inputDigest !== input.inputDigest.toString('hex') ||
    row.resultDigest !== input.resultDigest.toString('hex') ||
    typeof row.inputBytes !== 'string' ||
    !/^(?:[0-9a-f]{2})+$/.test(row.inputBytes) ||
    typeof row.resultBytes !== 'string' ||
    !/^(?:[0-9a-f]{2})+$/.test(row.resultBytes)
  )
    return false;
  const hash = (hex: string) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  if (
    !hash(row.inputBytes).equals(input.inputDigest) ||
    !hash(row.resultBytes).equals(input.resultDigest)
  )
    return false;
  try {
    return pcCbor1({
      evaluatorIdentity: row.evaluatorIdentity,
      truthState: row.truthState,
      permissions: row.permissions,
      obligations: row.obligations,
      conflicts: row.conflicts,
      explanationCodes: row.explanationCodes,
      inputDigest: row.inputDigest,
    }).bytes.equals(Buffer.from(row.resultBytes, 'hex'));
  } catch {
    return false;
  }
}

/** Selection is followed by canonical-byte verification at the lifecycle owner.
 * Digest, authority and dependency joins are retained by every caller. */
export function releaseSimulationSql(alias: string): string {
  if (!/^[a-z][a-z0-9_]*$/.test(alias)) throw new Error('Invalid simulation SQL owner');
  return `(${alias}.truth_state='SUCCESS' OR (${alias}.truth_state='DENIED'
    AND ${alias}.result_document->>'evaluatorIdentity'='${identity}'
    AND ${alias}.result_document->>'truthState'='DENIED'
    AND ${alias}.result_document->'permissions'='[]'::jsonb
    AND ${alias}.result_document->'obligations'='[]'::jsonb
    AND ${alias}.result_document->'conflicts'='[]'::jsonb
    AND ${alias}.result_document->'explanationCodes'='["${denial}"]'::jsonb
    AND ${alias}.result_document->>'inputDigest'=encode(${alias}.input_digest,'hex')
    AND ${alias}.result_document->>'resultDigest'=encode(${alias}.result_digest,'hex')))`;
}
