import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import { z } from 'zod';
import { parseStrictJsonBytes } from '../privacy-explorer/strict-json.js';

// Mirrors the existing typed Rust store_retirement{,_authority} wire owner.
// Object declaration order is significant; JSON objects must never be sorted.
// Integers remain bigint until encoded as exact JSON numeric tokens.
const hash = z.string().regex(/^[0-9a-f]{64}$/u);
const identifier = z
  .string()
  .min(1)
  .refine(
    (v) =>
      Buffer.byteLength(v) <= 256 &&
      !/^[\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]|[\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$/u.test(
        v,
      ) &&
      [...v].every((character) => {
        const point = character.codePointAt(0)!;
        return point > 31 && (point < 127 || point > 159);
      }) &&
      Buffer.from(v).toString('utf8') === v,
  );
const hostIdentifier = z.string().regex(/^[\x21-\x7e]{1,160}$/u);
const u64 = z.bigint().min(1n).max(18446744073709551615n);
const sqlInteger = u64.max(9223372036854775807n);
const store = z.enum(['openpc_facts', 'openpc_candidate_index']);
export const retirementScope = z.strictObject({
  participant_id: identifier,
  privacy_domain_id: identifier,
});
const source = z.strictObject({
  profile_id: identifier,
  generation_id: identifier,
  partition_id: identifier,
  identity_digest: hash,
});
const factRow = z.strictObject({
  candidate_id: identifier,
  fact_id: identifier,
  fact_delta_sequence: u64,
  candidate_feed_sequence: sqlInteger,
  payload_digest: hash,
  payload_bytes: sqlInteger,
  signed_fact_digest: hash,
  lineage_digest: hash,
  checkpoint_digest: hash,
});
const candidateRow = z.strictObject({
  candidate_id: identifier,
  candidate_feed_sequence: sqlInteger,
  payload_digest: hash,
  payload_bytes: sqlInteger,
  checkpoint_digest: hash,
});
export const retirementSelection = z
  .discriminatedUnion('class', [
    z.strictObject({
      class: z.literal('ADMITTED_FACT'),
      source,
      fact_generation_id: identifier,
      canonical_generation: u64,
      rows: z.array(factRow).min(1).max(256),
    }),
    z.strictObject({
      class: z.literal('CANDIDATE_PROJECTION'),
      source,
      rows: z.array(candidateRow).min(1).max(256),
    }),
  ])
  .superRefine((selection, ctx) => {
    const rows = selection.rows;
    const distinct = (values: readonly (string | bigint)[]) =>
      new Set(values).size === values.length;
    if (
      !distinct(rows.map((row) => row.candidate_id)) ||
      rows.some(
        (row, i) => i > 0 && row.candidate_feed_sequence <= rows[i - 1]!.candidate_feed_sequence,
      ) ||
      rows.reduce((sum, row) => sum + row.payload_bytes, 0n) > 9223372036854775807n ||
      (selection.class === 'ADMITTED_FACT' &&
        (!distinct(selection.rows.map((row) => row.fact_id)) ||
          !distinct(selection.rows.map((row) => row.fact_delta_sequence))))
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Retirement selection identity, ordering or size is invalid.',
      });
  });
const governance = z.strictObject({
  retention_policy_digest: hash,
  archive_manifest_digest: hash,
  archive_acknowledgement_digest: hash,
  approval_digest: hash,
  lifecycle_revision: sqlInteger,
  retention_not_before_ms: sqlInteger,
});
export const retirementAttempt = z
  .strictObject({
    scope: retirementScope,
    store,
    business_intent_id: identifier,
    attempt_id: identifier,
    governance,
    selection: retirementSelection,
    selection_digest: hash,
  })
  .superRefine((attempt, ctx) => {
    if (
      attempt.store !==
        (attempt.selection.class === 'ADMITTED_FACT' ? 'openpc_facts' : 'openpc_candidate_index') ||
      attempt.selection_digest !== retirementSelectionDigest(attempt.scope, attempt.selection)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Retirement attempt does not bind its exact selection and store.',
      });
  });
export type StoreRetirementAttempt = z.infer<typeof retirementAttempt>;
export const retirementHost = z.strictObject({
  environment_id: hostIdentifier,
  target_id: hostIdentifier,
  scope: retirementScope,
  store,
});
export type StoreRetirementHost = z.infer<typeof retirementHost>;
const requestClaims = z.strictObject({
  version: z.literal(1n),
  host: retirementHost,
  attempt: retirementAttempt,
  admission_receipt_digest: hash,
  committed_admission_digest: hash,
  issued_at_ms: sqlInteger,
  expires_at_ms: sqlInteger,
});
const cancelClaims = z.strictObject({
  version: z.literal(1n),
  host: retirementHost,
  attempt: retirementAttempt,
  cancellation_id: hostIdentifier,
  lifecycle_revision: sqlInteger,
  committed_cancellation_digest: hash,
  issued_at_ms: sqlInteger,
  expires_at_ms: sqlInteger,
});
const effect = z.discriminatedUnion('state', [
  z.strictObject({
    state: z.literal('APPLIED'),
    retired_rows: u64,
    retired_payload_bytes: u64,
    retained_lineage_digest: hash,
    outbox_event_digest: hash,
  }),
  z.strictObject({
    state: z.literal('REJECTED_NO_EFFECT'),
    rejection: z.enum([
      'SOURCE_CHANGED',
      'GENERATION_CHANGED',
      'REORG_FENCED',
      'CHECKPOINT_INCOMPLETE',
      'READINESS_PROTECTED',
      'PUBLICATION_PROTECTED',
      'REFERENCES_PROTECTED',
      'RETENTION_NOT_ELAPSED',
      'ARCHIVE_MISMATCH',
      'GOVERNANCE_CHANGED',
    ]),
  }),
  z.strictObject({ state: z.literal('CANCELLED_NO_EFFECT') }),
]);
const outcomeClaims = z.strictObject({
  version: z.literal(1n),
  host: retirementHost,
  business_intent_id: identifier,
  attempt_id: identifier,
  outcome: z.strictObject({ attempt_digest: hash, effect }),
  completed_at_ms: sqlInteger,
});
export const retirementPurposes = {
  request: 'openpc:store-retirement-request:v1',
  cancel: 'openpc:store-retirement-cancel:v1',
  outcome: 'openpc:store-retirement-outcome:v1',
} as const;

type WireValue = string | bigint | readonly WireValue[] | { readonly [key: string]: WireValue };
/** Only parsed closed structs are encoded. This is serde declaration order,
 * not the separately used sorted Control definition-JSON encoding. */
export function retirementWireBytes(value: WireValue): Buffer {
  const encode = (item: WireValue): string => {
    if (typeof item === 'bigint') return item.toString();
    if (typeof item === 'string') return JSON.stringify(item);
    if (Array.isArray(item)) return `[${item.map(encode).join(',')}]`;
    return `{${Object.entries(item)
      .map(([key, value]) => `${JSON.stringify(key)}:${encode(value)}`)
      .join(',')}}`;
  };
  const bytes = Buffer.from(encode(value));
  if (bytes.length > 1048576) throw new Error('retirement wire limit');
  return bytes;
}
export const retirementWireDigest = (value: WireValue) =>
  createHash('sha256').update(retirementWireBytes(value)).digest('hex');
export function retirementSelectionDigest(
  scope: z.infer<typeof retirementScope>,
  selection: z.infer<typeof retirementSelection>,
) {
  return retirementWireDigest([
    'OPENPC_STORE_RETIREMENT_SELECTION_V1',
    retirementScope.parse(scope),
    retirementSelection.parse(selection),
  ]);
}
export function retirementAttemptDigest(attempt: StoreRetirementAttempt) {
  return retirementWireDigest([
    'OPENPC_STORE_RETIREMENT_ATTEMPT_V1',
    retirementAttempt.parse(attempt),
  ]);
}

export function parseRetirementWire(bytes: Buffer): unknown {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 1048576)
    throw new Error('retirement wire limit');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  // Reuse strict duplicate-key, Unicode and depth validation without rounding
  // integers. Only numeric tokens outside JSON strings are neutralized here.
  const structural = text.replace(
    /"(?:\\[\s\S]|[^"\\])*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/gu,
    (token) => (token.startsWith('"') ? token : '0'),
  );
  parseStrictJsonBytes(Buffer.from(structural), { maximumDepth: 16 });
  return JSON.parse(text, (_key: string, value: unknown, context?: { source?: string }) => {
    if (typeof value !== 'number') return value;
    if (!context?.source || !/^(?:0|[1-9][0-9]{0,19})$/u.test(context.source))
      throw new Error('retirement integer encoding');
    return BigInt(context.source);
  }) as unknown;
}

const equal = (a: WireValue, b: WireValue) => retirementWireBytes(a).equals(retirementWireBytes(b));
function bindHost(
  host: StoreRetirementHost,
  attempt: StoreRetirementAttempt,
  expected: StoreRetirementHost,
) {
  if (
    !equal(host, retirementHost.parse(expected)) ||
    !equal(host.scope, attempt.scope) ||
    host.store !== attempt.store
  )
    throw new Error('retirement host binding');
}
export function retirementRequestClaims(
  value: unknown,
  expected: StoreRetirementHost,
  nowMs: bigint,
) {
  const claims = requestClaims.parse(value);
  bindHost(claims.host, claims.attempt, expected);
  lifetime(claims, nowMs);
  return claims;
}
export function retirementCancellationClaims(
  value: unknown,
  expected: StoreRetirementHost,
  nowMs: bigint,
) {
  const claims = cancelClaims.parse(value);
  bindHost(claims.host, claims.attempt, expected);
  lifetime(claims, nowMs);
  if (claims.lifecycle_revision < claims.attempt.governance.lifecycle_revision)
    throw new Error('retirement cancellation revision');
  return claims;
}
function lifetime(claims: { issued_at_ms: bigint; expires_at_ms: bigint }, nowMs: bigint) {
  if (
    nowMs < claims.issued_at_ms ||
    nowMs >= claims.expires_at_ms ||
    claims.expires_at_ms <= claims.issued_at_ms ||
    claims.expires_at_ms - claims.issued_at_ms > 60000n
  )
    throw new Error('retirement authority lifetime');
}

export function retirementOutcomeClaims(
  value: unknown,
  expected: StoreRetirementHost,
  original: StoreRetirementAttempt,
) {
  const claims = outcomeClaims.parse(value),
    attempt = retirementAttempt.parse(original);
  bindHost(claims.host, attempt, expected);
  if (
    claims.business_intent_id !== attempt.business_intent_id ||
    claims.attempt_id !== attempt.attempt_id ||
    claims.outcome.attempt_digest !== retirementAttemptDigest(attempt)
  )
    throw new Error('retirement outcome binding');
  const effect = claims.outcome.effect;
  if (
    effect.state === 'APPLIED' &&
    (effect.retired_rows !== BigInt(attempt.selection.rows.length) ||
      effect.retired_payload_bytes !==
        attempt.selection.rows.reduce((sum, row) => sum + row.payload_bytes, 0n))
  )
    throw new Error('retirement physical effect mismatch');
  return claims;
}

const envelope = z.strictObject({
  purpose: z.string(),
  claims: z.unknown(),
  claims_digest: hash,
  signature_p1363_hex: z.string().regex(/^[0-9a-f]{128}$/u),
});
function verifyEnvelope<T extends WireValue>(
  bytes: Buffer,
  key: KeyObject,
  purpose: string,
  parse: (value: unknown) => T,
) {
  const signed = envelope.parse(parseRetirementWire(bytes));
  const claims = parse(signed.claims);
  if (!retirementWireBytes({ ...signed, claims }).equals(bytes))
    throw new Error('retirement canonical wire encoding');
  const publicKey = key.type === 'public' ? key : createPublicKey(key);
  if (
    publicKey.asymmetricKeyType !== 'ec' ||
    publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
    signed.purpose !== purpose ||
    signed.claims_digest !== retirementWireDigest(claims) ||
    !verify(
      'sha256',
      retirementWireBytes([signed.purpose, signed.claims_digest]),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signed.signature_p1363_hex, 'hex'),
    )
  )
    throw new Error('retirement authority signature');
  return claims;
}

export function verifyRetirementRequest(
  bytes: Buffer,
  controlKey: KeyObject,
  host: StoreRetirementHost,
  nowMs: bigint,
) {
  return verifyEnvelope(bytes, controlKey, retirementPurposes.request, (value) =>
    retirementRequestClaims(value, host, nowMs),
  );
}
export function verifyRetirementCancellation(
  bytes: Buffer,
  controlKey: KeyObject,
  host: StoreRetirementHost,
  nowMs: bigint,
) {
  return verifyEnvelope(bytes, controlKey, retirementPurposes.cancel, (value) =>
    retirementCancellationClaims(value, host, nowMs),
  );
}
/** A terminal result is accepted only from the independently installed target
 * key and the exact original attempt. Absence is handled by the durable owner. */
export function verifyRetirementOutcome(
  bytes: Buffer,
  targetKey: KeyObject,
  host: StoreRetirementHost,
  attempt: StoreRetirementAttempt,
) {
  return verifyEnvelope(bytes, targetKey, retirementPurposes.outcome, (value) =>
    retirementOutcomeClaims(value, host, attempt),
  );
}
