import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../digest.js';
import type { ProviderRetryQualificationScope } from './provider-retry-qualification.js';

export type ProviderRetryProbeScope = ProviderRetryQualificationScope;
const uuid = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const scopeSchema = z.strictObject({ participantId: uuid, privacyDomainId: uuid, requestId: uuid });
const referenceSchema = z.strictObject({
  providerProfileId: uuid,
  observationId: uuid,
  qualificationWorkId: uuid,
  operationId: uuid,
  artifactDigest: digest,
  configurationDigest: digest,
  observationDigest: digest,
  resultReceiptDigest: digest,
  resultEventId: uuid,
  authorizationEvidenceDigest: digest,
});
export type ProviderRetryProbeReference = Readonly<z.infer<typeof referenceSchema>>;
export function parseProviderRetryProbeReference(value: unknown): ProviderRetryProbeReference {
  return Object.freeze(referenceSchema.parse(value));
}
export class ProviderRetryProbeSourceError extends Error {
  constructor(
    readonly code:
      | 'OPS_PROVIDER_PROBE_SOURCE_CONTEXT'
      | 'OPS_PROVIDER_PROBE_SOURCE_CHANGED'
      | 'OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE',
  ) {
    super(code);
  }
}
const unavailable = (): never => {
  throw new ProviderRetryProbeSourceError('OPS_PROVIDER_PROBE_SOURCE_UNAVAILABLE');
};
const changed = (): never => {
  throw new ProviderRetryProbeSourceError('OPS_PROVIDER_PROBE_SOURCE_CHANGED');
};
const ordinal = z.string().regex(/^[1-9][0-9]{0,18}$/u);
const millis = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,15})$/u)
  .refine((s) => Number.isSafeInteger(Number(s)));
const bytesHex = z
  .string()
  .min(2)
  .max(8 * 1024 * 1024)
  .regex(/^(?:[0-9a-f]{2})+$/u);
const historySchema = z.strictObject({
  reference: referenceSchema,
  participantId: uuid,
  privacyDomainId: uuid,
  workState: z.enum(['COMPLETED', 'FAILED']),
  sourceRevision: ordinal,
  observedRevision: ordinal,
  validUntilMs: millis,
  completedAtMs: millis,
  observation: z.record(z.string(), z.unknown()),
  resultReceipt: z.record(z.string(), z.unknown()),
  resultPayloadHex: bytesHex,
  authorizationEvidenceHex: bytesHex,
  authorizationCoseHex: bytesHex,
});
/** Historical evidence only, including when returned inside withCurrent. The
 * authorization COSE is the original mutation signature, not a result/operations
 * receipt. No value in this record grants authority after the callback ends. */
export type ProviderRetryProbeHistory = Readonly<z.infer<typeof historySchema>>;
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function history(
  value: unknown,
  scope: ProviderRetryProbeScope,
  reference: ProviderRetryProbeReference,
): ProviderRetryProbeHistory {
  const result = historySchema.parse(value);
  if (
    result.participantId !== scope.participantId ||
    result.privacyDomainId !== scope.privacyDomainId ||
    canonicalJson(result.reference) !== canonicalJson(reference) ||
    BigInt(result.observedRevision) !== BigInt(result.sourceRevision) + 1n
  )
    return unavailable();
  const payload = Buffer.from(result.resultPayloadHex, 'hex');
  if (
    payload.toString('utf8') !== canonicalJson(result.resultReceipt) ||
    sha256(payload) !== reference.resultReceiptDigest ||
    sha256(Buffer.from(result.authorizationEvidenceHex, 'hex')) !==
      reference.authorizationEvidenceDigest
  )
    return unavailable();
  if (result.workState === 'COMPLETED') {
    const artifact = z
      .array(z.number().int().min(0).max(255))
      .min(1)
      .max(4 * 1024 * 1024)
      .parse(result.resultReceipt.artifactCbor);
    if (
      sha256(Buffer.from(artifact)) !== reference.artifactDigest ||
      result.resultReceipt.liveObservationId !== reference.observationId ||
      result.resultReceipt.liveObservationDigest !== reference.observationDigest ||
      canonicalJson(result.resultReceipt.liveObservation) !== canonicalJson(result.observation)
    )
      return unavailable();
  }
  return freeze(result);
}
async function context(client: PoolClient, scope: ProviderRetryProbeScope) {
  await client.query('select openpc.assert_request_context(true)');
  const row = (
    await client.query<{
      role: string;
      isolation: string;
      rls: string;
      mode: string;
      participant: string;
      privacy: string;
      request: string;
      action: string;
      transaction: string;
      backend: number;
    }>(`select current_user::text role,current_setting('transaction_isolation') isolation,
    current_setting('row_security') rls,current_setting('openpc.context_mode',true) mode,
    current_setting('openpc.participant_id',true) participant,current_setting('openpc.privacy_domain_id',true) privacy,
    current_setting('openpc.operation_id',true) request,current_setting('openpc.action_intent_id',true) action,
    pg_current_xact_id()::text transaction,pg_backend_pid() backend`)
  ).rows[0];
  if (
    !row ||
    !['openpc_control_owner', 'openpc_operations_qualification_owner'].includes(row.role) ||
    row.isolation !== 'read committed' ||
    row.rls !== 'on' ||
    row.mode !== 'PARTICIPANT' ||
    row.participant !== scope.participantId ||
    row.privacy !== scope.privacyDomainId ||
    row.request !== scope.requestId ||
    row.action !== 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
  )
    throw new ProviderRetryProbeSourceError('OPS_PROVIDER_PROBE_SOURCE_CONTEXT');
  return row;
}
/** Caller owns an already scoped transaction. Expired or failed originals remain
 * readable, but missing/mixed identities and result lineage always fail closed. */
export async function readProviderRetryProbeOriginal(
  client: PoolClient,
  scope: ProviderRetryProbeScope,
  reference: ProviderRetryProbeReference,
): Promise<ProviderRetryProbeHistory> {
  const s = scopeSchema.parse(scope),
    ref = parseProviderRetryProbeReference(reference);
  const before = await context(client, s);
  const result = await client.query<{ history: unknown }>(
    'select openpc.read_provider_retry_probe_source($1::jsonb) history',
    [JSON.stringify(ref)],
  );
  if (canonicalJson(await context(client, s)) !== canonicalJson(before)) return changed();
  if (result.rowCount !== 1) return unavailable();
  return history(result.rows[0]!.history, s, ref);
}
const currentSchema = z.strictObject({
  history: z.unknown(),
  configurationInputId: uuid,
  moduleInstallationId: uuid,
  moduleConfigurationGenerationId: uuid,
});
/** Database-only consumption while real source fences remain held on this exact
 * transaction. No pool, role switch, BEGIN/COMMIT, network I/O or receipt issuance.
 * Caller MUST roll back the transaction on failure and release it afterwards. */
export async function withCurrentProviderRetryProbeSource<T>(
  client: PoolClient,
  scope: ProviderRetryProbeScope,
  reference: ProviderRetryProbeReference,
  consume: (sameClient: PoolClient, original: ProviderRetryProbeHistory) => Promise<T>,
): Promise<T> {
  const s = scopeSchema.parse(scope),
    ref = parseProviderRetryProbeReference(reference);
  const beforeContext = await context(client, s);
  const sameContext = async () => {
    if (canonicalJson(await context(client, s)) !== canonicalJson(beforeContext)) return changed();
  };
  await sameContext(); // Reject autocommit before either locks or consumption.
  const current = async () => {
    const result = await client.query<{ source: unknown }>(
      'select openpc.lock_provider_retry_probe_source($1::jsonb) source',
      [JSON.stringify(ref)],
    );
    if (result.rowCount !== 1) return unavailable();
    const source = currentSchema.parse(result.rows[0]!.source);
    const original = history(source.history, s, ref);
    if (original.workState !== 'COMPLETED') return unavailable();
    return { ...source, history: original };
  };
  const before = await current();
  await sameContext();
  const release = client.release;
  let releaseAttempted = false;
  const heldRelease: PoolClient['release'] = () => {
    releaseAttempted = true;
    return changed();
  };
  // PoolClient.release is public. Prevent accidentally returning this live,
  // transaction-owning client to its pool while the callback is still running.
  client.release = heldRelease;
  try {
    const result = await consume(client, before.history);
    if (releaseAttempted || client.release !== heldRelease) return changed();
    await sameContext();
    if (canonicalJson(await current()) !== canonicalJson(before)) return changed();
    await sameContext();
    return result;
  } finally {
    client.release = release;
  }
}
