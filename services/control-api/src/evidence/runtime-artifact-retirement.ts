import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { businessOccurrenceTime } from './business-source.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { readBusinessProvenance } from './receipt-provenance.js';
import { runtimeArtifactArchiveIdentity } from './runtime-artifact-archive-contract.js';
// @ts-expect-error The migration declaration is JavaScript-only; closed profile parsed below.
import { runtimeArtifactRetirementProfile as profileDeclaration } from './runtime-artifact-retirement-guards.mjs';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const profile = z
  .strictObject({
    profileId: z.string(),
    profileVersion: z.literal(1),
    profileDigest: digest,
    actionIntentId: z.string(),
    catalogOperationId: z.string(),
  })
  .parse(profileDeclaration);
export const runtimeArtifactRetirementSelector = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  configurationDigest: digest,
  // Omit to ask whether these bytes have any original retirement in this scope.
  // Supply only for exact historical readback, not new-use denial enforcement.
  runtimeConfigurationInputId: z.uuidv7().optional(),
});
export type RuntimeArtifactRetirementSelector = z.infer<typeof runtimeArtifactRetirementSelector>;
export const runtimeArtifactRetirementMetadata = z.strictObject({
  deletionJobId: z.uuidv7(),
  source: runtimeArtifactArchiveIdentity,
  retirementDigest: digest,
});
export type RuntimeArtifactRetirementMetadata = z.infer<typeof runtimeArtifactRetirementMetadata>;
export const runtimeArtifactRetirementView = z.strictObject({
  selector: runtimeArtifactRetirementSelector,
  status: z.literal('RETIRED'),
  authority: z.literal('NONE'),
  newUse: z.literal('DENIED'),
  servingRestoration: z.literal('DENIED'),
  originalReconciliation: z.literal('ORIGINAL_RESULT_READBACK_ONLY'),
  retirement: runtimeArtifactRetirementMetadata,
  receipt: z.strictObject({
    receiptId: z.uuidv7(),
    operationId: z.string().regex(/^urn:openpc:operation:[0-9a-f-]{36}$/u),
    evidenceId: z.uuidv7(),
    receiptDigest: digest,
    coseDigest: digest,
  }),
});
export class RuntimeArtifactRetirementError extends Error {
  constructor(readonly reason: 'INVALID' | 'UNAVAILABLE' | 'INTEGRITY' = 'UNAVAILABLE') {
    super(`Runtime artifact retirement ${reason}`);
  }
}
/** Canonical data identity only; hashing supplied data creates no effect proof. */
export function runtimeArtifactRetirementDigest(
  value: Omit<RuntimeArtifactRetirementMetadata, 'retirementDigest'>,
) {
  const parsed = runtimeArtifactRetirementMetadata
    .omit({ retirementDigest: true })
    .parse(immutableJsonCopy(value));
  return sha256({ domain: 'pc.evidence.runtime-artifact-retirement.v1', ...parsed });
}
export function parseRuntimeArtifactRetirement(selected: unknown, value: unknown) {
  try {
    const selector = runtimeArtifactRetirementSelector.parse(immutableJsonCopy(selected));
    const row = runtimeArtifactRetirementMetadata.parse(immutableJsonCopy(value));
    if (
      row.source.participantId !== selector.participantId ||
      row.source.privacyDomainId !== selector.privacyDomainId ||
      row.source.configurationDigest !== selector.configurationDigest ||
      (selector.runtimeConfigurationInputId !== undefined &&
        row.source.runtimeConfigurationInputId !== selector.runtimeConfigurationInputId) ||
      row.retirementDigest !==
        runtimeArtifactRetirementDigest({ deletionJobId: row.deletionJobId, source: row.source })
    )
      throw new Error();
    return immutableJsonCopy(row);
  } catch {
    throw new RuntimeArtifactRetirementError('INTEGRITY');
  }
}

/** Binding validation, never signature verification or authorization. Production
 * supplies only the result of readBusinessProvenance, which reads original
 * signing trust, verifies COSE/state and compares all committed outbox events. */
export function assertRuntimeArtifactRetirementReceipt(
  metadata: RuntimeArtifactRetirementMetadata,
  operationId: string,
  value: unknown,
) {
  const receipt = z
    .object({
      authority: z.literal('NONE'),
      integrity: z.literal('VERIFIED_PROFILE_COSE'),
      meaning: z.literal('COMMITTED_BUSINESS_TRANSITION'),
      receiptId: z.uuidv7(),
      operationId: z.string(),
      profileId: z.literal(profile.profileId),
      profileVersion: z.literal('1'),
      profileDigest: z.literal(profile.profileDigest),
      actionIntentId: z.literal(profile.actionIntentId),
      catalogOperationId: z.literal(profile.catalogOperationId),
      aggregateType: z.literal('evidence-deletion'),
      aggregateId: z.uuidv7(),
      before: z.object({ existence: z.literal(0), revision: z.literal('0') }),
      after: z.object({ existence: z.literal(1), revision: z.literal('1') }),
      outboxReferences: z
        .array(z.object({ eventType: z.literal('io.openpc.control.command.committed.v1') }))
        .length(1),
      authorizationReferences: z.array(z.object({ kind: z.number().int() })).length(2),
    })
    .safeParse(value);
  if (
    !z.uuidv7().safeParse(operationId).success ||
    !receipt.success ||
    receipt.data.aggregateId !== metadata.deletionJobId ||
    receipt.data.operationId !== `urn:openpc:operation:${operationId}` ||
    receipt.data.authorizationReferences.filter((r) => r.kind === 3).length !== 1 ||
    receipt.data.authorizationReferences.filter((r) => r.kind === 4).length !== 1
  )
    throw new RuntimeArtifactRetirementError('INTEGRITY');
}

/** Internal scoped historical readback under the real caller's authorization.
 * Requires READ COMMITTED. Take evidence-lifecycle before module/policy/row
 * fences; callers must not enter after locking an input/reference row.
 * A positive result denies new selection and serving even under a different
 * module generation. Missing metadata never grants either. Retained history
 * supports lookup of original outcomes only; it cannot renew, resubmit or serve.
 * No public transport, admission callback or transaction ownership is exposed. */
export async function readRuntimeArtifactRetirement(client: PoolClient, value: unknown) {
  try {
    const selector = runtimeArtifactRetirementSelector.parse(immutableJsonCopy(value));
    const context = await client.query<{ allowed: boolean }>(
      `select openpc.assert_request_context(true),
      openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
      and current_setting('transaction_isolation')='read committed' and current_setting('row_security')='on'
      and current_setting('session_replication_role')='origin' and not r.rolsuper and not r.rolbypassrls allowed
      from pg_roles r where r.rolname=current_user`,
      [selector.participantId, selector.privacyDomainId],
    );
    if (context.rowCount !== 1 || context.rows[0]?.allowed !== true)
      throw new RuntimeArtifactRetirementError();
    await lockEvidenceLifecycle(client, selector.participantId, selector.privacyDomainId);
    await client.query('select openpc.assert_runtime_artifact_retirement_context()');
    const result = await client.query<{ retirement: unknown }>(
      `select jsonb_build_object('deletionJobId',r.deletion_job_id::text,
      'retirementDigest',r.retirement_digest,'source',jsonb_build_object('participantId',r.participant_id::text,
      'privacyDomainId',r.privacy_domain_id::text,'runtimeConfigurationInputId',r.runtime_configuration_input_id::text,
      'moduleInstallationId',r.module_installation_id::text,'moduleConfigurationGenerationId',r.module_configuration_generation_id::text,
      'configurationDigest',r.configuration_digest,'configurationBytes',r.configuration_bytes,'resourceBindingsDigest',r.resource_bindings_digest,
      'createdAt',to_char(r.source_created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))) retirement
      from control.runtime_artifact_retirement r where r.participant_id=$1 and r.privacy_domain_id=$2 and r.configuration_digest=$3
      and ($4::uuid is null or r.runtime_configuration_input_id=$4::uuid)
      order by r.runtime_configuration_input_id,r.deletion_job_id limit 1`,
      [
        selector.participantId,
        selector.privacyDomainId,
        selector.configurationDigest,
        selector.runtimeConfigurationInputId ?? null,
      ],
    );
    if (result.rowCount === 0)
      return immutableJsonCopy({
        selector,
        status: 'NOT_OBSERVED' as const,
        authority: 'NONE' as const,
        newUse: 'NOT_ESTABLISHED' as const,
        servingRestoration: 'NOT_ESTABLISHED' as const,
        originalReconciliation: 'NOT_ESTABLISHED' as const,
        retirement: null,
      });
    if (result.rowCount !== 1) throw new RuntimeArtifactRetirementError('INTEGRITY');
    const retirement = parseRuntimeArtifactRetirement(selector, result.rows[0]!.retirement);
    const committed = await client.query<{
      operationId: string;
      recordId: string;
      recordDigest: string;
      recordedAtNs: string;
      evidenceFormat: string;
    }>(
      `select openpc.assert_runtime_artifact_retirement_committed(r),
      j.operation_id::text as "operationId",e.evidence_record_id::text as "recordId",'sha256:'||encode(sha256(a.cose_sign1),'hex') as "recordDigest",
      a.recorded_at_ns::text as "recordedAtNs",e.evidence_format as "evidenceFormat"
      from control.runtime_artifact_retirement r join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id)
      join control.audit_occurrence a on a.participant_id=j.participant_id and a.privacy_domain_id=j.privacy_domain_id and a.operation_id=j.operation_id
        and a.aggregate_type='evidence-deletion' and a.aggregate_id=j.deletion_job_id
      join control.evidence_record e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id and e.receipt_id=a.receipt_id
        and e.receipt_digest=a.receipt_digest and e.evidence_role='BUSINESS_TRANSITION_RECEIPT' and e.custody='CONTROL_STORE'
      where r.participant_id=$1 and r.privacy_domain_id=$2 and r.deletion_job_id=$3 limit 2`,
      [selector.participantId, selector.privacyDomainId, retirement.deletionJobId],
    );
    if (committed.rowCount !== 1) throw new RuntimeArtifactRetirementError('INTEGRITY');
    const original = committed.rows[0]!;
    const receipt = await readBusinessProvenance(
      client,
      {
        participantId: selector.participantId,
        privacyDomainId: selector.privacyDomainId,
        recordId: original.recordId,
        recordDigest: original.recordDigest,
        occurredAt: businessOccurrenceTime(BigInt(original.recordedAtNs)),
      },
      original.evidenceFormat,
    );
    assertRuntimeArtifactRetirementReceipt(retirement, original.operationId, receipt);
    return immutableJsonCopy({
      selector,
      status: 'RETIRED' as const,
      authority: 'NONE' as const,
      newUse: 'DENIED' as const,
      servingRestoration: 'DENIED' as const,
      originalReconciliation: 'ORIGINAL_RESULT_READBACK_ONLY' as const,
      retirement,
      receipt: {
        receiptId: receipt.receiptId,
        operationId: receipt.operationId,
        evidenceId: original.recordId,
        receiptDigest: receipt.payloadDigest,
        coseDigest: original.recordDigest,
      },
    });
  } catch (error) {
    if (error instanceof RuntimeArtifactRetirementError) throw error;
    throw new RuntimeArtifactRetirementError();
  }
}
