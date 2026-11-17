import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  handoverPossessionGenerationSchema,
  handoverPossessionGenerationDigest,
  handoverPossessionGenerationRequestSchema,
  type HandoverPossessionGeneration,
  type HandoverPossessionGenerationRequest,
} from '../domain/workload-signing-handover-possession.js';
import {
  canonical,
  hash,
  tagged,
  fail,
  type WorkloadSigningHandoverAttemptScope,
} from './workload-signing-handover-custody.js';

export interface HandoverGenerationRow {
  handoverId: string;
  generationId: string;
  operationId: string;
  makerPrincipalId: string;
  idempotencyKey: string;
  supersedesGenerationId: string | null;
  request: HandoverPossessionGenerationRequest;
  requestCanonical: Buffer;
  requestDigest: Buffer;
  document: HandoverPossessionGeneration;
  documentCanonical: Buffer;
  documentDigest: Buffer;
  createdAt: Date;
}
export const handoverGenerationColumns = `handover_id::text as "handoverId",generation_id::text as "generationId",operation_id::text as "operationId",maker_principal_id::text as "makerPrincipalId",idempotency_key as "idempotencyKey",supersedes_generation_id::text as "supersedesGenerationId",request,request_canonical as "requestCanonical",request_digest as "requestDigest",document,document_canonical as "documentCanonical",document_digest as "documentDigest",created_at as "createdAt"`;
export function authenticateHandoverGeneration(row: HandoverGenerationRow) {
  const request = handoverPossessionGenerationRequestSchema.parse(row.request),
    document = handoverPossessionGenerationSchema.parse(row.document);
  if (
    document.handoverId !== row.handoverId ||
    document.generationId !== row.generationId ||
    document.operationId !== row.operationId ||
    document.makerPrincipalId !== row.makerPrincipalId ||
    document.supersedesGenerationId !== row.supersedesGenerationId ||
    request.supersedesGenerationId !== row.supersedesGenerationId ||
    !canonical(request).equals(row.requestCanonical) ||
    !hash(
      'pc.identity.workload-signing-handover.possession-generation-request.v1',
      row.requestCanonical,
    ).equals(row.requestDigest) ||
    !canonical(document).equals(row.documentCanonical) ||
    handoverPossessionGenerationDigest(document) !== tagged(row.documentDigest)
  )
    fail('CORRUPT');
  return { ...row, request, document };
}
/** Historical custody read. Current authority is checked by effect owners, not
 * by collectors retaining a delayed response to an original proof command. */
export async function loadWorkloadSigningHandoverGeneration(
  client: PoolClient,
  scope: WorkloadSigningHandoverAttemptScope,
  generationId: string,
) {
  const selected = await client.query<HandoverGenerationRow>(
    `select ${handoverGenerationColumns} from control.workload_signing_handover_generation where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3`,
    [scope.participantId, scope.privacyDomainId, z.uuidv7().parse(generationId)],
  );
  if (selected.rowCount !== 1) fail('NOT_FOUND');
  const row = authenticateHandoverGeneration(selected.rows[0]!);
  if (
    row.document.participantId !== scope.participantId ||
    row.document.privacyDomainId !== scope.privacyDomainId
  )
    fail('CORRUPT');
  const owner = await client.query<{
    sourceDigest: Buffer;
    issuer: unknown;
    makerPrincipalId: string;
    environmentId: string;
  }>(
    `select source_digest as "sourceDigest",source->'issuer' as issuer,maker_principal_id::text as "makerPrincipalId",environment_id as "environmentId"
     from control.workload_signing_handover where participant_id=$1 and privacy_domain_id=$2 and handover_id=$3`,
    [scope.participantId, scope.privacyDomainId, row.handoverId],
  );
  if (owner.rowCount !== 1) fail('CORRUPT');
  const parent = owner.rows[0]!;
  if (
    row.document.sourceDigest !== tagged(parent.sourceDigest) ||
    !canonical(row.document.issuer).equals(canonical(parent.issuer)) ||
    row.makerPrincipalId !== parent.makerPrincipalId ||
    row.document.environmentId !== parent.environmentId
  )
    fail('CORRUPT');
  return row;
}

/** Later uncertainty cannot erase confirmation. Any different retained answer
 * blocks new proof effects, even when the generation captured an earlier one. */
export async function assertHandoverGenerationPreparationsStable(
  client: PoolClient,
  scope: WorkloadSigningHandoverAttemptScope,
  document: HandoverPossessionGeneration,
) {
  for (const key of document.keys) {
    const result = await client.query<{ confirmed: boolean }>(
      `select exists(
      select 1 from control.workload_signing_handover_attempt a
      join control.workload_signing_handover_dispatch d on d.participant_id=a.participant_id and d.privacy_domain_id=a.privacy_domain_id and d.attempt_id=a.attempt_id
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.handover_id=$3 and a.attempt_id=$4 and a.stage='PREPARATION'
       and a.binding=$5::jsonb and a.attempt=$6::jsonb
       and exists(select 1 from control.workload_signing_handover_observation o where o.participant_id=a.participant_id and o.privacy_domain_id=a.privacy_domain_id and o.attempt_id=a.attempt_id and o.result->>'state'='OBSERVED' and o.result->'observation'=$7::jsonb)
       and not exists(select 1 from control.workload_signing_handover_observation o where o.participant_id=a.participant_id and o.privacy_domain_id=a.privacy_domain_id and o.attempt_id=a.attempt_id and o.result->>'state'='OBSERVED' and o.result->'observation' is distinct from $7::jsonb)) as confirmed`,
      [
        scope.participantId,
        scope.privacyDomainId,
        document.handoverId,
        key.attempt.request.attemptId,
        key.binding,
        key.attempt,
        key.observation,
      ],
    );
    if (result.rows[0]?.confirmed !== true) fail('CONFLICT');
  }
}
export async function assertHandoverGenerationCanDispatch(
  client: PoolClient,
  scope: WorkloadSigningHandoverAttemptScope,
  document: HandoverPossessionGeneration,
) {
  const selected = await client.query<{ nowNs: string; superseded: boolean }>(
    `select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::numeric(20,0)::text as "nowNs",exists(select 1 from control.workload_signing_handover_generation where participant_id=$1 and privacy_domain_id=$2 and supersedes_generation_id=$3) as superseded`,
    [scope.participantId, scope.privacyDomainId, document.generationId],
  );
  const current = selected.rows[0]!;
  if (
    current.superseded ||
    BigInt(current.nowNs) < BigInt(document.issuedAtNs) ||
    BigInt(current.nowNs) >= BigInt(document.expiresAtNs)
  )
    fail('CONFLICT');
  await assertHandoverGenerationPreparationsStable(client, scope, document);
}
