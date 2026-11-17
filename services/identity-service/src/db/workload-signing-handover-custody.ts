import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import {
  workloadSigningHandoverRequestSchema,
  type WorkloadSigningHandoverRequest,
} from '../contracts/workload-signing-handover.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import type { captureWorkloadSigningHandoverSource } from './workload-signing-handover-source.js';
import { fenceBoundAuthorities, type BoundAuthority } from './authority-fence.js';
import { captureAuthoritySnapshot } from './authority-snapshot.js';

export type Source = Awaited<ReturnType<typeof captureWorkloadSigningHandoverSource>>['document'];
export interface WorkloadSigningHandoverScope {
  participantId: string;
  privacyDomainId: string;
  authority: BoundAuthority;
  environmentId: string;
  verifier: IdentityRuntimeVerifier;
}
export class WorkloadSigningHandoverStoreError extends Error {
  constructor(readonly code: 'DENIED' | 'CONFLICT' | 'NOT_FOUND' | 'CORRUPT') {
    super(`Workload signing handover ${code.toLowerCase()}`);
  }
}
export function fail(
  code: ConstructorParameters<typeof WorkloadSigningHandoverStoreError>[0],
): never {
  throw new WorkloadSigningHandoverStoreError(code);
}
export const canonical = (value: unknown) => Buffer.from(canonicalDefinitionJson(value));
export const hash = (domain: string, bytes: Buffer) =>
  createHash('sha256')
    .update(domain + '\0')
    .update(bytes)
    .digest();
export const tagged = (bytes: Buffer) => 'sha256:' + bytes.toString('hex');
export const idempotency = z
  .string()
  .min(16)
  .max(128)
  .regex(/^[A-Za-z0-9._~-]+$/u);
export const providerId = z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u);
export interface RequestRow {
  handoverId: string;
  operationId: string;
  makerPrincipalId: string;
  idempotencyKey: string;
  request: WorkloadSigningHandoverRequest;
  requestCanonical: Buffer;
  requestDigest: Buffer;
  source: Source;
  sourceCanonical: Buffer;
  sourceDigest: Buffer;
  createdAt: Date;
}
export const columns = `handover_id::text as "handoverId",operation_id::text as "operationId",maker_principal_id::text as "makerPrincipalId",
 idempotency_key as "idempotencyKey",request,request_canonical as "requestCanonical",request_digest as "requestDigest",
 source,source_canonical as "sourceCanonical",source_digest as "sourceDigest",created_at as "createdAt"`;
export function authenticate(row: RequestRow): RequestRow {
  const request = workloadSigningHandoverRequestSchema.parse(row.request);
  if (
    !canonical(request).equals(row.requestCanonical) ||
    !canonical(row.source).equals(row.sourceCanonical) ||
    !hash('pc.identity.workload-signing-handover.request.v1', row.requestCanonical).equals(
      row.requestDigest,
    ) ||
    !hash('pc.identity.workload-signing-handover.source.v1', row.sourceCanonical).equals(
      row.sourceDigest,
    ) ||
    row.source.schema !== 'pc.identity.workload-signing-handover.source.v1'
  )
    fail('CORRUPT');
  return row;
}
export function view(row: RequestRow) {
  return {
    handoverId: row.handoverId,
    preparationOperationId: row.operationId,
    state: 'PREPARING' as const,
    requestDigest: tagged(row.requestDigest),
    sourceDigest: tagged(row.sourceDigest),
    keyCount: row.source.keys.length,
    receiptSelectionCount: row.source.receiptSelections.length,
    envelopeSelectionCount: row.source.envelopeSelections.length,
    createdAt: row.createdAt.toISOString(),
  };
}
export async function admitMaker(client: PoolClient, scope: WorkloadSigningHandoverScope) {
  if (
    scope.authority.privacyDomainId !== scope.privacyDomainId ||
    scope.authority.actionIntentId !== signingRotationActions.create ||
    scope.authority.resourceId !== '*'
  )
    fail('DENIED');
  await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
}
export async function retained(
  client: PoolClient,
  scope: WorkloadSigningHandoverScope,
  handoverId: string,
) {
  const selected = await client.query<RequestRow>(
    `select ${columns} from control.workload_signing_handover
   where participant_id=$1 and privacy_domain_id=$2 and handover_id=$3`,
    [scope.participantId, scope.privacyDomainId, z.uuidv7().parse(handoverId)],
  );
  if (selected.rowCount !== 1) fail('NOT_FOUND');
  const row = authenticate(selected.rows[0]!);
  if (
    row.makerPrincipalId !== scope.authority.principalId ||
    row.source.participantId !== scope.participantId ||
    row.source.privacyDomainId !== scope.privacyDomainId ||
    row.source.environmentId !== scope.environmentId
  )
    fail('DENIED');
  return row;
}
export async function snapshot(
  client: PoolClient,
  scope: WorkloadSigningHandoverScope,
  operationId: string,
  source: Source,
) {
  const fence = await fenceBoundAuthorities(client, scope.participantId, [scope.authority], {
    principal: [{ id: source.issuer.workloadPrincipalId }],
    credential: [
      { id: source.provenance.predecessorCredentialId },
      { id: source.issuer.workloadCredentialId },
    ],
  });
  return captureAuthoritySnapshot(
    client,
    scope.participantId,
    scope.privacyDomainId,
    operationId,
    [scope.authority],
    fence,
  );
}

export interface WorkloadSigningHandoverAttemptScope {
  participantId: string;
  privacyDomainId: string;
}
