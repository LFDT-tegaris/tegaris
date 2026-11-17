import {
  factRetirementHosts,
  candidateRetirementHosts,
} from '../../../../../../services/control-api/src/evidence/store-retirement-contracts';
import {
  evidenceDeletionResultView,
  evidenceDeletionBatchPlan,
} from '../../../../../../services/control-api/src/evidence/deletion-continuation-contracts';
import { localEvidenceDeletionPlan } from '../../../../../../services/control-api/src/evidence/deletion-contracts';
import { rawProofDeletionPlan } from '../../../../../../services/control-api/src/evidence/raw-deletion-contracts';
import { projectionDeletionPlan } from '../../../../../../services/control-api/src/evidence/projection-deletion-contracts';
import { createHash } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { evidenceRecordView } from '../../../../../../services/control-api/src/evidence/catalogue-contracts';
import { evidenceProvenanceView } from '../../../../../../services/control-api/src/evidence/provenance-contracts';
import { evidenceHoldView } from '../../../../../../services/control-api/src/evidence/hold-contracts';
import { retentionPolicyView } from '../../../../../../services/control-api/src/evidence/retention-contracts';
import {
  evidenceExportRange,
  evidenceExportView,
  evidenceExportSelectionView,
  evidenceRecordExportRange,
} from '../../../../../../services/control-api/src/evidence/export-contracts';
import { evidenceExportDownload } from '../../../../../../services/control-api/src/evidence/export-artifact';
import {
  collectionResponseSchema,
  operationResponseSchema,
  scopedReadSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  readPublicCommand,
  safeProblem,
  sameOrigin,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { csrf, digest, isResponse, ownerJson, publicHeaders } from './local-governance-api';

const noStore = { 'Cache-Control': 'no-store' };
const actionIntentId = 'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1';
const actionIntentDigest = `sha256:${createHash('sha256')
  .update(
    [
      actionIntentId,
      'evidence-exports',
      'CREATE',
      'STANDARD',
      'false',
      'false',
      'true',
      'AUTHORIZED_TYPE_ONLY',
      'AUTHORIZED_MINIMAL',
      'CREATE_EVIDENCE_EXPORTS',
    ].join('\0'),
  )
  .digest('hex')}`;
const actor = (session: IdentitySession) => ({
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId!,
});
const actorKey = (session: IdentitySession) =>
  digest({
    ...actor(session),
    sessionId: session.sessionId,
    principalId: session.principalId,
    contextEpoch: session.contextEpoch,
  });
const recordsPage = collectionResponseSchema(evidenceRecordView),
  exportsPage = collectionResponseSchema(evidenceExportView),
  holdsPage = collectionResponseSchema(evidenceHoldView),
  retentionPage = collectionResponseSchema(retentionPolicyView),
  deletionsPage = collectionResponseSchema(evidenceDeletionResultView);
const querySchema = z.strictObject({
  recordDigest: z
    .string()
    .regex(/^sha256:[0-9a-f]{64}$/u)
    .optional(),
  provenanceRecordId: z.uuidv7().optional(),
  factRetirementRecordId: z.uuidv7().optional(),
  candidateRetirementRecordId: z.uuidv7().optional(),
  recordId: z.uuid().optional(),
  deletionRecordId: z.uuidv7().optional(),
  deletionBatchRecordId: z.uuidv7().optional(),
  deletionContinuationId: z.uuidv7().optional(),
  rawDeletionObjectId: z.uuidv7().optional(),
  rawDeletionContinuationId: z.uuidv7().optional(),
  searchProjectionRecordId: z.uuidv7().optional(),
  normalizedProjectionRecordId: z.uuidv7().optional(),
  projectionContinuationId: z.uuidv7().optional(),
  exportId: z.uuidv7().optional(),
  artifact: z.literal('1').optional(),
  recordsCursor: scopedReadSchema.shape.cursor,
  exportsCursor: scopedReadSchema.shape.cursor,
  holdsCursor: z.string().min(1).max(8192).optional(),
  retentionCursor: z.string().min(1).max(8192).optional(),
  deletionsCursor: z.string().min(1).max(8192).optional(),
});
const inputSchema = z.strictObject({
  actorKey: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  requestKey: z.uuid(),
  selection: evidenceExportRange,
  reason: z.string().min(1).max(1024),
});

function consistentCataloguePage(
  value: z.infer<typeof recordsPage | typeof exportsPage>,
  pageSize = 50,
) {
  return (
    value.items.length <= pageSize &&
    (!value.authorizedEmpty ||
      (value.items.length === 0 && value.total === '0' && value.completeness === 'COMPLETE'))
  );
}

async function context(request: NextRequest, mutation = false) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  if (mutation && !sameOrigin(request)) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  return { runtime, session };
}
async function stillCurrent(request: NextRequest, runtime: LocalConfig, session: IdentitySession) {
  const current = await authenticated(request, runtime);
  return (
    !!current && current.contextMode === 'PARTICIPANT' && actorKey(current) === actorKey(session)
  );
}
async function read<T>(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
) {
  const response = await fetch(`${runtime.publicApiUrl}/api/v1/${path}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session),
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
  }).catch(() => undefined);
  return ownerJson(response, schema, request);
}
export async function readEvidenceWorkbench(request: NextRequest) {
  const authorized = await context(request);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const query = querySchema.safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams].length !== Object.keys(query.data).length ||
    (query.data.artifact && !query.data.exportId) ||
    ((query.data.provenanceRecordId ||
      query.data.factRetirementRecordId ||
      query.data.candidateRetirementRecordId ||
      query.data.recordId ||
      query.data.deletionRecordId ||
      query.data.deletionBatchRecordId ||
      query.data.deletionContinuationId ||
      query.data.rawDeletionObjectId ||
      query.data.rawDeletionContinuationId ||
      query.data.searchProjectionRecordId ||
      query.data.normalizedProjectionRecordId ||
      query.data.projectionContinuationId) &&
      Object.keys(query.data).length !== 1) ||
    (query.data.exportId &&
      (query.data.recordDigest ||
        query.data.recordsCursor ||
        query.data.exportsCursor ||
        query.data.holdsCursor ||
        query.data.retentionCursor ||
        query.data.deletionsCursor))
  )
    return safeProblem('PC-DATA-6004', request);
  const binding = { actor: actor(session), actorKey: actorKey(session) };
  if (query.data.factRetirementRecordId || query.data.candidateRetirementRecordId) {
    const source = query.data.candidateRetirementRecordId ? 'candidate' : 'fact';
    const evidenceId = `urn:openpc:resource:${query.data.candidateRetirementRecordId ?? query.data.factRetirementRecordId}`;
    const hosts = await read(
      request,
      runtime,
      session,
      `evidence-records/${encodeURIComponent(evidenceId)}/${source}-retirement-hosts`,
      z.union([factRetirementHosts, candidateRetirementHosts]),
    );
    if (isResponse(hosts)) return hosts;
    if (
      hosts.items.some(
        (host) => host.store !== (source === 'fact' ? 'openpc_facts' : 'openpc_candidate_index'),
      )
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    if (!(await stillCurrent(request, runtime, session)))
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json({ ...binding, evidenceId, hosts }, { headers: noStore });
  }
  if (query.data.provenanceRecordId) {
    const ref = `urn:openpc:resource:${query.data.provenanceRecordId}`;
    const provenance = await read(
      request,
      runtime,
      session,
      `evidence-records/${encodeURIComponent(ref)}/provenance`,
      evidenceProvenanceView,
    );
    if (isResponse(provenance)) return provenance;
    if (
      provenance.evidenceId !== ref ||
      provenance.participantId !== `urn:openpc:participant:${session.participantId}` ||
      provenance.privacyDomainId !== session.privacyDomainId
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    if (!(await stillCurrent(request, runtime, session)))
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json({ ...binding, provenance }, { headers: noStore });
  }
  if (
    query.data.deletionBatchRecordId ||
    query.data.deletionContinuationId ||
    query.data.rawDeletionObjectId ||
    query.data.rawDeletionContinuationId ||
    query.data.searchProjectionRecordId ||
    query.data.normalizedProjectionRecordId ||
    query.data.projectionContinuationId
  ) {
    const continuation = !!(
      query.data.deletionContinuationId ||
      query.data.rawDeletionContinuationId ||
      query.data.projectionContinuationId
    );
    const raw = !!(query.data.rawDeletionObjectId || query.data.rawDeletionContinuationId);
    const projection = !!(
      query.data.searchProjectionRecordId ||
      query.data.normalizedProjectionRecordId ||
      query.data.projectionContinuationId
    );
    const ref = `urn:openpc:resource:${query.data.deletionContinuationId ?? query.data.deletionBatchRecordId ?? query.data.rawDeletionObjectId ?? query.data.rawDeletionContinuationId ?? query.data.searchProjectionRecordId ?? query.data.normalizedProjectionRecordId ?? query.data.projectionContinuationId}`;
    const path = continuation
      ? `evidence-deletions/${encodeURIComponent(ref)}/${projection ? 'projection-continuation-plan' : raw ? 'raw-continuation-plan' : 'continuation-plan'}`
      : projection
        ? `evidence-records/${encodeURIComponent(ref)}/${query.data.searchProjectionRecordId ? 'search' : 'normalized'}-projection-deletion-plan`
        : raw
          ? `protected-proofs/${encodeURIComponent(ref)}/deletion-plan`
          : `evidence-records/${encodeURIComponent(ref)}/deletion-batch-plan`;
    const plan = projection
      ? await read(request, runtime, session, path, projectionDeletionPlan)
      : raw
        ? await read(request, runtime, session, path, rawProofDeletionPlan)
        : await read(request, runtime, session, path, evidenceDeletionBatchPlan);
    if (isResponse(plan)) return plan;
    if (
      (projection &&
        !continuation &&
        (!('dataClass' in plan) ||
          plan.dataClass !==
            (query.data.searchProjectionRecordId
              ? 'SEARCH_PROJECTION'
              : 'NORMALIZED_JSON_PROJECTION') ||
          !('evidenceId' in plan) ||
          plan.evidenceId !== ref)) ||
      (raw && !continuation && (!('objectRef' in plan) || plan.objectRef !== ref)) ||
      ('objectRef' in plan &&
        plan.selection &&
        'objectRef' in plan.selection &&
        plan.selection.objectRef !== plan.objectRef) ||
      (plan.selection &&
        (plan.selection.participantId !== `urn:openpc:participant:${session.participantId}` ||
          plan.selection.privacyDomainId !== session.privacyDomainId ||
          (continuation
            ? plan.selection.priorCursor?.deletionJobId !== ref
            : plan.selection.priorCursor !== null)))
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    if (!(await stillCurrent(request, runtime, session)))
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json({ ...binding, plan }, { headers: noStore });
  }
  if (query.data.deletionRecordId) {
    const ref = `urn:openpc:resource:${query.data.deletionRecordId}`;
    const plan = await read(
      request,
      runtime,
      session,
      `evidence-records/${encodeURIComponent(ref)}/deletion-plan`,
      localEvidenceDeletionPlan,
    );
    if (isResponse(plan)) return plan;
    if (
      plan.evidenceId !== ref ||
      (plan.selection &&
        (plan.selection.evidenceId !== ref ||
          plan.selection.participantId !== `urn:openpc:participant:${session.participantId}` ||
          plan.selection.privacyDomainId !== session.privacyDomainId))
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    if (!(await stillCurrent(request, runtime, session)))
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json({ ...binding, plan }, { headers: noStore });
  }
  if (query.data.recordId) {
    const ref = `urn:openpc:resource:${query.data.recordId}`;
    const record = await read(
      request,
      runtime,
      session,
      `evidence-records/${encodeURIComponent(ref)}/export-range`,
      evidenceRecordExportRange,
    );
    if (isResponse(record)) return record;
    if (record.evidenceId !== ref || !(await stillCurrent(request, runtime, session)))
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json({ ...binding, record }, { headers: noStore });
  }
  if (query.data.exportId) {
    const path = `evidence-exports/${encodeURIComponent(`urn:openpc:resource:${query.data.exportId}`)}`;
    if (query.data.artifact) {
      const download = await read(
        request,
        runtime,
        session,
        `${path}/artifact`,
        evidenceExportDownload,
      );
      if (isResponse(download)) return download;
      if (
        download.artifact.evidenceExportId !== `urn:openpc:resource:${query.data.exportId}` ||
        download.artifact.participantId !== `urn:openpc:participant:${session.participantId}` ||
        download.artifact.privacyDomainId !==
          `urn:openpc:privacy-domain:${session.privacyDomainId}` ||
        digest(download.artifact) !== download.outputDigest ||
        !(await stillCurrent(request, runtime, session))
      )
        return safeProblem('PC-AUTH-0005', request);
      return NextResponse.json({ ...binding, download }, { headers: noStore });
    }
    const selected = await read(request, runtime, session, path, evidenceExportView);
    if (isResponse(selected)) return selected;
    const selection = await read(
      request,
      runtime,
      session,
      `${path}/selection`,
      evidenceExportSelectionView,
    );
    if (isResponse(selection)) return selection;
    if (
      selected.evidenceExportId !== `urn:openpc:resource:${query.data.exportId}` ||
      selected.requestDigest !== selection.requestDigest ||
      selected.participantId !== `urn:openpc:participant:${session.participantId}` ||
      !(await stillCurrent(request, runtime, session))
    )
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json({ ...binding, selected, selection }, { headers: noStore });
  }
  const recordPageSize = 10;
  const parameters = (cursor?: string, pageSize = 50) =>
    new URLSearchParams({ limit: String(pageSize), ...(cursor ? { cursor } : {}) });
  const recordParameters = parameters(query.data.recordsCursor, recordPageSize);
  if (query.data.recordDigest)
    recordParameters.set('filter', `recordDigest:eq:${query.data.recordDigest}`);
  const records = await read(
    request,
    runtime,
    session,
    `evidence-records?${recordParameters}`,
    recordsPage,
  );
  const exports = await read(
    request,
    runtime,
    session,
    `evidence-exports?${parameters(query.data.exportsCursor)}`,
    exportsPage,
  );
  const participant = `urn:openpc:participant:${session.participantId}`;
  const holds = await read(
    request,
    runtime,
    session,
    `evidence-holds?${parameters(query.data.holdsCursor)}`,
    holdsPage,
  );
  const retentionPolicies = await read(
    request,
    runtime,
    session,
    `retention-policies?${parameters(query.data.retentionCursor)}`,
    retentionPage,
  );
  const deletions = await read(
    request,
    runtime,
    session,
    `evidence-deletions?${parameters(query.data.deletionsCursor)}`,
    deletionsPage,
  );
  if (
    (!isResponse(deletions) &&
      deletions.items.some(
        (item) =>
          item.participantId !== participant ||
          item.selection.privacyDomainId !== session.privacyDomainId,
      )) ||
    (!isResponse(records) && records.items.some((item) => item.participantId !== participant)) ||
    (!isResponse(exports) && exports.items.some((item) => item.participantId !== participant)) ||
    (!isResponse(holds) && holds.items.some((item) => item.participantId !== participant)) ||
    (!isResponse(retentionPolicies) &&
      retentionPolicies.items.some((item) => item.participantId !== participant))
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  if (!(await stillCurrent(request, runtime, session))) return safeProblem('PC-AUTH-0005', request);
  if (
    (!isResponse(records) && !consistentCataloguePage(records, recordPageSize)) ||
    (!isResponse(exports) && !consistentCataloguePage(exports))
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(
    {
      ...binding,
      recordDigest: query.data.recordDigest ?? null,
      recordsCursor: query.data.recordsCursor ?? null,
      records: isResponse(records) ? null : records,
      exports: isResponse(exports) ? null : exports,
      holds: isResponse(holds) ? null : holds,
      recordsUnavailable: isResponse(records),
      exportsUnavailable: isResponse(exports),
      holdsUnavailable: isResponse(holds),
      retentionPolicies: isResponse(retentionPolicies) ? null : retentionPolicies,
      retentionPoliciesUnavailable: isResponse(retentionPolicies),
      deletions: isResponse(deletions) ? null : deletions,
      deletionsUnavailable: isResponse(deletions),
    },
    { headers: noStore },
  );
}
export async function createEvidenceRequest(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const authorized = await context(request, true);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const input = inputSchema.safeParse(await readPublicCommand(request, 16384));
  if (!input.success) return safeProblem('PC-DATA-6004', request);
  if (input.data.actorKey !== actorKey(session)) return safeProblem('PC-AUTH-0005', request);
  const token = await csrf(runtime, session, actionIntentId);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const key = `workbench-evidence-${input.data.requestKey}`;
  const response = await fetch(`${runtime.publicApiUrl}/api/v1/evidence-exports/from-selection`, {
    method: 'POST',
    cache: 'no-store',
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(20000)]),
    headers: {
      ...publicHeaders(runtime, session),
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'OpenPC-Action-Intent-Digest': actionIntentDigest,
      'Idempotency-Key': key,
    },
    body: JSON.stringify({
      participantId: `urn:openpc:participant:${session.participantId}`,
      selection: input.data.selection,
      reason: input.data.reason,
      actionIntentId,
      actionIntentDigest,
    }),
  }).catch(() => undefined);
  const operation = await ownerJson(response, operationResponseSchema, request);
  if (isResponse(operation)) return operation;
  if (
    response?.status !== 202 ||
    operation.actionIntentId !== actionIntentId ||
    operation.intentDigest !== actionIntentDigest ||
    operation.idempotencyKey !== key ||
    !(await stillCurrent(request, runtime, session))
  )
    return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(
    { actorKey: actorKey(session), operation },
    { status: 202, headers: noStore },
  );
}
export type EvidenceCataloguePage = z.infer<typeof recordsPage>;
export type EvidenceRequestsPage = z.infer<typeof exportsPage>;
export type EvidenceRequest = z.infer<typeof evidenceExportView>;
export type EvidenceSelection = z.infer<typeof evidenceExportSelectionView>;
export type EvidenceDownload = z.infer<typeof evidenceExportDownload>;
export type EvidenceRecordRange = z.infer<typeof evidenceRecordExportRange>;
export type EvidenceHoldsPage = z.infer<typeof holdsPage>;
export type RetentionPoliciesPage = z.infer<typeof retentionPage>;

export type EvidenceDeletionsPage = z.infer<typeof deletionsPage>;
export type LocalEvidenceDeletionPlan = z.infer<typeof localEvidenceDeletionPlan>;

export type LocalEvidenceDeletionBatchPlan = z.infer<typeof evidenceDeletionBatchPlan>;
export type RawProofDeletionPlan = z.infer<typeof rawProofDeletionPlan>;
export type ProjectionDeletionPlan = z.infer<typeof projectionDeletionPlan>;
export type FactRetirementHosts = z.infer<typeof factRetirementHosts>;

export type CandidateRetirementHosts = z.infer<typeof candidateRetirementHosts>;
