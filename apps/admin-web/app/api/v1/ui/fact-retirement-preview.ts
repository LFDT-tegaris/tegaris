import { z } from 'zod';
import type { NextRequest } from 'next/server';
import {
  admitStoreRetirement,
  exactStoreRetirementSourceBinding,
  factRetirementPlanInput,
  storeRetirementPlan,
} from '../../../../../../services/control-api/src/evidence/store-retirement-contracts';
import {
  authenticated,
  safeProblem,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { digest, isResponse, ownerJson, publicHeaders } from './local-governance-api';

const reference = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const fieldsSchema = factRetirementPlanInput.extend({ evidenceId: reference });
const actor = (session: IdentitySession) => ({
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId,
  principalId: session.principalId,
  sessionId: session.sessionId,
  contextEpoch: session.contextEpoch,
});

/** Obtain exact source bytes through the public native-selection owner. The
 * browser supplies a record, installed target and policy, never a selection. */
export async function factRetirementPreview(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  fields: Record<string, unknown>,
  source: 'fact' | 'candidate' = 'fact',
) {
  const { evidenceId, ...input } = fieldsSchema.parse(fields);
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/evidence-records/${encodeURIComponent(evidenceId)}/${source}-retirement-plan`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: { ...publicHeaders(runtime, session), 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
    },
  ).catch(() => undefined);
  const plan = await ownerJson(response, storeRetirementPlan, request);
  if (isResponse(plan)) return plan;
  const { selection } = exactStoreRetirementSourceBinding(plan.sourceBinding);
  if (
    plan.hostDigest !== input.hostDigest ||
    plan.retentionPolicyId !== input.retentionPolicyId ||
    selection.class !== (source === 'fact' ? 'ADMITTED_FACT' : 'CANDIDATE_PROJECTION') ||
    selection.rows.length !== 1 ||
    plan.sourceBinding.recordRefs.length !== 1 ||
    `urn:openpc:resource:${plan.sourceBinding.recordRefs[0]!.evidenceId}` !== evidenceId
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const current = await authenticated(request, runtime);
  if (
    !current ||
    current.contextMode !== 'PARTICIPANT' ||
    digest(actor(current)) !== digest(actor(session))
  )
    return safeProblem('PC-AUTH-0005', request);
  return {
    hostDigest: plan.hostDigest,
    retentionPolicyId: plan.retentionPolicyId,
    sourceBinding: plan.sourceBinding,
    previousAttemptId: null,
  };
}

/** Human-readable projection of the exact digest-bound candidate, for both
 * maker preview and independent checker. It conveys no execution eligibility. */
export function factRetirementSummary(value: unknown) {
  const input = admitStoreRetirement.parse(value);
  const { selection } = exactStoreRetirementSourceBinding(input.sourceBinding);
  if (selection.rows.length !== 1) throw new Error('Invalid store retirement candidate');
  const row = selection.rows[0]!;
  return {
    ...(selection.class === 'ADMITTED_FACT'
      ? {
          class: 'ADMITTED_FACT' as const,
          factId: selection.rows[0]!.fact_id,
          factGenerationId: selection.fact_generation_id,
          canonicalGeneration: String(selection.canonical_generation),
          signedFactDigest: selection.rows[0]!.signed_fact_digest,
        }
      : {
          class: 'CANDIDATE_PROJECTION' as const,
          generationId: selection.source.generation_id,
          partitionId: selection.source.partition_id,
          payloadDigest: row.payload_digest,
        }),
    candidateId: row.candidate_id,
    payloadBytes: String(row.payload_bytes),
    evidenceId: `urn:openpc:resource:${input.sourceBinding.recordRefs[0]!.evidenceId}`,
    retentionPolicyId: input.retentionPolicyId,
    hostDigest: input.hostDigest,
    archiveAcknowledgements: input.sourceBinding.acknowledgements[0]!.sinkReceipts.length,
    nativeSourceCheck: 'REQUIRED_AT_ADMISSION' as const,
  };
}
export type FactRetirementSummary = ReturnType<typeof factRetirementSummary>;
