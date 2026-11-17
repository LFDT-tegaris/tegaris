import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  businessSigningTrustPreimage,
  identityEnvelopeSigningTrustPreimage,
  identityEnvelopeSigningProfile,
  type HandoverAdmissionAuthorization,
} from '@openpc/security-kernel';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import {
  prepareHandoverAdmissionTransitionCandidate,
  WorkloadSigningHandoverCandidateUnavailable,
} from './workload-signing-handover-admission-candidate.js';
import { handoverNanosSchema } from './workload-signing-handover-admission-material.js';

const inputSchema = z.strictObject({
  candidate: z.unknown(),
  mutationCandidateId: z.uuidv7(),
  operationId: z.uuidv7(),
  admittedAtNs: handoverNanosSchema,
});
const maxCounter = 18446744073709551615n;
const unavailable = (): never => {
  throw new WorkloadSigningHandoverCandidateUnavailable();
};
function increment(value: string): string {
  const next = BigInt(value) + 1n;
  if (next > maxCounter) return unavailable();
  return next.toString();
}
const hash = (bytes: Buffer) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
function preimage<T extends { readonly schema: string }>(document: T): Buffer {
  return Buffer.concat([
    Buffer.from(document.schema + '\0'),
    Buffer.from(canonicalAuthorizationJson(document)),
  ]);
}

type TransitionBindingName =
  | 'statementType'
  | 'participantId'
  | 'privacyDomainId'
  | 'environmentId'
  | 'workloadPrincipalId'
  | 'workloadId'
  | 'handoverId'
  | 'operationId'
  | 'mutationCandidateId'
  | 'candidateDigest'
  | 'actionIntentDigest'
  | 'generationId'
  | 'generationDigest'
  | 'sourceDigest'
  | 'predecessorCredentialId'
  | 'predecessorCredentialEpoch'
  | 'successorCredentialId'
  | 'successorCredentialEpoch'
  | 'nativeReplacementProvenanceDigest'
  | 'admittedAtNs'
  | 'successorTrustSetDigest'
  | 'selectorTransitionDigest'
  | 'catalogOperationId'
  | 'actionIntentId'
  | 'expectedRevision';
export type HandoverAdmissionTransitionBindings = Pick<
  HandoverAdmissionAuthorization,
  TransitionBindingName
>;

/** Pure projection of an already authenticated candidate. These bytes bind the
 * proposed transition; they grant no authority and assert no database effect.
 * The transaction owner must reconstruct them under current authority/source
 * fences and independently authenticate the approval, step-up and signing root.
 * Selector bytes cover the authorization projection, not complete SQL rows.
 * Durable timestamps/change references and a post-authorization change digest
 * belong to the atomic owner and must not enter this preimage recursively.
 */
export function prepareHandoverAdmissionTransition(input: z.input<typeof inputSchema>) {
  const parsed = inputSchema.parse(input);
  const { mutationCandidateId, operationId, admittedAtNs } = parsed;
  const { candidate, candidateDigest, trusts } = prepareHandoverAdmissionTransitionCandidate(
    parsed.candidate,
    admittedAtNs,
  );
  // Bind the complete historical summary. Its native signatures/owner joins
  // remain an independent requirement; hashing it does not authenticate it.
  const provenance = {
    schema: 'pc.identity.workload-signing-handover.native-replacement-provenance.v1',
    ...candidate.source.provenance,
  } as const;
  const nativeReplacementProvenancePreimage = preimage(provenance);
  const nativeReplacementProvenanceDigest = hash(nativeReplacementProvenancePreimage);
  const binding = {
    participantId: candidate.participantId,
    privacyDomainId: candidate.privacyDomainId,
    environmentId: candidate.environmentId,
    workloadPrincipalId: candidate.source.issuer.workloadPrincipalId,
    workloadId: candidate.workloadId,
    handoverId: candidate.handoverId,
    mutationCandidateId,
    operationId,
    candidateDigest,
    generationId: candidate.generation.generationId,
    generationDigest: candidate.request.generationDigest,
    sourceDigest: candidate.generation.sourceDigest,
    predecessorCredentialId: candidate.source.provenance.predecessorCredentialId,
    predecessorCredentialEpoch: candidate.source.provenance.predecessorCredentialEpoch,
    successorCredentialId: candidate.source.provenance.successorCredentialId,
    successorCredentialEpoch: candidate.source.provenance.successorCredentialEpoch,
    nativeReplacementProvenanceDigest,
    admittedAtNs,
  } as const;
  // Candidate validation requires ascending, unique predecessor fingerprints.
  // Preserve that order and use each purpose's actual canonical trust bytes.
  const members = trusts.map((captured, index) => {
    const bytes =
      captured.signerRole === 'IDENTITY_ENVELOPE'
        ? identityEnvelopeSigningTrustPreimage(captured.trust)
        : businessSigningTrustPreimage(captured.trust);
    return {
      predecessorSignerId: candidate.predecessorTrusts[index]!.signerId,
      successorSignerId: captured.trust.signerId,
      signerRole: captured.signerRole,
      trustDigest: hash(bytes),
      trustPreimageBase64: bytes.toString('base64'),
    };
  });
  const successorTrustSet = {
    schema: 'pc.identity.workload-signing-handover.successor-trust-set.v1',
    ...binding,
    members,
  } as const;
  const successorTrustSetPreimage = preimage(successorTrustSet);
  const successorTrustSetDigest = hash(successorTrustSetPreimage);
  const byPredecessor = new Map(members.map((member) => [member.predecessorSignerId, member]));
  const receiptSelections = candidate.source.receiptSelections
    .map((before) => {
      const member = byPredecessor.get(before.signerId);
      if (!member || member.signerRole === 'IDENTITY_ENVELOPE') return unavailable();
      return {
        selectorKind: 'BUSINESS_RECEIPT' as const,
        signerRole: member.signerRole,
        before,
        after: {
          ...before,
          signerId: member.successorSignerId,
          credentialId: candidate.source.issuer.workloadCredentialId,
          rowVersion: increment(before.rowVersion),
          admissionVersion: increment(before.admissionVersion),
          fenceGeneration: increment(before.fenceGeneration),
          fencedOperationId: null,
        },
      };
    })
    .sort((left, right) => (left.before.profileDigest < right.before.profileDigest ? -1 : 1));
  const envelopeSelections = candidate.source.envelopeSelections.map((before) => {
    const member = byPredecessor.get(before.signerId);
    if (!member || member.signerRole !== 'IDENTITY_ENVELOPE') return unavailable();
    return {
      selectorKind: 'IDENTITY_ENVELOPE' as const,
      profileId: identityEnvelopeSigningProfile.profileId,
      profileVersion: 1 as const,
      before,
      after: {
        ...before,
        signerId: member.successorSignerId,
        credentialId: candidate.source.issuer.workloadCredentialId,
        admissionVersion: increment(before.admissionVersion),
      },
    };
  });
  const selectorTransition = {
    schema: 'pc.identity.workload-signing-handover.selector-transition.v1',
    ...binding,
    successorTrustSetDigest,
    receiptSelections,
    envelopeSelections,
  } as const;
  const selectorTransitionPreimage = preimage(selectorTransition);
  const selectorTransitionDigest = hash(selectorTransitionPreimage);
  const authorizationBindings: HandoverAdmissionTransitionBindings = {
    statementType: 'ADMISSION_AUTHORIZATION',
    ...binding,
    actionIntentDigest: candidate.request.actionIntentDigest,
    sourceDigest: candidate.generation.sourceDigest,
    predecessorCredentialId: candidate.source.provenance.predecessorCredentialId,
    predecessorCredentialEpoch: candidate.source.provenance.predecessorCredentialEpoch,
    successorCredentialId: candidate.source.provenance.successorCredentialId,
    successorCredentialEpoch: candidate.source.provenance.successorCredentialEpoch,
    successorTrustSetDigest,
    selectorTransitionDigest,
    catalogOperationId: candidate.catalogOperationId,
    actionIntentId: candidate.request.actionIntentId,
    expectedRevision: candidate.expectedRevision,
  };
  return {
    authorizationBindings,
    trusts,
    provenance,
    nativeReplacementProvenancePreimage,
    successorTrustSet,
    successorTrustSetPreimage,
    selectorTransition,
    selectorTransitionPreimage,
  };
}
