import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  businessSigningTrustPreimage,
  identityEnvelopeSigningTrustPreimage,
} from '@openpc/security-kernel';
import { businessTransitionProfiles } from '../../../../packages/security-kernel/src/business-transition/profiles.generated.js';
import { workloadSigningHandoverAdmissionOperation as operation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import { businessProviderObservationSchema } from './business-signing-provider.js';
import { identityEnvelopeRotationObservationSchema } from './identity-envelope-rotation-provider.js';
import {
  handoverPossessionGenerationSchema,
  handoverPossessionGenerationDigest,
  handoverPossessionAttemptSchema,
  verifyHandoverPossessionObservation,
} from './workload-signing-handover-possession.js';
import {
  handoverDigestSchema,
  handoverNanosSchema,
  handoverAdmissionSourceSchema,
  handoverAdmissionTrustSchema,
  handoverAdmissionKernelTrust,
  handoverAdmissionTrustDocument,
  type HandoverCapturedTrust,
} from './workload-signing-handover-admission-material.js';

export const handoverAdmissionCandidateRequestSchema = z.strictObject({
  schemaVersion: z.literal(1),
  actionIntentId: z.literal(operation.actionIntentId),
  actionIntentDigest: handoverDigestSchema,
  generationId: z.uuidv7(),
  generationDigest: handoverDigestSchema,
  reason: z.string().trim().min(12).max(1024),
});
const proofSchema = z.strictObject({
  attempt: handoverPossessionAttemptSchema,
  observation: z.union([
    businessProviderObservationSchema,
    identityEnvelopeRotationObservationSchema,
  ]),
});
const canonical = (value: unknown) => Buffer.from(canonicalAuthorizationJson(value));
const tagged = (bytes: Buffer) => 'sha256:' + bytes.toString('hex');
const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest();
function sourceDigest(value: unknown) {
  return tagged(
    createHash('sha256')
      .update('pc.identity.workload-signing-handover.source.v1\0')
      .update(canonical(value))
      .digest(),
  );
}
export class WorkloadSigningHandoverCandidateUnavailable extends Error {
  constructor() {
    super('Workload signing handover admission candidate is unavailable');
  }
}
function deny(): never {
  throw new WorkloadSigningHandoverCandidateUnavailable();
}
function same(left: unknown, right: unknown) {
  return canonical(left).equals(canonical(right));
}

/** An approval body, never authorization or a trust grant. Current source,
 * original observations, unsuperseded generation and actor authority must be
 * independently fenced by the durable staging/admission owners. */
export const handoverAdmissionCandidateSchema = z
  .strictObject({
    schema: z.literal('pc.identity.workload-signing-handover.admission-candidate.v1'),
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    environmentId: z.string().min(1).max(160),
    handoverId: z.uuidv7(),
    makerPrincipalId: z.uuidv7(),
    workloadId: z.string().min(1).max(160),
    catalogOperationId: z.literal(operation.catalogOperationId),
    expectedRevision: z.literal('1'),
    validityPolicy: z.literal('FROM_ATOMIC_ADMISSION_TO_EARLIEST_KEY_OR_CREDENTIAL_EXPIRY'),
    request: handoverAdmissionCandidateRequestSchema,
    preparedAtNs: handoverNanosSchema,
    expiresAtNs: handoverNanosSchema,
    source: handoverAdmissionSourceSchema,
    generation: handoverPossessionGenerationSchema,
    predecessorTrusts: z.array(handoverAdmissionTrustSchema).min(1).max(64),
    proofs: z.array(proofSchema).min(1).max(64),
  })
  .superRefine((value, context) => {
    try {
      const { source, generation, request } = value;
      const at = BigInt(value.preparedAtNs);
      if (
        value.participantId !== generation.participantId ||
        value.privacyDomainId !== generation.privacyDomainId ||
        value.environmentId !== generation.environmentId ||
        value.handoverId !== generation.handoverId ||
        value.makerPrincipalId !== generation.makerPrincipalId ||
        source.participantId !== value.participantId ||
        source.privacyDomainId !== value.privacyDomainId ||
        source.environmentId !== value.environmentId ||
        !same(source.issuer, generation.issuer) ||
        sourceDigest(source) !== generation.sourceDigest ||
        request.generationId !== generation.generationId ||
        request.generationDigest !== handoverPossessionGenerationDigest(generation) ||
        value.expiresAtNs !== generation.expiresAtNs ||
        at < BigInt(generation.issuedAtNs) ||
        at >= BigInt(value.expiresAtNs) ||
        source.keys.length !== generation.keys.length ||
        source.keys.length !== value.predecessorTrusts.length ||
        source.keys.length !== value.proofs.length ||
        new Set(source.receiptSelections.map((row) => row.profileDigest)).size !==
          source.receiptSelections.length
      )
        deny();
      const provenance = source.provenance;
      if (
        provenance.participantId !== value.participantId ||
        provenance.privacyDomainId !== value.privacyDomainId ||
        provenance.principalId !== source.issuer.workloadPrincipalId ||
        provenance.predecessorCredentialId === provenance.successorCredentialId ||
        provenance.successorCredentialId !== source.issuer.workloadCredentialId ||
        provenance.successorCredentialEpoch !== source.issuer.workloadCredentialEpoch ||
        BigInt(provenance.predecessorCredentialEpoch) + 1n !==
          BigInt(provenance.successorCredentialEpoch) ||
        provenance.makerPrincipalId === provenance.checkerPrincipalId
      )
        deny();
      const proofIds = new Set<string>();
      let receiptCount = 0,
        envelopeCount = 0,
        previous = '';
      for (let i = 0; i < source.keys.length; i++) {
        const old = source.keys[i]!,
          prepared = generation.keys[i]!,
          document = value.predecessorTrusts[i]!,
          proof = value.proofs[i]!;
        const captured = handoverAdmissionKernelTrust(document),
          trust = captured.trust;
        const preimage =
          captured.signerRole === 'IDENTITY_ENVELOPE'
            ? identityEnvelopeSigningTrustPreimage(captured.trust)
            : businessSigningTrustPreimage(captured.trust);
        const replacement = prepared.binding.replacement;
        if (
          old.oldFingerprint <= previous ||
          old.oldFingerprint !== trust.signerId ||
          captured.signerRole !== old.signerRole ||
          trust.participantId !== value.participantId ||
          trust.privacyDomainId !== value.privacyDomainId ||
          trust.environmentId !== value.environmentId ||
          trust.workloadCredentialId !== provenance.predecessorCredentialId ||
          trust.workloadCredentialEpoch.toString() !== provenance.predecessorCredentialEpoch ||
          old.oldCredentialEpoch !== provenance.predecessorCredentialEpoch ||
          trust.keyEpoch.toString() !== old.expectedKeyEpoch ||
          trust.keyEpoch >= 18446744073709551615n ||
          trust.secretReference !== old.oldReference ||
          trust.validFromNs.toString() !== old.oldKeyValidFromNs ||
          trust.validUntilNs.toString() !== old.oldKeyValidUntilNs ||
          trust.validFromNs > at ||
          preimage.toString('base64') !== old.oldTrustPreimageBase64 ||
          tagged(digest(preimage)) !== old.oldTrustDigest ||
          !same(replacement, {
            oldFingerprint: old.oldFingerprint,
            oldTrustDigest: old.oldTrustDigest,
            expectedKeyEpoch: old.expectedKeyEpoch,
            oldReference: old.oldReference,
            newReference: old.newReference,
            signerRole: old.signerRole,
            purpose: old.purpose,
          }) ||
          proof.attempt.predecessorFingerprint !== old.oldFingerprint ||
          proofIds.has(proof.attempt.request.attemptId)
        )
          deny();
        const verified = verifyHandoverPossessionObservation(
          generation,
          proof.attempt,
          proof.observation,
          value.preparedAtNs,
        );
        if (verified.state !== 'PROVEN') deny();
        proofIds.add(proof.attempt.request.attemptId);
        previous = old.oldFingerprint;
        if (captured.signerRole === 'IDENTITY_ENVELOPE') {
          const selectors = source.envelopeSelections.filter(
            (row) => row.signerId === old.oldFingerprint,
          );
          if (
            selectors.length !== 1 ||
            selectors[0]!.credentialId !== provenance.predecessorCredentialId ||
            selectors[0]!.profileDigest !== captured.trust.profileDigest ||
            captured.trust.workloadParticipantEpoch.toString() !==
              source.issuer.workloadParticipantEpoch ||
            captured.trust.workloadPrincipalEpoch.toString() !==
              source.issuer.workloadPrincipalEpoch
          )
            deny();
          envelopeCount++;
        } else {
          const selectors = source.receiptSelections.filter(
            (row) => row.signerId === old.oldFingerprint,
          );
          if (selectors.length !== captured.trust.grants.length) deny();
          const seen = new Set<string>();
          for (const grant of captured.trust.grants) {
            const profile = businessTransitionProfiles.find(
              (p) => p.profileId === grant.profileId && p.profileVersion === grant.profileVersion,
            );
            const matches = selectors.filter(
              (row) =>
                row.credentialId === provenance.predecessorCredentialId &&
                row.profileId === grant.profileId &&
                row.profileVersion === grant.profileVersion &&
                row.profileDigest === tagged(grant.profileDigest),
            );
            if (
              !profile ||
              profile.profileDigest !== tagged(grant.profileDigest) ||
              profile.actionIntentId !== grant.actionIntentId ||
              profile.catalogOperationId !== grant.catalogOperationId ||
              matches.length !== 1 ||
              seen.has(matches[0]!.profileDigest)
            )
              deny();
            seen.add(matches[0]!.profileDigest);
          }
          receiptCount += selectors.length;
        }
      }
      if (
        receiptCount !== source.receiptSelections.length ||
        envelopeCount !== source.envelopeSelections.length
      )
        deny();
    } catch {
      context.addIssue({
        code: 'custom',
        message: 'Invalid complete workload signing handover admission candidate',
      });
    }
  });
export type HandoverAdmissionCandidate = z.infer<typeof handoverAdmissionCandidateSchema>;
export type HandoverAdmissionCandidateRequest = z.infer<
  typeof handoverAdmissionCandidateRequestSchema
>;

export function handoverAdmissionCandidateBytes(input: HandoverAdmissionCandidate) {
  return canonical(handoverAdmissionCandidateSchema.parse(input));
}
/** Uses the existing shared approval digest, with schema and operation binding
 * in the closed body. A new private digest would not bind normal approvals. */
export function handoverAdmissionCandidateDigest(input: HandoverAdmissionCandidate) {
  return tagged(digest(handoverAdmissionCandidateBytes(input)));
}

export function buildHandoverAdmissionCandidate(input: {
  source: unknown;
  workloadId: string;
  trusts: readonly HandoverCapturedTrust[];
  generation: unknown;
  proofs: readonly z.input<typeof proofSchema>[];
  request: HandoverAdmissionCandidateRequest;
  preparedAtNs: string;
}): HandoverAdmissionCandidate {
  const generation = handoverPossessionGenerationSchema.parse(input.generation);
  return handoverAdmissionCandidateSchema.parse({
    schema: 'pc.identity.workload-signing-handover.admission-candidate.v1',
    participantId: generation.participantId,
    privacyDomainId: generation.privacyDomainId,
    environmentId: generation.environmentId,
    handoverId: generation.handoverId,
    makerPrincipalId: generation.makerPrincipalId,
    workloadId: input.workloadId,
    catalogOperationId: operation.catalogOperationId,
    expectedRevision: '1',
    validityPolicy: 'FROM_ATOMIC_ADMISSION_TO_EARLIEST_KEY_OR_CREDENTIAL_EXPIRY',
    request: input.request,
    preparedAtNs: input.preparedAtNs,
    expiresAtNs: generation.expiresAtNs,
    source: input.source,
    generation,
    predecessorTrusts: input.trusts.map(handoverAdmissionTrustDocument),
    proofs: input.proofs,
  });
}

/** Deterministic projection only. The admission owner must authenticate the
 * independent maker/checker witness and commit every key/selection atomically.
 * Its fenced admission timestamp prevents backdated authority for earlier bytes. */
function successorTrustsFromValidatedCandidate(
  candidate: HandoverAdmissionCandidate,
  at: bigint,
): HandoverCapturedTrust[] {
  if (at < BigInt(candidate.preparedAtNs) || at >= BigInt(candidate.expiresAtNs)) deny();
  const admissionDigest = digest(canonical(candidate));
  return candidate.predecessorTrusts.map((old, index) => {
    const captured = handoverAdmissionKernelTrust(old),
      descriptor = candidate.generation.keys[index]!.observation.descriptor;
    if (!descriptor) return deny();
    const issuerUntil = candidate.source.issuer.credentialValidUntilNs;
    const until =
      issuerUntil !== null && BigInt(issuerUntil) < BigInt(descriptor.validUntilNs)
        ? BigInt(issuerUntil)
        : BigInt(descriptor.validUntilNs);
    if (at < BigInt(descriptor.validFromNs) || at >= until) return deny();
    const common = {
      signerId: descriptor.fingerprint,
      publicKeySpkiDer: Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
      workloadCredentialId: candidate.source.issuer.workloadCredentialId,
      workloadCredentialEpoch: BigInt(candidate.source.issuer.workloadCredentialEpoch),
      keyEpoch: captured.trust.keyEpoch + 1n,
      validFromNs: at,
      validUntilNs: until,
      admissionKind: 'GOVERNED' as const,
      admissionReference: 'urn:openpc:workload-signing-handover:' + candidate.handoverId,
      admissionDigest,
      secretReference: descriptor.reference,
      secretVersion: descriptor.version,
    };
    const successor: HandoverCapturedTrust =
      captured.signerRole === 'IDENTITY_ENVELOPE'
        ? { signerRole: captured.signerRole, trust: { ...captured.trust, ...common } }
        : { signerRole: captured.signerRole, trust: { ...captured.trust, ...common } };
    if (successor.signerRole === 'IDENTITY_ENVELOPE')
      identityEnvelopeSigningTrustPreimage(successor.trust);
    else businessSigningTrustPreimage(successor.trust);
    return successor;
  });
}

export function handoverAdmissionSuccessorTrusts(
  input: HandoverAdmissionCandidate,
  admittedAtNs: string,
): HandoverCapturedTrust[] {
  return successorTrustsFromValidatedCandidate(
    handoverAdmissionCandidateSchema.parse(input),
    BigInt(handoverNanosSchema.parse(admittedAtNs)),
  );
}

/** Validate/copy once before deriving a complete transition. The parsed snapshot,
 * digest and successor trusts come from the same synchronous owner. No cached
 * readiness, unchecked public derivation or current authorization is supplied.
 */
export function prepareHandoverAdmissionTransitionCandidate(input: unknown, admittedAtNs: string) {
  const candidate = handoverAdmissionCandidateSchema.parse(input);
  const at = BigInt(handoverNanosSchema.parse(admittedAtNs));
  const maximum = 18446744073709551615n;
  for (const selection of candidate.source.receiptSelections) {
    for (const counter of [
      selection.rowVersion,
      selection.admissionVersion,
      selection.fenceGeneration,
    ]) {
      if (BigInt(counter) === maximum) return deny();
    }
  }
  for (const selection of candidate.source.envelopeSelections) {
    if (BigInt(selection.admissionVersion) === maximum) return deny();
  }
  const trusts = successorTrustsFromValidatedCandidate(candidate, at);
  return { candidate, candidateDigest: tagged(digest(canonical(candidate))), trusts };
}
