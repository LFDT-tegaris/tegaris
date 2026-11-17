import {
  identityEnvelopeSigningTrustDigest,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../../identity-service/src/contracts/authorization.js';
import {
  identityEnvelopeRotationRequestSchema,
  validateIdentityEnvelopeRotationObservation,
} from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';
import {
  planIdentityEnvelopeRotationAttempts,
  type IdentityEnvelopeRotationPlanInput,
} from '../../identity-service/src/domain/identity-envelope-rotation-plan.js';
import { buildIdentityEnvelopeRotationTrust } from '../../identity-service/src/domain/identity-envelope-rotation-trust.js';

export class IdentityEnvelopeRotationProofUnavailable extends Error {
  constructor() {
    super('Identity envelope dual possession proof unavailable');
  }
}

/** Cryptographic preflight only. The persistence owner must authenticate the
 * installed signed custody, current lease/issuer and immutable original journal;
 * these arguments never authorize trust admission or establish consumer use. */
export function authenticateIdentityEnvelopeRotationDualProof(
  input: Omit<IdentityEnvelopeRotationPlanInput, 'state' | 'toState'>,
  records: readonly {
    slot: string;
    request: unknown;
    firstObservation: unknown;
    observation: unknown;
  }[],
) {
  try {
    if (records.length !== 2 || !input.descriptor) throw new Error();
    const slots = ['old', 'new'] as const;
    const ordered = slots.map((slot) => {
      const matching = records.filter((record) => record.slot === slot);
      if (matching.length !== 1) throw new Error();
      const record = matching[0]!;
      const request = identityEnvelopeRotationRequestSchema.parse(record.request);
      if (request.method !== 'PROVE') throw new Error();
      const first = validateIdentityEnvelopeRotationObservation(request, record.firstObservation);
      const observation = validateIdentityEnvelopeRotationObservation(request, record.observation);
      if (
        observation.outcome !== 'SUCCEEDED' ||
        !observation.descriptor ||
        canonicalAuthorizationJson(first) !== canonicalAuthorizationJson(observation) ||
        BigInt(request.challengeIssuedAtNs) > input.nowNs ||
        BigInt(request.challengeExpiresAtNs) <= input.nowNs ||
        BigInt(observation.recordedAtNs) > input.nowNs
      )
        throw new Error();
      return { slot, request, observation };
    });
    const originalPlanTime = BigInt(ordered[0]!.request.challengeIssuedAtNs);
    if (ordered.some((record) => BigInt(record.request.challengeIssuedAtNs) !== originalPlanTime))
      throw new Error();
    let index = 0;
    const planned = planIdentityEnvelopeRotationAttempts(
      {
        ...input,
        state: 'DISTRIBUTED',
        toState: 'VERIFIED',
        nowNs: originalPlanTime,
      },
      () => ordered[index++]!.request.attemptId,
    );
    const trust = planned.successor;
    if (!trust || planned.attempts.length !== 2) throw new Error();
    // Rebuild at actual publication time too: an expired lease, issuer validity
    // or immutable descriptor cannot be rescued by an earlier proof timestamp.
    const current = buildIdentityEnvelopeRotationTrust({
      oldTrust: input.oldTrust,
      oldLifecycleState: 'ACTIVE',
      descriptor: input.descriptor,
      preparedIssuer: input.preparedIssuer,
      currentIssuer: input.currentIssuer,
      admission: input.admission,
      observedAtNs: input.nowNs,
    });
    if (
      input.nowNs >= input.authorityValidUntilNs ||
      identityEnvelopeSigningTrustDigest(current) !== identityEnvelopeSigningTrustDigest(trust)
    )
      throw new Error();
    for (let i = 0; i < ordered.length; i++) {
      const record = ordered[i]!;
      if (
        canonicalAuthorizationJson(planned.attempts[i]?.request) !==
        canonicalAuthorizationJson(record.request)
      )
        throw new Error();
      const descriptor = record.observation.descriptor!;
      if (record.slot === 'new') {
        if (canonicalAuthorizationJson(descriptor) !== canonicalAuthorizationJson(input.descriptor))
          throw new Error();
      } else if (!oldDescriptorMatches(input.oldTrust, descriptor)) throw new Error();
    }
    return {
      trust,
      trustDigest: identityEnvelopeSigningTrustDigest(trust),
      observationsDigest: canonicalAuthorizationDigest(ordered),
      proofExpiresAtNs: ordered
        .map((record) => BigInt(record.request.challengeExpiresAtNs))
        .reduce((a, b) => (a < b ? a : b)),
    };
  } catch {
    throw new IdentityEnvelopeRotationProofUnavailable();
  }
}

function oldDescriptorMatches(
  trust: IdentityEnvelopeSigningTrust,
  descriptor: NonNullable<
    ReturnType<typeof validateIdentityEnvelopeRotationObservation>['descriptor']
  >,
) {
  return (
    descriptor.participantId === trust.participantId &&
    descriptor.privacyDomainId === trust.privacyDomainId &&
    descriptor.environmentId === trust.environmentId &&
    descriptor.workloadCredentialId === trust.workloadCredentialId &&
    descriptor.workloadCredentialEpoch === trust.workloadCredentialEpoch.toString() &&
    descriptor.fingerprint === trust.signerId &&
    descriptor.publicKeySpkiHex === trust.publicKeySpkiDer.toString('hex') &&
    descriptor.reference === trust.secretReference &&
    descriptor.version === trust.secretVersion &&
    descriptor.validFromNs === trust.validFromNs.toString() &&
    descriptor.validUntilNs === trust.validUntilNs.toString() &&
    descriptor.state === 'ACTIVE' &&
    descriptor.revokedAtNs === null &&
    descriptor.retiredAtNs === null
  );
}

/** Exact original effective proof. This establishes possession only; the
 * publisher must separately authenticate the pinned actual typed consumer. */
export function authenticateIdentityEnvelopeRotationEffectiveProof(
  input: Omit<IdentityEnvelopeRotationPlanInput, 'state' | 'toState'> & {
    selectedTrust: IdentityEnvelopeSigningTrust;
  },
  record: { slot: string; request: unknown; firstObservation: unknown; observation: unknown },
) {
  try {
    const request = identityEnvelopeRotationRequestSchema.parse(record.request);
    if (record.slot !== 'effective' || request.method !== 'PROVE' || !input.descriptor)
      throw new Error();
    const first = validateIdentityEnvelopeRotationObservation(request, record.firstObservation);
    const observation = validateIdentityEnvelopeRotationObservation(request, record.observation);
    if (
      observation.outcome !== 'SUCCEEDED' ||
      !observation.descriptor ||
      canonicalAuthorizationJson(first) !== canonicalAuthorizationJson(observation) ||
      canonicalAuthorizationJson(observation.descriptor) !==
        canonicalAuthorizationJson(input.descriptor) ||
      BigInt(request.challengeIssuedAtNs) > input.nowNs ||
      BigInt(request.challengeExpiresAtNs) <= input.nowNs ||
      BigInt(observation.recordedAtNs) > input.nowNs ||
      input.nowNs >= input.authorityValidUntilNs
    )
      throw new Error();
    const plan = planIdentityEnvelopeRotationAttempts(
      {
        ...input,
        state: 'CUTOVER_FENCED',
        toState: 'OBSERVING',
        nowNs: BigInt(request.challengeIssuedAtNs),
      },
      () => request.attemptId,
    );
    const current = buildIdentityEnvelopeRotationTrust({
      oldTrust: input.oldTrust,
      oldLifecycleState: 'ACTIVE',
      descriptor: input.descriptor,
      preparedIssuer: input.preparedIssuer,
      currentIssuer: input.currentIssuer,
      admission: input.admission,
      observedAtNs: input.nowNs,
    });
    if (
      plan.attempts.length !== 1 ||
      canonicalAuthorizationJson(plan.attempts[0]?.request) !==
        canonicalAuthorizationJson(request) ||
      identityEnvelopeSigningTrustDigest(current) !==
        identityEnvelopeSigningTrustDigest(input.selectedTrust) ||
      identityEnvelopeSigningTrustDigest(plan.successor!) !==
        identityEnvelopeSigningTrustDigest(current)
    )
      throw new Error();
    return {
      trust: current,
      trustDigest: identityEnvelopeSigningTrustDigest(current),
      observationsDigest: canonicalAuthorizationDigest([
        { slot: 'effective', request, observation },
      ]),
    };
  } catch {
    throw new IdentityEnvelopeRotationProofUnavailable();
  }
}
