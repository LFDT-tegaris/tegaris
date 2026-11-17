import { createHash, timingSafeEqual } from 'node:crypto';

import {
  controlMutationForAction,
  decodeIdentityAuthContextAssertionPayload,
  encodeIdentityAuthContextAssertionPayload,
  type IdentityAuthContextAssertionPayload,
} from '@openpc/security-kernel';

const ASSERTION_TTL_MS = 60_000;
const CLOCK_SKEW_MS = 5_000;
const BROWSER_SESSION_SENDER_BINDING = 1 as const;

export interface IdentityRuntimeAuthorizationContext {
  readonly participantId: string;
  readonly principalId: string;
  readonly sessionId: string;
  readonly sessionEpoch: string;
  readonly sessionIssuedAt: Date;
  readonly sessionIdleExpiresAt: Date;
  readonly sessionAbsoluteExpiresAt: Date;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly assignmentId: string;
  readonly assignmentRowVersion: string;
  readonly authorityEnvelopeId: string;
  readonly authorityEpoch: string;
  readonly delegationEpoch: string;
  readonly authorityValidUntil?: Date | null;
  readonly actionIntentId: string;
  readonly catalogOperationId: string;
  readonly resourceId: string;
  readonly candidateDigest: string;
  readonly sessionToken: string;
  readonly configurationBinding?: {
    readonly privacyDomainId: string;
    readonly actionIntentDigest: string;
    readonly expectedRevision: string;
  };
}

function framedDigest(domain: string, values: readonly string[]): Buffer {
  const hash = createHash('sha256').update(`${domain}\0`);
  for (const value of values) {
    const encoded = Buffer.from(value, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(encoded.length);
    hash.update(length).update(encoded);
  }
  return hash.digest();
}

function mutationAudience(input: IdentityRuntimeAuthorizationContext): Buffer {
  const operation = controlMutationForAction(input.actionIntentId, input.catalogOperationId);
  const binding = input.configurationBinding;
  if (
    operation !== undefined ||
    input.catalogOperationId.startsWith('CFG-OP-') ||
    input.catalogOperationId.startsWith('OPS-OP-') ||
    binding !== undefined
  ) {
    if (
      operation === undefined ||
      operation.catalogOperationId !== input.catalogOperationId ||
      binding === undefined ||
      Object.keys(binding).length !== 3 ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        binding.privacyDomainId,
      ) ||
      !/^sha256:[0-9a-f]{64}$/u.test(binding.actionIntentDigest) ||
      !/^sha256:[0-9a-f]{64}$/u.test(input.candidateDigest) ||
      !/^(?:0|[1-9][0-9]{0,19})$/u.test(binding.expectedRevision) ||
      BigInt(binding.expectedRevision) > 18_446_744_073_709_551_615n
    )
      throw new Error('Invalid configuration authorization audience');
    return framedDigest('pc.control.configuration-mutation-audience.v1', [
      input.participantId,
      binding.privacyDomainId,
      input.actionIntentId,
      binding.actionIntentDigest,
      input.catalogOperationId,
      input.resourceId,
      input.candidateDigest,
      binding.expectedRevision,
    ]);
  }
  return identityMutationAudienceDigest(input);
}

/** Purpose binding for an Identity authorization assertion; shared by durable verification readers. */
export function identityMutationAudienceDigest(
  input: Pick<
    IdentityRuntimeAuthorizationContext,
    'actionIntentId' | 'catalogOperationId' | 'resourceId' | 'candidateDigest'
  >,
): Buffer {
  return framedDigest('pc.identity.mutation-audience.v2', [
    input.actionIntentId,
    input.catalogOperationId,
    input.resourceId,
    input.candidateDigest,
  ]);
}

/** Canonical actor identity binding shared by runtime assertions and governed receipts. */
export function identityActorKeyDigest(participantId: string, principalId: string): Buffer {
  return framedDigest('pc.identity.actor-key.v2', [participantId, principalId]);
}

function expectedBindings(input: IdentityRuntimeAuthorizationContext) {
  return {
    actorKeyDigest: identityActorKeyDigest(input.participantId, input.principalId),
    participantContextDigest: framedDigest('pc.identity.participant-context.v2', [
      input.participantId,
      input.participantEpoch,
    ]),
    audienceDigest: mutationAudience(input),
    assuranceProfileDigest: framedDigest('pc.identity.assurance-profile.v2', [
      'active-browser-session',
    ]),
    authorityVectorDigest: framedDigest('pc.identity.authority-vector.v2', [
      input.participantEpoch,
      input.principalEpoch,
      input.authorityEnvelopeId,
      input.authorityEpoch,
      input.assignmentId,
      input.assignmentRowVersion,
      input.delegationEpoch,
    ]),
    authenticationEvidenceDigest: framedDigest('pc.identity.authentication-evidence.v2', [
      input.sessionId,
      input.sessionEpoch,
      input.sessionIssuedAt.toISOString(),
    ]),
    senderCredentialBindingDigest: framedDigest('pc.identity.sender-credential.v2', [
      input.sessionToken,
    ]),
  };
}

function millisecondsToNanoseconds(value: number): bigint {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('invalid assertion time');
  return BigInt(value) * 1_000_000n;
}

export function createIdentityRuntimeAuthorizationAssertion(
  assertionId: string,
  input: IdentityRuntimeAuthorizationContext,
  issuedAt: Date,
): Buffer {
  const expiresAtMs = Math.min(
    issuedAt.getTime() + ASSERTION_TTL_MS,
    input.sessionIdleExpiresAt.getTime(),
    input.sessionAbsoluteExpiresAt.getTime(),
    input.authorityValidUntil?.getTime() ?? Infinity,
  );
  const bindings = expectedBindings(input);
  return encodeIdentityAuthContextAssertionPayload({
    assertionId,
    actorKeyDigest: bindings.actorKeyDigest,
    actorKind: 0,
    participantContextDigest: bindings.participantContextDigest,
    audienceDigest: bindings.audienceDigest,
    senderBindingKind: BROWSER_SESSION_SENDER_BINDING,
    assuranceProfileDigest: bindings.assuranceProfileDigest,
    authorityVectorDigest: bindings.authorityVectorDigest,
    issuedAtNs: millisecondsToNanoseconds(issuedAt.getTime()),
    expiresAtNs: millisecondsToNanoseconds(expiresAtMs),
    authenticationEvidenceDigest: bindings.authenticationEvidenceDigest,
    senderCredentialBindingDigest: bindings.senderCredentialBindingDigest,
  });
}

function equal(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

export function verifyIdentityRuntimeAuthorizationAssertion(
  evidenceCbor: Buffer,
  input: IdentityRuntimeAuthorizationContext,
  now: Date,
): IdentityAuthContextAssertionPayload | undefined {
  try {
    const assertion = decodeIdentityAuthContextAssertionPayload(evidenceCbor);
    const bindings = expectedBindings(input);
    const nowNs = millisecondsToNanoseconds(now.getTime());
    const skewNs = BigInt(CLOCK_SKEW_MS) * 1_000_000n;
    const ttlNs = BigInt(ASSERTION_TTL_MS) * 1_000_000n;
    const sessionExpiryNs = millisecondsToNanoseconds(
      Math.min(
        input.sessionIdleExpiresAt.getTime(),
        input.sessionAbsoluteExpiresAt.getTime(),
        input.authorityValidUntil?.getTime() ?? Infinity,
      ),
    );
    if (
      assertion.actorKind !== 0 ||
      assertion.senderBindingKind !== BROWSER_SESSION_SENDER_BINDING ||
      assertion.issuedAtNs > nowNs + skewNs ||
      assertion.expiresAtNs <= nowNs ||
      assertion.expiresAtNs - assertion.issuedAtNs > ttlNs ||
      assertion.expiresAtNs > sessionExpiryNs ||
      assertion.senderCredentialBindingDigest === undefined ||
      !equal(assertion.actorKeyDigest, bindings.actorKeyDigest) ||
      !equal(assertion.participantContextDigest, bindings.participantContextDigest) ||
      !equal(assertion.audienceDigest, bindings.audienceDigest) ||
      !equal(assertion.assuranceProfileDigest, bindings.assuranceProfileDigest) ||
      !equal(assertion.authorityVectorDigest, bindings.authorityVectorDigest) ||
      !equal(assertion.authenticationEvidenceDigest, bindings.authenticationEvidenceDigest) ||
      !equal(assertion.senderCredentialBindingDigest, bindings.senderCredentialBindingDigest)
    ) {
      return undefined;
    }
    return assertion;
  } catch {
    return undefined;
  }
}
