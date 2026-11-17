import { createPublicKey, verify } from 'node:crypto';
import {
  decodeWorkloadRenewalRequest,
  verifyWorkloadRenewalCose,
  workloadRenewalDigest,
} from '@openpc/security-kernel';
import {
  assertWorkloadAttestationData,
  decodeManagedWorkloadAttestationEvidence,
  encodeManagedWorkloadAttestationProfile,
  encodeManagedWorkloadAttestationStatement,
  encodeWorkloadRenewalChallenge,
  managedWorkloadAttestationProfileDigest,
  workloadRenewalChallengeDigest,
  type ManagedWorkloadAttestationProfile,
  type WorkloadRenewalChallenge,
} from '../contracts/workload-renewal-attestation.js';
import {
  workloadRenewalPolicyDefinitionDigest,
  workloadRenewalPolicyDefinitionSchema,
  type WorkloadRenewalPolicyDefinition,
} from '../contracts/workload-renewal-policy.js';

export interface AuthenticatedManagedWorkloadAttestation {
  readonly challengeId: string;
  readonly renewalId: string;
  readonly challengeDigest: string;
  readonly evidenceDigest: string;
  readonly attestationProfileDigest: string;
  readonly attestorKeyDigest: string;
  readonly statementIssuedAtNs: string;
  readonly statementValidUntilNs: string;
}

function ownDataRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error('Invalid workload attestation wrapper');
  const actual = Reflect.ownKeys(value);
  if (
    actual.length !== keys.length ||
    actual.some((key) => typeof key !== 'string' || !keys.includes(key))
  )
    throw new Error('Invalid workload attestation wrapper');
  return Object.fromEntries(
    keys.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !('value' in descriptor))
        throw new Error('Invalid workload attestation wrapper');
      return [key, descriptor.value];
    }),
  );
}

// Use TypedArray internal slots to measure/copy a Buffer. Buffer.from(value),
// value.length, value.copy/slice and constructor/species can be overridden on
// an input object. No input-supplied binary method participates in a snapshot.
const arrayLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'length',
)!.get!;
const arraySet = Uint8Array.prototype.set;
function binarySnapshot(value: unknown, maximum: number, exact?: number): Buffer {
  if (!Buffer.isBuffer(value) || Object.getPrototypeOf(value) !== Buffer.prototype)
    throw new Error('Invalid workload attestation binary input');
  const length = Reflect.apply(arrayLength, value, []) as number;
  if (length < 1 || length > maximum || (exact !== undefined && length !== exact))
    throw new Error('Invalid workload attestation binary input');
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== length ||
    keys.some((key) => typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(key))
  )
    throw new Error('Invalid workload attestation binary properties');
  const snapshot = Buffer.alloc(length);
  Reflect.apply(arraySet, snapshot, [value]);
  return snapshot;
}

/** Exact historical cryptographic verification against INDEPENDENT expected
 * inputs supplied by the owning installation/challenge composition. It cannot
 * authenticate that composition or current qualification, policy permission,
 * C04/ARCHIVE/family fences, live mTLS, issuance or durable nonce consumption.
 * Repeated verification of the same history is deliberately possible.
 *
 * The later durable owner must persist the real ARCHIVE and family-security
 * fences at challenge issuance, consume with the original admission, and
 * compare actual current fences/policy/instance under C04 again before signing.
 * Expired-leaf re-enrollment requires its distinct operation, never this proof.
 */
export function verifyManagedWorkloadRenewalAttestation(
  input: {
    readonly evidence: Buffer;
    readonly requestBytes: Buffer;
    readonly newKeyProof: Buffer;
    readonly successorSpkiDer: Buffer;
  },
  expected: {
    readonly challenge: WorkloadRenewalChallenge;
    readonly profile: ManagedWorkloadAttestationProfile;
    readonly policyDefinition: WorkloadRenewalPolicyDefinition;
    readonly policyRevision: string;
    readonly nowNs: bigint;
  },
): Readonly<AuthenticatedManagedWorkloadAttestation> | undefined {
  try {
    const supplied = ownDataRecord(input, [
      'evidence',
      'requestBytes',
      'newKeyProof',
      'successorSpkiDer',
    ]);
    const trusted = ownDataRecord(expected, [
      'challenge',
      'profile',
      'policyDefinition',
      'policyRevision',
      'nowNs',
    ]);
    const evidence = binarySnapshot(supplied.evidence, 16384);
    const requestBytes = binarySnapshot(supplied.requestBytes, 8192);
    const newKeyProof = binarySnapshot(supplied.newKeyProof, 8192);
    const successorSpkiDer = binarySnapshot(supplied.successorSpkiDer, 91, 91);
    const challengeBytes = encodeWorkloadRenewalChallenge(
      trusted.challenge as WorkloadRenewalChallenge,
    );
    // Snapshot trusted public inputs; no reference to a mutable caller object
    // survives validation. Profile digest binds its entire finite public key.
    const challenge = JSON.parse(challengeBytes.toString('utf8')) as WorkloadRenewalChallenge;
    const profile = JSON.parse(
      encodeManagedWorkloadAttestationProfile(
        trusted.profile as ManagedWorkloadAttestationProfile,
      ).toString('utf8'),
    ) as ManagedWorkloadAttestationProfile;
    assertWorkloadAttestationData(trusted.policyDefinition);
    const policy = workloadRenewalPolicyDefinitionSchema.parse(trusted.policyDefinition);
    const now = trusted.nowNs;
    if (typeof now !== 'bigint' || now < 0n || now > 18446744073709551615n || now % 1000n !== 0n)
      return undefined;
    const from = BigInt(challenge.issuedAtNs),
      until = BigInt(challenge.validUntilNs);
    const policyFrom = BigInt(Date.parse(policy.validFrom)) * 1000000n;
    const policyUntil = BigInt(Date.parse(policy.validUntil)) * 1000000n;
    const profileDigest = managedWorkloadAttestationProfileDigest(profile);
    if (
      now < from ||
      now >= until ||
      from < policyFrom ||
      until > policyUntil ||
      from < BigInt(profile.validFromNs) ||
      until > BigInt(profile.validUntilNs) ||
      challenge.environmentId !== profile.environmentId ||
      challenge.attestationProfileDigest !== profileDigest ||
      challenge.managedAttestorScopeDigest !== profile.managedAttestorScopeDigest ||
      challenge.managedAttestorScopeDigest !== policy.managedAttestorScopeDigest ||
      challenge.policyRevision !== trusted.policyRevision ||
      challenge.policyDigest !== workloadRenewalPolicyDefinitionDigest(policy) ||
      [
        'participantId',
        'privacyDomainId',
        'principalId',
        'workloadId',
        'policyId',
        'attestationProfileDigest',
        'issuerProfileDigest',
        'providerQualificationDigest',
      ].some(
        (field) =>
          challenge[field as keyof typeof challenge] !== policy[field as keyof typeof policy],
      ) ||
      BigInt(challenge.requestedCertificateNotBeforeNs) < policyFrom ||
      BigInt(challenge.requestedCertificateNotBeforeNs) > now ||
      BigInt(challenge.requestedCertificateNotAfterNs) > policyUntil ||
      BigInt(challenge.requestedCertificateNotAfterNs) <= now ||
      BigInt(challenge.requestedCertificateNotAfterNs) -
        BigInt(challenge.requestedCertificateNotBeforeNs) >
        BigInt(policy.certificateLifetimeSeconds) * 1000000000n
    )
      return undefined;

    const envelope = decodeManagedWorkloadAttestationEvidence(evidence);
    const statement = envelope.statement;
    const challengeDigest = workloadRenewalChallengeDigest(challenge);
    const spki = Buffer.from(profile.publicKeySpkiDerBase64, 'base64');
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const keyDigest = workloadRenewalDigest(spki);
    if (
      spki.length !== 44 ||
      key.asymmetricKeyType !== 'ed25519' ||
      !Buffer.from(key.export({ format: 'der', type: 'spki' })).equals(spki) ||
      statement.issuer !== profile.issuer ||
      statement.audience !== profile.audience ||
      statement.attestorKeyDigest !== keyDigest ||
      statement.attestationProfileDigest !== profileDigest ||
      statement.managedAttestorScopeDigest !== profile.managedAttestorScopeDigest ||
      statement.challengeDigest !== challengeDigest ||
      !encodeWorkloadRenewalChallenge(statement.challenge).equals(challengeBytes) ||
      !verify(
        null,
        encodeManagedWorkloadAttestationStatement(statement),
        key,
        Buffer.from(envelope.signatureBase64, 'base64'),
      )
    )
      return undefined;
    const issued = BigInt(statement.issuedAtNs),
      proofUntil = BigInt(statement.validUntilNs);
    if (
      issued < from ||
      issued > now ||
      now >= proofUntil ||
      proofUntil > until ||
      proofUntil - issued > BigInt(profile.maximumEvidenceLifetimeSeconds) * 1000000000n ||
      // Proof freshness supplements, and never replaces/extends, the separate
      // <=60s authentication/current assertion checked by the transport owner.
      now - issued > 60000000000n
    )
      return undefined;

    const request = decodeWorkloadRenewalRequest(requestBytes);
    if (
      !verifyWorkloadRenewalCose('REQUEST', successorSpkiDer, requestBytes, newKeyProof) ||
      workloadRenewalDigest(successorSpkiDer) !== challenge.newKeyDigest ||
      request.challengeDigest !== challengeDigest ||
      request.attestationDigest !== workloadRenewalDigest(evidence)
    )
      return undefined;
    for (const field of [
      'participantId',
      'privacyDomainId',
      'principalId',
      'workloadId',
      'familyId',
      'instanceId',
      'instanceGeneration',
      'renewalId',
      'predecessorCredentialId',
      'predecessorGeneration',
      'expectedFamilyRevision',
      'policyId',
      'policyRevision',
      'policyDigest',
      'attestationProfileDigest',
      'issuerProfileDigest',
      'providerQualificationDigest',
      'newKeyDigest',
      'challengeId',
      'requestedCertificateNotBeforeNs',
      'requestedCertificateNotAfterNs',
    ] as const)
      if (request[field] !== challenge[field]) return undefined;
    if (
      BigInt(request.requestValidFromNs) < issued ||
      BigInt(request.requestValidFromNs) > now ||
      BigInt(request.requestValidUntilNs) > proofUntil ||
      BigInt(request.requestValidUntilNs) <= now
    )
      return undefined;
    return Object.freeze({
      challengeId: challenge.challengeId,
      renewalId: challenge.renewalId,
      challengeDigest,
      evidenceDigest: workloadRenewalDigest(evidence),
      attestationProfileDigest: profileDigest,
      attestorKeyDigest: keyDigest,
      statementIssuedAtNs: statement.issuedAtNs,
      statementValidUntilNs: statement.validUntilNs,
    });
  } catch {
    return undefined;
  }
}
