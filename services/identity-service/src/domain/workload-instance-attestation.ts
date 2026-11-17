import { createPublicKey, verify } from 'node:crypto';
import type { z } from 'zod';
import { workloadRenewalDigest } from '@openpc/security-kernel';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import {
  workloadInstanceAdmissionProposalSchema,
  workloadInstanceAdmissionDefinitionBytes,
} from '../contracts/workload-instance-admission.js';
import {
  encodeWorkloadInstanceChallenge,
  workloadInstanceChallengeDigest,
  encodeManagedWorkloadInstanceStatement,
  decodeManagedWorkloadInstanceEvidence,
  snapshotWorkloadInstanceEvidence,
  workloadInstanceParentValiditySchema,
  type WorkloadInstanceParentValidity,
  type WorkloadInstanceChallenge,
} from '../contracts/workload-instance-attestation.js';
import {
  assertWorkloadAttestationData,
  encodeManagedWorkloadAttestationProfile,
  managedWorkloadAttestationProfileDigest,
  type ManagedWorkloadAttestationProfile,
} from '../contracts/workload-renewal-attestation.js';
import {
  workloadRenewalPolicyDefinitionSchema,
  workloadRenewalPolicyDefinitionDigest,
  type WorkloadRenewalPolicyDefinition,
} from '../contracts/workload-renewal-policy.js';

export interface HistoricalWorkloadInstanceAttestation {
  readonly enrollmentPreparationOperationId: string;
  readonly enrollmentAttemptId: string;
  readonly challengeId: string;
  readonly candidateDigest: string;
  readonly definitionDigest: string;
  readonly challengeDigest: string;
  readonly evidenceDigest: string;
  readonly nativeObservationDigest: string;
  readonly attestationProfileDigest: string;
  readonly attestorKeyDigest: string;
  readonly statementIssuedAtNs: string;
  readonly statementValidUntilNs: string;
}

/** Historical signature authentication only. The trusted installation must
 * supply actual original candidate/challenge, initial-qualified attestor profile
 * and digest of its real native handle. The caller's profile/JSON/measurement
 * cannot qualify itself. Complete current policy/ARCHIVE/mTLS/native registration,
 * one-use challenge, quota and human governance remain durable owning gates.
 * Repeating this PURE function is permitted; it cannot admit or consume state. */
export function verifyManagedWorkloadInstanceAttestation(
  inputEvidence: Buffer,
  expected: {
    readonly challenge: WorkloadInstanceChallenge;
    readonly profile: ManagedWorkloadAttestationProfile;
    readonly proposal: z.infer<typeof workloadInstanceAdmissionProposalSchema>;
    readonly policyDefinition: WorkloadRenewalPolicyDefinition;
    readonly policyRevision: string;
    readonly nativeObservationDigest: string;
    readonly parentValidity: WorkloadInstanceParentValidity;
    readonly nowNs: bigint;
  },
): Readonly<HistoricalWorkloadInstanceAttestation> | undefined {
  try {
    // Capture closed expected DATA properties once, before parsing anything.
    const keys = [
      'challenge',
      'profile',
      'proposal',
      'policyDefinition',
      'policyRevision',
      'nativeObservationDigest',
      'parentValidity',
      'nowNs',
    ];
    if (!expected || Object.getPrototypeOf(expected) !== Object.prototype) return undefined;
    const actual = Reflect.ownKeys(expected);
    if (
      actual.length !== keys.length ||
      actual.some((key) => typeof key !== 'string' || !keys.includes(key))
    )
      return undefined;
    const values = Object.fromEntries(
      keys.map((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(expected, key);
        if (!descriptor?.enumerable || !('value' in descriptor))
          throw new Error('Invalid initial instance expectations');
        return [key, descriptor.value];
      }),
    );
    const evidence = snapshotWorkloadInstanceEvidence(inputEvidence);
    const challengeBytes = encodeWorkloadInstanceChallenge(
      values.challenge as WorkloadInstanceChallenge,
    );
    const challenge = JSON.parse(challengeBytes.toString('utf8')) as WorkloadInstanceChallenge;
    const profile = JSON.parse(
      encodeManagedWorkloadAttestationProfile(
        values.profile as ManagedWorkloadAttestationProfile,
      ).toString('utf8'),
    ) as ManagedWorkloadAttestationProfile;
    assertWorkloadAttestationData(values.proposal);
    assertWorkloadAttestationData(values.policyDefinition);
    assertWorkloadAttestationData(values.parentValidity);
    const proposal = workloadInstanceAdmissionProposalSchema.parse(values.proposal);
    const policy = workloadRenewalPolicyDefinitionSchema.parse(values.policyDefinition);
    const parentValidity = workloadInstanceParentValiditySchema.parse(values.parentValidity);
    const definition = challenge.definition;
    const now = values.nowNs;
    if (
      typeof now !== 'bigint' ||
      now < 0n ||
      now > 18446744073709551615n ||
      now % 1000n !== 0n ||
      typeof values.nativeObservationDigest !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/u.test(values.nativeObservationDigest)
    )
      return undefined;
    const from = BigInt(challenge.issuedAtNs),
      until = BigInt(challenge.validUntilNs);
    const profileDigest = managedWorkloadAttestationProfileDigest(profile);
    if (
      now < from ||
      now >= until ||
      from < BigInt(Date.parse(policy.validFrom)) * 1000000n ||
      until > BigInt(Date.parse(policy.validUntil)) * 1000000n ||
      from < BigInt(profile.validFromNs) ||
      until > BigInt(profile.validUntilNs) ||
      from < BigInt(parentValidity.initialCredentialValidFromNs) ||
      until > BigInt(parentValidity.initialCredentialValidUntilNs) ||
      from < BigInt(parentValidity.approvalValidFromNs) ||
      until > BigInt(parentValidity.approvalValidUntilNs) ||
      challenge.approvalRequestId !== parentValidity.approvalRequestId ||
      Date.parse(definition.validFrom) < Date.parse(policy.validFrom) ||
      Date.parse(definition.validUntil) > Date.parse(policy.validUntil) ||
      definition.environmentId !== profile.environmentId ||
      definition.attestationProfileDigest !== profileDigest ||
      definition.managedAttestorScopeDigest !== profile.managedAttestorScopeDigest ||
      definition.policyRevision !== values.policyRevision ||
      definition.policyDigest !== workloadRenewalPolicyDefinitionDigest(policy) ||
      challenge.candidateDigest !== sha256(proposal) ||
      !workloadInstanceAdmissionDefinitionBytes(definition).equals(
        workloadInstanceAdmissionDefinitionBytes(proposal.definition),
      ) ||
      (
        [
          'participantId',
          'privacyDomainId',
          'principalId',
          'workloadId',
          'policyId',
          'attestationProfileDigest',
          'issuerProfileDigest',
          'providerQualificationDigest',
          'managedAttestorScopeDigest',
        ] as const
      ).some((field) => definition[field] !== policy[field])
    )
      return undefined;
    const envelope = decodeManagedWorkloadInstanceEvidence(evidence);
    const statement = envelope.statement;
    const challengeDigest = workloadInstanceChallengeDigest(challenge);
    const spki = Buffer.from(profile.publicKeySpkiDerBase64, 'base64');
    const key = createPublicKey({ key: spki, type: 'spki', format: 'der' });
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
      statement.nativeObservationDigest !== values.nativeObservationDigest ||
      statement.challengeDigest !== challengeDigest ||
      !encodeWorkloadInstanceChallenge(statement.challenge).equals(challengeBytes) ||
      !verify(
        null,
        encodeManagedWorkloadInstanceStatement(statement),
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
      proofUntil - issued > 60000000000n ||
      now - issued > 60000000000n
    )
      return undefined;
    return Object.freeze({
      enrollmentPreparationOperationId: challenge.enrollmentPreparationOperationId,
      enrollmentAttemptId: challenge.enrollmentAttemptId,
      challengeId: challenge.challengeId,
      candidateDigest: challenge.candidateDigest,
      definitionDigest: challenge.definitionDigest,
      challengeDigest,
      evidenceDigest: workloadRenewalDigest(evidence),
      nativeObservationDigest: statement.nativeObservationDigest,
      attestationProfileDigest: profileDigest,
      attestorKeyDigest: keyDigest,
      statementIssuedAtNs: statement.issuedAtNs,
      statementValidUntilNs: statement.validUntilNs,
    });
  } catch {
    return undefined;
  }
}
