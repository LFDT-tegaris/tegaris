import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  businessSigningTrustPreimage,
  identityEnvelopeSigningTrustPreimage,
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import { workloadSigningHandoverAdmissionOperation as operation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import { workloadHandoverSigningFamilies } from '../../../../tests/integration/identity/workload-signing-handover-fixture.js';
import {
  businessProviderPossessionPreimage,
  businessSigningPurpose,
} from './business-signing-provider.js';
import { identityEnvelopeRotationPossessionPreimage } from './identity-envelope-rotation-provider.js';
import {
  prepareHandoverProviderAttempt,
  handoverProviderBindingSchema,
} from './workload-signing-handover-provider.js';
import {
  handoverPossessionGenerationSchema,
  handoverPossessionGenerationDigest,
  prepareHandoverPossessionAttempt,
} from './workload-signing-handover-possession.js';
import {
  handoverAdmissionSourceSchema,
  type HandoverCapturedTrust,
} from './workload-signing-handover-admission-material.js';
import {
  buildHandoverAdmissionCandidate,
  handoverAdmissionCandidateSchema,
  handoverAdmissionCandidateRequestSchema,
  handoverAdmissionCandidateBytes,
  handoverAdmissionCandidateDigest,
  handoverAdmissionSuccessorTrusts,
  prepareHandoverAdmissionTransitionCandidate,
  type HandoverAdmissionCandidate,
} from './workload-signing-handover-admission-candidate.js';
import { prepareHandoverAdmissionTransition } from './workload-signing-handover-admission-transition.js';

const id = (n: number) => '01a10000-0000-7000-8000-' + n.toString().padStart(12, '0');
const hash = (n: number) => 'sha256:' + n.toString(16).padStart(64, '0');
const tagged = (value: Buffer) => 'sha256:' + value.toString('hex');
type Source = ReturnType<typeof handoverAdmissionSourceSchema.parse>;

function fixture(mutateSource?: (source: Source) => void) {
  const now = BigInt(Date.now()) * 1000000n;
  const issuer = {
    participantId: id(1),
    privacyDomainId: id(2),
    workloadCredentialId: id(4),
    workloadPrincipalId: id(5),
    workloadParticipantEpoch: '1',
    workloadPrincipalEpoch: '1',
    workloadCredentialEpoch: '5',
    workloadPublicKeyDigest: hash(1),
    credentialValidFromNs: (now - 60000000000n).toString(),
    credentialValidUntilNs: (now + 3600000000000n).toString(),
  };
  const families = workloadHandoverSigningFamilies()
    .map((family, index) => {
      const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' });
      const common = {
        participantId: id(1),
        privacyDomainId: id(2),
        environmentId: 'synthetic-admission',
        signerId: evidenceKeyId(publicKey),
        publicKeySpkiDer: publicKey,
        workloadCredentialId: id(3),
        workloadCredentialEpoch: 4n,
        keyEpoch: 3n,
        validFromNs: now - 7200000000000n,
        validUntilNs: now - 60000000000n,
        admissionKind: 'BOOTSTRAP' as const,
        admissionReference: 'synthetic-old-' + index,
        admissionDigest: Buffer.alloc(32, index + 1),
        secretClass: 'SECRET-SIGNING-KEY' as const,
        secretReference: 'secret://local/old-' + index + '#1',
        secretVersion: '1',
      };
      const captured: HandoverCapturedTrust =
        family.role === 'IDENTITY_ENVELOPE'
          ? {
              signerRole: family.role,
              trust: {
                ...common,
                workloadParticipantEpoch: 1n,
                workloadPrincipalEpoch: 1n,
                purpose: identityEnvelopeContext.purpose,
                profileId: identityEnvelopeSigningProfile.profileId,
                profileVersion: 1,
                profileDigest: identityEnvelopeSigningProfileDigest,
              },
            }
          : {
              signerRole: family.role,
              trust: {
                ...common,
                grants: family.profiles.map((p) => ({
                  profileId: p.profileId,
                  profileVersion: p.profileVersion,
                  profileDigest: Buffer.from(p.profileDigest.slice(7), 'hex'),
                  actionIntentId: p.actionIntentId,
                  catalogOperationId: p.catalogOperationId,
                })),
              },
            };
      return { captured, pair: generateKeyPairSync('ec', { namedCurve: 'P-256' }) };
    })
    .sort((a, b) => a.captured.trust.signerId.localeCompare(b.captured.trust.signerId));
  const trusts = families.map((family) => family.captured);
  const keys = trusts.map((captured, index) => {
    const trust = captured.trust;
    const preimage =
      captured.signerRole === 'IDENTITY_ENVELOPE'
        ? identityEnvelopeSigningTrustPreimage(captured.trust)
        : businessSigningTrustPreimage(captured.trust);
    return {
      oldFingerprint: trust.signerId,
      oldTrustDigest: tagged(createHash('sha256').update(preimage).digest()),
      expectedKeyEpoch: trust.keyEpoch.toString(),
      oldReference: trust.secretReference,
      newReference: 'secret://local/new-' + index + '#2',
      signerRole: captured.signerRole,
      purpose:
        captured.signerRole === 'IDENTITY_ENVELOPE'
          ? identityEnvelopeContext.purpose
          : businessSigningPurpose,
      oldTrustPreimageBase64: preimage.toString('base64'),
      oldCredentialEpoch: '4',
      oldKeyValidFromNs: trust.validFromNs.toString(),
      oldKeyValidUntilNs: trust.validUntilNs.toString(),
    };
  });
  const source = handoverAdmissionSourceSchema.parse({
    schema: 'pc.identity.workload-signing-handover.source.v1',
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'synthetic-admission',
    issuer,
    provenance: {
      participantId: id(1),
      privacyDomainId: id(2),
      predecessorCredentialId: id(3),
      predecessorCredentialEpoch: '4',
      successorCredentialId: id(4),
      successorCredentialEpoch: '5',
      credentialRotationOperationId: id(6),
      principalId: id(5),
      makerPrincipalId: id(11),
      checkerPrincipalId: id(12),
      candidateDigest: hash(3),
      evidenceDigest: hash(4),
    },
    keys,
    receiptSelections: trusts
      .flatMap((captured) =>
        captured.signerRole === 'IDENTITY_ENVELOPE'
          ? []
          : captured.trust.grants.map((g) => ({
              signerId: captured.trust.signerId,
              credentialId: id(3),
              profileId: g.profileId,
              profileVersion: g.profileVersion,
              profileDigest: tagged(g.profileDigest),
              rowVersion: '1',
              admissionVersion: '1',
              fenceGeneration: '1',
              fencedOperationId: null,
            })),
      )
      .sort((a, b) => a.profileDigest.localeCompare(b.profileDigest)),
    envelopeSelections: trusts
      .filter((t) => t.signerRole === 'IDENTITY_ENVELOPE')
      .map((t) => ({
        signerId: t.trust.signerId,
        credentialId: id(3),
        profileDigest: identityEnvelopeSigningProfileDigest,
        admissionVersion: '1',
      })),
  });
  mutateSource?.(source);
  const sourceDigest = tagged(
    createHash('sha256')
      .update('pc.identity.workload-signing-handover.source.v1\0')
      .update(canonicalAuthorizationJson(source))
      .digest(),
  );
  const preparations = keys.map((key, index) => {
    const replacement = {
      oldFingerprint: key.oldFingerprint,
      oldTrustDigest: key.oldTrustDigest,
      expectedKeyEpoch: key.expectedKeyEpoch,
      oldReference: key.oldReference,
      newReference: key.newReference,
      signerRole: key.signerRole,
      purpose: key.purpose,
    };
    const binding = handoverProviderBindingSchema.parse({
      participantId: id(1),
      privacyDomainId: id(2),
      environmentId: source.environmentId,
      handoverId: id(8),
      sourceDigest,
      successorCredentialId: id(4),
      successorCredentialEpoch: '5',
      participantEpoch: '1',
      principalEpoch: '1',
      replacement,
      providerId: 'synthetic-admission-provider',
    });
    const attempt = prepareHandoverProviderAttempt(binding, {
      operationId: id(100 + index),
      attemptId: id(200 + index),
    });
    const spki = families[index]!.pair.publicKey.export({ type: 'spki', format: 'der' });
    const descriptor = {
      participantId: id(1),
      privacyDomainId: id(2),
      environmentId: source.environmentId,
      workloadCredentialId: id(4),
      secretClass: 'SECRET-SIGNING-KEY' as const,
      reference: key.newReference,
      version: '2',
      algorithm: 'ES256' as const,
      publicKeySpkiHex: spki.toString('hex'),
      fingerprint: evidenceKeyId(spki),
      validFromNs: issuer.credentialValidFromNs,
      validUntilNs: (now + 7200000000000n).toString(),
      state: 'ACTIVE' as const,
      revokedAtNs: null,
      retiredAtNs: null,
    };
    const common = {
      schemaVersion: 1 as const,
      providerId: binding.providerId,
      operationId: attempt.request.operationId,
      attemptId: attempt.request.attemptId,
      requestDigest: attempt.requestDigest,
      recordedAtNs: (now - 1000000n).toString(),
      outcome: 'SUCCEEDED' as const,
      reason: null,
      resultHex: null,
    };
    const observation =
      attempt.purpose === identityEnvelopeContext.purpose
        ? {
            ...common,
            method: 'PREPARE' as const,
            descriptor: {
              ...descriptor,
              purpose: identityEnvelopeContext.purpose,
              workloadCredentialEpoch: '5',
              purposeCode: 371 as const,
              schemaId: 24034 as const,
              schemaVersion: 1 as const,
              schemaDefinitionDigest: attempt.request.schemaDefinitionDigest,
              profileId: attempt.request.profileId,
              profileVersion: 1 as const,
              profileDigest: attempt.request.profileDigest,
            },
          }
        : {
            ...common,
            method: 'INSPECT' as const,
            descriptor: { ...descriptor, purpose: businessSigningPurpose },
          };
    return { binding, attempt, observation };
  });
  const generation = handoverPossessionGenerationSchema.parse({
    schema: 'pc.identity.workload-signing-handover.possession-generation.v1',
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: source.environmentId,
    handoverId: id(8),
    sourceDigest,
    generationId: id(9),
    operationId: id(10),
    makerPrincipalId: id(11),
    supersedesGenerationId: null,
    issuedAtNs: now.toString(),
    expiresAtNs: (now + 300000000000n).toString(),
    issuer,
    keys: preparations,
  });
  const proofs = generation.keys.map((key, index) => {
    const attempt = prepareHandoverPossessionAttempt(
      generation,
      key.binding.replacement.oldFingerprint,
      {
        operationId: id(10),
        attemptId: id(300 + index),
        challengeNonceHex: (index + 1).toString(16).padStart(64, '0'),
      },
    );
    if (attempt.request.method !== 'PROVE') throw new Error('Expected proof');
    const preimage =
      attempt.purpose === identityEnvelopeContext.purpose
        ? identityEnvelopeRotationPossessionPreimage(attempt.request)
        : businessProviderPossessionPreimage(attempt.request);
    return {
      attempt,
      observation: {
        ...key.observation,
        method: 'PROVE' as const,
        operationId: id(10),
        attemptId: attempt.request.attemptId,
        requestDigest: attempt.requestDigest,
        recordedAtNs: (now + 1000n).toString(),
        resultHex: sign('sha256', preimage, {
          key: families[index]!.pair.privateKey,
          dsaEncoding: 'ieee-p1363',
        }).toString('hex'),
      },
    };
  });
  const request = handoverAdmissionCandidateRequestSchema.parse({
    schemaVersion: 1,
    actionIntentId: operation.actionIntentId,
    actionIntentDigest: hash(7),
    generationId: generation.generationId,
    generationDigest: handoverPossessionGenerationDigest(generation),
    reason: 'Admit the exact complete successor bundle without changing its permitted profiles.',
  });
  const input = {
    source,
    workloadId: 'urn:openpc:workload:synthetic-api',
    trusts,
    generation,
    proofs,
    request,
    preparedAtNs: (now + 2000n).toString(),
  };
  return {
    input,
    candidate: () => buildHandoverAdmissionCandidate(input),
    admittedAtNs: (now + 3000n).toString(),
  };
}

it('derives an acyclic complete trust and selector authorization projection from the candidate', () => {
  const f = fixture(),
    candidate = f.candidate();
  const originalBytes = Buffer.from(canonicalAuthorizationJson(candidate));
  const plan = prepareHandoverAdmissionTransition({
    candidate,
    mutationCandidateId: id(700),
    operationId: id(701),
    admittedAtNs: f.admittedAtNs,
  });
  const binding = plan.authorizationBindings;
  expect(binding.candidateDigest).toBe(canonicalAuthorizationDigest(candidate));
  expect(binding).toMatchObject({
    participantId: candidate.participantId,
    privacyDomainId: candidate.privacyDomainId,
    environmentId: candidate.environmentId,
    workloadId: candidate.workloadId,
    mutationCandidateId: id(700),
    operationId: id(701),
    admittedAtNs: f.admittedAtNs,
    predecessorCredentialId: candidate.source.provenance.predecessorCredentialId,
    successorCredentialId: candidate.source.provenance.successorCredentialId,
    generationDigest: candidate.request.generationDigest,
  });
  expect(plan.provenance).toEqual({
    schema: 'pc.identity.workload-signing-handover.native-replacement-provenance.v1',
    ...candidate.source.provenance,
  });
  for (const [domain, document, bytes, digest] of [
    [
      'pc.identity.workload-signing-handover.native-replacement-provenance.v1',
      plan.provenance,
      plan.nativeReplacementProvenancePreimage,
      binding.nativeReplacementProvenanceDigest,
    ],
    [
      'pc.identity.workload-signing-handover.successor-trust-set.v1',
      plan.successorTrustSet,
      plan.successorTrustSetPreimage,
      binding.successorTrustSetDigest,
    ],
    [
      'pc.identity.workload-signing-handover.selector-transition.v1',
      plan.selectorTransition,
      plan.selectorTransitionPreimage,
      binding.selectorTransitionDigest,
    ],
  ] as const) {
    const prefix = Buffer.from(domain + '\0');
    expect(bytes.subarray(0, prefix.length)).toEqual(prefix);
    expect(bytes.subarray(prefix.length).toString()).toBe(canonicalAuthorizationJson(document));
    expect(digest).toBe(tagged(createHash('sha256').update(bytes).digest()));
  }
  expect(plan.successorTrustSet.members).toHaveLength(7);
  plan.successorTrustSet.members.forEach((member, index) => {
    const next = plan.trusts[index]!;
    const bytes =
      next.signerRole === 'IDENTITY_ENVELOPE'
        ? identityEnvelopeSigningTrustPreimage(next.trust)
        : businessSigningTrustPreimage(next.trust);
    expect(member).toEqual({
      predecessorSignerId: candidate.predecessorTrusts[index]!.signerId,
      successorSignerId: next.trust.signerId,
      signerRole: next.signerRole,
      trustDigest: tagged(createHash('sha256').update(bytes).digest()),
      trustPreimageBase64: bytes.toString('base64'),
    });
    expect(tagged(next.trust.admissionDigest)).toBe(binding.candidateDigest);
  });
  expect(plan.selectorTransition.receiptSelections).toHaveLength(18);
  for (const change of plan.selectorTransition.receiptSelections) {
    const before = candidate.source.receiptSelections.find(
      (row) => row.profileDigest === change.before.profileDigest,
    )!;
    const pair = plan.successorTrustSet.members.find(
      (member) => member.predecessorSignerId === before.signerId,
    )!;
    expect(change.before).toEqual(before);
    expect(change.selectorKind).toBe('BUSINESS_RECEIPT');
    expect(change.signerRole).toBe(pair.signerRole);
    expect(change.after).toEqual({
      ...before,
      signerId: pair.successorSignerId,
      credentialId: candidate.source.issuer.workloadCredentialId,
      rowVersion: (BigInt(before.rowVersion) + 1n).toString(),
      admissionVersion: (BigInt(before.admissionVersion) + 1n).toString(),
      fenceGeneration: (BigInt(before.fenceGeneration) + 1n).toString(),
      fencedOperationId: null,
    });
    for (const metadata of ['changedAtNs', 'changeReference', 'changeDigest']) {
      expect(change.before).not.toHaveProperty(metadata);
      expect(change.after).not.toHaveProperty(metadata);
    }
  }
  expect(plan.selectorTransition.envelopeSelections).toHaveLength(1);
  const change = plan.selectorTransition.envelopeSelections[0]!;
  const pair = plan.successorTrustSet.members.find(
    (member) => member.predecessorSignerId === change.before.signerId,
  )!;
  expect(change.selectorKind).toBe('IDENTITY_ENVELOPE');
  expect(change.profileId).toBe(identityEnvelopeSigningProfile.profileId);
  expect(change.profileVersion).toBe(1);
  expect(change.after).toEqual({
    ...change.before,
    signerId: pair.successorSignerId,
    credentialId: candidate.source.issuer.workloadCredentialId,
    admissionVersion: (BigInt(change.before.admissionVersion) + 1n).toString(),
  });
  expect(plan.successorTrustSet).not.toHaveProperty('successorTrustSetDigest');
  expect(plan.selectorTransition.successorTrustSetDigest).toBe(binding.successorTrustSetDigest);
  expect(plan.selectorTransition).not.toHaveProperty('selectorTransitionDigest');
  for (const missingAuthority of [
    'makerAuthorityDigest',
    'checkerAuthorityDigest',
    'approvalRequestId',
    'makerStepUpProofDigest',
    'checkerStepUpProofDigest',
    'coseSign1',
  ])
    expect(binding).not.toHaveProperty(missingAuthority);
  expect(Buffer.from(canonicalAuthorizationJson(candidate))).toEqual(originalBytes);
});

it('orders receipt selector projections by exact digest even when the captured source is differently ordered', () => {
  const f = fixture((source) => {
    source.receiptSelections.reverse();
  });
  const plan = prepareHandoverAdmissionTransition({
    candidate: f.candidate(),
    mutationCandidateId: id(700),
    operationId: id(701),
    admittedAtNs: f.admittedAtNs,
  });
  const digests = plan.selectorTransition.receiptSelections.map((row) => row.before.profileDigest);
  expect(digests).toEqual([...digests].sort());
});

it.each(['operation', 'candidate-id', 'admission-time'])(
  'binds the trust set and selector projection to the exact %s without changing historical provenance',
  (field) => {
    const f = fixture();
    const input = {
      candidate: f.candidate(),
      mutationCandidateId: id(700),
      operationId: id(701),
      admittedAtNs: f.admittedAtNs,
    };
    const original = prepareHandoverAdmissionTransition(input);
    const changed = prepareHandoverAdmissionTransition({
      ...input,
      ...(field === 'operation'
        ? { operationId: id(702) }
        : field === 'candidate-id'
          ? { mutationCandidateId: id(703) }
          : { admittedAtNs: (BigInt(f.admittedAtNs) + 1000n).toString() }),
    });
    expect(changed.authorizationBindings.successorTrustSetDigest).not.toBe(
      original.authorizationBindings.successorTrustSetDigest,
    );
    expect(changed.authorizationBindings.selectorTransitionDigest).not.toBe(
      original.authorizationBindings.selectorTransitionDigest,
    );
    expect(changed.nativeReplacementProvenancePreimage).toEqual(
      original.nativeReplacementProvenancePreimage,
    );
  },
);

const transitionCounters = [
  'rowVersion',
  'admissionVersion',
  'fenceGeneration',
  'envelope-admission',
] as const;
it.each(transitionCounters)(
  'rejects %s overflow and admits its final representable increment',
  (counter) => {
    const maximum = 18446744073709551615n;
    for (const value of [maximum - 1n, maximum]) {
      const f = fixture((source) => {
        if (counter === 'envelope-admission')
          source.envelopeSelections[0]!.admissionVersion = value.toString();
        else source.receiptSelections[0]![counter] = value.toString();
      });
      const candidate = f.candidate();
      const prepare = () =>
        prepareHandoverAdmissionTransition({
          candidate,
          mutationCandidateId: id(700),
          operationId: id(701),
          admittedAtNs: f.admittedAtNs,
        });
      if (value === maximum) expect(prepare).toThrow();
      else {
        const plan = prepare();
        const actual =
          counter === 'envelope-admission'
            ? plan.selectorTransition.envelopeSelections[0]!.after.admissionVersion
            : plan.selectorTransition.receiptSelections.find(
                (row) =>
                  row.before.profileDigest === candidate.source.receiptSelections[0]!.profileDigest,
              )!.after[counter];
        expect(actual).toBe(maximum.toString());
      }
    }
  },
);

it.each([
  'extra-field',
  'injected-digest',
  'invalid-operation',
  'invalid-candidate',
  'backdated',
  'expired',
  'unaligned',
  'timestamp-overflow',
] as const)('rejects %s before emitting transition authorization bindings', (kind) => {
  const f = fixture();
  const input = {
    candidate: f.candidate(),
    mutationCandidateId: id(700),
    operationId: id(701),
    admittedAtNs: f.admittedAtNs,
  };
  const substituted = {
    ...input,
    ...{
      'extra-field': { ready: true },
      'injected-digest': { successorTrustSetDigest: hash(99) },
      'invalid-operation': { operationId: 'not-an-operation' },
      'invalid-candidate': { mutationCandidateId: 'not-a-candidate' },
      'backdated': { admittedAtNs: (BigInt(input.candidate.preparedAtNs) - 1000n).toString() },
      'expired': { admittedAtNs: input.candidate.expiresAtNs },
      'unaligned': { admittedAtNs: (BigInt(input.admittedAtNs) + 1n).toString() },
      'timestamp-overflow': { admittedAtNs: '18446744073709552000' },
    }[kind],
  };
  expect(() => prepareHandoverAdmissionTransition(substituted)).toThrow();
});

it.each(['possession-signature', 'source-provenance', 'generation-digest'])(
  'rejects a changed %s through the new guarded transition-candidate entry point',
  (kind) => {
    const f = fixture(),
      candidate = f.candidate();
    if (kind === 'possession-signature') {
      const proof = candidate.proofs[0]!.observation;
      const signature = proof.resultHex!;
      proof.resultHex = (signature[0] === '0' ? '1' : '0') + signature.slice(1);
    } else if (kind === 'source-provenance') candidate.source.provenance.evidenceDigest = hash(99);
    else candidate.generation.sourceDigest = hash(99);
    expect(() => prepareHandoverAdmissionTransitionCandidate(candidate, f.admittedAtNs)).toThrow();
  },
);

it('isolates the guarded parsed snapshot and derived trusts from later caller-input mutation', () => {
  const f = fixture(),
    candidate = f.candidate();
  const prepared = prepareHandoverAdmissionTransitionCandidate(candidate, f.admittedAtNs);
  const bytes = Buffer.from(canonicalAuthorizationJson(prepared.candidate));
  const digest = prepared.candidateDigest;
  const trustBytes = prepared.trusts.map((captured) =>
    captured.signerRole === 'IDENTITY_ENVELOPE'
      ? identityEnvelopeSigningTrustPreimage(captured.trust)
      : businessSigningTrustPreimage(captured.trust),
  );
  candidate.source.receiptSelections.pop();
  candidate.predecessorTrusts[0]!.publicKeySpkiHex = '00';
  candidate.proofs[0]!.observation.resultHex = '00'.repeat(64);
  candidate.makerPrincipalId = id(999);
  expect(Buffer.from(canonicalAuthorizationJson(prepared.candidate))).toEqual(bytes);
  expect(prepared.candidateDigest).toBe(digest);
  expect(
    prepared.trusts.map((captured) =>
      captured.signerRole === 'IDENTITY_ENVELOPE'
        ? identityEnvelopeSigningTrustPreimage(captured.trust)
        : businessSigningTrustPreimage(captured.trust),
    ),
  ).toEqual(trustBytes);
});

it('binds all seven fresh keys and all nineteen unchanged selections to one normal approval digest', () => {
  const f = fixture(),
    candidate = f.candidate();
  expect(candidate.predecessorTrusts).toHaveLength(7);
  expect(candidate.source.receiptSelections).toHaveLength(18);
  expect(candidate.source.envelopeSelections).toHaveLength(1);
  expect(candidate.proofs).toHaveLength(7);
  const candidateDigest = handoverAdmissionCandidateDigest(candidate);
  expect(candidateDigest).toBe(canonicalAuthorizationDigest(candidate));
  const bytes = handoverAdmissionCandidateBytes(candidate);
  expect(handoverAdmissionCandidateBytes(JSON.parse(bytes.toString()))).toEqual(bytes);
  expect(bytes.toString()).not.toContain('privateKey');
  expect(bytes.toString()).not.toContain('"authority":');
  const successors = handoverAdmissionSuccessorTrusts(candidate, f.admittedAtNs);
  successors.forEach((successor, index) => {
    const original = f.input.trusts[index]!;
    expect(successor.signerRole).toBe(original.signerRole);
    expect(successor.trust.workloadCredentialId).toBe(id(4));
    expect(successor.trust.workloadCredentialEpoch).toBe(5n);
    expect(successor.trust.keyEpoch).toBe(4n);
    expect(successor.trust.signerId).not.toBe(original.trust.signerId);
    expect(successor.trust.validFromNs).toBe(BigInt(f.admittedAtNs));
    expect(successor.trust.validUntilNs.toString()).toBe(
      candidate.source.issuer.credentialValidUntilNs,
    );
    expect(successor.trust.admissionKind).toBe('GOVERNED');
    expect(tagged(successor.trust.admissionDigest)).toBe(candidateDigest);
    expect(original.trust.validUntilNs).toBeLessThan(BigInt(candidate.preparedAtNs));
    if (
      successor.signerRole === 'IDENTITY_ENVELOPE' &&
      original.signerRole === 'IDENTITY_ENVELOPE'
    ) {
      expect(successor.trust.purpose).toBe(original.trust.purpose);
      expect(successor.trust.profileDigest).toBe(original.trust.profileDigest);
      expect(successor.trust).not.toHaveProperty('grants');
    } else if (
      successor.signerRole !== 'IDENTITY_ENVELOPE' &&
      original.signerRole !== 'IDENTITY_ENVELOPE'
    ) {
      expect(successor.trust.grants).toEqual(original.trust.grants);
      expect(
        successor.trust.grants.some((g) => g.actionIntentId === operation.actionIntentId),
      ).toBe(false);
      expect(successor.trust).not.toHaveProperty('purpose');
    } else throw new Error('Purpose changed');
  });
});

const candidateMutations: [string, (candidate: HandoverAdmissionCandidate) => void][] = [
  [
    'changed validity policy',
    (c) => {
      Object.assign(c, { validityPolicy: 'FROM_PREPARATION' });
    },
  ],
  [
    'foreign participant',
    (c) => {
      c.participantId = id(90);
    },
  ],
  [
    'foreign privacy domain',
    (c) => {
      c.privacyDomainId = id(90);
    },
  ],
  [
    'foreign environment',
    (c) => {
      c.environmentId = 'other';
    },
  ],
  [
    'different handover',
    (c) => {
      c.handoverId = id(90);
    },
  ],
  [
    'different maker',
    (c) => {
      c.makerPrincipalId = id(90);
    },
  ],
  [
    'legacy preparation permission',
    (c) => {
      Object.assign(c.request, { actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1' });
    },
  ],
  [
    'different generation',
    (c) => {
      c.request.generationId = id(90);
    },
  ],
  [
    'changed generation digest',
    (c) => {
      c.request.generationDigest = hash(90);
    },
  ],
  [
    'extended deadline',
    (c) => {
      c.expiresAtNs = (BigInt(c.expiresAtNs) + 1000n).toString();
    },
  ],
  [
    'expired preparation',
    (c) => {
      c.preparedAtNs = c.expiresAtNs;
    },
  ],
  [
    'pre-generation preparation',
    (c) => {
      c.preparedAtNs = (BigInt(c.generation.issuedAtNs) - 1000n).toString();
    },
  ],
  [
    'missing proof',
    (c) => {
      c.proofs.pop();
    },
  ],
  [
    'duplicate proof',
    (c) => {
      c.proofs[1] = c.proofs[0]!;
    },
  ],
  [
    'substituted signature',
    (c) => {
      c.proofs[0]!.observation.resultHex = '00'.repeat(64);
    },
  ],
  [
    'missing predecessor trust',
    (c) => {
      c.predecessorTrusts.pop();
    },
  ],
  [
    'reordered predecessor trusts',
    (c) => {
      c.predecessorTrusts.reverse();
    },
  ],
  [
    'changed old public key',
    (c) => {
      c.predecessorTrusts[0]!.publicKeySpkiHex = '00';
    },
  ],
  [
    'changed old reference',
    (c) => {
      c.predecessorTrusts[0]!.secretReference = 'secret://local/changed#1';
    },
  ],
  [
    'changed old validity',
    (c) => {
      c.predecessorTrusts[0]!.validUntilNs = c.expiresAtNs;
    },
  ],
  [
    'changed old key epoch',
    (c) => {
      c.predecessorTrusts[0]!.keyEpoch = '4';
    },
  ],
  [
    'changed old admission digest',
    (c) => {
      c.predecessorTrusts[0]!.admissionDigest = hash(90);
    },
  ],
  [
    'omitted old grant',
    (c) => {
      const trust = c.predecessorTrusts.find((t) => t.signerRole !== 'IDENTITY_ENVELOPE')!;
      trust.grants.pop();
    },
  ],
  [
    'changed grant action',
    (c) => {
      const trust = c.predecessorTrusts.find((t) => t.signerRole !== 'IDENTITY_ENVELOPE')!;
      trust.grants[0]!.actionIntentId = operation.actionIntentId;
    },
  ],
  [
    'unreviewed grant flag',
    (c) => {
      Object.assign(c.predecessorTrusts[0]!, { ready: true });
    },
  ],
  [
    'unknown candidate field',
    (c) => {
      Object.assign(c, { admitted: true });
    },
  ],
];
it.each(candidateMutations)('rejects %s without deriving any successor grant', (_name, mutate) => {
  const f = fixture(),
    candidate = f.candidate();
  mutate(candidate);
  expect(handoverAdmissionCandidateSchema.safeParse(candidate).success).toBe(false);
  expect(() => handoverAdmissionSuccessorTrusts(candidate, f.admittedAtNs)).toThrow();
});

const sourceMutations: [string, (source: Source) => void][] = [
  [
    'zero selector fence generation',
    (s) => {
      s.receiptSelections[0]!.fenceGeneration = '0';
    },
  ],
  [
    'omitted receipt selection',
    (s) => {
      s.receiptSelections.pop();
    },
  ],
  [
    'duplicated receipt selection',
    (s) => {
      s.receiptSelections.push({ ...s.receiptSelections[0]! });
    },
  ],
  [
    'foreign selected credential',
    (s) => {
      s.receiptSelections[0]!.credentialId = id(90);
    },
  ],
  [
    'unaccounted selected key',
    (s) => {
      s.receiptSelections[0]!.signerId = hash(90);
    },
  ],
  [
    'changed selected profile',
    (s) => {
      s.receiptSelections[0]!.profileDigest = hash(90);
    },
  ],
  [
    'changed selected profile version',
    (s) => {
      s.receiptSelections[0]!.profileVersion = 2;
    },
  ],
  [
    'changed envelope selection',
    (s) => {
      s.envelopeSelections[0]!.signerId = s.receiptSelections[0]!.signerId;
    },
  ],
  [
    'foreign envelope credential',
    (s) => {
      s.envelopeSelections[0]!.credentialId = id(90);
    },
  ],
  [
    'omitted source key',
    (s) => {
      s.keys.pop();
    },
  ],
  [
    'reordered source keys',
    (s) => {
      s.keys.reverse();
    },
  ],
  [
    'self-approved native provenance',
    (s) => {
      s.provenance.checkerPrincipalId = s.provenance.makerPrincipalId;
    },
  ],
];
it.each(sourceMutations)(
  'rejects %s even with possession proofs bound to that source digest',
  (_name, mutate) => {
    const f = fixture(mutate);
    expect(() => f.candidate()).toThrow();
  },
);

it.each(['grants', 'descriptor', 'ready', 'source', 'workloadId', 'authority', 'participantId'])(
  'rejects caller-supplied %s in the admission request',
  (field) => {
    const f = fixture();
    expect(
      handoverAdmissionCandidateRequestSchema.safeParse({ ...f.input.request, [field]: true })
        .success,
    ).toBe(false);
  },
);
it.each(['before-preparation', 'at-expiry', 'unaligned', 'overflow'])(
  'rejects an %s admission timestamp',
  (kind) => {
    const f = fixture(),
      candidate = f.candidate();
    const at =
      kind === 'before-preparation'
        ? (BigInt(candidate.preparedAtNs) - 1000n).toString()
        : kind === 'at-expiry'
          ? candidate.expiresAtNs
          : kind === 'unaligned'
            ? (BigInt(candidate.preparedAtNs) + 1n).toString()
            : '18446744073709552000';
    expect(() => handoverAdmissionSuccessorTrusts(candidate, at)).toThrow();
  },
);
it('changes the approval digest for a different action semantic digest or reason', () => {
  const candidate = fixture().candidate(),
    original = handoverAdmissionCandidateDigest(candidate);
  candidate.request.actionIntentDigest = hash(99);
  expect(handoverAdmissionCandidateDigest(candidate)).not.toBe(original);
  candidate.request.reason += ' Additional review context.';
  expect(handoverAdmissionCandidateDigest(candidate)).not.toBe(original);
});
