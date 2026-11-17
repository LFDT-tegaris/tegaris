import { createHash, generateKeyPairSync } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  encodeIdentityAuthorityEnvelope,
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  signIdentityAuthorityEnvelopeCose,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import {
  identityEnvelopeFixture,
  envelopeFixtureId as id,
} from '../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  identityEnvelopeProviderRequestSchema,
  identityEnvelopeProviderRequestDigest,
} from '../../identity-service/src/domain/identity-envelope-signing-provider.js';
import {
  readIdentityEnvelopeRotationConsumer,
  readHistoricalIdentityEnvelopeRotationConsumer,
} from './identity-envelope-rotation-consumer.js';
const owner = vi.hoisted(() => ({ creation: vi.fn(), effect: vi.fn() }));
vi.mock('../../identity-service/src/db/identity-envelope-readback.js', () => ({
  readEnvelopeCreation: owner.creation,
  readEnvelopeEffectReadback: owner.effect,
}));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = Buffer.from(pair.publicKey.export({ type: 'spki', format: 'der' }));
  const privateKey = Buffer.from(pair.privateKey.export({ type: 'pkcs8', format: 'der' }));
  const trust: IdentityEnvelopeSigningTrust = {
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'test',
    signerId: evidenceKeyId(pub),
    publicKeySpkiDer: pub,
    workloadCredentialId: id(221),
    workloadCredentialEpoch: 11n,
    workloadParticipantEpoch: 2n,
    workloadPrincipalEpoch: 1n,
    keyEpoch: 2n,
    validFromNs: 1800000000000000000n,
    validUntilNs: 1800003600000000000n,
    admissionKind: 'GOVERNED',
    admissionReference: 'urn:openpc:resource:' + id(900),
    admissionDigest: Buffer.alloc(32, 1),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://test/envelope#version-1',
    secretVersion: 'version-1',
    purpose: identityEnvelopeContext.purpose,
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  const artifact = identityEnvelopeFixture(trust.signerId);
  artifact.signer = {
    ...artifact.signer,
    profileId: trust.profileId,
    profileDigest: trust.profileDigest,
    trustContextDigest: identityEnvelopeSigningTrustDigest(trust),
  };
  const payload = encodeIdentityAuthorityEnvelope(artifact);
  const binding = {
    participantId: trust.participantId,
    privacyDomainId: trust.privacyDomainId,
    environmentId: trust.environmentId,
    workloadCredentialId: trust.workloadCredentialId,
    workloadCredentialEpoch: '11',
    secretClass: trust.secretClass,
    reference: trust.secretReference,
    version: trust.secretVersion,
    purpose: trust.purpose,
    purposeCode: 371 as const,
    schemaId: 24034 as const,
    schemaVersion: 1 as const,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: trust.profileId,
    profileVersion: 1 as const,
    profileDigest: trust.profileDigest,
    trustContextDigest: identityEnvelopeSigningTrustDigest(trust),
  };
  const request = identityEnvelopeProviderRequestSchema.parse({
    ...binding,
    method: 'SIGN_AUTHORITY_ENVELOPE',
    callerWorkloadCredentialId: trust.workloadCredentialId,
    attemptId: id(901),
    operationId: artifact.activation.operationId,
    expectedFingerprint: trust.signerId,
    payloadHex: payload.toString('hex'),
  });
  const observation = {
    schemaVersion: 1,
    method: request.method,
    attemptId: request.attemptId,
    operationId: request.operationId,
    requestDigest: identityEnvelopeProviderRequestDigest(request),
    recordedAtNs: '1800000001001000000',
    descriptor: {
      ...binding,
      algorithm: 'ES256',
      publicKeySpkiHex: pub.toString('hex'),
      fingerprint: trust.signerId,
      validFromNs: trust.validFromNs.toString(),
      validUntilNs: trust.validUntilNs.toString(),
      state: 'ACTIVE',
    },
    coseHex: signIdentityAuthorityEnvelopeCose(privateKey, pub, payload).toString('hex'),
  };
  const selected = {
    operationId: request.operationId,
    envelopeId: id(60),
    principalId: id(100),
    idempotencyKey: 'original-activation-unit-0001',
    reservedAtNs: artifact.issuedAtNs,
    committedAtNs: '1800000001002000000',
  };
  const activation = {
    ...selected,
    attemptId: request.attemptId,
    payload,
    request,
    requestDigest: Buffer.from(identityEnvelopeProviderRequestDigest(request).slice(7), 'hex'),
    state: 'COMMITTED',
    observation,
  };
  const cbor = Buffer.from('original-consumer-receipt');
  const receipt = {
    cbor,
    digest: createHash('sha256').update(cbor).digest(),
    cose: Buffer.from('unit-purpose338-cose'),
  };
  const creation = {
    stored: {
      bytes: artifact.proposalBytes,
      digest: Buffer.from(artifact.proposalDigest.slice(7), 'hex'),
    },
  };
  const effect = { operationId: request.operationId, state: 'ACTIVE', version: '4' };
  owner.creation.mockResolvedValue(creation);
  owner.effect.mockResolvedValue(effect);
  let absent = false;
  const query = vi.fn(async (sql: string): Promise<{ rowCount: number; rows: unknown[] }> => {
    if (sql.startsWith('select a.operation_id'))
      return { rowCount: absent ? 0 : 1, rows: absent ? [] : [selected] };
    if (sql.startsWith('select operation_id')) return { rowCount: 1, rows: [activation] };
    if (sql.startsWith('select evidence.evidence_cbor')) return { rowCount: 1, rows: [receipt] };
    throw Error('unexpected query');
  });
  const input = {
    trust,
    cutoverAtNs: 1800000000000000000n,
    observedAtNs: 1800000001003000000n,
    operationId: request.operationId as string | undefined,
  };
  const signer = {
    verifyCanonicalAssertion: vi.fn(async () => true),
    signCanonicalAssertion: vi.fn(),
  };
  const read = () =>
    readIdentityEnvelopeRotationConsumer({ query } as never, input, signer as never);
  const historicalInput = {
    ...input,
    operationId: request.operationId,
    envelopeId: selected.envelopeId,
  };
  const readHistorical = () =>
    readHistoricalIdentityEnvelopeRotationConsumer({ query } as never, historicalInput, {
      verifyCanonicalAssertion: signer.verifyCanonicalAssertion,
    } as never);
  return {
    trust,
    artifact,
    request,
    observation,
    selected,
    activation,
    receipt,
    creation,
    effect,
    input,
    signer,
    query,
    read,
    historicalInput,
    readHistorical,
    absent: () => (absent = true),
  };
}
it('authenticates actual normal371 signature, committed effect readback and original signed receipt/outbox without creating permission or effects', async () => {
  const f = fixture();
  expect(await f.read()).toEqual({
    operationId: f.request.operationId,
    envelopeId: f.selected.envelopeId,
    payloadDigest: 'sha256:' + createHash('sha256').update(f.activation.payload).digest('hex'),
    receiptDigest: 'sha256:' + f.receipt.digest.toString('hex'),
  });
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  expect(f.query.mock.calls.every(([sql]) => sql.startsWith('select'))).toBe(true);
  expect(owner.creation).toHaveBeenCalledTimes(1);
  expect(owner.effect).toHaveBeenCalledTimes(1);
});
it('reports missing actual consumer instead of a readiness claim', async () => {
  const f = fixture();
  f.absent();
  expect(await f.read()).toBeUndefined();
  expect(owner.creation).not.toHaveBeenCalled();
  expect(f.signer.verifyCanonicalAssertion).not.toHaveBeenCalled();
});
it.each([
  'original-operation',
  'before-cutover',
  'different-reservation',
  'future-commit',
  'uncommitted',
  'missing-observation',
  'bad-normal-signature',
  'wrong-trust',
  'wrong-caller',
  'changed-key-validity',
  'future-observation',
  'changed-proposal',
  'wrong-effect',
  'receipt-digest',
  'receipt-signature',
] as const)('rejects %s without accepting a probe as a consumer', async (kind) => {
  const f = fixture();
  if (kind === 'original-operation') f.selected.operationId = id(999);
  if (kind === 'before-cutover') f.selected.reservedAtNs = (f.input.cutoverAtNs - 1n).toString();
  if (kind === 'different-reservation')
    f.selected.reservedAtNs = (BigInt(f.selected.reservedAtNs) + 1000n).toString();
  if (kind === 'future-commit') f.selected.committedAtNs = (f.input.observedAtNs + 1n).toString();
  if (kind === 'uncommitted') f.activation.state = 'OBSERVED';
  if (kind === 'missing-observation') f.activation.observation = null as never;
  if (kind === 'bad-normal-signature') f.observation.coseHex = '00'.repeat(160);
  if (kind === 'wrong-trust') f.input.trust = { ...f.trust, keyEpoch: 3n };
  if (kind === 'wrong-caller') {
    f.activation.request = { ...f.request, callerWorkloadCredentialId: id(999) };
    f.activation.requestDigest = Buffer.from(
      identityEnvelopeProviderRequestDigest(f.activation.request).slice(7),
      'hex',
    );
    f.observation.requestDigest = identityEnvelopeProviderRequestDigest(f.activation.request);
  }
  if (kind === 'changed-key-validity')
    f.input.trust = { ...f.trust, validUntilNs: f.trust.validUntilNs + 1000n };
  if (kind === 'future-observation')
    f.observation.recordedAtNs = (BigInt(f.selected.committedAtNs) + 1n).toString();
  if (kind === 'changed-proposal') f.creation.stored.bytes = Buffer.from('different proposal');
  if (kind === 'wrong-effect') f.effect.operationId = id(999);
  if (kind === 'receipt-digest') f.receipt.digest = Buffer.alloc(32);
  if (kind === 'receipt-signature') f.signer.verifyCanonicalAssertion.mockResolvedValue(false);
  await expect(f.read()).rejects.toThrow();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  expect(f.query.mock.calls.every(([sql]) => sql.startsWith('select'))).toBe(true);
});

it('authenticates the exact historical typed371 activation without consulting current envelope state or discovering another consumer', async () => {
  const f = fixture();
  const value = await f.readHistorical();
  expect(value).toEqual({
    operationId: f.request.operationId,
    envelopeId: f.selected.envelopeId,
    payloadDigest: 'sha256:' + createHash('sha256').update(f.activation.payload).digest('hex'),
    receiptDigest: 'sha256:' + f.receipt.digest.toString('hex'),
  });
  const first = f.query.mock.calls[0]!;
  expect(first[0]).toContain('a.operation_id=$3 and a.envelope_id=$4');
  expect(first[0]).not.toContain('control.authority_envelope');
  expect(first[0]).not.toContain('order by');
  expect(
    f.query.mock.calls.find(([sql]) => sql.startsWith('select operation_id'))?.[0],
  ).not.toContain('for update');
  expect(f.query.mock.calls.every(([sql]) => sql.startsWith('select'))).toBe(true);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  expect(owner.creation).toHaveBeenCalledTimes(1);
  expect(owner.effect).toHaveBeenCalledTimes(1);
});
it('fails a missing pinned historical consumer rather than discovering another activation', async () => {
  const f = fixture();
  f.absent();
  await expect(f.readHistorical()).rejects.toThrow();
  expect(f.query).toHaveBeenCalledTimes(1);
  expect(owner.creation).not.toHaveBeenCalled();
  expect(f.signer.verifyCanonicalAssertion).not.toHaveBeenCalled();
});
it.each([
  'operation',
  'envelope',
  'typed-signature',
  'receipt-signature',
  'receipt-digest',
  'proposal',
  'effect',
  'reservation',
  'future-commit',
] as const)(
  'rejects historical %s mismatch without issuing or accepting a replacement',
  async (kind) => {
    const f = fixture();
    if (kind === 'operation') f.selected.operationId = id(999);
    if (kind === 'envelope') f.selected.envelopeId = id(999);
    if (kind === 'typed-signature') f.observation.coseHex = '00'.repeat(160);
    if (kind === 'receipt-signature') f.signer.verifyCanonicalAssertion.mockResolvedValue(false);
    if (kind === 'receipt-digest') f.receipt.digest = Buffer.alloc(32);
    if (kind === 'proposal') f.creation.stored.bytes = Buffer.from('altered proposal');
    if (kind === 'effect') f.effect.operationId = id(999);
    if (kind === 'reservation')
      f.selected.reservedAtNs = (BigInt(f.selected.reservedAtNs) + 1000n).toString();
    if (kind === 'future-commit') f.selected.committedAtNs = (f.input.observedAtNs + 1n).toString();
    await expect(f.readHistorical()).rejects.toThrow();
    expect(f.query.mock.calls.every(([sql]) => sql.startsWith('select'))).toBe(true);
    expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  },
);
