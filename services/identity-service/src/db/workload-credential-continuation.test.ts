import { generateKeyPairSync, createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  encodeIdentityCredentialPayload,
  signIdentityCredentialCoseSign1Es256,
} from '@openpc/security-kernel';
import { createLocalIdentityRuntimeCryptoAdapter } from '../domain/identity-runtime-crypto.js';
import { createIdentityRuntimeAuthorizationAssertion } from '../domain/identity-runtime-authorization.js';
import { assertWorkloadCredentialContinuation } from './workload-credential-continuation.js';

const id = (value: number) => '01990000-0000-7000-8000-' + String(value).padStart(12, '0');
const input = {
  participantId: id(1),
  privacyDomainId: id(2),
  predecessorId: id(3),
  successorId: id(4),
  predecessorEpoch: '1',
  successorEpoch: '2',
  principalId: id(5),
};
async function fixture() {
  const key = generateKeyPairSync('ed25519');
  const publicKey = key.publicKey.export({ format: 'der', type: 'spki' });
  const credentialPublicKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  const crypto = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const committedAt = new Date('2026-10-01T10:00:01.000Z'),
    issuedAt = new Date('2026-10-01T10:00:00.000Z');
  const maker = id(6),
    session = id(7),
    candidateDigest = Buffer.alloc(32, 8);
  const cbor = createIdentityRuntimeAuthorizationAssertion(
    id(9),
    {
      participantId: input.participantId,
      principalId: maker,
      sessionId: session,
      sessionEpoch: '1',
      sessionIssuedAt: new Date('2026-10-01T09:00:00.000Z'),
      sessionIdleExpiresAt: new Date('2026-10-01T10:30:00.000Z'),
      sessionAbsoluteExpiresAt: new Date('2026-10-01T20:00:00.000Z'),
      participantEpoch: '1',
      principalEpoch: '1',
      assignmentId: id(10),
      assignmentRowVersion: '1',
      authorityEnvelopeId: id(11),
      authorityEpoch: '1',
      delegationEpoch: '1',
      actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
      resourceId: session,
      candidateDigest: 'sha256:' + candidateDigest.toString('hex'),
      sessionToken: input.participantId + '.' + session,
    },
    issuedAt,
  );
  const signed = await crypto.signCanonicalAssertion(cbor);
  const row = {
    principalId: input.principalId,
    checkerPrincipalId: maker,
    verificationCandidateDigest: candidateDigest as Buffer | null,
    verificationSessionId: session as string | null,
    credentialPublicKey,
    credentialPublicKeyDigest: createHash('sha256').update(credentialPublicKey).digest(),
    evidenceCbor: signed.evidenceCbor,
    evidenceDigest: signed.evidenceDigest,
    coseSign1: signed.coseSign1,
    verificationOccurredAt: committedAt as Date | null,
  };
  const query = vi.fn(async () => ({ rowCount: 1, rows: [row] }));
  return { crypto, row, query, client: { query } as unknown as PoolClient };
}
it('authenticates original signed rotation at its historical commit without reviving original authority', async () => {
  const f = await fixture();
  await expect(
    assertWorkloadCredentialContinuation(f.client, input, f.crypto),
  ).resolves.toBeUndefined();
  expect(f.query).toHaveBeenCalledTimes(1);
  const [sql, values] = f.query.mock.calls[0] as unknown as [string, unknown[]];
  expect(values).toEqual([
    input.participantId,
    input.privacyDomainId,
    input.predecessorId,
    input.successorId,
    '1',
    '2',
    input.principalId,
  ]);
  expect(sql).toContain('openpc.read_identity_envelope_credential_continuation');
  expect(sql).not.toMatch(/\b(insert|update|delete)\b/iu);
});
it.each([
  'missing verifier',
  'same credential',
  'missing history',
  'ambiguous history',
  'foreign principal',
  'foreign checker',
  'wrong candidate',
  'wrong credential key',
  'wrong session',
  'foreign privacy',
  'changed payload',
  'changed signature',
  'expired at commit',
  'future at commit',
  'missing committed verification',
] as const)('denies %s continuation', async (failure) => {
  const f = await fixture();
  let selected = input,
    verifier: typeof f.crypto | undefined = f.crypto;
  if (failure === 'missing verifier') verifier = undefined;
  if (failure === 'same credential') selected = { ...input, successorId: input.predecessorId };
  if (failure === 'missing history') f.query.mockResolvedValue({ rowCount: 0, rows: [] });
  if (failure === 'ambiguous history')
    f.query.mockResolvedValue({ rowCount: 2, rows: [f.row, f.row] });
  if (failure === 'foreign principal') f.row.principalId = id(90);
  if (failure === 'foreign checker') f.row.checkerPrincipalId = id(90);
  if (failure === 'wrong candidate') f.row.verificationCandidateDigest = Buffer.alloc(32, 90);
  if (failure === 'wrong credential key') f.row.credentialPublicKeyDigest = Buffer.alloc(32, 90);
  if (failure === 'wrong session') f.row.verificationSessionId = id(90);
  if (failure === 'foreign privacy') {
    selected = { ...input, privacyDomainId: id(90) };
    f.query.mockResolvedValue({ rowCount: 0, rows: [] });
  }
  if (failure === 'changed payload') f.row.evidenceCbor = Buffer.from('00', 'hex');
  if (failure === 'changed signature') {
    f.row.coseSign1 = Buffer.from(f.row.coseSign1);
    f.row.coseSign1[f.row.coseSign1.length - 1] = f.row.coseSign1[f.row.coseSign1.length - 1]! ^ 1;
  }
  if (failure === 'expired at commit')
    f.row.verificationOccurredAt = new Date('2026-10-01T10:02:00.000Z');
  if (failure === 'future at commit')
    f.row.verificationOccurredAt = new Date('2026-10-01T09:59:00.000Z');
  if (failure === 'missing committed verification') f.row.verificationCandidateDigest = null;
  await expect(assertWorkloadCredentialContinuation(f.client, selected, verifier)).rejects.toThrow(
    'issuer is unavailable',
  );
  if (failure === 'missing verifier' || failure === 'same credential')
    expect(f.query).not.toHaveBeenCalled();
});

it('preserves the existing historical ES256 checker evidence contract', async () => {
  const f = await fixture();
  const credential = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  f.row.credentialPublicKey = credential.publicKey.export({ format: 'der', type: 'spki' });
  f.row.credentialPublicKeyDigest = createHash('sha256').update(f.row.credentialPublicKey).digest();
  f.row.evidenceCbor = encodeIdentityCredentialPayload({
    participantId: 'urn:openpc:participant:' + input.participantId,
    principalId: 'urn:openpc:principal:' + f.row.checkerPrincipalId,
    authorityEpoch: '1',
    issuedAt: '2026-10-01T10:00:00.000000Z',
    expiresAt: '2026-10-01T10:05:00.000000Z',
  });
  f.row.evidenceDigest = createHash('sha256').update(f.row.evidenceCbor).digest();
  f.row.coseSign1 = signIdentityCredentialCoseSign1Es256(
    credential.privateKey.export({ format: 'der', type: 'pkcs8' }),
    f.row.credentialPublicKey,
    f.row.evidenceCbor,
  );
  f.row.verificationCandidateDigest = null;
  f.row.verificationSessionId = null;
  f.row.verificationOccurredAt = null;
  await expect(
    assertWorkloadCredentialContinuation(f.client, input, f.crypto),
  ).resolves.toBeUndefined();
  f.row.coseSign1 = Buffer.from(f.row.coseSign1);
  f.row.coseSign1[f.row.coseSign1.length - 1] = f.row.coseSign1[f.row.coseSign1.length - 1]! ^ 1;
  await expect(assertWorkloadCredentialContinuation(f.client, input, f.crypto)).rejects.toThrow(
    'issuer is unavailable',
  );
});
