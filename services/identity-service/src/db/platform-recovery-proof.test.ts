import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { expect, it } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import {
  acceptPlatformRecoveryProof,
  issuePlatformRecoveryChallenge,
} from './platform-recovery-proof.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';

const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();
const origin = 'https://openpc.local';
function fixture(failure?: string) {
  const { source, intent } = platformRecoveryFixture();
  const signer = source.enrollment.recoveryPrincipal;
  const actor = {
    participantId: source.enrollment.participantId,
    principalId: signer.principalId,
    platform: true,
    sessionToken: `${source.enrollment.participantId}.${id(800)}`,
  };
  const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' });
  const challenge = 'a-platform-recovery-challenge-000000001';
  const credentialId = 'aS1hbS10aGUtcmVjb3Zlcnkta2V5';
  const clientData = Buffer.from(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: failure === 'wrong nonce' ? 'different-recovery-challenge-000000001' : challenge,
      origin: failure === 'wrong origin' ? 'https://foreign.local' : origin,
      crossOrigin: failure === 'cross origin',
    }),
  );
  const authenticatorData = Buffer.alloc(37);
  hash('openpc.local').copy(authenticatorData);
  authenticatorData[32] = failure === 'missing UV' ? 1 : 5;
  authenticatorData.writeUInt32BE(2, 33);
  const signature = sign(
    'sha256',
    Buffer.concat([authenticatorData, hash(clientData)]),
    keys.privateKey,
  );
  if (failure === 'bad signature') signature[signature.length - 1] = signature.at(-1)! ^ 1;
  const input = {
    challengeId: id(801),
    challenge,
    intentDigest: canonicalAuthorizationDigest(intent),
    assertion: JSON.stringify({
      credentialId,
      authenticatorData: authenticatorData.toString('base64url'),
      clientDataJson: clientData.toString('base64url'),
      signature: signature.toString('base64url'),
    }),
  };
  const writes: { sql: string; values: unknown[] }[] = [];
  const query = async (sql: string, values: unknown[]) => {
    if (/^(insert|update) /u.test(sql)) {
      writes.push({ sql, values });
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes('s.opaque_token_digest'))
      return {
        rowCount: failure === 'revoked session' ? 0 : 1,
        rows: [
          {
            tokenDigest:
              failure === 'wrong session token' ? Buffer.alloc(32) : hash(actor.sessionToken),
            sessionEpoch: '1',
            durationProfile: 'C17',
            expiresAt: new Date(source.now.getTime() + 900_000),
          },
        ],
      };
    if (sql.includes('from control.platform_recovery_challenge'))
      return {
        rowCount: failure === 'expired challenge' ? 0 : 1,
        rows: [{ verifiedProofMaxAgeMs: failure === 'invalid proof age' ? 600000 : 300000 }],
      };
    if (sql.startsWith('select subject,public_key_spki_der'))
      return {
        rowCount: failure === 'revoked credential' ? 0 : 1,
        rows: [
          {
            subject: credentialId,
            publicKey,
            keyDigest: hash(publicKey),
            counter: failure === 'counter replay' ? '2' : '1',
          },
        ],
      };
    if (sql.startsWith('select subject,valid_until'))
      return { rowCount: 1, rows: [{ subject: credentialId, validUntil: null }] };
    throw new Error('Unexpected proof query');
  };
  const context = {
    enrollment: source.enrollment,
    intent,
    state: 'DRAFT',
    proofs: [],
    now: source.now,
  };
  return { context, actor, input, writes, client: { query } as never };
}
it('persists the exact verified assertion and advances the counter in the owning transaction', async () => {
  const v = fixture();
  const result = await acceptPlatformRecoveryProof(
    v.client,
    v.context,
    v.actor,
    'REQUEST',
    origin,
    v.input,
  );
  expect(result).toMatchObject({
    principalId: v.actor.principalId,
    phase: 'REQUEST',
    intentDigest: v.input.intentDigest,
  });
  expect(v.writes).toHaveLength(3);
  expect(v.writes[0]!.values[13]).toMatchObject({
    assertion: JSON.parse(v.input.assertion),
    verified: { userVerification: 'REQUIRED_VERIFIED', signCount: '2' },
  });
  expect(v.writes[2]!.values.slice(2)).toEqual(['1', '2', '0']);
  expect(v.writes.some((v) => /control\.(assignment|authority_envelope)\b/u.test(v.sql))).toBe(
    false,
  );
});
it.each([
  'wrong nonce',
  'wrong origin',
  'cross origin',
  'missing UV',
  'bad signature',
  'revoked session',
  'wrong session token',
  'expired challenge',
  'invalid proof age',
  'revoked credential',
  'counter replay',
])('rejects %s before storing proof or changing counters', async (failure) => {
  const v = fixture(failure);
  await expect(
    acceptPlatformRecoveryProof(v.client, v.context, v.actor, 'REQUEST', origin, v.input),
  ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
});
it('rejects an intent substitution before proof mutation', async () => {
  const v = fixture();
  v.input.intentDigest = `sha256:${'0'.repeat(64)}`;
  await expect(
    acceptPlatformRecoveryProof(v.client, v.context, v.actor, 'REQUEST', origin, v.input),
  ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
});
it('issues a fresh challenge for the fixed signer, bounded by the original lease deadline', async () => {
  const v = fixture();
  v.context.now = new Date(Date.parse(v.context.intent.validUntil) - 1000);
  const result = await issuePlatformRecoveryChallenge(
    v.client,
    v.context,
    v.actor,
    'REQUEST',
    origin,
  );
  expect(result.expiresAt).toBe(v.context.intent.validUntil);
  expect(result.userVerification).toBe('required');
  expect(v.writes).toHaveLength(1);
  expect(v.writes[0]!.values[10]).toEqual(hash(result.challenge));
  expect(v.writes[0]!.values).not.toContain(result.challenge);
});
