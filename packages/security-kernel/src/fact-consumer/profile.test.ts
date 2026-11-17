import { generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { runtimeSourceLogin } from '../runtime-source-identity.js';
import { describe, expect, it } from 'vitest';
import { decodeCbor, encodeCbor, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { factConsumerProfileContext as context } from './generated.js';
import {
  decodeFactConsumerProfile,
  encodeFactConsumerProfile,
  factConsumerProfileDigest,
  factConsumerRetryAfterFailure,
  type FactConsumerProfile,
} from './profile.js';
import {
  signFactConsumerProfile,
  verifyFactConsumerProfileSignature,
  verifyInstalledFactConsumerProfile,
  type InstalledFactConsumerProfile,
} from './cose.js';

const key = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
  };
};
function fixture(consumerId: FactConsumerProfile['consumerId'] = 'LS-FLEET-CONTROL') {
  const issuer = key();
  const profile: FactConsumerProfile = {
    environmentId: 'local-acceptance',
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    profileId: 'fact-admission',
    revision: '18446744073709551615',
    consumerId,
    subscriptionId:
      consumerId === 'LS-FLEET-CONTROL'
        ? 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1'
        : 'SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1',
    validFromMs: 1000,
    validUntilMs: 100000,
    issuerKeyId: evidenceKeyId(issuer.spki),
    workloadCredentialId: '018f0000-0000-7000-8000-000000000301',
    workloadCredentialEpoch: '18446744073709551615',
    databaseRole: 'fact_consumer',
    maximumAttempts: 5,
    initialBackoffMs: 100,
    maximumBackoffMs: 300,
  };
  const payload = encodeFactConsumerProfile(profile);
  const cose = signFactConsumerProfile(issuer.privateKey, issuer.spki, payload);
  const installed: InstalledFactConsumerProfile = {
    issuerSpkiDer: issuer.spki,
    signedProfileDigest: factConsumerProfileDigest(cose),
    environmentId: profile.environmentId,
    participantId: profile.participantId,
    privacyDomainId: profile.privacyDomainId,
    profileId: profile.profileId,
    revision: profile.revision,
    consumerId,
    subscriptionId: profile.subscriptionId,
    workloadCredentialId: profile.workloadCredentialId,
    workloadCredentialEpoch: profile.workloadCredentialEpoch,
    databaseRole: profile.databaseRole,
  };
  return { issuer, profile, payload, cose, installed };
}
describe('canonical signed Fact consumer profile', () => {
  it('preserves the installed native login and rejects substituted scope and role syntax', () => {
    const f = fixture();
    const privacyDomainId = '018f0000-0000-7000-8000-000000007201';
    const databaseRole = runtimeSourceLogin(f.profile.participantId, privacyDomainId);
    expect(databaseRole).toBe('openpc_rs_login_MKKiERMDsgOMN-RH8MIkV68t_AtuGWZCx26uBYoE4c8');
    const profile = { ...f.profile, privacyDomainId, databaseRole };
    expect(decodeFactConsumerProfile(encodeFactConsumerProfile(profile))).toEqual(profile);
    for (const patch of [
      { privacyDomainId: f.profile.privacyDomainId },
      { participantId: privacyDomainId },
      { databaseRole: databaseRole.toLowerCase() },
      { databaseRole: `${databaseRole.slice(0, -1)}A` },
      { databaseRole: `${databaseRole}=` },
      { databaseRole: `"${databaseRole}"` },
      { databaseRole: 'OtherRole' },
      { privacyDomainId: privacyDomainId.toUpperCase() },
      { privacyDomainId: privacyDomainId.replace('-7000-', '-4000-') },
    ])
      expect(() => encodeFactConsumerProfile({ ...profile, ...patch })).toThrow();
    for (const role of ['fact_consumer', 'openpc_local_control_worker', 'a1'])
      expect(
        decodeFactConsumerProfile(encodeFactConsumerProfile({ ...profile, databaseRole: role }))
          .databaseRole,
      ).toBe(role);
  });
  it.each(['LS-CONTROL-WORK', 'LS-FLEET-CONTROL'] as const)(
    'binds the %s subscription without rounding u64 values',
    (consumer) => {
      const f = fixture(consumer);
      expect(decodeFactConsumerProfile(f.payload)).toEqual(f.profile);
      expect(verifyInstalledFactConsumerProfile(f.installed, f.payload, f.cose, 1000)).toEqual(
        f.profile,
      );
      expect(
        Object.isFrozen(verifyInstalledFactConsumerProfile(f.installed, f.payload, f.cose, 99999)),
      ).toBe(true);
      const wire = decodeCbor(f.payload) as Map<number, CborValue>;
      expect([...wire.keys()]).toEqual(Array.from({ length: 17 }, (_, i) => i));
      expect(wire.get(5)).toBe(18446744073709551615n);
      expect(wire.get(12)).toBe(18446744073709551615n);
      expect(wire.get(2)).toEqual(Buffer.from('018f0000000070008000000000000101', 'hex'));
    },
  );
  it('rejects every altered installation binding and does not trust a valid self-signed profile', () => {
    const f = fixture();
    const replacements = {
      environmentId: 'other',
      participantId: '018f0000-0000-7000-8000-000000000102',
      privacyDomainId: '018f0000-0000-7000-8000-000000000202',
      profileId: 'other',
      revision: '1',
      consumerId: 'LS-CONTROL-WORK',
      subscriptionId: 'SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1',
      workloadCredentialId: '018f0000-0000-7000-8000-000000000302',
      workloadCredentialEpoch: '0',
      databaseRole: 'other',
      signedProfileDigest: `sha256:${'0'.repeat(64)}`,
    };
    for (const [field, replacement] of Object.entries(replacements))
      expect(
        () =>
          verifyInstalledFactConsumerProfile(
            { ...f.installed, [field]: replacement },
            f.payload,
            f.cose,
            1000,
          ),
        field,
      ).toThrow('Installed Fact consumer profile rejected');
    expect(() =>
      verifyInstalledFactConsumerProfile(
        { ...f.installed, issuerSpkiDer: key().spki },
        f.payload,
        f.cose,
        1000,
      ),
    ).toThrow();
    const successor = { ...f.profile, revision: '1', maximumAttempts: 10 };
    const payload = encodeFactConsumerProfile(successor);
    const cose = signFactConsumerProfile(f.issuer.privateKey, f.issuer.spki, payload);
    expect(verifyFactConsumerProfileSignature(f.issuer.spki, payload, cose)).toBe(true);
    expect(() => verifyInstalledFactConsumerProfile(f.installed, payload, cose, 1000)).toThrow();
  });
  it('checks validity at both boundaries and rejects invalid clocks', () => {
    const f = fixture();
    for (const now of [999, 100000, -1, NaN, Infinity, 1000.1])
      expect(() =>
        verifyInstalledFactConsumerProfile(f.installed, f.payload, f.cose, now),
      ).toThrow();
  });
  it('rejects unknown, noncanonical and schema-substituted payloads', () => {
    const f = fixture();
    const wire = decodeCbor(f.payload) as Map<number, CborValue>;
    const unknown = new Map(wire).set(17, 0);
    const missing = new Map(wire);
    missing.delete(16);
    const wrongDefinition = new Map(wire).set(0, Buffer.alloc(32));
    const wrongConsumer = new Map(wire).set(6, 'LS-NOTIFICATION');
    const mixedSubscription = new Map(wire).set(7, 'SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1');
    for (const bad of [unknown, missing, wrongDefinition, wrongConsumer, mixedSubscription])
      expect(() => decodeFactConsumerProfile(encodeCbor(bad))).toThrow();
    for (const bad of [
      Buffer.concat([f.payload, Buffer.from([0])]),
      Buffer.concat([Buffer.from([0xb8, 17]), f.payload.subarray(1)]),
    ])
      expect(() => decodeFactConsumerProfile(bad)).toThrow();
    expect(() =>
      encodeFactConsumerProfile({ ...f.profile, unexpected: true } as FactConsumerProfile),
    ).toThrow();
    const accessor = { ...f.profile };
    Object.defineProperty(accessor, 'maximumAttempts', {
      get: () => {
        throw new Error('getter must never run');
      },
    });
    expect(() => encodeFactConsumerProfile(accessor)).toThrow('Invalid Fact consumer profile');
  });
  it('rejects changed COSE context even when the altered context is correctly signed', () => {
    const f = fixture();
    const parts = decodeCbor(f.cose.subarray(1), 66560) as CborValue[];
    const header = decodeCbor(parts[0] as Buffer) as Map<number, CborValue>;
    for (const [field, replacement] of [
      [100, 24002],
      [101, 2],
      [102, 339],
      [103, 1],
      [3, 'application/openpc+cbor'],
    ] as const) {
      const altered = encodeCbor(new Map(header).set(field, replacement));
      const signature = sign(
        'sha256',
        encodeCbor(
          ['Signature1', altered, Buffer.from(context.externalAadHex, 'hex'), f.payload],
          66560,
        ),
        {
          key: f.issuer.privateKey,
          format: 'der',
          type: 'pkcs8',
          dsaEncoding: 'ieee-p1363',
        },
      );
      const forged = Buffer.concat([
        Buffer.from([0xd2]),
        encodeCbor([altered, new Map(), f.payload, signature], 66560),
      ]);
      expect(verifyFactConsumerProfileSignature(f.issuer.spki, f.payload, forged)).toBe(false);
    }
    const corrupt = Buffer.from(f.cose);
    corrupt[corrupt.length - 1]! ^= 1;
    expect(verifyFactConsumerProfileSignature(f.issuer.spki, f.payload, corrupt)).toBe(false);
    expect(verifyFactConsumerProfileSignature(f.issuer.spki, f.payload, f.cose.subarray(1))).toBe(
      false,
    );
    expect(() => signFactConsumerProfile(key().privateKey, f.issuer.spki, f.payload)).toThrow();
  });
  it('enforces finite budgets and nonzero ordered delays', () => {
    const f = fixture();
    for (const patch of [
      { maximumAttempts: 0 },
      { maximumAttempts: 1001 },
      { maximumAttempts: 1.5 },
      { initialBackoffMs: 0 },
      { maximumBackoffMs: 99 },
      { maximumBackoffMs: 3600001 },
      { validUntilMs: 1000 },
      { validFromMs: -0 },
      { revision: '0' },
      { revision: '18446744073709551616' },
      { workloadCredentialEpoch: '01' },
      { workloadCredentialId: '018f0000-0000-4000-8000-000000000301' },
      { databaseRole: 'other role' },
    ])
      expect(() => encodeFactConsumerProfile({ ...f.profile, ...patch })).toThrow();
  });
});
it.skipIf(!process.env.OPENPC_FACT_WORKLOAD_TEST_BINARY)(
  'native profile wire interoperability preserves exact scoped login, signed bytes and denials',
  () => {
    const f = fixture();
    const native = (
      profile: FactConsumerProfile,
      payload: Buffer,
      cose: Buffer,
      accepted: boolean,
      derived: boolean,
      nowMs = 1000,
    ) => {
      const result = spawnSync(
        process.env.OPENPC_FACT_WORKLOAD_TEST_BINARY!,
        [
          'consumer_profile::tests::typescript_profile_wire_interoperability',
          '--exact',
          '--ignored',
          '--nocapture',
        ],
        {
          encoding: 'utf8',
          timeout: 10000,
          maxBuffer: 1024 * 1024,
          env: {
            ...process.env,
            OPENPC_FACT_PROFILE_WIRE: JSON.stringify({
              profile,
              payload: payload.toString('hex'),
              cose: cose.toString('hex'),
              spki: f.issuer.spki.toString('hex'),
              accepted,
              derived,
              nowMs,
            }),
          },
        },
      );
      expect(result.status, result.stderr + result.stdout).toBe(0);
      expect(result.stdout).toContain('OPENPC_FACT_PROFILE_WIRE|PASS');
    };
    native(f.profile, f.payload, f.cose, true, false);
    for (const privacyDomainId of [
      '018f0000-0000-7000-8000-000000007201',
      '018f0000-0000-7000-8000-000000000201',
      '018f0000-0000-7000-8000-000000008101',
    ]) {
      const profile = {
        ...f.profile,
        privacyDomainId,
        databaseRole: runtimeSourceLogin(f.profile.participantId, privacyDomainId),
      };
      const payload = encodeFactConsumerProfile(profile);
      const cose = signFactConsumerProfile(f.issuer.privateKey, f.issuer.spki, payload);
      native(profile, payload, cose, true, true);
      native(profile, payload, cose, false, true, profile.validUntilMs);
      const parts = decodeCbor(cose.subarray(1), 66560) as CborValue[];
      const header = parts[0] as Buffer;
      for (const databaseRole of [
        profile.databaseRole.toUpperCase(),
        `${profile.databaseRole.slice(0, -1)}!`,
        runtimeSourceLogin(privacyDomainId, profile.participantId),
      ]) {
        const badProfile = { ...profile, databaseRole };
        expect(() => encodeFactConsumerProfile(badProfile)).toThrow();
        const wire = new Map(decodeCbor(payload) as Map<number, CborValue>).set(13, databaseRole);
        const badPayload = encodeCbor(wire);
        const signature = sign(
          'sha256',
          encodeCbor(
            ['Signature1', header, Buffer.from(context.externalAadHex, 'hex'), badPayload],
            66560,
          ),
          {
            key: f.issuer.privateKey,
            format: 'der',
            type: 'pkcs8',
            dsaEncoding: 'ieee-p1363',
          },
        );
        const badCose = Buffer.concat([
          Buffer.from([0xd2]),
          encodeCbor([header, new Map(), badPayload, signature], 66560),
        ]);
        expect(verifyFactConsumerProfileSignature(f.issuer.spki, badPayload, badCose)).toBe(false);
        native(badProfile, badPayload, badCose, false, false);
      }
    }
  },
);
describe('finite retry scheduling (no effect authority)', () => {
  it('counts the initial attempt and caps exponential delay before quarantine', () => {
    const { profile } = fixture();
    expect([1, 2, 3, 4].map((n) => factConsumerRetryAfterFailure(profile, n, 1000))).toEqual([
      { kind: 'RETRY', notBeforeMs: 1100 },
      { kind: 'RETRY', notBeforeMs: 1200 },
      { kind: 'RETRY', notBeforeMs: 1300 },
      { kind: 'RETRY', notBeforeMs: 1300 },
    ]);
    expect(factConsumerRetryAfterFailure(profile, 5, 1000)).toEqual({
      kind: 'QUARANTINE',
      reason: 'ATTEMPTS_EXHAUSTED',
    });
    expect(factConsumerRetryAfterFailure({ ...profile, maximumAttempts: 1 }, 1, 1000).kind).toBe(
      'QUARANTINE',
    );
    expect(factConsumerRetryAfterFailure({ ...profile, maximumAttempts: 1000 }, 999, 1000)).toEqual(
      { kind: 'RETRY', notBeforeMs: 1300 },
    );
  });
  it('does not schedule at expiry, overflow the clock or reset durable attempts on replacement', () => {
    const { profile } = fixture();
    for (const time of [999, 99900, 100000])
      expect(factConsumerRetryAfterFailure(profile, 1, time)).toEqual({
        kind: 'BLOCKED',
        reason: 'PROFILE_NOT_CURRENT',
      });
    expect(
      factConsumerRetryAfterFailure(
        { ...profile, validUntilMs: Number.MAX_SAFE_INTEGER },
        1,
        Number.MAX_SAFE_INTEGER - 50,
      ).kind,
    ).toBe('BLOCKED');
    expect(
      factConsumerRetryAfterFailure({ ...profile, revision: '1', maximumAttempts: 3 }, 4, 1000)
        .kind,
    ).toBe('QUARANTINE');
    for (const attempts of [0, -1, 1.5, 1001, NaN])
      expect(() => factConsumerRetryAfterFailure(profile, attempts, 1000)).toThrow();
  });
});
