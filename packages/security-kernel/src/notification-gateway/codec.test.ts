import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { evidenceKeyId } from '../business-transition/cose.js';
import { decodeCbor, encodeCbor, type CborValue } from '../canonical-cbor.js';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  signNotificationClaim,
  verifyNotificationClaim,
  type NotificationChannelProfileClaims,
  type NotificationCompletionWorkerProfileClaims,
  type NotificationDeliveryReceiptClaims,
  type NotificationRoutingProfileClaims,
} from './codec.js';

function keys() {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: key.publicKey.export({ format: 'der', type: 'spki' }),
  };
}
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: number) => `sha256:${String(n).repeat(64)}`;
const issuer = keys(),
  signer = keys();
const profile: NotificationChannelProfileClaims = {
  environmentId: 'test',
  participantId: id(1),
  privacyDomainId: id(2),
  profileId: id(3),
  revision: '1',
  validFromMs: 1000,
  validUntilMs: 10000,
  transportProfileDigest: digest(1),
  receiptSignerSpki: signer.spki.toString('hex'),
  issuerKeyId: evidenceKeyId(issuer.spki),
};
const receipt: NotificationDeliveryReceiptClaims = {
  environmentId: 'test',
  participantId: id(1),
  privacyDomainId: id(2),
  receiptId: id(4),
  signedProfileDigest: digest(1),
  attemptDigest: digest(2),
  contextDigest: digest(3),
  outcome: 'AMBIGUOUS',
  observedAtMs: 2000,
  signerKeyId: evidenceKeyId(signer.spki),
};
describe('canonical notification profile and observation', () => {
  it('round trips both independently signed families and all registered outcomes', () => {
    const signed = signNotificationClaim(
      'NotificationChannelProfileV1',
      issuer.privateKey,
      issuer.spki,
      profile,
    );
    expect(
      verifyNotificationClaim(
        'NotificationChannelProfileV1',
        issuer.spki,
        signed.payload,
        signed.cose,
      ),
    ).toEqual(profile);
    for (const outcome of [
      'DELIVERED',
      'RETRYABLE_NO_EFFECT',
      'PERMANENT_FAILURE',
      'AMBIGUOUS',
    ] as const) {
      const claim = { ...receipt, outcome };
      const signed = signNotificationClaim(
        'NotificationDeliveryReceiptV1',
        signer.privateKey,
        signer.spki,
        claim,
      );
      expect(
        verifyNotificationClaim(
          'NotificationDeliveryReceiptV1',
          signer.spki,
          signed.payload,
          signed.cose,
        ),
      ).toEqual(claim);
    }
  });
  it('rejects wrong signer, cross-purpose substitution, altered payload and untagged COSE', () => {
    const signed = signNotificationClaim(
      'NotificationDeliveryReceiptV1',
      signer.privateKey,
      signer.spki,
      receipt,
    );
    expect(() =>
      verifyNotificationClaim(
        'NotificationDeliveryReceiptV1',
        issuer.spki,
        signed.payload,
        signed.cose,
      ),
    ).toThrow();
    expect(() =>
      verifyNotificationClaim(
        'NotificationChannelProfileV1',
        signer.spki,
        signed.payload,
        signed.cose,
      ),
    ).toThrow();
    expect(() =>
      verifyNotificationClaim(
        'NotificationDeliveryReceiptV1',
        signer.spki,
        encodeNotificationClaim('NotificationDeliveryReceiptV1', {
          ...receipt,
          outcome: 'DELIVERED',
        }),
        signed.cose,
      ),
    ).toThrow();
    expect(() =>
      verifyNotificationClaim(
        'NotificationDeliveryReceiptV1',
        signer.spki,
        signed.payload,
        signed.cose.subarray(1),
      ),
    ).toThrow();
    expect(() =>
      signNotificationClaim(
        'NotificationDeliveryReceiptV1',
        issuer.privateKey,
        signer.spki,
        receipt,
      ),
    ).toThrow();
  });
  it('rejects invalid lifetimes, issuer/observer key conflation, unknown fields and accessors without evaluating them', () => {
    for (const change of [
      { validUntilMs: 1000 },
      { validFromMs: -0 },
      { revision: '18446744073709551616' },
      { receiptSignerSpki: issuer.spki.toString('hex') },
      { participantId: id(1).replace('-7000-', '-4000-') },
      { extra: 1 },
    ])
      expect(() =>
        encodeNotificationClaim('NotificationChannelProfileV1', { ...profile, ...change }),
      ).toThrow();
    const malicious = { ...profile };
    let reads = 0;
    Object.defineProperty(malicious, 'issuerKeyId', {
      get() {
        reads++;
        return profile.issuerKeyId;
      },
    });
    expect(() => encodeNotificationClaim('NotificationChannelProfileV1', malicious)).toThrow();
    expect(reads).toBe(0);
  });
  it('rejects changed definitions, unknown keys, wrong primitive types and trailing bytes', () => {
    const bytes = encodeNotificationClaim('NotificationDeliveryReceiptV1', receipt);
    for (const [key, value] of [
      [0, Buffer.alloc(32)],
      [4, 'not-a-uuid'],
      [8, 0],
      [99, 1],
    ] as [number, CborValue][]) {
      const map = decodeCbor(bytes) as Map<number, CborValue>;
      map.set(key, value);
      expect(() =>
        decodeNotificationClaim('NotificationDeliveryReceiptV1', encodeCbor(map)),
      ).toThrow();
    }
    expect(() =>
      decodeNotificationClaim(
        'NotificationDeliveryReceiptV1',
        Buffer.concat([bytes, Buffer.from([0])]),
      ),
    ).toThrow();
  });
});

describe('canonical immutable notification routing profile', () => {
  const route: NotificationRoutingProfileClaims = {
    environmentId: profile.environmentId,
    participantId: profile.participantId,
    privacyDomainId: profile.privacyDomainId,
    profileId: id(5),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 10000,
    sourceEvent: 'EvidenceExportCompleted',
    endpointId: id(6),
    endpointRevision: '2',
    signedChannelProfileDigest: digest(1),
    templateDigest: digest(2),
    recipientSetDigest: digest(3),
    redactionProfileDigest: digest(4),
    preferenceGeneration: '1',
    encryptionProfileDigest: digest(5),
    payloadKeyPolicyDigest: digest(6),
    issuerKeyId: evidenceKeyId(issuer.spki),
  };
  it.each(['EvidenceExportCompleted', 'NotificationDeliveryRequested'] as const)(
    'round trips the registered %s source binding',
    (sourceEvent) => {
      const claims = { ...route, sourceEvent };
      const signed = signNotificationClaim(
        'NotificationRoutingProfileV1',
        issuer.privateKey,
        issuer.spki,
        claims,
      );
      expect(
        verifyNotificationClaim(
          'NotificationRoutingProfileV1',
          issuer.spki,
          signed.payload,
          signed.cose,
        ),
      ).toEqual(claims);
      expect(() =>
        verifyNotificationClaim(
          'NotificationChannelProfileV1',
          issuer.spki,
          signed.payload,
          signed.cose,
        ),
      ).toThrow();
      expect(() =>
        verifyNotificationClaim(
          'NotificationRoutingProfileV1',
          signer.spki,
          signed.payload,
          signed.cose,
        ),
      ).toThrow();
    },
  );
  it('rejects substituted endpoint, template, recipients and key policy under the original signature', () => {
    const signed = signNotificationClaim(
      'NotificationRoutingProfileV1',
      issuer.privateKey,
      issuer.spki,
      route,
    );
    for (const change of [
      { endpointId: id(7) },
      { endpointRevision: '3' },
      { templateDigest: digest(7) },
      { recipientSetDigest: digest(7) },
      { payloadKeyPolicyDigest: digest(7) },
      { preferenceGeneration: '2' },
    ]) {
      const altered = encodeNotificationClaim('NotificationRoutingProfileV1', {
        ...route,
        ...change,
      });
      expect(() =>
        verifyNotificationClaim('NotificationRoutingProfileV1', issuer.spki, altered, signed.cose),
      ).toThrow();
    }
  });
  it('rejects absent, unknown, ambiguous and unbounded routing claims', () => {
    for (const change of [
      { sourceEvent: 'AnyEvent' },
      { endpointRevision: '0' },
      { preferenceGeneration: '18446744073709551616' },
      { validUntilMs: 1000 },
      { payloadKeyPolicyDigest: 'secret://vault/latest' },
      { recipientSetDigest: undefined },
      { allowDispatch: true },
    ])
      expect(() =>
        encodeNotificationClaim('NotificationRoutingProfileV1', {
          ...route,
          ...change,
        } as NotificationRoutingProfileClaims),
      ).toThrow();
    const payload = encodeNotificationClaim('NotificationRoutingProfileV1', route);
    const map = decodeCbor(payload) as Map<number, CborValue>;
    map.set(99, 1);
    expect(() =>
      decodeNotificationClaim('NotificationRoutingProfileV1', encodeCbor(map)),
    ).toThrow();
    expect(() =>
      decodeNotificationClaim(
        'NotificationRoutingProfileV1',
        Buffer.concat([payload, Buffer.from([0])]),
      ),
    ).toThrow();
  });
});

const completionProfile: NotificationCompletionWorkerProfileClaims = {
  environmentId: 'test',
  participantId: id(1),
  privacyDomainId: id(2),
  profileId: id(8),
  revision: '1',
  validFromMs: 1000,
  validUntilMs: 10000,
  serviceId: 'LS-CONTROL-WORK',
  processRole: 'ROLE-CONTROL-WORKER',
  subscriptionId: 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1',
  principalId: id(9),
  workloadCredentialId: id(10),
  workloadEpoch: '1',
  workloadId: 'control-work',
  workloadKeyDigest: evidenceKeyId(signer.spki),
  producerTrustDigest: digest(3),
  maximumAttempts: 3,
  initialBackoffMs: 100,
  maximumBackoffMs: 1000,
  issuerKeyId: evidenceKeyId(issuer.spki),
};
it('binds the distinct completion consumer profile and refuses prior worker purpose substitution', () => {
  const signed = signNotificationClaim(
    'NotificationCompletionWorkerProfileV1',
    issuer.privateKey,
    issuer.spki,
    completionProfile,
  );
  expect(
    verifyNotificationClaim(
      'NotificationCompletionWorkerProfileV1',
      issuer.spki,
      signed.payload,
      signed.cose,
    ),
  ).toEqual(completionProfile);
  expect(() =>
    verifyNotificationClaim(
      'NotificationWorkerProfileV1',
      issuer.spki,
      signed.payload,
      signed.cose,
    ),
  ).toThrow();
  expect(() =>
    verifyNotificationClaim(
      'NotificationCompletionWorkerProfileV1',
      signer.spki,
      signed.payload,
      signed.cose,
    ),
  ).toThrow();
  expect(() =>
    verifyNotificationClaim(
      'NotificationCompletionWorkerProfileV1',
      issuer.spki,
      encodeNotificationClaim('NotificationCompletionWorkerProfileV1', {
        ...completionProfile,
        maximumAttempts: 4,
      }),
      signed.cose,
    ),
  ).toThrow();
});
it.each([
  { maximumAttempts: 0 },
  { maximumAttempts: 1001 },
  { maximumAttempts: 1.5 },
  { maximumAttempts: -0 },
  { initialBackoffMs: 0 },
  { maximumBackoffMs: 99 },
  { maximumBackoffMs: 3600001 },
  { validUntilMs: 1000 },
  { workloadKeyDigest: completionProfile.issuerKeyId },
])('rejects invalid completion consumer lifetime or finite retry policy %j', (change) => {
  expect(() =>
    encodeNotificationClaim('NotificationCompletionWorkerProfileV1', {
      ...completionProfile,
      ...change,
    }),
  ).toThrow();
});
it('rejects completion subscription aliases, unregistered fields and noncanonical data at decode', () => {
  const map = decodeCbor(
    encodeNotificationClaim('NotificationCompletionWorkerProfileV1', completionProfile),
  );
  if (!(map instanceof Map)) throw new Error('Expected map');
  for (const [key, value] of [
    [10, 3],
    [17, 0],
    [21, 1],
  ] as const) {
    const changed = new Map(map);
    changed.set(key, value);
    expect(() =>
      decodeNotificationClaim('NotificationCompletionWorkerProfileV1', encodeCbor(changed)),
    ).toThrow();
  }
});

describe('completion disposition is a distinct finite-attempt receipt', () => {
  const completion: import('./codec.js').NotificationCompletionDispositionReceiptClaims = {
    environmentId: 'test',
    participantId: id(1),
    privacyDomainId: id(2),
    receiptId: id(4),
    operationId: id(5),
    sourceEventId: id(6),
    sourceEnvelopeDigest: digest(1),
    sourceDataDigest: digest(2),
    sourcePartitionDigest: digest(3),
    producerTrustDigest: digest(4),
    sourceReceiptDigest: digest(5),
    initialWorkerInstallationDigest: digest(1),
    initialWorkerProfileDigest: digest(2),
    workerInstallationDigest: digest(3),
    workerProfileDigest: digest(4),
    authoritySnapshotDigest: digest(5),
    attemptChainDigest: digest(6),
    attemptCount: 2,
    attemptLimit: 3,
    initialAttemptLimit: 5,
    initialBackoffMs: 100,
    maximumBackoffMs: 1000,
    signerInstallationDigest: digest(7),
    disposition: 'ADMITTED',
    safeProblem: 'NONE',
    workItemKind: 'NONE',
    workItemId: id(4),
    beforeStateDigest: digest(8),
    afterStateDigest: digest(9),
    cursorMode: 'ADVANCE',
    recordedAtMs: 2000,
    signerKeyId: evidenceKeyId(signer.spki),
  };
  const family = 'NotificationCompletionDispositionReceiptV1';
  it('round trips admitted success, original producer failure and exhausted quarantine', () => {
    for (const claim of [
      completion,
      { ...completion, workItemKind: 'DELIVERY_FAILURE' as const, workItemId: id(9) },
      {
        ...completion,
        disposition: 'QUARANTINED' as const,
        safeProblem: 'PC-OPS-9001' as const,
        cursorMode: 'HOLD' as const,
        workItemKind: 'REMEDIATION' as const,
        attemptCount: 3,
      },
    ]) {
      const signed = signNotificationClaim(family, signer.privateKey, signer.spki, claim);
      expect(verifyNotificationClaim(family, signer.spki, signed.payload, signed.cose)).toEqual(
        claim,
      );
      expect((decodeCbor(signed.payload) as Map<number, CborValue>).size).toBe(33);
    }
  });
  it('rejects replenished budgets, false exhaustion, cursor gaps and fabricated WorkItem modes', () => {
    for (const change of [
      { attemptCount: 0 },
      { attemptCount: 6 },
      { attemptLimit: 0 },
      { attemptLimit: 6 },
      { initialAttemptLimit: 1001 },
      { initialBackoffMs: 0 },
      { maximumBackoffMs: 99 },
      { maximumBackoffMs: 3600001 },
      { beforeStateDigest: completion.afterStateDigest },
      { cursorMode: 'HOLD' },
      { safeProblem: 'PC-OPS-9001' },
      { workItemKind: 'REMEDIATION' },
      { workItemId: id(10) },
      { recordedAtMs: -0 },
      { extra: 1 },
      {
        disposition: 'QUARANTINED',
        safeProblem: 'PC-OPS-9001',
        cursorMode: 'HOLD',
        workItemKind: 'REMEDIATION',
      },
      {
        disposition: 'QUARANTINED',
        safeProblem: 'PC-OPS-9001',
        cursorMode: 'HOLD',
        workItemKind: 'REMEDIATION',
        attemptCount: 3,
        workItemId: id(10),
      },
    ])
      expect(() =>
        encodeNotificationClaim(family, { ...completion, ...change } as typeof completion),
      ).toThrow();
  });
  it('rejects wrong keys, other families, changed provenance and noncanonical frames', () => {
    const signed = signNotificationClaim(family, signer.privateKey, signer.spki, completion);
    expect(() =>
      verifyNotificationClaim(family, issuer.spki, signed.payload, signed.cose),
    ).toThrow();
    expect(() =>
      verifyNotificationClaim(
        'NotificationDeliveryOutcomeReceiptV1',
        signer.spki,
        signed.payload,
        signed.cose,
      ),
    ).toThrow();
    expect(() =>
      verifyNotificationClaim(
        family,
        signer.spki,
        encodeNotificationClaim(family, { ...completion, attemptChainDigest: digest(7) }),
        signed.cose,
      ),
    ).toThrow();
    expect(() =>
      verifyNotificationClaim(family, signer.spki, signed.payload, signed.cose.subarray(1)),
    ).toThrow();
    for (const [key, value] of [
      [0, Buffer.alloc(32)],
      [18, true],
      [24, 0],
      [33, 1],
    ] as [number, CborValue][]) {
      const map = decodeCbor(signed.payload) as Map<number, CborValue>;
      map.set(key, value);
      expect(() => decodeNotificationClaim(family, encodeCbor(map))).toThrow();
    }
    expect(() =>
      decodeNotificationClaim(family, Buffer.concat([signed.payload, Buffer.from([0])])),
    ).toThrow();
  });
  it('never evaluates accessors in completion claims', () => {
    const claim = { ...completion };
    let reads = 0;
    Object.defineProperty(claim, 'attemptCount', {
      enumerable: true,
      get() {
        reads++;
        return 2;
      },
    });
    expect(() => encodeNotificationClaim(family, claim)).toThrow();
    expect(reads).toBe(0);
  });
});
