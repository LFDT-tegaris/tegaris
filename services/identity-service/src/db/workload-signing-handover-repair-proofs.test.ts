import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import { verifyLocalWebAuthnAssertion } from '../domain/local-webauthn-trust-adapter.js';
import { verifiedWebAuthnAssertionDigest } from '../domain/trust-adapter.js';
import { readWorkloadSigningRepairProofs } from './workload-signing-handover-repair-proofs.js';

const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();
const tagged = (value: Buffer) => 'sha256:' + value.toString('hex');
function fixture(
  options: { zeroCounter?: boolean; tenfold?: boolean; activationDelayMs?: number } = {},
) {
  const f = identityEnvelopeRecoveryFixture(),
    origin = 'https://tegaris.test';
  const lifetimes = options.tenfold
    ? { profile: 'LOCAL_QA_10X' as const, leaseMs: 9000000, administratorMs: 36000000 }
    : undefined;
  const intent = identityEnvelopeRecoveryIntent.parse({
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: f.enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(f.enrollment),
    rotationId: id(401),
    creationOperationId: id(402),
    sourceParticipantEpoch: f.enrollment.issuerParticipantEpoch,
    sourceIssuerPrincipalEpoch: f.enrollment.issuerPrincipalEpoch,
    sourceIssuerCredentialEpoch: f.enrollment.issuerCredentialEpoch,
    oldTrustDigest: f.enrollment.oldTrustDigest,
    selectionAdmissionVersion: f.enrollment.selectionAdmissionVersion,
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    ...(lifetimes ? { lifetimes } : {}),
    postReviewRequired: true,
  });
  const intentDigest = canonicalAuthorizationDigest(intent);
  const actors = [
    f.enrollment.recoveryPrincipal,
    ...f.enrollment.custodians,
    f.enrollment.recoveryPrincipal,
  ];
  const phases = ['REQUEST', 'APPROVE', 'APPROVE', 'ACTIVATE'] as const;
  const keys = new Map(
    actors.map((actor) => [
      actor.credentialId,
      generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    ]),
  );
  const rows = actors.map((actor, index) => {
    const key = keys.get(actor.credentialId)!,
      publicKey = Buffer.from(key.publicKey.export({ format: 'der', type: 'spki' }));
    const challenge = `original-recovery-challenge-${index}-` + 'a'.repeat(32),
      verifiedAt = new Date(f.now.getTime() + (index + 1) * 1000);
    const externalCredentialId = Buffer.from('authenticator-' + actor.credentialId).toString(
      'base64url',
    );
    const clientData = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }),
    );
    const auth = Buffer.alloc(37);
    hash('tegaris.test').copy(auth);
    auth[32] = 0x05;
    auth.writeUInt32BE(options.zeroCounter ? 0 : index + 1, 33);
    const assertion = {
      credentialId: externalCredentialId,
      authenticatorData: auth.toString('base64url'),
      clientDataJson: clientData.toString('base64url'),
      signature: sign('sha256', Buffer.concat([auth, hash(clientData)]), key.privateKey).toString(
        'base64url',
      ),
    };
    const sessionId = id(8000 + index);
    const verified = verifyLocalWebAuthnAssertion(
      {
        credentialId: actor.credentialId,
        externalCredentialId,
        publicKeySpkiDer: publicKey,
        publicKeyDigest: hash(publicKey),
      },
      {
        principalId: actor.principalId,
        sessionId,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceDigest: intentDigest,
        challenge,
        rpIdHash: tagged(hash('tegaris.test')),
        allowedOrigin: origin,
        assertion: JSON.stringify(assertion),
      },
      verifiedAt,
    );
    expect(verified).toBeDefined();
    return {
      participantId: f.enrollment.participantId,
      privacyDomainId: f.enrollment.privacyDomainId,
      recoveryId: intent.recoveryId,
      proofId: id(5000 + index),
      ...actor,
      sessionId,
      sessionEpoch: '1',
      phase: phases[index]!,
      intentDigest: Buffer.from(intentDigest.slice(7), 'hex'),
      assertionEvidence: { assertion, verified: JSON.parse(JSON.stringify(verified)) as unknown },
      assertionDigest: verifiedWebAuthnAssertionDigest(verified!),
      signCount: verified!.signCount,
      verifiedAt,
      challengeDigest: hash(challenge),
      origin,
      createdAt: new Date(verifiedAt.getTime() - 1000),
      expiresAt: new Date(verifiedAt.getTime() - 1000 + (options.tenfold ? 3000000 : 300000)),
      consumedAt: verifiedAt,
      durationProfile: options.tenfold ? 'LOCAL_QA_10X' : 'C17',
      maxAgeMs: options.tenfold ? 3000000 : 300000,
      externalCredentialId,
      publicKey,
      publicKeyDigest: hash(publicKey),
    };
  });
  const lease = identityEnvelopeRecoveryLease.parse({
    schema: 'pc.identity.identity-envelope-recovery-lease',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: intent.recoveryId,
    enrollmentId: intent.enrollmentId,
    enrollmentDigest: intent.enrollmentDigest,
    intentDigest,
    rotationId: intent.rotationId,
    creationOperationId: intent.creationOperationId,
    activationOperationId: id(9000),
    executorPrincipalId: f.enrollment.recoveryPrincipal.principalId,
    issuer: {
      participantId: f.enrollment.participantId,
      privacyDomainId: f.enrollment.privacyDomainId,
      workloadCredentialId: f.enrollment.request.workloadCredentialId,
      workloadPrincipalId: f.enrollment.issuerPrincipalId,
      workloadParticipantEpoch: '7',
      workloadPrincipalEpoch: '2',
      workloadCredentialEpoch: '1',
      workloadPublicKeyDigest: f.enrollment.issuerCredentialPublicKeyDigest,
      credentialValidFromNs: '0',
      credentialValidUntilNs: null,
    },
    oldTrustDigest: intent.oldTrustDigest,
    selectionAdmissionVersion: intent.selectionAdmissionVersion,
    proofIds: rows.map((row) => row.proofId),
    proofEvidenceDigest: 'sha256:' + '00'.repeat(32),
    validFrom: new Date(f.now.getTime() + (options.activationDelayMs ?? 5000)).toISOString(),
    validUntil: new Date(f.now.getTime() + 600000).toISOString(),
    ...(lifetimes ? { lifetimes } : {}),
    postReviewRequired: true,
  });
  const recommit = () => {
    lease.proofEvidenceDigest = canonicalAuthorizationDigest(
      lease.proofIds.map((proofId) => {
        const row = rows.find((row) => row.proofId === proofId)!;
        return {
          proofId: row.proofId,
          principalId: row.principalId,
          principalEpoch: row.principalEpoch,
          credentialId: row.credentialId,
          credentialEpoch: row.credentialEpoch,
          sessionId: row.sessionId,
          sessionEpoch: row.sessionEpoch,
          phase: row.phase,
          intentDigest,
          verifiedAt: row.verifiedAt.toISOString(),
          assertionDigest: tagged(row.assertionDigest),
        };
      }),
    );
  };
  recommit();
  const query = vi.fn(async (sql: string) => {
    if (sql === 'select openpc.assert_request_context(true)') return { rowCount: 1, rows: [] };
    if (sql.includes('from control.platform_recovery_proof p'))
      return { rowCount: rows.length, rows };
    throw Error('Unexpected query');
  });
  return {
    ...f,
    intent,
    lease,
    rows,
    query,
    recommit,
    read: () => readWorkloadSigningRepairProofs({ query } as never, f.enrollment, intent, lease),
  };
}

it('reverifies the original four signatures and ordered activation commitment without writing or reading current authority', async () => {
  const f = fixture(),
    before = JSON.stringify(f.rows);
  // Database order does not replace the original order committed in the lease.
  f.rows.reverse();
  expect(await f.read()).toEqual({
    proofIds: f.lease.proofIds,
    proofEvidenceDigest: f.lease.proofEvidenceDigest,
  });
  expect(f.query).toHaveBeenCalledTimes(2);
  expect(JSON.stringify([...f.rows].reverse())).toBe(before);
});
it('preserves valid zero-counter authenticator history', async () => {
  const f = fixture({ zeroCounter: true });
  expect(await f.read()).toBeDefined();
});
it('uses the original long proof profile without requiring a current QA flag', async () => {
  const f = fixture({ tenfold: true, activationDelayMs: 360000 });
  expect(await f.read()).toBeDefined();
});

type Row = ReturnType<typeof fixture>['rows'][number];
const mutations: readonly [string, (row: Row) => void][] = [
  [
    'participant',
    (row) => {
      row.participantId = id(999);
    },
  ],
  [
    'privacy',
    (row) => {
      row.privacyDomainId = id(999);
    },
  ],
  [
    'recovery',
    (row) => {
      row.recoveryId = id(999);
    },
  ],
  [
    'principal',
    (row) => {
      row.principalId = id(999);
    },
  ],
  [
    'principal epoch',
    (row) => {
      row.principalEpoch = '2';
    },
  ],
  [
    'credential',
    (row) => {
      row.credentialId = id(999);
    },
  ],
  [
    'credential epoch',
    (row) => {
      row.credentialEpoch = '2';
    },
  ],
  [
    'session ID',
    (row) => {
      row.sessionId = 'not-a-session';
    },
  ],
  [
    'session epoch',
    (row) => {
      row.sessionEpoch = '2e1';
    },
  ],
  [
    'intent',
    (row) => {
      row.intentDigest = Buffer.alloc(32, 9);
    },
  ],
  [
    'assertion digest',
    (row) => {
      row.assertionDigest = Buffer.alloc(32, 9);
    },
  ],
  [
    'challenge',
    (row) => {
      row.challengeDigest = Buffer.alloc(32, 9);
    },
  ],
  [
    'origin',
    (row) => {
      row.origin = 'https://foreign.test';
    },
  ],
  [
    'credential public key',
    (row) => {
      row.publicKey = Buffer.from(
        generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
          format: 'der',
          type: 'spki',
        }),
      );
      row.publicKeyDigest = hash(row.publicKey);
    },
  ],
  [
    'counter',
    (row) => {
      row.signCount = '99';
    },
  ],
  [
    'unconsumed timestamp',
    (row) => {
      row.consumedAt = new Date(row.verifiedAt.getTime() + 1);
    },
  ],
  [
    'challenge created after proof',
    (row) => {
      row.createdAt = new Date(row.verifiedAt.getTime() + 1);
    },
  ],
  [
    'expired original challenge',
    (row) => {
      row.expiresAt = row.verifiedAt;
    },
  ],
  [
    'unknown age',
    (row) => {
      row.maxAgeMs = 500;
    },
  ],
  [
    'unknown profile',
    (row) => {
      row.durationProfile = 'OTHER';
    },
  ],
  [
    'long proof without original lineage',
    (row) => {
      row.maxAgeMs = 3000000;
    },
  ],
  [
    'signature',
    (row) => {
      const bytes = Buffer.from(row.assertionEvidence.assertion.signature, 'base64url');
      bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
      row.assertionEvidence.assertion.signature = bytes.toString('base64url');
    },
  ],
  [
    'stored verified metadata',
    (row) => {
      row.assertionEvidence.verified = {
        ...(row.assertionEvidence.verified as Record<string, unknown>),
        sessionId: id(999),
      };
    },
  ],
];
it.each(mutations)('rejects changed %s evidence', async (_name, mutate) => {
  const f = fixture();
  mutate(f.rows[0]!);
  await expect(f.read()).rejects.toThrow();
});
it.each([0, 3, 5])(
  'rejects %i native rows rather than accepting partial or duplicated history',
  async (count) => {
    const f = fixture();
    if (count < 4) f.rows.length = count;
    else f.rows.push({ ...f.rows[0]! });
    await expect(f.read()).rejects.toThrow();
  },
);
it('rejects a duplicate proof identity even when four rows are returned', async () => {
  const f = fixture();
  f.rows[1]!.proofId = f.rows[0]!.proofId;
  await expect(f.read()).rejects.toThrow();
});
it('rejects a changed original proof order instead of sorting a new commitment', async () => {
  const f = fixture();
  [f.lease.proofIds[1], f.lease.proofIds[2]] = [f.lease.proofIds[2], f.lease.proofIds[1]];
  await expect(f.read()).rejects.toThrow();
});
it('rejects proof age at the exact original freshness boundary', async () => {
  const f = fixture({ activationDelayMs: 301000 });
  await expect(f.read()).rejects.toThrow();
});
it('rejects an original long-profile challenge that had expired by activation', async () => {
  const f = fixture({ tenfold: true, activationDelayMs: 360000 });
  f.rows[0]!.expiresAt = new Date(f.lease.validFrom);
  await expect(f.read()).rejects.toThrow();
});
it('rejects substituted snapshot epochs even if a caller recomputes the commitment', async () => {
  const f = fixture();
  f.rows[0]!.credentialEpoch = '2';
  f.recommit();
  await expect(f.read()).rejects.toThrow();
});
