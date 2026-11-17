import { createHash, generateKeyPairSync } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityActorKeyDigest,
  identityMutationAudienceDigest,
} from '../domain/identity-runtime-authorization.js';
import {
  createLocalIdentityRuntimeCryptoAdapter,
  createLocalIdentityRuntimeVerifier,
} from '../domain/identity-runtime-crypto.js';
import {
  readWorkloadSigningRepairReview,
  WorkloadSigningRepairReviewUnavailable,
} from './workload-signing-handover-repair-review.js';

const id = (n: number) => '01a10000-0000-7000-8000-' + n.toString().padStart(12, '0');
const hash = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest();
const digest = (value: unknown) => Buffer.from(canonicalAuthorizationDigest(value).slice(7), 'hex');
async function fixture(
  options: {
    foreignActor?: boolean;
    foreignAudience?: boolean;
    expiredAtVerification?: boolean;
  } = {},
) {
  const input = {
    participantId: id(1),
    privacyDomainId: id(2),
    recoveryId: id(3),
    reviewOperationId: id(4),
  };
  const checkerId = id(6),
    sessionId = id(50);
  const verificationDigest = Buffer.alloc(32, 51);
  const verifiedAt = new Date('2026-01-01T00:00:10.000Z');
  const issuedAt = BigInt(verifiedAt.getTime() - 10000) * 1000000n;
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const verifier = createLocalIdentityRuntimeVerifier([publicKey]);
  const payload = encodeIdentityAuthContextAssertionPayload({
    assertionId: id(52),
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(
      input.participantId,
      options.foreignActor ? id(99) : checkerId,
    ),
    participantContextDigest: Buffer.alloc(32, 1),
    audienceDigest: identityMutationAudienceDigest({
      actionIntentId: options.foreignAudience
        ? 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
        : 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
      resourceId: sessionId,
      candidateDigest: 'sha256:' + verificationDigest.toString('hex'),
    }),
    senderBindingKind: 1,
    senderCredentialBindingDigest: Buffer.alloc(32, 2),
    assuranceProfileDigest: Buffer.alloc(32, 3),
    authorityVectorDigest: Buffer.alloc(32, 4),
    authenticationEvidenceDigest: Buffer.alloc(32, 5),
    issuedAtNs: issuedAt,
    expiresAtNs: options.expiredAtVerification
      ? BigInt(verifiedAt.getTime()) * 1000000n
      : issuedAt + 60000000000n,
  });
  const signed = await signer.signCanonicalAssertion(payload);
  const checker = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  const candidate = {
    recoveryId: input.recoveryId,
    note: 'Independent review of the completed repair and its original retained effects.',
  };
  const reviewedAt = new Date('2026-01-01T00:00:30.000Z');
  const result = {
    recoveryId: input.recoveryId,
    postReviewStatus: 'REVIEWED',
    reviewedAt: reviewedAt.toISOString(),
  };
  const row = {
    ...input,
    enrollmentId: id(7),
    enrollmentDigest: Buffer.alloc(32, 7),
    caseState: 'REVOKED',
    reviewerPrincipalId: id(5),
    checkerPrincipalId: checkerId,
    reviewedAt,
    noteDigest: hash(candidate.note),
    candidateId: id(20),
    candidate,
    candidateDigest: digest(candidate),
    closedCaseRevision: '6',
    result,
    resultDigest: digest(result),
    resultRevision: '7',
    approvalRequestId: id(30),
    approvalDecisionId: id(31),
    approvalDecisionDigest: Buffer.alloc(32, 32),
    checkerCredentialId: id(40),
    checkerPublicKey: checker,
    checkerPublicKeyDigest: hash(checker),
    evidenceCbor: payload,
    evidenceDigest: hash(payload),
    coseSign1: Buffer.from(signed.coseSign1),
  };
  const verification = {
    candidate_digest: verificationDigest,
    session_id: sessionId,
    occurred_at: verifiedAt,
  };
  let count = 1;
  const query = vi.fn(async (sql: string) => {
    if (sql === 'select openpc.assert_request_context(true)') return { rowCount: 1, rows: [{}] };
    if (sql.includes('from control.platform_recovery_case recovery'))
      return { rowCount: count, rows: count === 0 ? [] : Array.from({ length: count }, () => row) };
    if (sql.includes('from control.mutation_evidence verification'))
      return { rowCount: 1, rows: [verification] };
    throw new Error('Unexpected query in read-only review reconstruction');
  });
  return {
    input,
    row,
    query,
    verification,
    verifier,
    setCount: (value: number) => {
      count = value;
    },
    read: () => readWorkloadSigningRepairReview({ query } as never, input, verifier),
  };
}

it('authenticates retained review evidence at its original verification time and returns the immutable closed-case version', async () => {
  const f = await fixture();
  Object.assign(f.row, {
    currentCaseRevision: '900',
    updatedAt: new Date('2099-01-01T00:00:00.000Z'),
  });
  const result = await f.read();
  expect(result).toMatchObject({
    ...f.input,
    closedCaseRevision: '6',
    leaseClosureState: 'REVOKED',
    reviewedAt: f.row.result.reviewedAt,
    candidateDigest: canonicalAuthorizationDigest(f.row.candidate),
    resultDigest: canonicalAuthorizationDigest(f.row.result),
  });
  expect(result).not.toHaveProperty('note');
  expect(result).not.toHaveProperty('evidenceCbor');
  expect(result).not.toHaveProperty('checkerPublicKey');
  const calls = f.query.mock.calls;
  expect(calls[0]![0]).toBe('select openpc.assert_request_context(true)');
  expect(calls[1]![0]).toContain('candidate.expected_revision::text as "closedCaseRevision"');
  expect(calls[1]![0]).toContain("candidate.state='CONSUMED'");
  expect(calls[1]![0]).toContain("committed.terminal_state='COMMITTED'");
  expect(calls[1]![0]).not.toContain('set role');
  expect(calls[1]![0]).not.toContain('recovery.updated_at');
  expect(calls[2]![0]).toContain('decision.approval_request_id=$7');
});

it.each([0, 2])(
  'rejects %i matching native reviews instead of selecting an arbitrary record',
  async (count) => {
    const f = await fixture();
    f.setCount(count);
    await expect(f.read()).rejects.toBeInstanceOf(WorkloadSigningRepairReviewUnavailable);
    expect(f.query).toHaveBeenCalledTimes(2);
  },
);

const mutations: [string, (row: Awaited<ReturnType<typeof fixture>>['row']) => void][] = [
  [
    'foreign participant',
    (r) => {
      r.participantId = id(99);
    },
  ],
  [
    'foreign privacy domain',
    (r) => {
      r.privacyDomainId = id(99);
    },
  ],
  [
    'different recovery',
    (r) => {
      r.recoveryId = id(99);
    },
  ],
  [
    'different review operation',
    (r) => {
      r.reviewOperationId = id(99);
    },
  ],
  [
    'nonterminal lease case',
    (r) => {
      Object.assign(r, { caseState: 'ACTIVE' });
    },
  ],
  [
    'self review',
    (r) => {
      r.reviewerPrincipalId = r.checkerPrincipalId;
    },
  ],
  [
    'altered candidate digest',
    (r) => {
      r.candidateDigest = Buffer.alloc(32, 99);
    },
  ],
  [
    'altered review note',
    (r) => {
      r.candidate.note = 'A substituted review note that was not approved.';
    },
  ],
  [
    'altered note digest',
    (r) => {
      r.noteDigest = Buffer.alloc(32, 99);
    },
  ],
  [
    'different reviewed recovery',
    (r) => {
      r.result.recoveryId = id(99);
      r.resultDigest = digest(r.result);
    },
  ],
  [
    'different review time',
    (r) => {
      r.result.reviewedAt = '2026-01-01T00:00:31.000Z';
      r.resultDigest = digest(r.result);
    },
  ],
  [
    'altered result digest',
    (r) => {
      r.resultDigest = Buffer.alloc(32, 99);
    },
  ],
  [
    'noncanonical closed revision',
    (r) => {
      r.closedCaseRevision = '06';
    },
  ],
  [
    'zero closed revision',
    (r) => {
      r.closedCaseRevision = '0';
    },
  ],
  [
    'overflowing result revision',
    (r) => {
      r.resultRevision = '18446744073709551616';
    },
  ],
  [
    'wrong result revision',
    (r) => {
      r.resultRevision = '8';
    },
  ],
  [
    'altered checker public-key digest',
    (r) => {
      r.checkerPublicKeyDigest = Buffer.alloc(32, 99);
    },
  ],
  [
    'altered evidence digest',
    (r) => {
      r.evidenceDigest = Buffer.alloc(32, 99);
    },
  ],
  [
    'corrupted signature',
    (r) => {
      const last = r.coseSign1.length - 1;
      r.coseSign1[last] = r.coseSign1[last]! ^ 1;
    },
  ],
  [
    'injected candidate authority',
    (r) => {
      Object.assign(r.candidate, { authority: true });
    },
  ],
  [
    'injected successful-result flag',
    (r) => {
      Object.assign(r.result, { verified: true });
      r.resultDigest = digest(r.result);
    },
  ],
];
it.each(mutations)('rejects %s in the native review reconstruction', async (_name, mutate) => {
  const f = await fixture();
  mutate(f.row);
  await expect(f.read()).rejects.toBeInstanceOf(WorkloadSigningRepairReviewUnavailable);
});

it.each(['foreignActor', 'foreignAudience', 'expiredAtVerification'] as const)(
  'rejects authentically signed %s evidence',
  async (kind) => {
    const f = await fixture({ [kind]: true });
    await expect(f.read()).rejects.toBeInstanceOf(WorkloadSigningRepairReviewUnavailable);
  },
);

it('rejects a signer outside the configured historical verification ring', async () => {
  const f = await fixture();
  const foreign = generateKeyPairSync('ed25519');
  const verifier = createLocalIdentityRuntimeVerifier([
    foreign.publicKey.export({ format: 'der', type: 'spki' }),
  ]);
  await expect(
    readWorkloadSigningRepairReview({ query: f.query } as never, f.input, verifier),
  ).rejects.toBeInstanceOf(WorkloadSigningRepairReviewUnavailable);
});

it('rejects a substituted stored verification session even with an authentic signature', async () => {
  const f = await fixture();
  f.verification.session_id = id(99);
  await expect(f.read()).rejects.toBeInstanceOf(WorkloadSigningRepairReviewUnavailable);
});

it('preserves unavailable database/transport failures instead of treating them as a completed review', async () => {
  const f = await fixture();
  const failed = new Error('Database collection unavailable');
  f.query.mockImplementation(async (sql: string) => {
    if (sql === 'select openpc.assert_request_context(true)') return { rowCount: 1, rows: [{}] };
    throw failed;
  });
  await expect(f.read()).rejects.toBe(failed);
});
