import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  encodeIdentityAuthContextAssertionPayload,
  signIdentityAuthContextAssertionCoseSign1Ed25519,
} from '@openpc/security-kernel';
import { createLocalIdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import {
  identityActorKeyDigest,
  identityMutationAudienceDigest,
} from '../domain/identity-runtime-authorization.js';
import { sql } from 'drizzle-orm';
import { getTableConfig, pgPolicy, PgDialect } from 'drizzle-orm/pg-core';
import {
  idempotencyRecords,
  mutationEvidence,
  outboxEvents,
  mutationCandidates,
  approvalRequests,
} from './schema/workflow.js';
import { mfaChallenges } from './schema/participants.js';
import { authorityEnvelopes, assignments } from './schema/authority.js';
import { identityEnvelopeProposals } from './schema/identity-envelope-proposal.js';
import {
  approvalHistoryOwnerLeafPolicy,
  platformRecoveryApprovalOwnerReadDefinitions,
} from './schema/platform-recovery-source.js';
import { controlOwnerRole } from './schema/common.js';
import type { PlatformRecoveryApprovalContinuation } from '../contracts/platform-recovery.js';
import { beforeEach, expect, it, vi } from 'vitest';
import { readPlatformRecoveryApprovalContinuation } from './platform-recovery-approval-continuation.js';
import { readStoredPlatformRecoveryReceipt } from './platform-recovery-readback.js';
import { pendingExpiryPlatformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
vi.mock('./platform-recovery-readback.js', () => ({ readStoredPlatformRecoveryReceipt: vi.fn() }));
beforeEach(() => vi.resetAllMocks());

type ReceivingEvidence = {
  operationId: string;
  candidateDigest: Buffer;
  sessionId: string;
  reservedAt: Date;
  evidenceCbor: Buffer;
  evidenceDigest: Buffer;
  cose: Buffer;
};
type TestCase = {
  receiving: ReceivingEvidence;
  witness: PlatformRecoveryApprovalContinuation;
  authenticated: {
    enrollment: ReturnType<typeof pendingExpiryPlatformRecoveryFixture>['source']['enrollment'];
    activationEvidenceDigest: Buffer;
    receipt: {
      intent: ReturnType<typeof pendingExpiryPlatformRecoveryFixture>['intent'];
      state: 'EXPIRED';
      authority: 'NONE';
      activation: { operationId: string };
      intentDigest: string;
      proofs: { proofId: string }[];
    };
  };
};
function fixture(depth = 2) {
  const f = pendingExpiryPlatformRecoveryFixture();
  const enrollment = f.source.enrollment;
  const cases: TestCase[] = [];
  const keys = generateKeyPairSync('ed25519'),
    publicKey = keys.publicKey.export({ format: 'der', type: 'spki' }),
    privateKey = keys.privateKey.export({ format: 'der', type: 'pkcs8' });
  const verifier = createLocalIdentityRuntimeVerifier([publicKey]);
  function signReceiving(
    operationId: string,
    principalId = f.intent.preparation.administrators[0]!.principalId,
  ) {
    const candidateDigest = Buffer.alloc(32, 9),
      sessionId = id(1450),
      reservedAt = new Date('2026-10-08T11:09:19.531Z');
    const issuedAtNs = BigInt(reservedAt.getTime() - 57000) * 1000000n;
    const evidenceCbor = encodeIdentityAuthContextAssertionPayload({
      assertionId: id(9000),
      actorKeyDigest: identityActorKeyDigest(enrollment.participantId, principalId),
      actorKind: 0,
      participantContextDigest: Buffer.alloc(32, 2),
      audienceDigest: identityMutationAudienceDigest({
        actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
        resourceId: sessionId,
        candidateDigest: 'sha256:' + candidateDigest.toString('hex'),
      }),
      senderBindingKind: 1,
      assuranceProfileDigest: Buffer.alloc(32, 4),
      authorityVectorDigest: Buffer.alloc(32, 5),
      issuedAtNs,
      expiresAtNs: issuedAtNs + 60000000000n,
      authenticationEvidenceDigest: Buffer.alloc(32, 6),
      senderCredentialBindingDigest: Buffer.alloc(32, 7),
    });
    return {
      operationId,
      candidateDigest,
      sessionId,
      reservedAt,
      evidenceCbor,
      evidenceDigest: createHash('sha256').update(evidenceCbor).digest(),
      cose: signIdentityAuthContextAssertionCoseSign1Ed25519(privateKey, publicKey, evidenceCbor),
    };
  }
  let parent: PlatformRecoveryApprovalContinuation | undefined;
  for (let index = 0; index < depth; index++) {
    const intent = structuredClone(f.intent);
    intent.recoveryId = id(900 + index);
    if (parent) intent.approvalContinuation = parent;
    const receiptDigest = Buffer.alloc(32, index + 1);
    const witness = {
      schema: 'pc.identity.platform-prepare-approval-continuation' as const,
      schemaVersion: 1 as const,
      recoveryId: intent.recoveryId,
      intentDigest: canonicalAuthorizationDigest(intent),
      activationOperationId: id(1000 + index),
      activationReceiptDigest: 'sha256:' + receiptDigest.toString('hex'),
      candidateId: id(1100 + index),
      approvalId: id(1200 + index),
      candidateDigest: canonicalAuthorizationDigest(intent.preparation),
      businessKey: 'original-immutable-business-key',
      attempt: String(index + 1),
    };
    cases.push({
      receiving: signReceiving(id(1400 + index)),
      witness,
      authenticated: {
        enrollment,
        activationEvidenceDigest: receiptDigest,
        receipt: {
          intent,
          state: 'EXPIRED',
          authority: 'NONE',
          activation: { operationId: witness.activationOperationId },
          intentDigest: witness.intentDigest,
          proofs: Array.from({ length: 4 }, (_, n) => ({ proofId: id(1300 + index * 4 + n) })),
        },
      },
    });
    parent = witness;
  }
  const row = { witness: parent!, preparation: f.intent.preparation, sourceCurrent: true };
  let receivingRows: number | undefined;
  const query = vi.fn(async (_sql: string, _args: unknown[]) => {
    if (_sql.includes('join control.mutation_evidence verification')) {
      const original = cases.find((c) => c.witness.candidateId === _args[2]);
      const rows = original ? [original.receiving] : [];
      return { rowCount: receivingRows ?? rows.length, rows };
    }
    return { rowCount: 1, rows: [row] };
  });
  vi.mocked(readStoredPlatformRecoveryReceipt).mockImplementation(async (_c, _s, _e, recovery) => {
    const found = cases.find((c) => c.witness.recoveryId === recovery);
    if (!found) throw new PlatformRecoveryError();
    return found.authenticated as Awaited<ReturnType<typeof readStoredPlatformRecoveryReceipt>>;
  });
  const execute = () =>
    readPlatformRecoveryApprovalContinuation({ query } as never, enrollment as never, verifier);
  return {
    cases,
    row,
    execute,
    query,
    enrollment,
    signReceiving,
    setReceivingRows: (n: number) => {
      receivingRows = n;
    },
  };
}

it.each([1, 2, 3, 32])(
  'authenticates all %i immutable receipts without reviving historical grants',
  async (depth) => {
    const f = fixture(depth),
      before = JSON.stringify(f.cases);
    const result = await f.execute();
    expect(result?.approvalContinuation).toEqual(f.row.witness);
    expect(result?.preparation).toEqual(f.row.preparation);
    expect(readStoredPlatformRecoveryReceipt).toHaveBeenCalledTimes(depth);
    expect(JSON.stringify(f.cases)).toEqual(before);
    expect(f.query.mock.calls[0]?.length).toBe(2);
  },
);
it('binds selection to the unique terminal and native authenticated history, without max-attempt selection', async () => {
  const f = fixture();
  await f.execute();
  const selected = (f.query.mock.calls as unknown as [string, unknown[]][])[0]![0];
  expect(selected).toContain('not exists(select 1 from control.mutation_candidate child');
  expect(selected).toContain('platform_recovery_pending_approval_history_current');
  expect(selected).not.toMatch(/max\s*\(|order by/iu);
});
it.each([
  'cycle',
  'candidate-cycle',
  'attempt-gap',
  'changed-key',
  'changed-body',
  'foreign-enrollment',
  'missing-receipt',
  'bad-receipt-hash',
  'replayed-proof',
])('denies %s ancestry before issuing a preparation', async (variant) => {
  const f = fixture();
  const head = f.cases[1]!.authenticated;
  const parent = head.receipt.intent.approvalContinuation!;
  if (variant === 'cycle') parent.recoveryId = f.row.witness.recoveryId;
  if (variant === 'candidate-cycle') parent.candidateId = f.row.witness.candidateId;
  if (variant === 'attempt-gap') parent.attempt = '7';
  if (variant === 'changed-key') parent.businessKey = 'foreign-original-business-key';
  if (variant === 'changed-body')
    f.cases[0]!.authenticated.receipt.intent.preparation.reason += ' altered';
  if (variant === 'foreign-enrollment')
    head.enrollment = { ...f.enrollment, enrollmentId: id(2000) };
  if (variant === 'missing-receipt') f.cases.shift();
  if (variant === 'bad-receipt-hash') head.activationEvidenceDigest = Buffer.alloc(32, 255);
  if (variant === 'replayed-proof')
    head.receipt.proofs[1]!.proofId = head.receipt.proofs[0]!.proofId;
  // Re-seal only the mock's already-authenticated head claim so edge negatives
  // reach the ancestry boundary. The unchanged cryptographic reader is separate.
  head.receipt.intentDigest = canonicalAuthorizationDigest(head.receipt.intent);
  f.row.witness.intentDigest = head.receipt.intentDigest;
  await expect(f.execute()).rejects.toBeInstanceOf(PlatformRecoveryError);
});
it('denies traversal beyond the fixed capacity', async () => {
  const f = fixture(33);
  await expect(f.execute()).rejects.toBeInstanceOf(PlatformRecoveryError);
});
it('denies an expired or effected native source instead of substituting a passing receipt', async () => {
  const f = fixture();
  f.row.sourceCurrent = false;
  await expect(f.execute()).rejects.toBeInstanceOf(PlatformRecoveryError);
  expect(readStoredPlatformRecoveryReceipt).not.toHaveBeenCalled();
});

it.each([idempotencyRecords, mutationEvidence, outboxEvents, mfaChallenges])(
  'exposes only the exact resumed receiving-proof history to the private owner: %s',
  (table) => {
    const policy = getTableConfig(table).policies.find(
      (p) => p.name === 'platform_prepare_approval_resume_history_read',
    );
    expect(policy?.for).toBe('select');
    expect(policy?.to).toEqual([controlOwnerRole]);
    expect(policy?.withCheck).toBeUndefined();
    const definition = platformRecoveryApprovalOwnerReadDefinitions(table).find((d) =>
      d.functionName.endsWith('_resume_read'),
    )!;
    const statement = new PgDialect().sqlToQuery(definition.predicate).sql;
    expect(definition.body).toContain('SECURITY INVOKER');
    expect(definition.body).toContain('SET row_security=on');
    expect(definition.body).toContain('FROM PUBLIC');
    expect(definition.body).not.toContain('TO openpc_control_runtime');
    for (const bound of [
      "historical.state='EXPIRED'",
      "source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'",
      "source.document->>'schemaVersion'='4'",
      'source.row_version',
      'source.document_digest',
      'openpc.matches_privacy(',
      'openpc.platform_recovery_continuation_root_matches(',
      "resume_candidate.candidate_document=historical.intent->'preparation'",
      "resume_candidate.idempotency_key=historical.intent#>>'{approvalContinuation,businessKey}'",
      'resume_candidate.consumed_operation_id is null',
      'resume_candidate.expires_at<=clock_timestamp()',
      'historical.lease_bindings',
      'used_operation_id',
    ])
      expect(statement).toContain(bound);
    expect(statement).not.toMatch(
      /set_config\(|platform_recovery_pending_approval_history_current\(/iu,
    );
  },
);
it.each([mutationCandidates, approvalRequests])(
  'retains exact historical lease bindings for resumed candidates and their approval: %s',
  (table) => {
    const policy = getTableConfig(table).policies.find(
      (p) => p.name === 'platform_prepare_approval_continuation_history_read',
    );
    expect(policy?.for).toBe('select');
    expect(policy?.to).toEqual([controlOwnerRole]);
    const definition = platformRecoveryApprovalOwnerReadDefinitions(table).find((d) =>
      d.functionName.endsWith('_case_read'),
    );
    const statement = new PgDialect().sqlToQuery(definition?.predicate ?? policy!.using!).sql;
    expect(statement).toContain('historical.lease_bindings');
    expect(statement).not.toContain('original.predecessor_candidate_id is null');
    expect(statement).not.toContain('"mutation_candidate"."predecessor_candidate_id" is null');
  },
);

it.each([
  'missing',
  'duplicate',
  'altered-digest',
  'altered-cose',
  'foreign-actor',
  'foreign-session',
  'foreign-verification-input',
  'expired-at-admission',
  'issued-after-admission',
])('denies %s durable receiving proof without using a transient request field', async (variant) => {
  const f = fixture(),
    receiving = f.cases[1]!.receiving;
  if (variant === 'missing') f.setReceivingRows(0);
  if (variant === 'duplicate') f.setReceivingRows(2);
  if (variant === 'altered-digest') receiving.evidenceDigest = Buffer.alloc(32, 255);
  if (variant === 'altered-cose') receiving.cose = Buffer.from('invalid');
  if (variant === 'foreign-actor')
    f.cases[1]!.receiving = f.signReceiving(receiving.operationId, id(7777));
  if (variant === 'foreign-session') receiving.sessionId = id(7778);
  if (variant === 'foreign-verification-input') receiving.candidateDigest = Buffer.alloc(32, 8);
  if (variant === 'expired-at-admission')
    receiving.reservedAt = new Date(receiving.reservedAt.getTime() + 3000);
  if (variant === 'issued-after-admission')
    receiving.reservedAt = new Date(receiving.reservedAt.getTime() - 62001);
  await expect(f.execute()).rejects.toBeInstanceOf(PlatformRecoveryError);
});

it('uses exact original generic RESUME proof and immutable admission, never a fabricated consumed link', async () => {
  const f = fixture();
  await f.execute();
  const sql = (f.query.mock.calls as unknown as [string, unknown[]][]).find(([q]) =>
    q.includes('join control.mutation_evidence verification'),
  )![0];
  for (const bound of [
    'challenge.resource_id=original.predecessor_approval_id::text',
    'openpc.signing_canonical_json(original.resume_request)',
    'admitted.operation_id=verification.operation_id',
    "admitted.terminal_state='COMMITTED'",
    'admitted.webauthn_assertion_binding_digest=verification.webauthn_assertion_binding_digest',
    'admitted.created_at<=challenge.consumed_at',
  ])
    expect(sql).toContain(bound);
});

it.each([idempotencyRecords, mutationEvidence, outboxEvents, mfaChallenges])(
  'checks row eligibility before expensive receiving history: %s',
  (table) => {
    const p = getTableConfig(table).policies.find(
      (p) => p.name === 'platform_prepare_approval_resume_history_read',
    )!;
    const sql = new PgDialect().sqlToQuery(p.using!).sql;
    expect(sql.trim()).toMatch(/^case when/iu);
    expect(sql).not.toContain('control.platform_recovery_enrollment');
    expect(sql).toContain('to_jsonb(');
    expect(sql).toContain('openpc.platform_history_');
    expect(sql).toMatch(/else false end$/iu);
  },
);
it('does not inspect Root outbox rows through the Platform-case history branch', () => {
  const p = getTableConfig(outboxEvents).policies.find(
    (p) => p.name === 'platform_prepare_approval_continuation_history_read',
  )!;
  const sql = new PgDialect().sqlToQuery(p.using!).sql;
  expect(sql.trim()).toMatch(/^case when/iu);
  expect(sql.slice(0, sql.indexOf('then'))).toContain("'platform-recovery'");
  expect(sql.slice(0, sql.indexOf('then'))).toContain(
    "'openpc.identity.platform-recovery.activated.v1'",
  );
  expect(sql).toMatch(/else false end$/iu);
});

it.each([
  ['root_expiry_admin_outbox_source_read', 'platform_history_outbox_event_root_source_read'],
  [
    'root_expiry_admin_installation_receipt_read',
    'platform_history_outbox_event_root_installation_read',
  ],
])(
  'isolates the actual Root outbox policy %s with its complete receipt binding',
  (name, functionName) => {
    const policy = getTableConfig(outboxEvents).policies.find((p) => p.name === name)!;
    const predicate = new PgDialect().sqlToQuery(policy.using!).sql;
    expect(predicate).toContain(functionName);
    expect(predicate.slice(0, predicate.indexOf('then'))).toContain("'local-root-expiry-recovery'");
    expect(policy.to).toEqual([controlOwnerRole]);
    const definition = platformRecoveryApprovalOwnerReadDefinitions(outboxEvents).find(
      (d) => d.functionName === functionName,
    )!;
    expect(definition.body).toContain('receipt.evidence_cbor');
    expect(definition.body).toContain('receipt.evidence_digest');
    expect(definition.body).toContain('receipt.evidence_cose');
    expect(definition.body).toContain("'openpc.identity.local-root-expiry-recovery.completed.v1'");
  },
);

it.each([
  [
    'root_expiry_pending_effect_source_read',
    'platform_history_approval_request_pending_effect_read',
  ],
  [
    'platform_prepare_approval_continuation_history_read',
    'platform_history_approval_request_case_read',
  ],
])('isolates approval policy %s without weakening its row predicate', (name, functionName) => {
  const policy = getTableConfig(approvalRequests).policies.find((p) => p.name === name)!;
  const definition = platformRecoveryApprovalOwnerReadDefinitions(approvalRequests).find(
    (d) => d.functionName === functionName,
  )!;
  const dialect = new PgDialect();
  expect(policy.for).toBe('select');
  expect(policy.to).toEqual([controlOwnerRole]);
  expect(policy.withCheck).toBeUndefined();
  expect(dialect.sqlToQuery(policy.using!).sql).toBe(
    'openpc.' + functionName + '(to_jsonb("approval_request"))',
  );
  const original = dialect.sqlToQuery(definition.predicate);
  expect(original.params).toEqual([]);
  expect(original.sql).toContain('control.mutation_candidate');
  expect(original.sql).toContain('openpc.matches_participant(');
  expect(original.sql).toContain('openpc.matches_privacy(');
  const bound = original.sql
    .replaceAll('"control"."approval_request".', 'r.')
    .replaceAll('"approval_request".', 'r.');
  expect(definition.body).toContain('RETURN coalesce((' + bound + '),false);');
  expect(definition.body).not.toContain('TO openpc_control_runtime');
});

it.each(['unsupported', 'constructor', 'toString'])(
  'rejects unsupported approval policy %s',
  (name) => {
    expect(() =>
      approvalHistoryOwnerLeafPolicy(
        pgPolicy(name, { for: 'select', to: [controlOwnerRole], using: sql`true` }),
      ),
    ).toThrow('Invalid approval history leaf');
  },
);

it('rejects approval wrappers that change command, role or policy combination', () => {
  const name = 'root_expiry_pending_effect_source_read';
  for (const policy of [
    pgPolicy(name, { for: 'all', to: [controlOwnerRole], using: sql`true` }),
    pgPolicy(name, { for: 'select', to: ['public'], using: sql`true` }),
    pgPolicy(name, { for: 'select', to: [controlOwnerRole], using: sql`true`, as: 'restrictive' }),
    pgPolicy(name, {
      for: 'select',
      to: [controlOwnerRole],
      using: sql`true`,
      withCheck: sql`true`,
    }),
    pgPolicy(name, { for: 'select', to: [controlOwnerRole] }),
  ])
    expect(() => approvalHistoryOwnerLeafPolicy(policy)).toThrow('Invalid approval history leaf');
});

it('keeps native owner preambles fail closed and binds their exact row types', () => {
  const definitions = [
    approvalRequests,
    mfaChallenges,
    idempotencyRecords,
    mutationEvidence,
    outboxEvents,
    authorityEnvelopes,
    assignments,
    identityEnvelopeProposals,
    mutationCandidates,
  ].flatMap(platformRecoveryApprovalOwnerReadDefinitions);
  expect(definitions).toHaveLength(15);
  expect(new Set(definitions.map((d) => d.functionName)).size).toBe(15);
  for (const d of definitions) {
    expect(d.preamble).toContain('BEGIN RETURN false; END');
    expect(d.body).toContain('jsonb_populate_record(NULL::control.' + d.tableName + ',p_row)');
    expect(d.body).toContain('SET search_path=pg_catalog,control SET row_security=on');
    expect(d.body).toContain('TO openpc_control_owner;');
    expect(d.body).toContain(
      (d.tableName === 'approval_request' ? 'STABLE' : 'VOLATILE') + ' SECURITY INVOKER',
    );
    expect(d.body).toContain('to_jsonb(r) IS DISTINCT FROM p_row');
    expect(d.body.indexOf("IF p_row IS NULL OR jsonb_typeof(p_row)<>'object'")).toBeLessThan(
      d.body.indexOf('r:=jsonb_populate_record('),
    );
    expect(d.body).not.toContain('SECURITY DEFINER');
    expect(d.body).not.toContain('set_config(');
  }
});

it('isolates unused-handoff attempt history from surrounding RLS query plans', () => {
  const policy = getTableConfig(idempotencyRecords).policies.find(
    (p) => p.name === 'platform_recovery_uneffected_effect_read',
  )!;
  const predicate = new PgDialect().sqlToQuery(policy.using!).sql;
  expect(predicate.trim()).toMatch(/^case when/iu);
  expect(predicate).not.toContain('control.mutation_candidate');
  expect(predicate).not.toContain('control.platform_recovery_enrollment');
  const definition = platformRecoveryApprovalOwnerReadDefinitions(idempotencyRecords).find(
    (d) => d.functionName === 'platform_history_idempotency_record_uneffected_read',
  )!;
  expect(definition.body).toContain('control.mutation_candidate attempted');
  expect(definition.body).toContain('attempted.catalog_operation_id=r."catalog_operation_id"');
  expect(definition.body).toContain('attempted.idempotency_key=r."idempotency_key"');
  expect(definition.body).not.toContain('terminal_state');
});

it('rejects unrelated pending approvals before their full provenance predicate', () => {
  const definitions = platformRecoveryApprovalOwnerReadDefinitions(approvalRequests);
  const pending = definitions.find(
    (d) => d.functionName === 'platform_history_approval_request_pending_effect_read',
  )!;
  const other = definitions.find(
    (d) => d.functionName === 'platform_history_approval_request_case_read',
  )!;
  expect(pending.body).toContain("candidate_resource::text=administrator->>'envelopeId'");
  expect(pending.body).toContain('c.mutation_candidate_id=r.subject_id');
  expect(pending.body).toContain(
    "pending.state='WITHDRAWING' AND pending.row_version=1 AND pending.superseded_by IS NULL",
  );
  expect(pending.body.indexOf('to_jsonb(r) IS DISTINCT FROM p_row')).toBeLessThan(
    pending.body.indexOf('<<candidate_binding>>'),
  );
  expect(pending.body.indexOf('IF NOT binding_found THEN RETURN false; END IF;')).toBeLessThan(
    pending.body.indexOf('RETURN coalesce(('),
  );
  expect(other.body).not.toContain('binding_found');
});

it('defers activation receipt lookup while retaining the original creation receipt arm', () => {
  const policy = getTableConfig(idempotencyRecords).policies.find(
    (p) => p.name === 'platform_recovery_pending_expiry_effect_read',
  )!;
  const text = new PgDialect().sqlToQuery(policy.using!).sql;
  expect(text).toContain("partial_effect#>>'{effect,createOperationId}'");
  expect(text).toContain(
    'case when "control"."idempotency_record"."catalog_operation_id"=\'ID-OP-ENVELOPE-ACTIVATE\'',
  );
  expect(text).toContain('openpc.platform_recovery_pending_activation_receipt_current(');
  expect(text).toContain("partial_effect->>'envelopeId'");
  expect(text).not.toContain('control.mutation_candidate activation');
});
