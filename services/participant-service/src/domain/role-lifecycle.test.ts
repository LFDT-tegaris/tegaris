import { createHash, generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  encodeIdentityCredentialPayload,
  signIdentityCredentialCoseSign1Es256,
} from '@openpc/security-kernel';
import { canonicalAuthorizationJson } from '../../../identity-service/src/contracts/authorization.js';
import { readRoleProposal } from './role-lifecycle.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const participant = id(1),
  privacy = id(2),
  role = id(3),
  operation = id(4),
  approval = id(5),
  checker = id(6),
  credential = id(7);
const digest = (value: unknown) =>
  createHash('sha256').update(canonicalAuthorizationJson(value)).digest();
function fixture(mutation: 'CREATE' | 'ARCHIVE' = 'CREATE') {
  const definition = {
    id: role,
    participantId: participant,
    roleId: `urn:openpc:role:${role}`,
    displayName: 'Original role',
    actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
    state: 'ACTIVE' as const,
  };
  const document = mutation === 'CREATE' ? definition : { roleId: role, state: 'ARCHIVED' };
  const candidateDigest = 'sha256:' + digest(document).toString('hex');
  const effect = {
    ...definition,
    state: mutation === 'CREATE' ? 'ACTIVE' : 'ARCHIVED',
    revision: mutation === 'CREATE' ? '1' : '2',
    origin: 'GOVERNED',
  };
  const result = mutation === 'CREATE' ? effect : { effect, newEpoch: '9', revokedAssignments: 13 };
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' });
  const bytes = encodeIdentityCredentialPayload({
    participantId: `urn:openpc:participant:${participant}`,
    principalId: `urn:openpc:principal:${checker}`,
    authorityEpoch: '1',
    issuedAt: '2026-09-15T00:00:00.000000Z',
    expiresAt: '2026-09-15T00:05:00.000000Z',
  });
  const signature = signIdentityCredentialCoseSign1Es256(
    keys.privateKey.export({ type: 'pkcs8', format: 'der' }),
    publicKey,
    bytes,
  );
  const proposal = {
    catalog_operation_id: `ID-OP-ROLE-${mutation}`,
    expected_revision: mutation === 'CREATE' ? '0' : '1',
    state: 'CONSUMED',
    expires_at: new Date('2026-09-15T00:10:00Z'),
    candidate_document: document,
    consumed_operation_id: operation as string | null,
  };
  const proof = {
    operation_id: operation,
    result_payload: result as unknown,
    result_digest: digest(result),
    result_revision: effect.revision,
    approval_request_id: approval,
    checker_principal_id: checker,
    signer_credential_id: credential,
    public_key_spki_der: publicKey,
    public_key_digest: createHash('sha256').update(publicKey).digest(),
    evidence_cbor: bytes,
    evidence_digest: createHash('sha256').update(bytes).digest(),
    cose_sign1: signature,
    maker_binding_digest: Buffer.alloc(32, 1) as Buffer | null,
    evidence_maker_binding_digest: Buffer.alloc(32, 1) as Buffer | null,
    event_maker_binding_digest: Buffer.alloc(32, 1) as Buffer | null,
  };
  let proofCount = 1;
  const query = vi.fn(async (sql: string, _values?: unknown[]) => {
    if (sql.includes('select catalog_operation_id')) return { rowCount: 1, rows: [proposal] };
    if (sql.includes('select receipt.operation_id'))
      return { rowCount: proofCount, rows: Array.from({ length: proofCount }, () => proof) };
    throw new Error('Unexpected/latest-state read is forbidden in consumed history');
  });
  const client = { query } as unknown as PoolClient;
  return {
    proposal,
    proof,
    query,
    definition,
    effect,
    candidateDigest,
    client,
    setCount: (n: number) => {
      proofCount = n;
    },
    read: () => readRoleProposal(client, participant, privacy, candidateDigest, role),
  };
}
describe('original ROLE consumption readback (mocked SQL, real retained signature checks)', () => {
  it.each([
    'missing receipt',
    'unequal receipt',
    'both missing',
    'missing outbox',
    'malformed receipt',
  ])('denies original maker binding %s', async (failure) => {
    const f = fixture();
    if (failure === 'missing receipt') f.proof.maker_binding_digest = null;
    if (failure === 'unequal receipt') f.proof.maker_binding_digest = Buffer.alloc(32, 2);
    if (failure === 'both missing') {
      f.proof.evidence_maker_binding_digest = null;
      f.proof.event_maker_binding_digest = null;
    }
    if (failure === 'missing outbox') f.proof.event_maker_binding_digest = null;
    if (failure === 'malformed receipt') f.proof.maker_binding_digest = Buffer.alloc(31, 1);
    await expect(f.read()).rejects.toThrow();
  });
  it('keeps original committed CREATE ACTIVE without substituting later ARCHIVE/current role state', async () => {
    const f = fixture();
    const result = await f.read();
    expect(result.consumption).toEqual({ operationId: operation, effect: f.effect });
    expect(result.proposedRole).toEqual(f.definition);
    expect(f.query).toHaveBeenCalledTimes(2);
    expect(Object.isFrozen(result.consumption)).toBe(true);
    expect(Object.isFrozen(result.consumption?.effect.actionIntentIds)).toBe(true);
  });
  it('reads original ARCHIVE and discloses only role effect/operation under role READ', async () => {
    const f = fixture('ARCHIVE'),
      result = await f.read();
    expect(result.consumption).toEqual({ operationId: operation, effect: f.effect });
    expect(result.proposedRole.state).toBe('ARCHIVED');
    expect(Object.keys(result.consumption!).sort()).toEqual(['effect', 'operationId']);
    expect(JSON.stringify(result)).not.toContain('revokedAssignments');
    expect(JSON.stringify(result)).not.toContain('newEpoch');
    expect(JSON.stringify(result)).not.toContain(approval);
    expect(JSON.stringify(result)).not.toContain(checker);
  });
  it('preserves empty valid administrative capabilities', async () => {
    const f = fixture();
    f.definition.actionIntentIds.length = 0;
    f.proof.result_digest = digest(f.proof.result_payload);
    const candidateDigest = 'sha256:' + digest(f.proposal.candidate_document).toString('hex');
    expect(
      (await readRoleProposal(f.client, participant, privacy, candidateDigest, role)).consumption
        ?.effect.actionIntentIds,
    ).toEqual([]);
  });
  it('keeps unconsumed proposals metadata only, without asserting a terminal effect', async () => {
    const f = fixture();
    f.proposal.state = 'PROPOSED';
    f.proposal.consumed_operation_id = null;
    expect((await f.read()).consumption).toBeNull();
    expect(f.query).toHaveBeenCalledTimes(1);
  });
  it.each([0, 2])(
    'denies missing/ambiguous original committed association (%s rows)',
    async (count) => {
      const f = fixture();
      f.setCount(count);
      await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
    },
  );
  it.each(['APPROVED', 'EXPIRED', 'CANCELLED'])(
    'never promotes %s with a consumed operation',
    async (state) => {
      const f = fixture();
      f.proposal.state = state;
      await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
    },
  );
  it('denies CONSUMED without its original operation', async () => {
    const f = fixture();
    f.proposal.consumed_operation_id = null;
    await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
  });
  it('denies a substituted latest/approval operation ID', async () => {
    const f = fixture();
    f.proof.operation_id = approval;
    await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
  });
  it.each(['result_digest', 'public_key_digest', 'evidence_digest', 'cose_sign1'] as const)(
    'denies altered %s',
    async (field) => {
      const f = fixture();
      f.proof[field] = Buffer.from(f.proof[field]);
      f.proof[field][0] = f.proof[field][0]! ^ 1;
      await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
    },
  );
  it('denies a signature under an unrelated key even with its matching digest', async () => {
    const f = fixture(),
      other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    f.proof.public_key_spki_der = other.publicKey.export({ type: 'spki', format: 'der' });
    f.proof.public_key_digest = createHash('sha256').update(f.proof.public_key_spki_der).digest();
    await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
  });
  it.each([
    { participantId: id(8) },
    { id: id(8) },
    { state: 'ARCHIVED' },
    { revision: '0' },
    { origin: 'BOOTSTRAP' },
    { displayName: 'Substituted role' },
    { extra: 'private' },
  ])('denies incompatible CREATE committed payload %s', async (change) => {
    const f = fixture();
    f.proof.result_payload = { ...(f.proof.result_payload as object), ...change };
    f.proof.result_digest = digest(f.proof.result_payload);
    await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
  });
  it.each(['0', '1', '3', '-1', '01', 'not-a-revision'])(
    'denies ARCHIVE POST revision %s instead of its actual producer transition',
    async (revision) => {
      const f = fixture('ARCHIVE');
      f.effect.revision = revision;
      f.proof.result_revision = revision;
      f.proof.result_digest = digest(f.proof.result_payload);
      await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
    },
  );
  it('keeps migrated/bootstrap origin for an original governed ARCHIVE', async () => {
    const f = fixture('ARCHIVE');
    f.effect.origin = 'BOOTSTRAP';
    f.proof.result_digest = digest(f.proof.result_payload);
    expect((await f.read()).consumption?.effect.origin).toBe('BOOTSTRAP');
  });
  it('denies candidate-document drift despite an otherwise valid receipt', async () => {
    const f = fixture();
    f.proposal.candidate_document = { ...f.definition, displayName: 'Drift' };
    await expect(f.read()).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
  });
  it.each([id(8), 'not-an-id'])(
    'denies foreign/invalid original result resource %s',
    async (resource) => {
      const f = fixture();
      await expect(
        readRoleProposal(f.client, participant, privacy, f.candidateDigest, resource),
      ).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
    },
  );
  it('binds the exact original scoped tuple and distinct PRE/POST sources, no current signer/head predicate', async () => {
    const f = fixture('ARCHIVE');
    await f.read();
    const [sql, args] = f.query.mock.calls[1]!;
    expect(args).toEqual([
      participant,
      privacy,
      Buffer.from(f.candidateDigest.slice(7), 'hex'),
      role,
      'ID-OP-ROLE-ARCHIVE',
      '1',
      operation,
    ]);
    // Real SQL authorization/joins/cardinality still require the retained owner
    // gate; these assertions preserve the exact consumer invocation contract.
    expect(sql).toContain('receipt.expected_aggregate_version=candidate.expected_revision');
    expect(sql).toContain('evidence.aggregate_version=candidate.expected_revision');
    expect(sql).toContain("receipt.terminal_state='COMMITTED'");
    expect(sql).toContain('approval.subject_id=candidate.mutation_candidate_id');
    expect(sql).toContain('decision.evidence_cbor=evidence.evidence_cbor');
    expect(sql).toContain('event.cose_sign1=evidence.cose_sign1');
    expect(sql).not.toContain('clock_timestamp()');
    expect(sql).not.toContain("credential.state='ACTIVE'");
    expect(sql).not.toContain('control.authority_role');
    expect(sql).not.toContain('outbox_aggregate_head');
  });
});
