import { readFile } from 'node:fs/promises';
import { createHash, generateKeyPairSync } from 'node:crypto';

import type { Pool, PoolClient } from 'pg';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  encodeIdentityCredentialPayload,
  signIdentityCredentialCoseSign1Es256,
} from '@openpc/security-kernel';
import * as approvalFence from '../db/approval-authority-fence.js';
import * as authorityFence from '../db/authority-fence.js';
import * as stepUpSigner from '../db/identity-step-up-signer.js';
import * as storedEvidence from '../db/verified-step-up-evidence.js';

import { buildIdentityService, type IdentityAuthorizationAdapter } from '../app.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import {
  IdentityKernel,
  IdentityKernelError,
  PostgresIdentityRepository,
  type AuthenticatedIdentityActor,
} from './identity-kernel.js';
import { stepUpAuthorizationCandidate } from './step-up-authorization.js';
import { createVerifiedWebAuthnAssertion } from './trust-adapter.js';
import { createLocalIdentityRuntimeCryptoAdapter } from './identity-runtime-crypto.js';
import { createIdentityRuntimeAuthorizationAssertion } from './identity-runtime-authorization.js';

describe('authenticated session heartbeat coalescing', () => {
  const participantId = '018f0000-0000-7000-8000-000000000101';
  const sessionId = '018f0000-0000-7000-8000-000000000117';
  const principalId = '018f0000-0000-7000-8000-000000000111';
  const token = `${participantId}.${sessionId}`;
  const now = new Date('2026-10-16T10:00:00Z');

  function fixture(ageMs: number, invalid?: string, idleTimeoutMs = 30 * 60 * 1_000) {
    const current = {
      session_id: sessionId,
      participant_id: participantId,
      principal_id: principalId,
      context_mode: 'PARTICIPANT',
      privacy_domain_id: '018f0000-0000-7000-8000-000000000201',
      context_epoch: '1',
      state: 'ACTIVE',
      opaque_token_digest: createHash('sha256').update(token).digest(),
      authority_epoch: '2',
      participant_epoch: '3',
      delegation_epoch: '4',
      session_epoch: '5',
      refresh_family_id: '018f0000-0000-7000-8000-000000000118',
      issued_at: new Date(now.getTime() - 60_000),
      last_seen_at: new Date(now.getTime() - ageMs),
      idle_expires_at: new Date(now.getTime() - ageMs + idleTimeoutMs),
      absolute_expires_at: new Date(now.getTime() + 60 * 60 * 1_000),
      idle_timeout_ms: idleTimeoutMs,
      step_up_verified_at: null,
    };
    const authority = {
      participant_epoch: '3',
      participant_state: 'ACTIVE',
      principal_epoch: '2',
      principal_state: 'ACTIVE',
      privacy_state: 'ACTIVE',
      delegation_epoch: '4',
    };
    if (invalid === 'revoked') current.state = 'REVOKED';
    if (invalid === 'wrong token') current.opaque_token_digest = Buffer.alloc(32);
    if (invalid === 'idle expired') current.idle_expires_at = now;
    if (invalid === 'absolute expired') current.absolute_expires_at = now;
    if (invalid === 'near absolute expiry') {
      current.absolute_expires_at = new Date(now.getTime() + 100);
      current.idle_expires_at = current.absolute_expires_at;
    }
    if (invalid === 'participant epoch') authority.participant_epoch = '9';
    if (invalid === 'principal epoch') authority.principal_epoch = '9';
    if (invalid === 'delegation epoch') authority.delegation_epoch = '9';
    if (invalid === 'participant inactive') authority.participant_state = 'SUSPENDED';
    if (invalid === 'principal inactive') authority.principal_state = 'SUSPENDED';
    if (invalid === 'privacy inactive') authority.privacy_state = 'SUSPENDED';
    if (invalid === 'platform with privacy') current.context_mode = 'PLATFORM';
    const query = vi.fn(async (sql: string, values: unknown[] = []) => {
      if (sql.includes('select participant_id from control.participant')) {
        return { rowCount: 1, rows: [{ participant_id: participantId }] };
      }
      if (sql.includes('from control.session')) return { rowCount: 1, rows: [current] };
      if (sql.includes('from control.participant participant')) {
        return { rowCount: 1, rows: [authority] };
      }
      if (sql.includes('update control.session')) {
        return {
          rowCount: 1,
          rows: [{ ...current, last_seen_at: values[2], idle_expires_at: values[3] }],
        };
      }
      throw new Error('unexpected session query');
    });
    const client = { query } as unknown as PoolClient;
    const repository = new PostgresIdentityRepository({} as Pool, { now: () => now });
    const scoped = repository as unknown as {
      scopedTx: (
        participant: string,
        action: string,
        run: (client: PoolClient) => Promise<unknown>,
      ) => Promise<unknown>;
    };
    vi.spyOn(scoped, 'scopedTx').mockImplementation((_participant, _action, run) => run(client));
    return { repository, query, current };
  }

  it.each([0, 1, 999])(
    'returns the stored snapshot without a timestamp write at age %ims',
    async (age) => {
      const { repository, query, current } = fixture(age);
      const snapshot = await repository.sessionSnapshot(token);
      expect(snapshot).toMatchObject({
        lastSeenAt: current.last_seen_at,
        idleExpiresAt: current.idle_expires_at,
        absoluteExpiresAt: current.absolute_expires_at,
      });
      expect(query.mock.calls.map(([sql]) => sql)).toEqual([
        expect.stringContaining('select participant_id from control.participant'),
        expect.stringContaining('from control.session'),
        expect.stringContaining('from control.participant participant'),
      ]);
      expect(query.mock.calls[1]?.[0]).toContain('for update');
    },
  );

  it.each([-1, 1_000, 1_001])(
    'uses the ordinary refresh outside the window at age %ims',
    async (age) => {
      const { repository, query } = fixture(age);
      const snapshot = await repository.sessionSnapshot(token);
      expect(snapshot.lastSeenAt).toEqual(now);
      expect(snapshot.idleExpiresAt).toEqual(new Date(now.getTime() + 30 * 60 * 1_000));
      expect(
        query.mock.calls.filter(([sql]) => sql.includes('update control.session')),
      ).toHaveLength(1);
    },
  );

  it.each([499, 500])('bounds coalescing by the stored idle timeout at age %ims', async (age) => {
    const { repository, current } = fixture(age, undefined, 5_000);
    const snapshot = await repository.sessionSnapshot(token);
    expect(snapshot.lastSeenAt).toEqual(age < 500 ? current.last_seen_at : now);
    expect(snapshot.idleExpiresAt).toEqual(
      age < 500 ? current.idle_expires_at : new Date(now.getTime() + 5_000),
    );
  });

  it.each([0, 1_000])('preserves the absolute expiry at age %ims', async (age) => {
    const { repository, current } = fixture(age, 'near absolute expiry');
    const snapshot = await repository.sessionSnapshot(token);
    expect(snapshot.idleExpiresAt).toEqual(current.absolute_expires_at);
    expect(snapshot.absoluteExpiresAt).toEqual(current.absolute_expires_at);
  });

  it.each([
    'revoked',
    'wrong token',
    'idle expired',
    'absolute expired',
    'participant epoch',
    'principal epoch',
    'delegation epoch',
    'participant inactive',
    'principal inactive',
    'privacy inactive',
    'platform with privacy',
  ])('rejects a recently touched but invalid session: %s', async (invalid) => {
    const { repository, query } = fixture(1, invalid);
    await expect(repository.sessionSnapshot(token)).rejects.toMatchObject({ code: 'PC-AUTH-0003' });
    expect(query.mock.calls.every(([sql]) => !sql.includes('update control.session'))).toBe(true);
  });
});

describe('committed Identity step-up reconciliation composition', () => {
  afterEach(() => vi.restoreAllMocks());
  const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  it.each([
    'valid',
    'missing key',
    'foreign origin',
    'semantic digest',
    'CSRF',
    'missing approval',
    'authorization denied',
  ])('forwards only the validated HTTP key: %s', async (kind) => {
    // Public handler composition with external DB/authorization owners mocked.
    const semantic = `sha256:${'a'.repeat(64)}`;
    const issue = vi.fn().mockResolvedValue({ result: { credentialId: id(701) } });
    const verifyCsrf = vi.fn().mockResolvedValue(undefined);
    if (kind === 'CSRF') verifyCsrf.mockRejectedValue(new IdentityKernelError('PC-AUTH-0001'));
    const kernel = {
      sessionSnapshot: vi.fn().mockResolvedValue({ participantId: id(101), principalId: id(111) }),
      actionIntentSemanticDigest: vi.fn().mockResolvedValue(semantic),
      verifyCsrf,
      issueWorkloadFromIssuer: issue,
    } as unknown as IdentityKernel;
    const authorize = vi.fn().mockResolvedValue({
      allowed: true,
      evidenceKind: 'USER_WEBAUTHN',
      privacyDomainId: id(201),
      checkerPrincipalId: id(112),
      signerCredentialId: id(501),
      evidenceCbor: Buffer.from('original-checker'),
      evidenceDigest: Buffer.alloc(32, 1),
      coseSign1: Buffer.from('original-signature'),
    });
    const authorization = {
      propose: vi.fn().mockResolvedValue({ privacyDomainId: id(201) }),
      authorize,
    } as IdentityAuthorizationAdapter;
    if (kind === 'authorization denied') authorize.mockResolvedValue({ allowed: false });
    const stage = vi.fn().mockResolvedValue(id(601));
    const app = buildIdentityService(
      kernel,
      undefined,
      undefined,
      authorization,
      undefined,
      undefined,
      undefined,
      { stage },
    );
    try {
      const key = generateKeyPairSync('ed25519')
        .publicKey.export({ type: 'spki', format: 'der' })
        .toString('base64');
      const headers: Record<string, string> = {
        'cookie': `__Host-openpc_session=${id(101)}.${id(117)}`,
        'host': 'control.openpc.example',
        'origin':
          kind === 'foreign origin'
            ? 'https://foreign.openpc.example'
            : 'https://control.openpc.example',
        'x-csrf-token': 'fixture-csrf',
        'x-openpc-approval-request-id': id(601),
        'x-openpc-aggregate-version': '0',
        'openpc-action-intent-digest': semantic,
      };
      if (kind !== 'missing key') headers['idempotency-key'] = 'exact-original-business-key';
      if (kind === 'missing approval') delete headers['x-openpc-approval-request-id'];
      if (kind === 'semantic digest')
        headers['openpc-action-intent-digest'] = `sha256:${'b'.repeat(64)}`;
      const reply = await app.inject({
        method: 'POST',
        url: '/v1/identity/workloads',
        headers,
        payload: {
          credentialId: id(701),
          principalId: id(111),
          workloadId: `urn:openpc:workload:${id(702)}`,
          publicKeySpkiDer: key,
        },
      });
      if (kind === 'valid') {
        expect(reply.statusCode).toBe(201);
        expect(authorize).toHaveBeenCalledOnce();
        expect(authorize.mock.calls[0]?.[0].idempotencyKey).toBe(headers['idempotency-key']);
        expect(stage.mock.calls[0]?.[0].idempotencyKey).toBe(headers['idempotency-key']);
        expect(issue.mock.calls[0]?.[0].mutationAuthorization.idempotencyKey).toBe(
          headers['idempotency-key'],
        );
      } else {
        expect(reply.statusCode).toBe(
          kind === 'semantic digest' || kind === 'authorization denied'
            ? 409
            : kind === 'CSRF'
              ? 401
              : 403,
        );
        expect(issue).not.toHaveBeenCalled();
        if (kind === 'authorization denied') expect(authorize).toHaveBeenCalledOnce();
        else expect(authorize).not.toHaveBeenCalled();
        // The existing proposal stage precedes approval/authorization admission.
        // These mocks prove no issuer dispatch, not durable staging behavior.
        if (kind === 'missing approval' || kind === 'authorization denied')
          expect(stage).toHaveBeenCalledOnce();
        else expect(stage).not.toHaveBeenCalled();
      }
    } finally {
      await app.close();
    }
  });
  async function fixture(catalogOperationId = 'ID-OP-WORKLOAD-ISSUE') {
    // Real historical ES256 verification; SQL/authority owners are mocked.
    // This proves orchestration and forbidden calls, not installed grants or age.
    const now = new Date('2026-10-06T10:00:00Z');
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const key = keys.publicKey.export({ type: 'spki', format: 'der' });
    const evidence = encodeIdentityCredentialPayload({
      participantId: `urn:openpc:participant:${id(101)}`,
      principalId: `urn:openpc:principal:${id(111)}`,
      authorityEpoch: '1',
      issuedAt: '2026-10-06T09:50:00.000000Z',
      expiresAt: '2026-10-06T09:55:00.000000Z',
    });
    const cose = signIdentityCredentialCoseSign1Es256(
      keys.privateKey.export({ type: 'pkcs8', format: 'der' }),
      key,
      evidence,
    );
    const request = { resource: id(701) };
    const result = { credentialId: id(701) };
    const proofCbor = Buffer.from('original checker approval');
    const proofCose = Buffer.from('original checker signature');
    const assertion = Buffer.alloc(32, 7);
    const actor: AuthenticatedIdentityActor = {
      participantId: id(101),
      principalId: id(111),
      sessionToken: `${id(101)}.${id(117)}`,
      platform: false,
      mutationAuthorization: {
        authorized: true,
        idempotencyKey: 'exact-original-business-key',
        candidateDigest: canonicalAuthorizationDigest(request),
        privacyDomainId: id(201),
        approvalRequestId: id(601),
        checkerPrincipalId: id(112),
        aggregateVersion: '0',
        evidenceKind: 'USER_WEBAUTHN',
        signerCredentialId: id(501),
        evidenceCbor: proofCbor,
        evidenceDigest: createHash('sha256').update(proofCbor).digest(),
        coseSign1: proofCose,
        webauthnAssertionBindingDigest: assertion,
      },
    };
    const original: stepUpSigner.CommittedIdentityStepUp = {
      operationId: id(801),
      result,
      currentAssurance: {
        sourceId: id(902),
        verifiedAt: now,
        credentialId: id(503),
        credentialEpoch: '2',
      },
      resultDigest: canonicalAuthorizationDigestBytes(result),
      resultAggregateVersion: '1',
      expectedAggregateVersion: '0',
      mfaChallengeId: id(901),
      assertionBindingDigest: assertion,
      credentialId: id(502),
      credentialPublicKey: key,
      credentialPublicKeyDigest: createHash('sha256').update(key).digest(),
      verificationEvidenceCbor: evidence,
      verificationEvidenceDigest: createHash('sha256').update(evidence).digest(),
      verificationCoseSign1: cose,
      verificationCandidateDigest: Buffer.alloc(32, 8),
      verificationOccurredAt: new Date('2026-10-06T09:50:01Z'),
      verificationSessionId: id(117),
      boundParticipantEpoch: '1',
      boundPrincipalEpoch: '1',
      boundAuthorityEnvelopeId: id(401),
      boundEnvelopeEpoch: '1',
      boundAssignmentId: id(301),
    };
    const events: string[] = [];
    const query = vi.fn<
      (
        sql: string,
        values?: readonly unknown[],
      ) => Promise<{ rowCount: number; rows: Record<string, unknown>[] }>
    >(async (sql) => {
      if (/^\s*(?:insert|update|delete)\b/iu.test(sql)) throw new Error('business write reached');
      if (sql.includes('set_request_context')) return { rowCount: 1, rows: [] };
      if (sql.includes('from control.action_intent'))
        return {
          rowCount: 1,
          rows: [
            {
              idempotency_required: true,
              operation_class: 'UPDATE',
              resource_type: 'WORKLOAD_CREDENTIAL',
              semantic_digest: Buffer.alloc(32, 1),
            },
          ],
        };
      if (sql.includes('with recursive authority_chain'))
        return {
          rowCount: 1,
          rows: [
            {
              assignment_id: id(301),
              assignment_row_version: '1',
              authority_envelope_id: id(401),
              envelope_epoch: '1',
              participant_epoch: '1',
              principal_epoch: '1',
              delegation_epoch: '1',
            },
          ],
        };
      if (sql.includes('select ad.cose_sign1'))
        return {
          rowCount: 1,
          rows: [
            {
              evidence_cbor: proofCbor,
              cose_sign1: proofCose,
              public_key_spki_der: key,
              public_key_digest: createHash('sha256').update(key).digest(),
            },
          ],
        };
      throw new Error('unexpected live admission query');
    });
    const client = { query } as unknown as PoolClient;
    const runtimeKeys = generateKeyPairSync('ed25519');
    const runtimePublicKey = runtimeKeys.publicKey.export({ type: 'spki', format: 'der' });
    const runtime = createLocalIdentityRuntimeCryptoAdapter({
      activePrivateKeyPkcs8Der: runtimeKeys.privateKey.export({ type: 'pkcs8', format: 'der' }),
      activePublicKeySpkiDer: runtimePublicKey,
      trustedPublicKeysSpkiDer: [runtimePublicKey],
    });
    const repository = new PostgresIdentityRepository({} as Pool, { now: () => now }, runtime);
    const internals = repository as unknown as {
      scopedTx: (
        p: string,
        a: string,
        run: (c: PoolClient, operationId: string) => Promise<unknown>,
      ) => Promise<unknown>;
      activeSession: (...args: unknown[]) => Promise<Record<string, unknown>>;
      assertPinnedStepUpCurrent: (...args: unknown[]) => Promise<void>;
      currentAggregateVersion: (...args: unknown[]) => Promise<string>;
      beginMutationIdempotency: (...args: unknown[]) => Promise<unknown>;
      committedMutation: (...args: unknown[]) => Promise<unknown>;
      admittedMutation: (
        actor: AuthenticatedIdentityActor,
        action: string,
        catalog: string,
        type: string,
        resource: string,
        request: unknown,
        effect: () => Promise<unknown>,
        dependencies?: undefined,
        assertion?: undefined,
        preparation?: () => Promise<unknown>,
      ) => Promise<unknown>;
    };
    vi.spyOn(internals, 'scopedTx').mockImplementation((_p, _a, run) => run(client, id(802)));
    vi.spyOn(internals, 'activeSession').mockResolvedValue({
      participant_id: id(101),
      principal_id: id(111),
      session_id: id(117),
      context_mode: 'PARTICIPANT',
      privacy_domain_id: id(201),
      session_epoch: '1',
      participant_epoch: '1',
      authority_epoch: '1',
      step_up_verified_at: now,
      step_up_mfa_challenge_id: id(902),
    });
    const currentSource = vi
      .spyOn(internals, 'assertPinnedStepUpCurrent')
      .mockResolvedValue(undefined);
    const aggregate = vi
      .spyOn(internals, 'currentAggregateVersion')
      .mockImplementation(async () => {
        events.push('aggregate');
        return '1';
      });
    const begin = vi
      .spyOn(internals, 'beginMutationIdempotency')
      .mockRejectedValue(new Error('new idempotency admission reached'));
    const committed = vi.spyOn(internals, 'committedMutation').mockImplementation(async () => {
      events.push('return');
      return { result, operation: { operationId: original.operationId } };
    });
    const fence = vi.spyOn(authorityFence, 'fenceBoundAuthorities').mockImplementation(async () => {
      events.push('authority fence');
      return {};
    });
    const approval = vi
      .spyOn(approvalFence, 'approvalAuthorityDependencies')
      .mockResolvedValue({ authorities: [], rows: {} });
    const signer = vi
      .spyOn(stepUpSigner, 'identityStepUpSigner')
      .mockResolvedValue(original.credentialId);
    const classified = vi
      .spyOn(stepUpSigner, 'selectCommittedIdentityStepUp')
      .mockImplementation(async (_c, _input, lock) => {
        events.push(lock ? 'locked original' : 'classify');
        return original;
      });
    vi.spyOn(storedEvidence, 'verifyStoredStepUpEvidence').mockResolvedValue(true);
    const effect = vi.fn(async () => ({ newCredential: true }));
    const preparation = vi.fn(async () => ({ issuerDispatch: true }));
    const run = () =>
      internals.admittedMutation(
        actor,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        catalogOperationId,
        'workload-credential',
        id(701),
        request,
        effect,
        undefined,
        undefined,
        catalogOperationId === 'ID-OP-WORKLOAD-ROTATE' ? preparation : undefined,
      );
    return {
      run,
      original,
      result,
      actor,
      query,
      events,
      currentSource,
      aggregate,
      begin,
      committed,
      fence,
      approval,
      signer,
      classified,
      effect,
      preparation,
      runtime,
    };
  }
  it.each(['ID-OP-WORKLOAD-ISSUE', 'ID-OP-WORKLOAD-ROTATE'])(
    'returns original %s before any new effect or preparation',
    async (catalog) => {
      const f = await fixture(catalog);
      await expect(f.run()).resolves.toEqual({
        result: f.result,
        operation: { operationId: f.original.operationId },
      });
      expect(f.begin).not.toHaveBeenCalled();
      expect(f.effect).not.toHaveBeenCalled();
      expect(f.preparation).not.toHaveBeenCalled();
      expect(f.currentSource).toHaveBeenCalledOnce();
      expect(f.approval).toHaveBeenCalledTimes(2);
      expect(f.signer).toHaveBeenCalledTimes(2);
      expect(f.signer.mock.calls[0]?.[1].committedHistory?.operationId).toBe(
        f.original.operationId,
      );
      expect(f.fence.mock.calls[0]?.[3]?.credential).toEqual(
        expect.arrayContaining([
          { id: id(501) },
          { id: f.original.credentialId },
          { id: f.original.currentAssurance.credentialId },
        ]),
      );
      expect(f.events.indexOf('locked original')).toBeGreaterThan(
        f.events.indexOf('authority fence'),
      );
      expect(f.events.indexOf('aggregate')).toBeGreaterThan(f.events.indexOf('locked original'));
    },
  );
  it.each(['source', 'timestamp', 'credential', 'epoch'])(
    'denies a changed current C2 %s under the original fence',
    async (kind) => {
      const f = await fixture();
      const changed = { ...f.original.currentAssurance };
      if (kind === 'source') changed.sourceId = id(903);
      if (kind === 'timestamp') changed.verifiedAt = new Date(changed.verifiedAt.getTime() + 1);
      if (kind === 'credential') changed.credentialId = id(504);
      if (kind === 'epoch') changed.credentialEpoch = '3';
      f.classified
        .mockResolvedValueOnce(f.original)
        .mockResolvedValueOnce({ ...f.original, currentAssurance: changed });
      await expect(f.run()).rejects.toThrow('PC-AUTH-0005');
      expect(f.fence).toHaveBeenCalledOnce();
      expect(f.classified).toHaveBeenCalledTimes(2);
      expect(f.classified.mock.calls.every((call) => call[2] !== true)).toBe(true);
      expect(f.aggregate).not.toHaveBeenCalled();
      expect(f.begin).not.toHaveBeenCalled();
      expect(f.effect).not.toHaveBeenCalled();
      expect(f.preparation).not.toHaveBeenCalled();
      expect(f.committed).not.toHaveBeenCalled();
    },
  );
  it('uses the actual SELECT-only original commit return helper', async () => {
    const f = await fixture();
    const created = new Date('2026-10-06T09:50:01Z');
    const updated = new Date('2026-10-06T09:50:02Z');
    f.committed.mockRestore();
    const admissionQuery = f.query.getMockImplementation()!;
    f.query.mockImplementation(async (sql: string) => {
      if (sql.includes('select record.created_at'))
        return { rowCount: 1, rows: [{ created_at: created, updated_at: updated, revision: '1' }] };
      return admissionQuery(sql);
    });
    await expect(f.run()).resolves.toEqual({
      result: f.result,
      operation: {
        operationId: f.original.operationId,
        resourceRef: `urn:openpc:resource:${id(701)}`,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        intentDigest: `sha256:${Buffer.alloc(32, 1).toString('hex')}`,
        idempotencyKey: 'exact-original-business-key',
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        createdAt: '2026-10-06T09:50:01.000000Z',
        updatedAt: '2026-10-06T09:50:02.000000Z',
        revision: '1',
      },
    });
    const query = f.query.mock.calls.find((call) => call[0].includes('select record.created_at'));
    expect(query?.[1]).toEqual([id(101), f.original.operationId]);
    expect(
      f.query.mock.calls.every((call) => !/^\s*(?:insert|update|delete)\b/iu.test(call[0])),
    ).toBe(true);
    expect(f.begin).not.toHaveBeenCalled();
    expect(f.effect).not.toHaveBeenCalled();
    expect(f.preparation).not.toHaveBeenCalled();
  });
  it('hands a noncommitted consumed record to the real live owner, which denies before issuer preparation', async () => {
    // Composition only: no installed storage contradiction or SQL join behavior
    // is inferred. The actual existing read-only preparation owner denies it.
    const f = await fixture('ID-OP-WORKLOAD-ROTATE');
    f.classified.mockResolvedValue(undefined);
    f.begin.mockRestore();
    const admissionQuery = f.query.getMockImplementation()!;
    f.query.mockImplementation(async (sql: string) => {
      if (sql.includes('select operation_id,input_digest'))
        return {
          rowCount: 1,
          rows: [
            {
              operation_id: f.original.operationId,
              input_digest: Buffer.from(
                f.actor.mutationAuthorization!.candidateDigest.slice(7),
                'hex',
              ),
              webauthn_assertion_binding_digest: f.original.assertionBindingDigest,
              expected_aggregate_version: '0',
              result_aggregate_version: null,
              result_payload: null,
              terminal_state: null,
            },
          ],
        };
      return admissionQuery(sql);
    });
    await expect(f.run()).rejects.toThrow('PC-IDENTITY-1009');
    expect(f.aggregate).not.toHaveBeenCalled();
    expect(f.effect).not.toHaveBeenCalled();
    expect(f.preparation).not.toHaveBeenCalled();
    expect(f.committed).not.toHaveBeenCalled();
    expect(
      f.query.mock.calls.every((call) => !/^\s*(?:insert|update|delete)\b/iu.test(call[0])),
    ).toBe(true);
  });
  it.each(['valid', 'actor', 'audience', 'before issuance', 'at expiry', 'untrusted signature'])(
    'authenticates the real historical runtime payload: %s',
    async (kind) => {
      const f = await fixture();
      const issued = new Date('2026-10-06T09:50:00Z');
      const context = {
        participantId: id(101),
        principalId: kind === 'actor' ? id(119) : id(111),
        sessionId: id(117),
        sessionEpoch: '1',
        sessionIssuedAt: new Date(issued.getTime() - 60000),
        sessionIdleExpiresAt: new Date(issued.getTime() + 600000),
        sessionAbsoluteExpiresAt: new Date(issued.getTime() + 3600000),
        participantEpoch: '1',
        principalEpoch: '1',
        assignmentId: id(301),
        assignmentRowVersion: '1',
        authorityEnvelopeId: id(401),
        authorityEpoch: '1',
        delegationEpoch: '1',
        actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
        resourceId: kind === 'audience' ? id(118) : id(117),
        candidateDigest: `sha256:${f.original.verificationCandidateDigest.toString('hex')}`,
        sessionToken: `${id(101)}.${id(117)}`,
      };
      const evidence = createIdentityRuntimeAuthorizationAssertion(
        'historic-verification',
        context,
        issued,
      );
      const signed = await f.runtime.signCanonicalAssertion(evidence);
      let signature = signed.coseSign1;
      if (kind === 'untrusted signature') {
        signature = Buffer.from(signature);
        signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
      }
      f.classified.mockResolvedValue({
        ...f.original,
        verificationEvidenceCbor: evidence,
        verificationEvidenceDigest: createHash('sha256').update(evidence).digest(),
        verificationCoseSign1: signature,
        verificationOccurredAt: new Date(
          issued.getTime() +
            (kind === 'before issuance' ? -6000 : kind === 'at expiry' ? 60000 : 500),
        ),
      });
      if (kind === 'valid')
        await expect(f.run()).resolves.toEqual({
          result: f.result,
          operation: { operationId: f.original.operationId },
        });
      else {
        await expect(f.run()).rejects.toThrow('PC-IDENTITY-1005');
        expect(f.committed).not.toHaveBeenCalled();
      }
      expect(f.begin).not.toHaveBeenCalled();
      expect(f.effect).not.toHaveBeenCalled();
      expect(f.preparation).not.toHaveBeenCalled();
    },
  );
  it.each([
    'empty key',
    'authority',
    'current source',
    'later revision',
    'changed original epoch',
    'changed result',
    'corrupt signature',
    'missing locked original',
    'changed locked operation',
  ])('denies %s without a new business admission', async (kind) => {
    const f = await fixture();
    let expected = 'PC-IDENTITY-1005';
    if (kind === 'empty key') {
      Object.assign(f.actor.mutationAuthorization!, { idempotencyKey: '' });
      expected = 'PC-IDENTITY-1009';
    }
    if (kind === 'authority') {
      f.fence.mockRejectedValue(new Error('current authority denied'));
      expected = 'current authority denied';
    }
    if (kind === 'current source') {
      f.currentSource.mockRejectedValue(new IdentityKernelError('PC-AUTH-0005'));
      expected = 'PC-AUTH-0005';
    }
    if (kind === 'later revision') {
      f.aggregate.mockResolvedValue('2');
      expected = 'PC-IDENTITY-1001';
    }
    if (kind === 'changed original epoch')
      f.classified.mockResolvedValue({ ...f.original, boundParticipantEpoch: '0' });
    if (kind === 'changed result')
      f.classified.mockResolvedValue({ ...f.original, resultDigest: Buffer.alloc(32, 9) });
    if (kind === 'corrupt signature') {
      const corrupted = Buffer.from(f.original.verificationCoseSign1);
      corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1;
      f.classified.mockResolvedValue({ ...f.original, verificationCoseSign1: corrupted });
    }
    if (kind === 'missing locked original') {
      f.classified
        .mockResolvedValueOnce(f.original)
        .mockResolvedValueOnce(f.original)
        .mockResolvedValueOnce(undefined);
      expected = 'PC-IDENTITY-1009';
    }
    if (kind === 'changed locked operation') {
      f.classified
        .mockResolvedValueOnce(f.original)
        .mockResolvedValueOnce(f.original)
        .mockResolvedValueOnce({ ...f.original, operationId: id(899) });
      expected = 'PC-IDENTITY-1009';
    }
    await expect(f.run()).rejects.toThrow(expected);
    expect(f.begin).not.toHaveBeenCalled();
    expect(f.effect).not.toHaveBeenCalled();
    expect(f.preparation).not.toHaveBeenCalled();
    expect(f.committed).not.toHaveBeenCalled();
  });
});

describe('authoritative identity boundary', () => {
  it.each([
    { source: null, ageMs: 299_999, rows: [], accepted: true },
    { source: null, ageMs: 300_000, rows: [], accepted: false },
    { source: 'pinned-source', ageMs: 480_000, rows: [{ fresh: true }], accepted: true },
    { source: 'invalid-source', ageMs: 1_000, rows: [{ fresh: null }], accepted: false },
    { source: 'expired-source', ageMs: 1_000, rows: [{ fresh: false }], accepted: false },
    { source: 'missing-source', ageMs: 1_000, rows: [], accepted: false },
    {
      source: 'ambiguous-source',
      ageMs: 1_000,
      rows: [{ fresh: true }, { fresh: true }],
      accepted: false,
    },
  ])('uses authoritative freshness for $source without a legacy fallback', async (input) => {
    // Composition only: SQL supplies the source decision; these mocks do not
    // establish an installed role, provenance, or a fifty-minute lifetime.
    const participantId = '018f1e2d-3c4b-7a69-8abc-3123456789ab';
    const sessionId = '018f1e2d-3c4b-7a69-8abc-2123456789ab';
    const principalId = '018f1e2d-3c4b-7a69-8abc-1123456789ab';
    const now = new Date('2026-10-06T00:00:00Z');
    const query = vi.fn().mockResolvedValue({ rowCount: input.rows.length, rows: input.rows });
    const client = { query } as unknown as PoolClient;
    const repository = new PostgresIdentityRepository({} as Pool, { now: () => now });
    const internals = repository as unknown as {
      scopedTx: (
        participant: string,
        action: string,
        run: (client: PoolClient) => Promise<void>,
      ) => Promise<void>;
      activeSession: (...args: unknown[]) => Promise<Record<string, unknown>>;
    };
    vi.spyOn(internals, 'scopedTx').mockImplementation((_participant, _action, run) => run(client));
    vi.spyOn(internals, 'activeSession').mockResolvedValue({
      participant_id: participantId,
      principal_id: principalId,
      session_id: sessionId,
      step_up_verified_at: new Date(now.getTime() - input.ageMs),
      step_up_mfa_challenge_id: input.source,
    });
    const result = repository.requireFreshStepUp(`${participantId}.${sessionId}`);
    if (input.accepted) await expect(result).resolves.toBeUndefined();
    else await expect(result).rejects.toThrow('PC-AUTH-0005');
    if (input.source === null) expect(query).not.toHaveBeenCalled();
    else expect(query.mock.calls[0]?.[1]).toEqual([participantId, sessionId, principalId]);
  });

  it('projects every trusted WebAuthn binding into one canonical authorization candidate', () => {
    const assertionInput = {
      credentialId: '018f1e2d-3c4b-7a69-8abc-0123456789ab',
      credentialPublicKeyDigest: `sha256:${'11'.repeat(32)}`,
      principalId: '018f1e2d-3c4b-7a69-8abc-1123456789ab',
      sessionId: '018f1e2d-3c4b-7a69-8abc-2123456789ab',
      actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
      resourceDigest: `sha256:${'22'.repeat(32)}`,
      challengeDigest: `sha256:${'33'.repeat(32)}`,
      rpIdHash: `sha256:${'44'.repeat(32)}`,
      origin: 'https://control.openpc.example',
      authenticatorDataDigest: `sha256:${'55'.repeat(32)}`,
      clientDataJsonDigest: `sha256:${'66'.repeat(32)}`,
      signatureDigest: `sha256:${'77'.repeat(32)}`,
      signCount: '1',
      verifiedAt: '2026-09-10T00:00:00.000Z',
    } as const;
    const input = {
      sessionToken: '018f1e2d-3c4b-7a69-8abc-3123456789ab.018f1e2d-3c4b-7a69-8abc-2123456789ab',
      actionIntentId: assertionInput.actionIntentId,
      resourceDigest: assertionInput.resourceDigest,
      challenge: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      rpIdHash: assertionInput.rpIdHash,
      verifiedAssertion: createVerifiedWebAuthnAssertion(assertionInput),
    };
    const candidate = stepUpAuthorizationCandidate(input);
    const baseline = canonicalAuthorizationDigest(candidate);
    expect(Reflect.ownKeys(candidate)).toEqual([
      'sessionToken',
      'actionIntentId',
      'resourceDigest',
      'challenge',
      'rpIdHash',
      'verifiedAssertionDigest',
    ]);
    const resourceId = '018f1e2d-3c4b-7a69-8abc-4123456789ab';
    const bound = stepUpAuthorizationCandidate({ ...input, resourceId });
    expect(bound.resourceId).toBe(resourceId);
    expect(canonicalAuthorizationDigest(bound)).not.toBe(baseline);
    expect(
      canonicalAuthorizationDigest(
        stepUpAuthorizationCandidate({
          ...input,
          resourceId: '018f1e2d-3c4b-7a69-8abc-5123456789ab',
        }),
      ),
    ).not.toBe(canonicalAuthorizationDigest(bound));
    expect(stepUpAuthorizationCandidate({ ...input, resourceId: undefined })).toEqual(candidate);

    const mutations = [
      { ...input, sessionToken: `${input.sessionToken}x` },
      { ...input, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
      { ...input, resourceDigest: `sha256:${'23'.repeat(32)}` },
      { ...input, challenge: `${input.challenge}A` },
      { ...input, rpIdHash: `sha256:${'45'.repeat(32)}` },
      {
        ...input,
        verifiedAssertion: createVerifiedWebAuthnAssertion({ ...assertionInput, signCount: '2' }),
      },
    ];
    for (const mutation of mutations) {
      expect(canonicalAuthorizationDigest(stepUpAuthorizationCandidate(mutation))).not.toBe(
        baseline,
      );
    }
    expect(() =>
      stepUpAuthorizationCandidate({
        ...input,
        verifiedAssertion: { ...input.verifiedAssertion },
      }),
    ).toThrow('untrusted WebAuthn assertion binding');
  });

  it('fails closed when no PostgreSQL repository is wired', () => {
    const kernel = new IdentityKernel();
    expect(() =>
      kernel.beginOidc({
        issuer: 'https://issuer.openpc.example',
        clientId: 'openpc-control',
        redirectUri: 'https://control.openpc.example/callback',
      }),
    ).toThrow(
      expect.objectContaining({ code: 'PC-IDENTITY-1004' } satisfies Partial<IdentityKernelError>),
    );
  });

  it('does not accept caller-supplied OIDC state, nonce, or PKCE verifier', async () => {
    const kernel = {
      beginOidc: async () => ({
        authorization: {
          transactionId: '018f1e2d-3c4b-7a69-8abc-0123456789ab',
          state: 'server-state-server-state-server-state',
          nonce: 'server-nonce-server-nonce-server-nonce',
          codeChallenge: 'server-generated-code-challenge-which-is-long-enough',
          issuer: 'https://issuer.openpc.example',
          clientId: 'openpc-control',
          redirectUri: 'https://control.openpc.example/callback',
        },
        custody: {
          browserSession: 'server-browser-session-custody',
          codeVerifier: 'server-code-verifier-custody',
        },
      }),
    } as unknown as IdentityKernel;
    const app = buildIdentityService(kernel, undefined, {
      issuer: 'https://issuer.openpc.example',
      clientId: 'openpc-control',
      redirectUri: 'https://control.openpc.example/callback',
    });

    const rejected = await app.inject({
      method: 'POST',
      url: '/v1/identity/oidc/begin',
      payload: { state: 'caller', nonce: 'caller', codeVerifier: 'caller' },
    });
    expect(rejected.statusCode).toBe(401);

    const accepted = await app.inject({
      method: 'POST',
      url: '/v1/identity/oidc/begin',
      payload: {},
    });
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json()).toMatchObject({ state: 'server-state-server-state-server-state' });
    expect(accepted.headers['set-cookie']).toContain('__Host-openpc_oidc=');
    expect(accepted.body).not.toContain('codeVerifier');
    expect(accepted.body).not.toContain('browserSession');
    await app.close();
  });

  it('contains no process-local runtime maps, preserves absolute expiry, and delegates transaction security', async () => {
    const source = await readFile(new URL('./identity-kernel.ts', import.meta.url), 'utf8');
    const transactionSource = await readFile(
      new URL('../db/scoped-transaction.ts', import.meta.url),
      'utf8',
    );
    expect(source).not.toContain('new Map<');
    expect(source).toContain('current.issued_at');
    expect(source).toContain('current.absolute_expires_at');
    const snapshotSource = source.slice(
      source.indexOf('async sessionSnapshot('),
      source.indexOf('async selectParticipantContext('),
    );
    expect(snapshotSource).toContain(
      'set last_seen_at=$3,idle_expires_at=$4,updated_at=clock_timestamp()',
    );
    expect(snapshotSource).not.toContain('row_version=row_version+1');
    expect(source).toContain("from '../db/scoped-transaction.js'");
    expect(source).toContain('return await runScopedTransaction(');
    expect(transactionSource).toContain('discard all');
    expect(transactionSource).toContain('set local row_security=on');
    expect(transactionSource).toContain("current_setting('openpc.operation_id',true)");
    expect(transactionSource).toContain('r.rolbypassrls bypass,r.rolsuper superuser');
    expect(transactionSource).toContain("actual.context_scope !== 'TRANSACTION_LOCAL'");
  });

  it('verifies the frozen ES256 Sig_structure vector and rejects mutation', () => {
    const kernel = new IdentityKernel();
    const publicKey =
      '3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';
    const message =
      '846a5369676e6174757265315867a5012603776170706c69636174696f6e2f6f70656e70632b63626f720458205cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd31903e91957e51903ea781d6f70656e70633a6964656e746974792d63726564656e7469616c3a763140590108a901781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631021957e50365312e302e300458202bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b111105783b75726e3a6f70656e70633a7061727469636970616e743a30313866316532642d336334622d376136392d386162632d30313233343536373839616206783975726e3a6f70656e70633a7072696e636970616c3a30313866316532642d336334622d376136392d386162632d31313233343536373839616207613708781b323032362d30382d32345430303a30303a30302e3030303030305a09781b323032362d30382d32345430303a30353a30302e3030303030305a';
    const signature =
      'c0283047c7739a45f0600ea88a379d7d0f20b76da383eb11173620b6c9befe4e3969529b1dba1b493fc93bf204a437a92f71e8b17447d7631a4663290eef19bf';
    expect(kernel.verifyFrozenEs256Vector(publicKey, message, signature)).toBe(true);
    expect(kernel.verifyFrozenEs256Vector(publicKey, message, `${signature.slice(0, -2)}00`)).toBe(
      false,
    );
  });
});
