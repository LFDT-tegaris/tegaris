import type { Pool, PoolClient } from 'pg';
import { cp, writeFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { expect } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { prepareInitialEnvelopeActivation } from '../../../services/identity-service/src/db/identity-envelope-activation-prepare.js';
import {
  claimInitialEnvelopeActivationDispatch,
  readInitialEnvelopeActivation,
  recordInitialEnvelopeActivationObservation,
} from '../../../services/identity-service/src/db/identity-envelope-activation-store.js';
import type { contractAdministrationFixture } from './contract-administration-fixture.js';
import type { envelopeActivationSigningFixture } from './envelope-activation-signing-fixture.js';
import { digest } from './public-governance-client.js';
import type { BoundAuthority } from '../../../services/identity-service/src/db/authority-fence.js';
import { fenceInitialEnvelopeActivationIntent } from '../../../services/identity-service/src/db/identity-envelope-activation-authority.js';

const actionIntentId = 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1';
const submitAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';

/** Same principal/action/catalogue/key in another valid privacy domain is a
 * distinct cache tuple. It cannot select or consume this activation original. */
async function assertActivationPrivacyCollision(input: {
  platform: Pool;
  participantId: string;
  privacyDomainId: string;
  principalId: string;
  idempotencyKey: string;
  envelopeId: string;
}) {
  const { platform, participantId, privacyDomainId, principalId, idempotencyKey, envelopeId } =
    input;
  await expect(
    runScopedTransaction(
      platform,
      { participantId, privacyDomainId, actionIntentId },
      id,
      async (c, operationId) => {
        const inserted = await c.query(
          `insert into control.idempotency_record
           (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,
            operation_id,input_digest,webauthn_assertion_binding_digest,expected_aggregate_version,expires_at)
           values($1,$2,$3,$4,'ID-OP-ENVELOPE-ACTIVATE',$5,$6,$7,$7,3,clock_timestamp()+interval '24 hours')`,
          [
            participantId,
            privacyDomainId,
            principalId,
            actionIntentId,
            idempotencyKey,
            operationId,
            Buffer.from(digest({ envelopeId }).slice(7), 'hex'),
          ],
        );
        expect(inserted.rowCount).toBe(1);
        expect(
          await readInitialEnvelopeActivation(
            c,
            { participantId, privacyDomainId },
            { principalId, idempotencyKey, envelopeId },
          ),
        ).toBeUndefined();
        throw new Error('ROLLBACK-PRIVACY-COLLISION');
      },
    ),
  ).rejects.toThrow('ROLLBACK-PRIVACY-COLLISION');
}

/** Runtime roles cannot delete cache rows. The existing maintenance role may
 * delete unrelated cache entries, but must preserve a consumed activation. */
export async function assertActivationCacheProtection(input: {
  admin: Pool;
  platform: Pool;
  participantId: string;
  privacyDomainId: string;
  principalId: string;
  envelopeId: string;
  operationId: string;
}) {
  const { admin, platform, participantId, privacyDomainId, principalId, envelopeId, operationId } =
    input;
  const scope = { participantId, privacyDomainId, actionIntentId };
  const unrelatedId = await runScopedTransaction(
    platform,
    scope,
    id,
    async (c, unrelatedOperation) => {
      const inserted = await c.query<{ id: string }>(
        `insert into control.idempotency_record
      (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,
       operation_id,input_digest,webauthn_assertion_binding_digest,expected_aggregate_version,expires_at)
      values($1,$2,$3,$4,'ID-OP-ENVELOPE-ACTIVATE',$5,$6,$7,$7,3,clock_timestamp()+interval '1 minute')
      returning idempotency_record_id::text id`,
        [
          participantId,
          privacyDomainId,
          principalId,
          actionIntentId,
          `unrelated-cache-${id()}`,
          unrelatedOperation,
          Buffer.from(digest({ envelopeId }).slice(7), 'hex'),
        ],
      );
      return inserted.rows[0]!.id;
    },
  );
  await expect(
    runScopedTransaction(platform, scope, id, (c) =>
      c.query('delete from control.idempotency_record where idempotency_record_id=$1', [
        unrelatedId,
      ]),
    ),
  ).rejects.toThrow('permission denied for table idempotency_record');
  const client = await admin.connect();
  try {
    await client.query('begin');
    await client.query('set local role openpc_control_maintenance');
    expect((await client.query('select current_user as role')).rows).toEqual([
      { role: 'openpc_control_maintenance' },
    ]);
    await client.query('savepoint protected_original');
    await expect(
      client.query('delete from control.idempotency_record where operation_id=$1', [operationId]),
    ).rejects.toThrow('ENVELOPE-ACTIVATION-ORIGINAL-INTENT');
    await client.query('rollback to savepoint protected_original');
    const removed = await client.query(
      'delete from control.idempotency_record where idempotency_record_id=$1',
      [unrelatedId],
    );
    expect(removed.rowCount).toBe(1);
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
}

/** Public business preparation, then the real scoped attempt owner. This is
 * component acceptance only: no ACTIVE result, assignment or public execution
 * success is asserted while sealed publication remains closed. */
export async function envelopeActivationAttemptCases(input: {
  admin: Pool;
  platform: Pool;
  fixture: Awaited<ReturnType<typeof contractAdministrationFixture>>;
  signing: Awaited<ReturnType<typeof envelopeActivationSigningFixture>>;
  envelopeId: string;
  environmentId: string;
  collisionPrivacyDomainId: string;
  approve(ref: string, hash: string): Promise<unknown>;
}) {
  const { admin, platform, fixture, signing, envelopeId, environmentId, approve } = input;
  const { participantId, privacyDomainId } = fixture;
  const { client, maker, checker } = fixture.governance;
  const scope = { participantId, privacyDomainId, actionIntentId };
  const requestBody = { envelopeId };
  const candidateDigest = digest(requestBody);
  const idempotencyKey = `envelope-activation-${id()}`;
  const operationId = id();
  let approvalRef: string | undefined;
  await cp(fixture.service.directory, join(signing.root, 'identity-runtime'), { recursive: true });
  const preserve = async () =>
    writeFile(
      join(signing.root, 'original-case.json'),
      JSON.stringify({
        participantId,
        privacyDomainId,
        envelopeId,
        environmentId,
        operationId,
        idempotencyKey,
        approvalRequestId: approvalRef?.slice(-36),
        maker,
        checker,
        callerWorkloadCredentialId: signing.callerCredentialId,
        devices: [...fixture.governance.devices.entries()].map(([principal, device]) => ({
          principal,
          credentialId: device.credentialId,
          count: device.count,
          privateKeyHex: device.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex'),
        })),
      }),
      { mode: 0o600 },
    );
  await preserve();
  try {
    const stage = await client.request(
      `${fixture.service.participantUrl()}/v1/participants/${participantId}/envelopes/${envelopeId}/activate`,
      maker,
      requestBody,
      {
        'Authorization': `Bearer ${maker.sessionToken}`,
        'X-CSRF-Token': await client.csrf(maker, actionIntentId, fixture.service.participantUrl()),
        'Idempotency-Key': idempotencyKey,
        'X-OpenPC-Aggregate-Version': '3',
        'X-OpenPC-Approval-Request-ID': id(),
        'OpenPC-Action-Intent-Digest': client.actionDigests.get(actionIntentId)!,
      },
    );
    expect(stage.status, JSON.stringify(stage)).toBeGreaterThanOrEqual(400);
    const staged = await admin.query(
      `select state from control.mutation_candidate where participant_id=$1
    and privacy_domain_id=$2 and resource_id=$3 and idempotency_key=$4 and catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'`,
      [participantId, privacyDomainId, envelopeId, idempotencyKey],
    );
    expect(
      staged.rows,
      JSON.stringify({ stage, denials: fixture.service.identityDenials() }),
    ).toEqual([{ state: 'PROPOSED' }]);
    const approval = await client.policyMutation(maker, '/api/v1/approval-requests', {
      actionIntentId: submitAction,
      actionIntentDigest: client.actionDigests.get(submitAction)!,
      candidateDigest,
      makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
      reason: 'Review the independent exact ACTIVATE intent.',
    });
    expect(approval.status, JSON.stringify(approval)).toBe(202);
    approvalRef = String(approval.body.resourceRef);
    await approve(approvalRef, candidateDigest);
    await client.stepUp(maker, actionIntentId, envelopeId, candidateDigest);
    const prepare = (c: PoolClient) =>
      prepareInitialEnvelopeActivation(
        c,
        { ...scope, operationId },
        {
          principalId: maker.principalId,
          sessionId: maker.sessionId,
          envelopeId,
          approvalRequestId: approvalRef!.slice(-36),
          idempotencyKey,
          environmentId,
          callerWorkloadCredentialId: signing.callerCredentialId,
        },
        fixture.identityRuntimeVerifier,
      );
    const transaction = <T>(operation: (c: PoolClient) => Promise<T>) =>
      runScopedTransaction(platform, scope, () => operationId, operation);
    const identity = { principalId: maker.principalId, idempotencyKey, envelopeId };
    const read = () => transaction((c) => readInitialEnvelopeActivation(c, scope, identity));
    const effects = async () =>
      (
        await admin.query(
          `select
      (select count(*) from control.identity_envelope_activation where envelope_id=$1)::text attempts,
      (select count(*) from control.authority_envelope where authority_envelope_id=$1 and state='ACTIVE')::text active,
      (select count(*) from control.assignment where authority_envelope_id=$1)::text assignments,
      (select count(*) from control.idempotency_record where operation_id=$2)::text operations,
      (select count(*) from control.mfa_challenge where used_operation_id=$2)::text consumed`,
          [envelopeId, operationId],
        )
      ).rows[0];
    const none = { attempts: '0', active: '0', assignments: '0', operations: '0', consumed: '0' };
    expect(await effects()).toEqual(none);
    // Rollback must preserve the original live proof and leave no replacement
    // identity. The next call is the very same business input and transaction ID.
    await expect(
      transaction(async (c) => {
        await prepare(c);
        throw new Error('ACTIVATION-ROLLBACK');
      }),
    ).rejects.toThrow('ACTIVATION-ROLLBACK');
    expect(await effects()).toEqual(none);
    const prepared = await transaction(prepare);
    const original = await read();
    expect(original).toMatchObject({
      operationId,
      envelopeId,
      principalId: maker.principalId,
      idempotencyKey,
      state: 'PREPARED',
    });
    expect(original!.payload).toEqual(prepared.payload);
    expect(original!.request).toEqual(prepared.request);
    await assertActivationPrivacyCollision({
      platform,
      participantId,
      privacyDomainId: input.collisionPrivacyDomainId,
      principalId: maker.principalId,
      idempotencyKey,
      envelopeId,
    });
    expect(await read()).toEqual(original);
    await transaction(async (c) => {
      await fenceInitialEnvelopeActivationIntent(c, { ...scope, operationId }, original!);
      // Supersession uses this exact canonical advisory identity. The predicate
      // must remain stable while the dispatch transaction owns its decision.
      const competing = await transaction((other) =>
        other.query<{ acquired: boolean }>(
          `select pg_try_advisory_xact_lock(hashtextextended(openpc.signing_canonical_json(
           jsonb_build_array('mutation-intent',$1::text,$2::text,$3::text,$4::text,
             'ID-OP-ENVELOPE-ACTIVATE',$5::text)),0)) acquired`,
          [participantId, privacyDomainId, maker.principalId, actionIntentId, idempotencyKey],
        ),
      );
      expect(competing.rows).toEqual([{ acquired: false }]);
      for (const [table, column] of [
        ['mutation_candidate', 'candidate_id'],
        ['approval_request', 'approval_request_id'],
      ] as const) {
        await expect(
          transaction((other) =>
            other.query(
              `select 1 from control.${table} owner join control.identity_envelope_activation original
               on owner.participant_id=original.participant_id
                and owner.${table === 'mutation_candidate' ? 'mutation_candidate_id' : column}=original.${column}
               where original.operation_id=$1 for update of owner nowait`,
              [operationId],
            ),
          ),
        ).rejects.toMatchObject({ code: '55P03' });
      }
    });
    await expect(
      transaction((c) =>
        fenceInitialEnvelopeActivationIntent(
          c,
          { ...scope, operationId },
          {
            ...original!,
            idempotencyKey: `${idempotencyKey}-substituted`,
          },
        ),
      ),
    ).rejects.toThrow('authority dependency is unavailable');
    expect(await effects()).toEqual({
      attempts: '1',
      active: '0',
      assignments: '0',
      operations: '1',
      consumed: '1',
    });
    expect(await signing.transport.lookup(prepared.request)).toMatchObject({ state: 'NOT_FOUND' });
    const foreignScope = { ...scope, privacyDomainId: id() };
    const foreign = await runScopedTransaction(platform, foreignScope, id, (c) =>
      readInitialEnvelopeActivation(c, foreignScope, identity),
    );
    expect(foreign).toBeUndefined();
    await expect(
      transaction((c) =>
        readInitialEnvelopeActivation(c, scope, { ...identity, envelopeId: id() }),
      ),
    ).rejects.toThrow();
    const dispatchAuthority = (
      await transaction((c) =>
        c.query<{ authority: BoundAuthority }>(
          `select maker_authority#>'{durable,grant}' || jsonb_build_object(
        'sessionId',maker_authority#>'{binding,sessionId}','sessionEpoch',maker_authority#>'{binding,sessionEpoch}') as authority
       from control.identity_envelope_activation where operation_id=$1`,
          [operationId],
        ),
      )
    ).rows[0]!.authority;
    expect(dispatchAuthority.principalId).toBe(maker.principalId);
    expect(dispatchAuthority.sessionId).toBe(maker.sessionId);
    await expect(
      transaction(async (c) => {
        const revoked = await c.query(
          `update control.assignment set state='REVOKED',row_version=row_version+1
        where participant_id=$1 and assignment_id=$2`,
          [participantId, dispatchAuthority.assignmentId],
        );
        expect(revoked.rowCount).toBe(1);
        await claimInitialEnvelopeActivationDispatch(
          c,
          { ...scope, operationId },
          original!.attemptId,
          dispatchAuthority,
        );
      }),
    ).rejects.toThrow('authority dependency is unavailable');
    expect((await read())!.state).toBe('PREPARED');
    const claim = () =>
      transaction((c) =>
        claimInitialEnvelopeActivationDispatch(
          c,
          { ...scope, operationId },
          original!.attemptId,
          dispatchAuthority,
        ),
      );
    const claims = await Promise.all([claim(), claim()]);
    expect(claims.sort()).toEqual([false, true]);
    expect((await read())!.state).toBe('DISPATCHED');
    // A DISPATCHED/NOT_FOUND attempt remains lookup-only. A new owner cannot
    // reclaim a first send even when the external provider has no observation.
    expect(await signing.transport.lookup(prepared.request)).toMatchObject({ state: 'NOT_FOUND' });
    expect(await claim()).toBe(false);
    // The winner sends once, after its claim has committed. Retain only lookup
    // readback to model a lost response at the database/provider boundary.
    await writeFile(
      join(signing.root, 'identity-envelope', 'faults', original!.attemptId + '.drop'),
      '',
    );
    await expect(signing.transport.perform(prepared.request)).rejects.toThrow('reconciliation');
    const observed = await signing.transport.lookup(prepared.request);
    expect(observed.state).toBe('OBSERVED');
    if (observed.state !== 'OBSERVED') throw new Error('Original signature was not observed');
    const tampered = Buffer.from(observed.observation.coseHex, 'hex');
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
    await expect(
      transaction((c) =>
        recordInitialEnvelopeActivationObservation(c, { ...scope, operationId }, original!, {
          ...observed.observation,
          coseHex: tampered.toString('hex'),
        }),
      ),
    ).rejects.toThrow();
    expect((await read())!.state).toBe('DISPATCHED');
    await transaction((c) =>
      recordInitialEnvelopeActivationObservation(
        c,
        { ...scope, operationId },
        original!,
        observed.observation,
      ),
    );
    await transaction((c) =>
      recordInitialEnvelopeActivationObservation(
        c,
        { ...scope, operationId },
        original!,
        observed.observation,
      ),
    );
    expect((await read())!).toMatchObject({ state: 'OBSERVED', observation: observed.observation });
    for (const update of [
      "update control.identity_envelope_activation set state='COMMITTED',row_version=4,committed_at=clock_timestamp() where operation_id=$1",
      "update control.idempotency_record set expires_at=clock_timestamp()-interval '1 day' where operation_id=$1",
      'delete from control.idempotency_record where operation_id=$1',
    ])
      await expect(transaction((c) => c.query(update, [operationId]))).rejects.toThrow();
    await assertActivationCacheProtection({
      admin,
      platform,
      participantId,
      privacyDomainId,
      principalId: maker.principalId,
      envelopeId,
      operationId,
    });
    await fixture.service.restartParticipant();
    expect((await read())!.observation).toEqual(observed.observation);
    expect(await signing.transport.lookup(prepared.request, observed.observation)).toEqual(
      observed,
    );
    expect(await readdir(join(signing.root, 'identity-envelope', 'attempts'))).toEqual([
      original!.attemptId + '.json',
    ]);
    const publicFixture = process.env.OPENPC_ENVELOPE_ACTIVATION_PUBLIC_FIXTURE;
    if (!publicFixture?.startsWith('/')) throw new Error('Native original wire output is required');
    await writeFile(
      publicFixture,
      JSON.stringify({
        envelopeId,
        participantId,
        payload: [...original!.payload],
        cose: [...Buffer.from(observed.observation.coseHex, 'hex')],
        spki: [...signing.trust.publicKeySpkiDer],
      }),
      { mode: 0o600 },
    );
    expect(await effects()).toEqual({
      attempts: '1',
      active: '0',
      assignments: '0',
      operations: '1',
      consumed: '1',
    });
  } finally {
    await preserve();
  }
}
