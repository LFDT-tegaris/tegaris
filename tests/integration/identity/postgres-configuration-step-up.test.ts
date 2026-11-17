import { readFile } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { createLocalConfigurationAuthorizer } from '../../../services/control-api/src/configuration/local-authorizer.js';
import { AtomicConfigurationMutation } from '../../../services/control-api/src/configuration/persistence/atomic-mutation.js';
import type { MutationContext } from '../../../services/control-api/src/configuration/persistence/types.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { digest } from './public-governance-client.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

integration('binds typed checker envelopes through the exact checker assignment', async () => {
  const source = await readFile(
    new URL(
      '../../../services/control-api/src/configuration/persistence/atomic-mutation.ts',
      import.meta.url,
    ),
    'utf8',
  );
  const productionJoins = source.match(
    /join control\.assignment ca on ([\s\S]*?)join control\.credential decision_credential/u,
  )?.[0];
  expect(productionJoins).toBeDefined();
  const joins = productionJoins!
    .replace('join control.credential decision_credential', '')
    .replace('control.assignment', 'assignment_fixture')
    .replace('control.authority_envelope', 'envelope_fixture')
    .replace(
      /\$(2|4|5)\b/gu,
      (_, parameter: string) => ({ '2': '$6', '4': '$5', '5': '$7' })[parameter]!,
    );
  const pool = new Pool({ connectionString: runtimeUrl, max: 1 });
  const participant = id(),
    checker = id(),
    foreign = id(),
    assignmentId = id(),
    envelopeId = id();
  const action = 'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
    privacy = id(),
    resource = id();
  const assignment = {
    participant_id: participant,
    assignment_id: assignmentId,
    principal_id: checker,
    authority_envelope_id: envelopeId,
    state: 'ACTIVE',
    valid_during: '[2020-01-01T00:00:00Z,2100-01-01T00:00:00Z)',
    maker_checker_required: true,
    row_version: '7',
    delegation_epoch: '2',
    action_intent_ids: [action],
    privacy_domain_ids: [privacy],
    resource_ids: [resource],
  };
  const envelope = {
    participant_id: participant,
    authority_envelope_id: envelopeId,
    principal_id: null as string | null,
    representation: 'TYPED_V1',
    state: 'ACTIVE',
    authority_epoch: '3',
    delegation_epoch: '2',
    valid_from: '2020-01-01T00:00:00Z',
    valid_until: '2100-01-01T00:00:00Z',
    maker_checker_required: true,
    action_intent_ids: [action],
    privacy_domain_ids: [privacy],
    resource_ids: [resource],
  };
  const decision = {
    participant_id: participant,
    approver_assignment_id: assignmentId,
    approver_assignment_row_version: '7',
    approver_delegation_epoch: '2',
    approver_authority_envelope_id: envelopeId,
    approver_envelope_epoch: '3',
  };
  const cases = [
    { label: 'typed assigned', admitted: true },
    { label: 'foreign assignment', assignment: { principal_id: foreign }, admitted: false },
    { label: 'foreign typed principal', envelope: { principal_id: foreign }, admitted: false },
    {
      label: 'different assignment envelope',
      assignment: { authority_envelope_id: foreign },
      admitted: false,
    },
    {
      label: 'different decision envelope',
      decision: { approver_authority_envelope_id: foreign },
      admitted: false,
    },
    { label: 'changed assignment version', assignment: { row_version: '8' }, admitted: false },
    { label: 'changed envelope epoch', envelope: { authority_epoch: '4' }, admitted: false },
    {
      label: 'expired assignment',
      assignment: { valid_during: '[2020-01-01T00:00:00Z,2021-01-01T00:00:00Z)' },
      admitted: false,
    },
    {
      label: 'expired envelope',
      envelope: { valid_until: '2021-01-01T00:00:00Z' },
      admitted: false,
    },
    { label: 'foreign resource', envelope: { resource_ids: [foreign] }, admitted: false },
    {
      label: 'foreign privacy domain',
      assignment: { privacy_domain_ids: [foreign] },
      admitted: false,
    },
    { label: 'missing action', envelope: { action_intent_ids: [] }, admitted: false },
    {
      label: 'missing checker requirement',
      assignment: { maker_checker_required: false },
      admitted: false,
    },
    {
      label: 'legacy assigned',
      envelope: { representation: 'LEGACY_V1', principal_id: checker },
      admitted: true,
    },
    { label: 'legacy unbound', envelope: { representation: 'LEGACY_V1' }, admitted: false },
    { label: 'recovery unbound', envelope: { representation: 'RECOVERY_V1' }, admitted: false },
  ];
  try {
    for (const scenario of cases) {
      const result = await pool.query(
        `with assignment_fixture as (
          select * from jsonb_to_record($1::jsonb) as a(
            participant_id uuid,assignment_id uuid,principal_id uuid,authority_envelope_id uuid,
            state text,valid_during tstzrange,maker_checker_required boolean,row_version bigint,
            delegation_epoch bigint,action_intent_ids text[],privacy_domain_ids text[],resource_ids text[])
        ), envelope_fixture as (
          select * from jsonb_to_record($2::jsonb) as e(
            participant_id uuid,authority_envelope_id uuid,principal_id uuid,representation text,
            state text,authority_epoch bigint,delegation_epoch bigint,valid_from timestamptz,
            valid_until timestamptz,maker_checker_required boolean,action_intent_ids text[],
            privacy_domain_ids text[],resource_ids text[])
        ), ad as (
          select * from jsonb_to_record($3::jsonb) as d(
            participant_id uuid,approver_assignment_id uuid,approver_assignment_row_version bigint,
            approver_delegation_epoch bigint,approver_authority_envelope_id uuid,approver_envelope_epoch bigint)
        ) select count(*)::int n from ad cross join (select $4::uuid principal_id) checker ${joins}`,
        [
          JSON.stringify({ ...assignment, ...scenario.assignment }),
          JSON.stringify({ ...envelope, ...scenario.envelope }),
          JSON.stringify({ ...decision, ...scenario.decision }),
          checker,
          action,
          privacy,
          resource,
        ],
      );
      expect(result.rows[0].n, scenario.label).toBe(scenario.admitted ? 1 : 0);
    }
  } finally {
    await pool.end();
  }
});

integration(
  'retries module-reference contention before any mutation reservation under the real runtime role',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 3 });
    const blocker = await pool.connect();
    const participant = '018f0000-0000-7000-8000-000000000101';
    const privacy = '018f0000-0000-7000-8000-000000000201';
    const action = 'ACT-INDEXER_APPROVE_PROFILE-V1';
    const gate = "hashtextextended('module-admission:'||$1::text||':'||$2::text,0)";
    let blocking = false;
    const events: string[] = [];
    const stop = new Error('reservation boundary reached');
    try {
      await blocker.query('begin');
      await blocker.query(`select pg_advisory_xact_lock(${gate})`, [participant, privacy]);
      blocking = true;
      const probe = await pool.connect();
      try {
        await probe.query('begin');
        await probe.query('set local role openpc_control_runtime');
        await probe.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          participant,
          privacy,
          id(),
          action,
        ]);
        await expect(
          probe.query('update control.indexer_profile set revision=revision where false'),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
      } finally {
        await probe.query('rollback');
        probe.release();
      }
      const connect = vi.fn(async () => {
        const client = await pool.connect();
        return {
          async query(sql: string, values?: unknown[]) {
            if (sql.includes('insert into control.idempotency_record')) {
              events.push('reserve');
              throw stop;
            }
            const result = await client.query(sql, values);
            if (sql.startsWith('begin isolation level')) {
              await client.query('set local role openpc_control_runtime');
              expect((await client.query('select current_user')).rows[0].current_user).toBe(
                'openpc_control_runtime',
              );
            }
            if (sql.includes('pg_try_advisory_xact_lock_shared'))
              events.push(`lock:${result.rows[0].locked}`);
            if (sql === 'rollback') {
              events.push('rollback');
              if (blocking) {
                await blocker.query('rollback');
                blocking = false;
              }
            }
            return result;
          },
          release(discard?: boolean) {
            client.release(discard);
            events.push('release');
          },
        } as unknown as PoolClient;
      });
      const context = {
        catalogOperationId: 'CFG-OP-ADMIT-INDEXER-PROFILE',
        actionIntentId: action,
        resourceType: 'indexer-profile',
        aggregateType: 'indexer-profile',
        operationClass: 'APPROVE',
        resourceId: id(),
        expectedRevision: '1',
        idempotencyKey: 'module-reference-contention',
        candidate: {},
        authorization: { participantId: participant, privacyDomainId: privacy, principalId: id() },
      } as MutationContext;
      const write = vi.fn(),
        profile = vi.fn(),
        fence = vi.fn(),
        authority = vi.fn();
      const before = await pool.query('select count(*)::text n from control.idempotency_record');
      await expect(
        new AtomicConfigurationMutation({ connect } as unknown as Pool).execute(
          context,
          write,
          profile,
          fence,
          authority,
        ),
      ).rejects.toBe(stop);
      expect(connect).toHaveBeenCalledTimes(2);
      expect(events).toEqual([
        'lock:false',
        'rollback',
        'release',
        'lock:true',
        'reserve',
        'rollback',
        'release',
      ]);
      for (const callback of [write, profile, fence, authority])
        expect(callback).not.toHaveBeenCalled();
      expect(
        (await pool.query('select count(*)::text n from control.idempotency_record')).rows,
      ).toEqual(before.rows);
    } finally {
      if (blocking) await blocker.query('rollback');
      blocker.release();
      await pool.end();
    }
  },
);

integration(
  'authenticates a distinct fresh actor step-up without inventing checker approval or endpoint effects',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const pool = new Pool({ connectionString: runtimeUrl, max: 2 });
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      const catalogue = await admin.query(`select action_intent_id,resource_type,risk_class,
      maker_checker_required,step_up_required from control.action_intent
      where action_intent_id in ('ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
        'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1','ACT-NOTIFICATION_UPDATE_VERIFY-V1')
      order by action_intent_id`);
      expect(catalogue.rows).toEqual([
        ...['CREATE', 'UPDATE'].map((command) => ({
          action_intent_id: `ACT-NOTIFICATION_ENDPOINTS_${command}_RESOURCE-V1`,
          resource_type: 'notification-endpoints',
          risk_class: 'HIGH',
          maker_checker_required: false,
          step_up_required: true,
        })),
        {
          action_intent_id: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
          resource_type: 'notification-endpoint',
          risk_class: 'STANDARD',
          maker_checker_required: false,
          step_up_required: false,
        },
      ]);
      const participantId = id(),
        privacyDomainId = id(),
        resourceId = id();
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
      );
      // Local login starts in Platform context. Its context-entry challenge is
      // bound to the Participant, before selecting the exact privacy domain.
      for (const actor of ['maker', 'checker'] as const) {
        await fixture.governance.client.stepUp(
          fixture.governance[actor],
          'ACT-IDENTITY_CREATE_SESSION-V1',
          participantId,
          digest({ participantId, privacyDomainId }),
        );
        await fixture.selectPrivacyContext(actor);
      }
      const { client, maker, checker } = fixture.governance;
      const actionIntentId = 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1';
      const actionIntentDigest = client.actionDigests.get(actionIntentId)!;
      const body = {
        actionIntentId,
        actionIntentDigest,
        participantId: `urn:openpc:participant:${participantId}`,
        channel: 'WEBHOOK',
        destinationRef: `urn:openpc:resource:${id()}`,
        reason: 'Verify the exact endpoint authorization boundary.',
      };
      const candidateDigest = digest(body);
      const authorizer = createLocalConfigurationAuthorizer(
        fixture.service.identityUrl,
        fixture.service.identityInternalToken,
        privacyDomainId,
      );
      const input = {
        sessionToken: maker.sessionToken,
        participantId,
        privacyDomainId,
        resourceId,
        catalogOperationId: 'CFG-OP-CREATE-NOTIFICATION-ENDPOINT',
        idempotencyKey: `endpoint-auth-${id()}`,
        actionIntentId,
        actionIntentDigest,
        candidateDigest,
        expectedRevision: '0',
        makerCheckerRequired: false,
        stepUpRequired: true,
        origin: fixture.service.identityUrl,
        host: new URL(fixture.service.identityUrl).host,
        csrfToken: await client.csrf(maker, actionIntentId, fixture.service.identityUrl),
      };
      await expect(authorizer.authorize(input)).rejects.toThrow('PC-AUTH-0005');
      await client.stepUp(checker, actionIntentId, resourceId, candidateDigest);
      await expect(authorizer.authorize(input)).rejects.toThrow('PC-AUTH-0005');
      await client.stepUp(maker, actionIntentId, resourceId, candidateDigest);
      const proof = await authorizer.authorize(input);
      expect(proof.evidenceKind).toBe('IDENTITY_RUNTIME_STEP_UP');
      expect(proof.checkerPrincipalId).toBeUndefined();
      expect(proof.approvalRequestId).toBeUndefined();
      if (proof.evidenceKind !== 'IDENTITY_RUNTIME_STEP_UP')
        throw new Error('Missing distinct proof');
      const verifier = createLocalIdentityRuntimeVerifier([
        await readFile(`${fixture.service.directory}/public.der`),
      ]);
      expect(
        await verifier.verifyCanonicalAssertion(proof.evidenceCbor, proof.coseSign1),
      ).toBeDefined();
      await expect(
        authorizer.authorize({ ...input, candidateDigest: `sha256:${'ab'.repeat(32)}` }),
      ).rejects.toThrow('PC-AUTH-0005');
      const context: MutationContext = {
        authorization: proof,
        sessionToken: maker.sessionToken,
        actionIntentId,
        actionIntentDigest,
        catalogOperationId: input.catalogOperationId,
        idempotencyKey: input.idempotencyKey,
        resourceId,
        resourceType: 'notification-endpoints',
        aggregateType: 'notification-endpoint',
        operationClass: 'CREATE',
        expectedRevision: '0',
        candidate: body,
      };
      const atomic = new AtomicConfigurationMutation(pool, verifier);
      const boundary = new Error('Verified authority; endpoint persistence deliberately unopened');
      let reached = 0;
      await expect(
        atomic.execute(context, async () => {
          reached++;
          throw boundary;
        }),
      ).rejects.toBe(boundary);
      expect(reached).toBe(1);
      for (const authorization of [
        { ...proof, webauthnSessionId: checker.sessionId },
        { ...proof, webauthnEvidenceDigest: Buffer.alloc(32) },
        { ...proof, coseSign1: Buffer.alloc(proof.coseSign1.length) },
        { ...proof, approvalRequestId: id() },
      ])
        await expect(
          atomic.execute({ ...context, authorization }, async () => {
            throw boundary;
          }),
        ).rejects.toThrow('PC-AUTH-0005');
      const unchanged = await admin.query(
        `select
      (select count(*)::int from control.approval_request where participant_id=$1) approvals,
      (select count(*)::int from control.idempotency_record where participant_id=$1 and catalog_operation_id=$2) operations,
      (select count(*)::int from control.mfa_challenge where participant_id=$1 and action_intent_id=$3 and used_at is not null) consumed`,
        [participantId, input.catalogOperationId, actionIntentId],
      );
      expect(unchanged.rows[0]).toEqual({ approvals: 0, operations: 0, consumed: 0 });
    } finally {
      await fixture?.close();
      await pool.end();
      await admin.end();
    }
  },
);

for (const fault of [
  'none',
  'maker-assignment',
  'maker-envelope',
  'maker-role',
  'checker-assignment',
  'checker-envelope',
  'checker-role',
  'checker-privacy',
  'checker-resource',
  'maker-epoch',
  'checker-epoch',
  'foreign-privacy',
] as const) {
  integration(
    `checks the underlying approval authority before decision effects: ${fault}`,
    async () => {
      const admin = new Pool({ connectionString: adminUrl, max: 1 });
      const participantId = id(),
        privacyDomainId = id();
      const fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
      );
      try {
        const { client, maker, checker, policyUrl } = fixture.governance;
        const action = 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1';
        const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
        // Each case has independent initial trust. Faults only remove authority;
        // no decision, execution, successor or effect is seeded or repaired.
        const roles = new Map<string, string>();
        for (const actor of [maker, checker]) {
          const roleId = id(),
            roleRef = `urn:openpc:role:${roleId}`;
          await admin.query(
            `insert into control.authority_role
          (authority_role_id,participant_id,role_id,display_name,action_intent_ids,created_by_principal_id)
          values($1,$2,$3,'Approval authority initial trust',ARRAY(select action_intent_id from control.action_intent),$4)`,
            [roleId, participantId, roleRef, actor.principalId],
          );
          await admin.query(
            `update control.assignment set role_id=$3
          where participant_id=$1 and principal_id=$2`,
            [participantId, actor.principalId, roleRef],
          );
          const narrowId = id(),
            narrowRef = `urn:openpc:role:${narrowId}`;
          await admin.query(
            `insert into control.authority_role
             (authority_role_id,participant_id,role_id,display_name,action_intent_ids,created_by_principal_id)
             values($1,$2,$3,'Narrow approval initial trust',
               ARRAY(select action_intent_id from control.action_intent where action_intent_id<>$5),$4)`,
            [narrowId, participantId, narrowRef, actor.principalId, action],
          );
          roles.set(actor.principalId, narrowRef);
        }
        const proposed = fixture.ordinaryMutation('evidence-holds', action, {
          participantId: `urn:openpc:participant:${participantId}`,
          holdKind: 'LEGAL',
          selector: { type: 'PRIVACY_DOMAIN' },
        });
        expect((await proposed.call(proposed.body, true)).status).toBe(200);
        const created = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
          actionIntentDigest: client.actionDigests.get('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'),
          candidateDigest: proposed.hash,
          makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
          reason: 'Approve the exact preservation intent.',
        });
        expect(created.status, JSON.stringify(created.body)).toBe(202);
        const approvalRef = String(created.body.resourceRef),
          approvalId = approvalRef.slice(-36);
        const decisionDigest = digest({
          actionIntentId: approveAction,
          approvalRequestId: approvalRef,
          candidateDigest: proposed.hash,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        await client.stepUp(checker, approveAction, approvalId, decisionDigest);
        const requestKey = `approval-authority-${id()}`;
        const headers = {
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${fault === 'foreign-privacy' ? id() : privacyDomainId}`,
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
          'Idempotency-Key': requestKey,
          'X-CSRF-Token': await client.csrf(checker, approveAction, policyUrl),
          'OpenPC-Action-Intent-Digest': client.actionDigests.get(approveAction)!,
          'X-OpenPC-Action-Intent-Digest': client.actionDigests.get(approveAction)!,
          'If-Match': `"${digest({ resourceId: approvalId, revision: '1' })}"`,
        };
        const body = {
          targetRef: approvalRef,
          actionIntentId: approveAction,
          actionIntentDigest: client.actionDigests.get(approveAction),
          inputDigest: decisionDigest,
          expectedRevision: '1',
          reason: 'Independent review of the original immutable intent.',
        };
        const call = () =>
          client.request(
            `${policyUrl}/api/v1/approval-requests/${approvalRef}/approve`,
            checker,
            body,
            headers,
          );
        const subject = fault.startsWith('maker-') ? maker : checker;
        if (fault.endsWith('-assignment')) {
          await admin.query(
            `update control.assignment set action_intent_ids=array_remove(action_intent_ids,$3)
          where participant_id=$1 and principal_id=$2`,
            [participantId, subject.principalId, action],
          );
        } else if (fault.endsWith('-envelope')) {
          await admin.query(
            `update control.authority_envelope set action_intent_ids=array_remove(action_intent_ids,$3)
          where participant_id=$1 and principal_id=$2`,
            [participantId, subject.principalId, action],
          );
        } else if (fault.endsWith('-role')) {
          await admin.query(
            `update control.assignment set role_id=$3,action_intent_ids=array_remove(action_intent_ids,$4)
          where participant_id=$1 and principal_id=$2`,
            [participantId, subject.principalId, roles.get(subject.principalId), action],
          );
        } else if (fault.endsWith('-epoch')) {
          await admin.query(
            `update control.principal set authority_epoch=authority_epoch+1
          where participant_id=$1 and principal_id=$2`,
            [participantId, subject.principalId],
          );
        } else if (fault === 'checker-privacy' || fault === 'checker-resource') {
          const column = fault === 'checker-privacy' ? 'privacy_domain_ids' : 'resource_ids';
          // The grant still permits reviewing this approval, but cannot cover the
          // candidate's business resource/privacy when the dependency is checked.
          await admin.query(
            `update control.assignment set ${column}=$3::text[]
          where participant_id=$1 and principal_id=$2`,
            [
              participantId,
              checker.principalId,
              [fault === 'checker-resource' ? approvalId : id()],
            ],
          );
        }
        const snapshot = async () =>
          (
            await admin.query(
              `select
        (select count(*)::int from control.approval_decision_record where approval_request_id=$1) decisions,
        (select count(*)::int from control.idempotency_record where participant_id=$2 and idempotency_key=$3) operations,
        (select count(*)::int from control.mfa_challenge where participant_id=$2 and principal_id=$4
          and action_intent_id=$5 and resource_digest=$6 and used_at is not null) used_stepups,
        (select count(*)::int from control.outbox_event where participant_id=$2 and aggregate_id=$1) events,
        (select count(*)::int from control.retention_hold where participant_id=$2) holds`,
              [
                approvalId,
                participantId,
                requestKey,
                checker.principalId,
                approveAction,
                Buffer.from(decisionDigest.slice(7), 'hex'),
              ],
            )
          ).rows[0];
        const before = await snapshot();
        const response = await call();
        if (fault === 'none') {
          expect(response.status, JSON.stringify(response.body)).toBe(202);
          const committed = await snapshot();
          expect(committed).toMatchObject({
            decisions: 1,
            operations: 1,
            used_stepups: 1,
            holds: 0,
          });
          const replay = await call();
          expect(replay.status, JSON.stringify(replay.body)).toBe(202);
          expect(replay.body).toEqual(response.body);
          expect(await snapshot()).toEqual(committed);
          // A once-valid decision cannot continue through a narrowed role/grant.
          await admin.query(
            `update control.assignment set role_id=$3,action_intent_ids=array_remove(action_intent_ids,$4)
          where participant_id=$1 and principal_id=$2`,
            [participantId, checker.principalId, roles.get(checker.principalId), action],
          );
          expect([403, 404, 409]).toContain((await call()).status);
          expect(await snapshot()).toEqual(committed);
        } else {
          expect([403, 404, 409], JSON.stringify(response.body)).toContain(response.status);
          expect(await snapshot()).toEqual(before);
          const state = (
            await admin.query(
              `select r.state,r.row_version::text revision,c.state candidate_state
          from control.approval_request r join control.mutation_candidate c on c.mutation_candidate_id=r.subject_id
          where r.approval_request_id=$1`,
              [approvalId],
            )
          ).rows[0];
          expect(state).toEqual({
            state: 'OPEN',
            revision: '1',
            candidate_state: 'APPROVAL_REQUESTED',
          });
        }
      } finally {
        await fixture.close();
        await admin.end();
      }
    },
    120000,
  );
}
