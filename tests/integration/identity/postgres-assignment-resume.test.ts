import type { ApprovalCandidateView } from '../../../services/module-registry/src/approval-candidate-contract.js';
import { Pool } from 'pg';
import { setTimeout as delay } from 'node:timers/promises';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { digest } from './public-governance-client.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const integration = process.env.OPENPC_I02_ADMIN_DATABASE_URL ? it : it.skip;
const action = 'ACT-PARTICIPANT_CREATE_MEMBER-V1';
const resumeAction = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
const approvalAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';

// Initial identity trust only. Every candidate, approval, assignment and successor
// uses HTTP owners; expiry is natural and no business timestamp is rewritten.
integration(
  'resumes an expired assignment approval with one exact public Participant effect',
  async () => {
    const admin = new Pool({ connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL, max: 2 });
    const database = new URL(process.env.OPENPC_I02_RUNTIME_DATABASE_URL!);
    database.username = 'openpc_participant_runtime';
    const participantRuntime = new Pool({ connectionString: database.href, max: 2 });
    const pid = id(),
      privacy = id(),
      workload = id(),
      assignmentId = id();
    const fixture = await contractAdministrationFixture(
      admin,
      process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
      pid,
      privacy,
      { participantRuntime },
    );
    const { client, policyUrl } = fixture.governance;
    const maker = () => fixture.governance.maker,
      checker = () => fixture.governance.checker;
    const key = `assignment-resume-${assignmentId}`;
    try {
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Initial unassigned workload','ACTIVE',1)`,
        [workload, pid],
      );
      const envelope = (
        await admin.query(
          `select authority_envelope_id from control.authority_envelope where participant_id=$1 and principal_id=$2`,
          [pid, maker().principalId],
        )
      ).rows[0].authority_envelope_id;
      const body = {
        assignmentId,
        principalId: workload,
        authorityEnvelopeId: envelope,
        scopeDigest: digest({ assignmentId, workload }),
        privacyDomainIds: [privacy],
        actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
        capabilityIds: [],
        resourceIds: ['*'],
        riskClasses: ['LOW'],
        validFrom: new Date().toISOString(),
        validUntil: '2030-01-01T00:00:00.000Z',
        makerCheckerRequired: true,
        stepUpRequired: true,
        onwardDelegationDepth: 0,
      };
      const candidate = {
        id: assignmentId,
        participantId: pid,
        state: 'ACTIVE',
        delegationEpoch: '0',
        ...body,
      };
      const hash = digest(candidate);
      const execute = async (
        approvalId: string,
        changed = body,
        override: Record<string, string> = {},
        loseResponse = false,
      ) => {
        const origin = fixture.service.participantUrl();
        const headers = {
          'Authorization': `Bearer ${maker().sessionToken}`,
          'X-CSRF-Token': await client.csrf(maker(), action, origin),
          'Idempotency-Key': key,
          'X-OpenPC-Aggregate-Version': '0',
          'X-OpenPC-Approval-Request-ID': approvalId,
          'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
          ...override,
        };
        const url = `${origin}/v1/participants/${pid}/assignments`;
        if (loseResponse) {
          const response = await fetch(url, {
            method: 'POST',
            headers: {
              ...headers,
              'Content-Type': 'application/json',
              'Origin': origin,
              'Cookie': `__Host-openpc_session=${maker().sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
            },
            body: JSON.stringify(changed),
          });
          expect(response.status).toBe(201);
          await response.body?.cancel();
          return { status: 0, body: {} };
        }
        return client.request(url, maker(), changed, headers);
      };
      const read = async (approvalId: string) => {
        const result = await fixture.approvalRead(approvalId);
        expect(result.status, JSON.stringify(result.body)).toBe(200);
        return result.body;
      };
      const approve = async (approvalId: string) => {
        const ref = `urn:openpc:resource:${approvalId}`;
        const decision = digest({
          actionIntentId: approveAction,
          approvalRequestId: ref,
          candidateDigest: hash,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        await client.stepUp(checker(), approveAction, approvalId, decision);
        const response = await client.policyMutation(
          checker(),
          `/api/v1/approval-requests/${ref}/approve`,
          {
            targetRef: ref,
            actionIntentId: approveAction,
            actionIntentDigest: client.actionDigests.get(approveAction),
            inputDigest: decision,
            expectedRevision: '1',
            reason: 'Approve the unchanged assignment independently.',
          },
          '1',
        );
        expect(response.status, JSON.stringify(response.body)).toBe(202);
      };
      const resumeBody = (view: ApprovalCandidateView) => ({
        command: 'RESUME',
        actionIntentId: resumeAction,
        actionIntentDigest: client.actionDigests.get(resumeAction),
        expectedRevision: '2',
        predecessorCandidateId: view.attemptId,
        expectedAttempt: view.attempt,
        candidateDigest: hash,
        reason: 'Resume the original expired assignment approval.',
      });
      const resume = async (
        approvalId: string,
        input: ReturnType<typeof resumeBody>,
        requestKey: string,
        actor = maker(),
        override: Record<string, string> = {},
      ) =>
        client.request(
          `${policyUrl}/api/v1/approval-requests/urn:openpc:resource:${approvalId}`,
          actor,
          input,
          {
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': `urn:openpc:participant:${pid}`,
            'X-Request-ID': id(),
            'X-Correlation-ID': id(),
            'Idempotency-Key': requestKey,
            'X-CSRF-Token':
              override['X-CSRF-Token'] ?? (await client.csrf(actor, resumeAction, policyUrl)),
            'X-OpenPC-Action-Intent-Digest': client.actionDigests.get(resumeAction)!,
            'If-Match': `"${digest({ resourceId: approvalId, revision: input.expectedRevision })}"`,
            ...override,
          },
          'PATCH',
        );
      const effects = async () =>
        (
          await admin.query(
            `select
      (select count(*)::int from control.assignment where participant_id=$1 and assignment_id=$2) assignments,
      (select count(*)::int from control.idempotency_record where participant_id=$1 and catalog_operation_id='ID-OP-ASSIGNMENT-CREATE' and idempotency_key=$3) operations,
      (select count(*)::int from control.mutation_evidence where participant_id=$1 and aggregate_id=$2) evidence,
      (select count(*)::int from control.outbox_event where participant_id=$1 and aggregate_id=$2) outbox`,
            [pid, assignmentId, key],
          )
        ).rows[0];
      const zero = { assignments: 0, operations: 0, evidence: 0, outbox: 0 };
      expect((await execute(id())).status).toBe(403);
      expect(await effects()).toEqual(zero);
      const proposed = await client.policyMutation(maker(), '/api/v1/approval-requests', {
        actionIntentId: approvalAction,
        actionIntentDigest: client.actionDigests.get(approvalAction),
        candidateDigest: hash,
        makerSubjectRef: `urn:openpc:resource:${maker().principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${checker().principalId}`,
        reason: 'Assign this initial workload through public governance.',
      });
      expect(proposed.status, JSON.stringify(proposed.body)).toBe(202);
      const oldId = String(proposed.body.resourceRef).slice(-36);
      await approve(oldId);
      const original = await read(oldId);
      expect(original).toMatchObject({ approvalUsable: true, canRequestResume: false, candidate });
      const originalHistory = (
        await admin.query(
          `select to_jsonb(c) candidate,to_jsonb(a) approval,to_jsonb(d) decision
      from control.mutation_candidate c join control.approval_request a on a.subject_id=c.mutation_candidate_id
      join control.approval_decision_record d using(approval_request_id) where a.approval_request_id=$1`,
          [oldId],
        )
      ).rows;
      const request = resumeBody(original),
        resumeKey = `resume-${original.attemptId}`;
      expect([403, 409]).toContain((await resume(oldId, request, resumeKey)).status);
      for (const change of [{ expectedAttempt: '2' }, { expectedRevision: '9' }])
        expect((await resume(oldId, { ...request, ...change }, `stale-${id()}`)).status).toBe(412);
      for (const [actor, headers] of [
        [checker(), {}],
        [maker(), { 'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${id()}` }],
        [maker(), { 'OpenPC-Participant-ID': `urn:openpc:participant:${id()}` }],
      ] as const)
        expect([403, 404]).toContain(
          (await resume(oldId, request, `foreign-${id()}`, actor, headers)).status,
        );
      expect([403, 404, 422]).toContain(
        (await resume(oldId, { ...request, candidateDigest: digest({}) }, `changed-${id()}`))
          .status,
      );
      expect(await effects()).toEqual(zero);
      const expiry = (
        await admin.query(
          `select extract(epoch from least(m.expires_at,m.consumed_at+interval '5 minutes'))*1000 expiry
      from control.approval_decision_record d join control.mfa_challenge m using(participant_id,mfa_challenge_id) where d.approval_request_id=$1`,
          [oldId],
        )
      ).rows[0].expiry;
      while (Date.now() <= Number(expiry)) {
        process.stdout.write(
          `OPENPC_ASSIGNMENT_RESUME|natural-expiry|remaining_ms=${Math.ceil(Number(expiry) - Date.now())}\n`,
        );
        await delay(Math.min(30000, Number(expiry) - Date.now() + 100));
      }
      // A reserved operation is ambiguous, even without an assignment or receipt.
      // This adversarial transaction is rolled back; it creates no accepted effect.
      const reserved = await admin.connect();
      try {
        await reserved.query('begin');
        await reserved.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          pid,
          privacy,
          id(),
          action,
        ]);
        await reserved.query(
          "insert into control.idempotency_record(participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,operation_id,input_digest,expires_at) values($1,$2,$3,$4,'ID-OP-ASSIGNMENT-CREATE',$5,$6,$7,clock_timestamp()+interval '1 hour')",
          [pid, privacy, maker().principalId, action, key, id(), Buffer.from(hash.slice(7), 'hex')],
        );
        await expect(
          reserved.query('select openpc.assert_mutation_resume_no_effect($1)', [
            original.attemptId,
          ]),
        ).rejects.toThrow('PC-POLICY-2004');
      } finally {
        await reserved.query('rollback');
        reserved.release();
      }
      expect(await effects()).toEqual(zero);
      // Revoke the actual maker session through its owner. A cached CSRF token
      // cannot turn the stale session into current authority for a resume.
      const oldMaker = maker(),
        cachedCsrf = await client.csrf(oldMaker, resumeAction, policyUrl);
      const logoutAction = 'ACT-IDENTITY_DELETE_SESSION-V1',
        reason = 'Rotate this test session before the resumed intent.';
      const revision = (
        await admin.query('select row_version::text from control.session where session_id=$1', [
          oldMaker.sessionId,
        ])
      ).rows[0].row_version;
      const loggedOut = await client.request(
        fixture.service.identityUrl + '/api/v1/session/logout',
        oldMaker,
        {
          targetRef: `urn:openpc:resource:${oldMaker.sessionId}`,
          actionIntentId: logoutAction,
          actionIntentDigest: client.actionDigests.get(logoutAction),
          inputDigest: digest({ sessionId: oldMaker.sessionId, reason }),
          expectedRevision: revision,
          reason,
        },
        {
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${pid}`,
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
          'Idempotency-Key': `logout-${id()}`,
          'OpenPC-Action-Intent-Digest': client.actionDigests.get(logoutAction)!,
          'If-Match': `"${digest({ resourceType: 'session', sessionId: oldMaker.sessionId, revision })}"`,
          'X-CSRF-Token': await client.csrf(oldMaker, logoutAction, fixture.service.identityUrl),
        },
      );
      expect(loggedOut.status, JSON.stringify(loggedOut.body)).toBe(202);
      expect([401, 403]).toContain(
        (await resume(oldId, request, `revoked-${id()}`, oldMaker, { 'X-CSRF-Token': cachedCsrf }))
          .status,
      );
      await fixture.refresh();
      const expired = await read(oldId);
      expect(expired).toMatchObject({ approvalUsable: false, canRequestResume: true });
      await client.stepUp(maker(), action, assignmentId, hash);
      expect((await execute(oldId)).status).toBe(409);
      expect(await effects()).toEqual(zero);
      // Two independent resume requests share one intent; exactly one successor wins.
      const competitorKey = `competitor-${id()}`;
      const raced = await Promise.all([
        resume(oldId, request, resumeKey),
        resume(oldId, request, competitorKey),
      ]);
      expect(raced.filter((result) => result.status === 202)).toHaveLength(1);
      expect(raced.filter((result) => [403, 409].includes(result.status))).toHaveLength(1);
      const won = raced.find((result) => result.status === 202)!;
      const wonKey = raced[0]!.status === 202 ? resumeKey : competitorKey;
      expect(await resume(oldId, request, wonKey)).toEqual(won);
      const nextId = String(won.body.resourceRef).slice(-36),
        next = await read(nextId);
      expect(next).toMatchObject({
        attempt: '2',
        predecessorApprovalRef: `urn:openpc:resource:${oldId}`,
        candidate,
        businessIdempotencyKey: key,
        state: 'APPROVAL_REQUESTED',
        operationRef: null,
      });
      expect((await execute(oldId)).status).toBe(403);
      await approve(nextId);
      await client.stepUp(maker(), action, assignmentId, hash);
      const epochs = async () =>
        (
          await admin.query(
            `select p.authority_epoch::text participant_epoch,pr.authority_epoch::text principal_epoch
      from control.participant p join control.principal pr using(participant_id) where p.participant_id=$1 and pr.principal_id=$2`,
            [pid, workload],
          )
        ).rows[0];
      const before = await epochs();
      await admin.query(`create function openpc.assignment_resume_failure() returns trigger language plpgsql as $$begin
      if NEW.aggregate_id='${assignmentId}' then raise exception 'injected assignment evidence failure'; end if; return NEW; end$$;
      create trigger assignment_resume_failure before insert on control.mutation_evidence for each row execute function openpc.assignment_resume_failure()`);
      expect((await execute(nextId)).status).toBeGreaterThanOrEqual(400);
      expect(await effects()).toEqual(zero);
      expect(await epochs()).toEqual(before);
      expect((await read(nextId)).state).toBe('APPROVED');
      await admin.query(
        'drop trigger assignment_resume_failure on control.mutation_evidence; drop function openpc.assignment_resume_failure()',
      );
      const live = await read(nextId);
      const [lost, deniedResume] = await Promise.all([
        execute(nextId, body, {}, true),
        resume(nextId, resumeBody(live), `live-resume-${id()}`),
      ]);
      expect(lost).toEqual({ status: 0, body: {} });
      expect([403, 409]).toContain(deniedResume.status);
      expect(await effects()).toEqual({ assignments: 1, operations: 1, evidence: 1, outbox: 1 });
      const after = await epochs();
      await fixture.service.restartParticipant();
      await fixture.restartPolicy();
      const recovered = await fixture.service.get(maker().sessionToken, assignmentId, privacy);
      expect(recovered.status).toBe(200);
      expect(recovered.body).toMatchObject({
        operationId: (await read(nextId)).operationRef?.slice(-36),
        effect: { id: assignmentId, principalId: workload, state: 'ACTIVE' },
      });
      const committed = await execute(nextId);
      expect(committed.status).toBe(201);
      expect(recovered.body).toMatchObject({ effect: committed.body });
      expect(await execute(nextId)).toEqual(committed);
      expect((await execute(nextId, { ...body, resourceIds: [id()] })).status).toBe(403);
      expect(await epochs()).toEqual(after);
      expect((await read(nextId)).state).toBe('CONSUMED');
      expect([403, 409]).toContain(
        (await resume(nextId, resumeBody(await read(nextId)), `consumed-${id()}`)).status,
      );
      expect(await effects()).toEqual({ assignments: 1, operations: 1, evidence: 1, outbox: 1 });
      expect(
        (
          await admin.query(
            `select to_jsonb(c) candidate,to_jsonb(a) approval,to_jsonb(d) decision
      from control.mutation_candidate c join control.approval_request a on a.subject_id=c.mutation_candidate_id
      join control.approval_decision_record d using(approval_request_id) where a.approval_request_id=$1`,
            [oldId],
          )
        ).rows,
      ).toEqual(originalHistory);
      const chain = (
        await admin.query(
          `select c.state,c.consumed_operation_id=a.last_mutation_operation_id candidate_matches,
      e.operation_id=a.last_mutation_operation_id evidence_matches,e.evidence_digest=sha256(e.evidence_cbor) digest_matches,
      e.evidence_cbor=o.payload_cbor and e.cose_sign1=o.cose_sign1 outbox_matches,octet_length(e.cose_sign1)>0 signed
      from control.assignment a join control.mutation_candidate c on c.resource_id=a.assignment_id and c.state='CONSUMED'
      join control.mutation_evidence e on e.operation_id=a.last_mutation_operation_id
      join control.outbox_event o on o.aggregate_id=a.assignment_id and o.event_type='openpc.assignment.mutation.committed.v1'
      where a.assignment_id=$1`,
          [assignmentId],
        )
      ).rows;
      expect(chain).toEqual([
        {
          state: 'CONSUMED',
          candidate_matches: true,
          evidence_matches: true,
          digest_matches: true,
          outbox_matches: true,
          signed: true,
        },
      ]);
    } finally {
      await fixture.close();
      await participantRuntime.end();
      await admin.end();
    }
  },
  480000,
);
