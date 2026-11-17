import { generateKeyPairSync } from 'node:crypto';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { participantReadbackRuntime } from './participant-readback-runtime.js';
import {
  publicGovernanceClient,
  digest,
  sha,
  type TestAuthenticator,
} from './public-governance-client.js';
import {
  buildPolicyService,
  HttpPolicyIdentityGateway,
} from '../../../services/module-registry/src/policy-http.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  groupOperationIds,
  type GroupChange,
} from '../../../services/participant-service/src/contracts/group-operations.js';
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const participantId = '018f0000-0000-7000-8000-000000000101',
  privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const operatorId = '018f0000-0000-7000-8000-000000000111',
  checkerId = '018f0000-0000-7000-8000-000000000112';
const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1',
  createApproval = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
// AF30-REQ-62F9AA702CCB45A354C80B23: real public governance; groups never create implicit permissions.
integration(
  'governs Participant-local group history, exact approvals, denial, replay and offboarding',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const database = new URL(runtimeUrl!);
    database.username = 'openpc_participant_runtime';
    const runtime = new Pool({ connectionString: database.href });
    database.username = 'openpc_policy_runtime';
    const policyPool = new Pool({ connectionString: database.href });
    const service = await participantReadbackRuntime({
      runtime,
      identityDatabaseUrl: runtimeUrl!,
      participantId,
      privacyDomainId,
      operatorPrincipalId: operatorId,
      checkerPrincipalId: checkerId,
    });
    const policy = buildPolicyService({
      pool: policyPool,
      identityGateway: new HttpPolicyIdentityGateway(
        service.identityUrl,
        service.identityInternalToken,
      ),
      trustedArtifactSigners: [],
      internalToken: service.identityInternalToken,
    });
    const policyUrl = await policy.listen({ host: '127.0.0.1', port: 0 });
    try {
      const devices = new Map<string, TestAuthenticator>();
      for (const principalId of [operatorId, checkerId]) {
        const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' }),
          publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }),
          credentialId = id();
        await admin.query(
          `insert into control.credential(credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from)
        values($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute')`,
          [credentialId, participantId, principalId, sha(publicKey), publicKey],
        );
        devices.set(principalId, { credentialId, privateKey: keys.privateKey, count: 0 });
      }
      const maker = { ...(await service.login('operator')), principalId: operatorId },
        checker = { ...(await service.login('viewer')), principalId: checkerId };
      const client = await publicGovernanceClient({
        admin,
        identityUrl: service.identityUrl,
        policyUrl,
        participantId,
        privacyDomainId,
        devices,
      });
      const path = () => `${service.participantUrl()}/v1/participants/${participantId}`;
      const headers = (session = maker, privacy = privacyDomainId) => ({
        'Authorization': `Bearer ${session.sessionToken}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
      });
      const read = async (suffix: string, session = maker, privacy = privacyDomainId) => {
        const r = await fetch(`${path()}/${suffix}`, { headers: headers(session, privacy) });
        return { status: r.status, body: await r.json() };
      };
      const send = async (
        change: GroupChange,
        key: string,
        revision: string,
        approvalId?: string,
        prepare = false,
      ) =>
        client.request(`${path()}/groups/${prepare ? 'prepare' : 'mutate'}`, maker, change, {
          'Authorization': `Bearer ${maker.sessionToken}`,
          'X-CSRF-Token': await client.csrf(maker, action, service.participantUrl()),
          'Idempotency-Key': key,
          'X-OpenPC-Aggregate-Version': revision,
          'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
          ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
        });
      const approve = async (candidateDigest: string, resourceId: string, intent = action) => {
        const created = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: createApproval,
          actionIntentDigest: client.actionDigests.get(createApproval),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${operatorId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
          reason: 'Review this exact local group authority change.',
        });
        expect(created.status, JSON.stringify(created.body)).toBe(202);
        const approvalRef = created.body.resourceRef as string,
          approvalId = approvalRef.slice(-36);
        const decisionDigest = digest({
          actionIntentId: approveAction,
          approvalRequestId: approvalRef,
          candidateDigest,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        await client.stepUp(checker, approveAction, approvalId, decisionDigest);
        const approved = await client.policyMutation(
          checker,
          `/api/v1/approval-requests/${approvalRef}/approve`,
          {
            targetRef: approvalRef,
            actionIntentId: approveAction,
            actionIntentDigest: client.actionDigests.get(approveAction),
            inputDigest: decisionDigest,
            expectedRevision: '1',
            reason: 'Independent group review accepted.',
          },
          '1',
        );
        expect(approved.status, JSON.stringify(approved.body)).toBe(202);
        await client.stepUp(maker, intent, resourceId, candidateDigest);
        return approvalId;
      };
      const prepare = async (change: GroupChange, revision: string) => {
        const key = `group-journey-${id()}`,
          candidateDigest = digest({ ...change, expectedRevision: revision });
        const staged = await send(change, key, revision, undefined, true);
        expect(staged).toEqual({
          status: 202,
          body: {
            state: 'PREPARED',
            resourceId: change.groupId,
            candidateDigest,
            expectedRevision: revision,
          },
        });
        await client.stepUp(
          checker,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          change.groupId,
          candidateDigest,
        );
        expect(
          await read(
            `group-proposals/${candidateDigest}?expectedRevision=${revision}&makerPrincipalId=${operatorId}`,
            checker,
          ),
        ).toMatchObject({ status: 200, body: { candidate: change, operationId: null } });
        expect(
          (
            await read(
              `group-proposals/${candidateDigest}?expectedRevision=${revision}&makerPrincipalId=${operatorId}`,
              checker,
              id(),
            )
          ).status,
        ).toBe(404);
        const approvalId = await approve(candidateDigest, change.groupId);
        expect(
          await read(`group-proposals/${candidateDigest}?approvalRequestId=${approvalId}`, checker),
        ).toMatchObject({
          status: 200,
          body: { candidate: change, approval: { approvalRequestId: approvalId } },
        });
        return { key, approvalId, commit: () => send(change, key, revision, approvalId) };
      };
      const execute = async (change: GroupChange, revision: string) => {
        const ready = await prepare(change, revision),
          result = await ready.commit();
        expect(result.status, JSON.stringify(result.body)).toBe(200);
        return { ready, result };
      };
      const groupId = id();
      const created = await execute(
        { mutation: 'CREATE', groupId, groupName: 'Local reviewers' },
        '0',
      );
      expect(created.result.body).toMatchObject({
        effect: { groupId, revision: '1', state: 'ACTIVE' },
        revokedAssignments: 0,
      });
      expect(await created.ready.commit()).toEqual(created.result);
      expect((await read(`groups/${groupId}`, maker, id())).status).toBe(404);
      // Initial identity binding only: no business approvals, groups or grants are seeded.
      const memberId = id(),
        subjectId = id(),
        otherId = id(),
        otherMember = id();
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Other group owner','ACTIVE',1)`,
        [otherId],
      );
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'USER','Group member','ACTIVE',1),($3,$4,'USER','Other member','ACTIVE',1)`,
        [memberId, participantId, otherMember, otherId],
      );
      await admin.query('insert into control.identity_subject(identity_subject_id) values($1)', [
        subjectId,
      ]);
      await admin.query(
        `insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$3),($4,$5,$3)`,
        [memberId, participantId, subjectId, otherMember, otherId],
      );
      const cross = await prepare(
        { mutation: 'ADD_MEMBER', groupId, principalId: otherMember },
        '1',
      );
      expect(await cross.commit()).toMatchObject({
        status: 403,
        body: { error: { code: 'PC-IDENTITY-1002' } },
      });
      const before = (
        await admin.query(
          'select assignment_id from control.assignment where participant_id=$1 order by assignment_id',
          [participantId],
        )
      ).rows;
      const assign = async (selectedGroupId: string, validFrom = new Date().toISOString()) => {
        const assignmentId = id(),
          key = `group-assignment-${id()}`;
        const body = {
          assignmentId,
          groupId: selectedGroupId,
          principalId: memberId,
          authorityEnvelopeId: '018f0000-0000-7000-8000-000000000121',
          scopeDigest: digest({ assignmentId, selectedGroupId }),
          privacyDomainIds: [privacyDomainId],
          actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
          capabilityIds: [],
          resourceIds: [assignmentId],
          riskClasses: ['LOW'],
          validFrom,
          validUntil: new Date(Date.now() + 600_000).toISOString(),
          makerCheckerRequired: true,
          stepUpRequired: true,
          onwardDelegationDepth: 0,
        };
        const candidate = {
          id: assignmentId,
          participantId,
          state: 'ACTIVE',
          delegationEpoch: '0',
          ...body,
        };
        const intent = 'ACT-PARTICIPANT_CREATE_MEMBER-V1';
        const sendAssignment = async (approvalId?: string) =>
          client.request(`${path()}/assignments`, maker, body, {
            'Authorization': `Bearer ${maker.sessionToken}`,
            'X-CSRF-Token': await client.csrf(maker, intent, service.participantUrl()),
            'Idempotency-Key': key,
            'X-OpenPC-Aggregate-Version': '0',
            'OpenPC-Action-Intent-Digest': client.actionDigests.get(intent)!,
            ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
          });
        expect((await sendAssignment('018f0000-0000-7000-8000-000000000001')).status).toBe(403);
        expect(await read(`grant-proposals/${digest(candidate)}`)).toMatchObject({
          status: 200,
          body: { proposedGrant: { groupId: selectedGroupId } },
        });
        const approvalId = await approve(digest(candidate), assignmentId, intent);
        const result = await sendAssignment(approvalId);
        return { assignmentId, result, replay: () => sendAssignment(approvalId) };
      };
      expect((await assign(groupId)).result).toMatchObject({
        status: 403,
        body: { error: { code: 'PC-IDENTITY-1002' } },
      });
      await execute({ mutation: 'ADD_MEMBER', groupId, principalId: memberId }, '1');
      expect(
        (
          await admin.query(
            'select assignment_id from control.assignment where participant_id=$1 order by assignment_id',
            [participantId],
          )
        ).rows,
      ).toEqual(before);
      expect(await read(`groups/${groupId}`)).toMatchObject({
        status: 200,
        body: {
          effect: { revision: '2' },
          members: [{ principalId: memberId, current: true, state: 'ACTIVE' }],
        },
      });
      expect((await assign(id())).result).toMatchObject({ status: 403 });
      expect(
        (await assign(groupId, new Date(Date.now() - 3600_000).toISOString())).result,
      ).toMatchObject({ status: 403 });
      // AF30-REQ-F5AF01AB2906A9AD87A33FF0: access review reads the real
      // subject's current grant intersection; a group itself is not authority.
      expect(await read(`access-review/${memberId}`)).toMatchObject({
        status: 200,
        body: { authoritative: false, authorizedEmpty: true, items: [] },
      });
      const assigned = await assign(groupId);
      expect(assigned.result.status, JSON.stringify(assigned.result.body)).toBe(201);
      expect(assigned.result.body).toMatchObject({
        id: assigned.assignmentId,
        groupId,
        principalId: memberId,
        state: 'ACTIVE',
      });
      expect(await assigned.replay()).toEqual(assigned.result);
      expect(await read(`assignments/${assigned.assignmentId}`)).toMatchObject({
        status: 200,
        body: { effect: { groupId, state: 'ACTIVE' } },
      });
      const accessReview = await read(`access-review/${memberId}?limit=1`);
      expect(accessReview).toMatchObject({
        status: 200,
        body: {
          authoritative: false,
          subject: { id: memberId, state: 'ACTIVE' },
          completeness: 'COMPLETE',
          nextCursor: null,
          authorizedEmpty: false,
          items: [
            {
              assignmentId: assigned.assignmentId,
              current: true,
              reasons: [],
              grant: { effect: { id: assigned.assignmentId, groupId } },
              remediation: { id: assigned.assignmentId, kind: 'assignment', revision: '1' },
            },
          ],
        },
      });
      expect((await read(`access-review/${memberId}`, maker, id())).status).toBe(404);
      expect((await read(`access-review/${id()}`)).status).toBe(404);
      expect((await read(`access-review/${memberId}?limit=0`)).status).toBe(400);
      expect((await read(`access-review/${memberId}?after=invalid`)).status).toBe(400);
      const stale = await prepare({ mutation: 'RENAME', groupId, groupName: 'Stale name' }, '2');
      const removedGrant = await execute(
        { mutation: 'REMOVE_MEMBER', groupId, principalId: memberId },
        '2',
      );
      expect(removedGrant.result.body.revokedAssignments).toBe(1);
      Object.assign(maker, await service.login('operator'));
      Object.assign(checker, await service.login('viewer'));
      await client.stepUp(
        maker,
        action,
        groupId,
        digest({ mutation: 'RENAME', groupId, groupName: 'Stale name', expectedRevision: '2' }),
      );
      expect(await stale.commit()).toMatchObject({ status: 409 });
      const removed = await read(`groups/${groupId}`);
      expect(removed).toMatchObject({
        status: 200,
        body: {
          effect: { revision: '3' },
          members: [{ principalId: memberId, current: false, state: 'REVOKED' }],
        },
      });
      expect(await read(`access-review/${memberId}`)).toMatchObject({
        status: 200,
        body: {
          items: [
            {
              current: false,
              reasons: expect.arrayContaining([
                'GRANT_NOT_ACTIVE',
                'GROUP_MEMBERSHIP_OR_DIRECTORY_NOT_CURRENT',
              ]),
              remediation: null,
            },
          ],
        },
      });
      await execute({ mutation: 'ADD_MEMBER', groupId, principalId: memberId }, '3');
      expect(await read(`assignments/${assigned.assignmentId}`)).toMatchObject({
        status: 200,
        body: { effect: { groupId, state: 'REVOKED' } },
      });
      await execute({ mutation: 'RENAME', groupId, groupName: 'Participant review team' }, '4');
      const offboardingStale = await prepare(
        { mutation: 'RENAME', groupId, groupName: 'Before offboarding' },
        '5',
      );
      const removalCandidate = { principalId: memberId, state: 'OFFBOARDED' },
        removalDigest = digest(removalCandidate),
        removalKey = `group-offboarding-${id()}`;
      expect(
        await client.mutation(
          maker,
          `/v1/identity/memberships/${memberId}/remove`,
          {},
          removalKey,
          '1',
        ),
      ).toMatchObject({ status: 409 });
      const removalApproval = await approve(removalDigest, memberId);
      const offboarded = await client.mutation(
        maker,
        `/v1/identity/memberships/${memberId}/remove`,
        {},
        removalKey,
        '1',
        removalApproval,
      );
      expect(offboarded.status, JSON.stringify(offboarded.body)).toBe(200);
      expect((await read(`groups/${groupId}`)).status).toBe(404);
      Object.assign(maker, await service.login('operator'));
      Object.assign(checker, await service.login('viewer'));
      expect((await offboardingStale.commit()).status).toBeGreaterThanOrEqual(400);
      expect(await read(`groups/${groupId}`)).toMatchObject({
        status: 200,
        body: { effect: { revision: '6' }, members: [{ current: false }, { current: false }] },
      });
      const cannotRejoin = await prepare(
        { mutation: 'ADD_MEMBER', groupId, principalId: memberId },
        '6',
      );
      expect(await cannotRejoin.commit()).toMatchObject({ status: 403 });
      const retired = await execute({ mutation: 'RETIRE', groupId }, '6');
      expect(retired.result.body).toMatchObject({ effect: { state: 'RETIRED', revision: '7' } });
      const terminal = await prepare(
        { mutation: 'RENAME', groupId, groupName: 'Cannot reopen' },
        '7',
      );
      expect(await terminal.commit()).toMatchObject({
        status: 403,
        body: { error: { code: 'PC-IDENTITY-1009' } },
      });
      await service.restartParticipant();
      await service.restartIdentity();
      expect(await read(`access-review/${memberId}`)).toMatchObject({
        status: 200,
        body: {
          subject: { state: 'OFFBOARDED' },
          items: [{ current: false, remediation: null }],
        },
      });

      expect(await read(`assignments/${assigned.assignmentId}`)).toMatchObject({
        status: 200,
        body: { effect: { groupId, state: 'REVOKED' } },
      });
      expect(await read(`groups/${groupId}`)).toMatchObject({
        status: 200,
        body: { effect: retired.result.body.effect },
      });
      expect(await retired.ready.commit()).toEqual(retired.result);
      expect(
        (
          await read(
            `group-proposals/${digest({ mutation: 'RETIRE', groupId, expectedRevision: '6' })}?approvalRequestId=${retired.ready.approvalId}`,
          )
        ).body.operationId,
      ).toBe((retired.result.body.effect as { operationId: string }).operationId);
      expect(
        (
          await admin.query(
            `select catalog_operation_id,count(*)::int n from control.mutation_evidence where participant_id=$1 and aggregate_id=$2 group by catalog_operation_id`,
            [participantId, groupId],
          )
        ).rows,
      ).toEqual(
        expect.arrayContaining([
          { catalog_operation_id: groupOperationIds.CREATE, n: 1 },
          { catalog_operation_id: groupOperationIds.ADD_MEMBER, n: 2 },
          { catalog_operation_id: groupOperationIds.RETIRE, n: 1 },
        ]),
      );
      await expect(
        admin.query('delete from control.authority_group where authority_group_id=$1', [groupId]),
      ).rejects.toThrow('GROUP-TOMBSTONE');
      await expect(
        admin.query(
          `update control.authority_group set state='ACTIVE',row_version=row_version+1 where authority_group_id=$1`,
          [groupId],
        ),
      ).rejects.toThrow('GROUP-TRANSITION');
    } finally {
      await policy.close();
      await service.close();
      await Promise.all([admin.end(), runtime.end(), policyPool.end()]);
    }
  },
  60000,
);

// Supporting regression for pre-existing explicit group-linked grants. The public
// journey above establishes approval/API acceptance; this fixture probes dependency revocation.
integration(
  'bounds explicit group authority by membership validity and revokes its delegation chain',
  async () => {
    const admin = new Pool({ connectionString: adminUrl }),
      runtime = new Pool({ connectionString: runtimeUrl });
    const { runScopedTransaction } =
      await import('../../../services/identity-service/src/db/scoped-transaction.js');
    const { mutateGroup } =
      await import('../../../services/participant-service/src/domain/group-lifecycle.js');
    const groupId = id(),
      assignmentId = id(),
      first = id(),
      second = id(),
      operationId = id();
    try {
      await admin.query(
        `insert into control.authority_group(authority_group_id,participant_id,group_name,state) values($1,$2,$3,'ACTIVE')`,
        [groupId, participantId, `Historical explicit group ${groupId}`],
      );
      await admin.query(
        `insert into control.authority_group_member(participant_id,authority_group_id,principal_id,valid_during,state)
      values($1,$2,$3,tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),'ACTIVE')`,
        [participantId, groupId, operatorId],
      );
      const insertGrant = (grantId: string, upper: string) =>
        admin.query(
          `insert into control.assignment(assignment_id,participant_id,principal_id,authority_group_id,authority_envelope_id,delegation_epoch,scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
      select $1::uuid,participant_id,principal_id,$2,authority_envelope_id,delegation_epoch,scope_digest,tstzrange(clock_timestamp(),clock_timestamp()+$3::interval,'[)'),'ACTIVE',created_by_principal_id,privacy_domain_ids,action_intent_ids,ARRAY[$1::uuid::text],risk_classes,maker_checker_required,step_up_required,2
      from control.assignment where assignment_id='018f0000-0000-7000-8000-000000000122'`,
          [grantId, groupId, upper],
        );
      await expect(insertGrant(id(), '2 hours')).rejects.toThrow('ASSIGNMENT-GROUP');
      await insertGrant(assignmentId, '30 minutes');
      await admin.query(
        `insert into control.delegation(delegation_id,participant_id,parent_assignment_id,grantor_principal_id,delegate_principal_id,delegation_epoch,scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state)
      select $1,participant_id,assignment_id,principal_id,$2,delegation_epoch,scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,1,valid_during,'ACTIVE' from control.assignment where assignment_id=$3`,
        [first, checkerId, assignmentId],
      );
      await admin.query(
        `insert into control.delegation(delegation_id,participant_id,parent_delegation_id,grantor_principal_id,delegate_principal_id,delegation_epoch,scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state)
      select $1,participant_id,delegation_id,delegate_principal_id,$2,delegation_epoch,scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,0,valid_during,'ACTIVE' from control.delegation where delegation_id=$3`,
        [second, operatorId, first],
      );
      const permits = async () =>
        (
          await admin.query(
            `select openpc.assignment_group_permits(participant_id,authority_group_id,principal_id,valid_during) allowed from control.assignment where assignment_id=$1`,
            [assignmentId],
          )
        ).rows[0]!.allowed;
      expect(await permits()).toBe(true);
      const { readAdministrativeAccess } =
        await import('../../../services/participant-service/src/domain/access-review.js');
      const dependencyIds = new Set<string>();
      const review = (after?: string, limit = 50) =>
        runScopedTransaction(
          runtime,
          { participantId, privacyDomainId, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
          id,
          (client) =>
            readAdministrativeAccess(
              client,
              participantId,
              privacyDomainId,
              operatorId,
              { after, limit },
              async (resourceId) => {
                dependencyIds.add(resourceId);
              },
            ),
        );
      const reviewed = await review();
      expect(reviewed.items.find((item) => item.grant.effect.id === second)).toMatchObject({
        current: true,
        ancestry: [{ id: assignmentId }, { id: first }, { id: second }],
        remediation: { id: second, kind: 'delegation' },
        constraints: { resourceIds: [assignmentId], onwardDelegationDepth: 0 },
      });
      expect([...dependencyIds]).toEqual(
        expect.arrayContaining([assignmentId, first, second, groupId]),
      );
      const pagedIds: string[] = [];
      let cursor: string | undefined;
      do {
        const page = await review(cursor, 1);
        pagedIds.push(...page.items.map((item) => item.grant.effect.id));
        cursor = page.nextCursor ?? undefined;
      } while (cursor);
      expect(pagedIds).toEqual(reviewed.items.map((item) => item.grant.effect.id));

      await expect(
        admin.query(
          `update control.authority_group set state='RETIRED',row_version=row_version+1 where authority_group_id=$1`,
          [groupId],
        ),
      ).rejects.toThrow('GROUP-DEPENDENTS');
      const removed = await runScopedTransaction(
        runtime,
        { participantId, privacyDomainId, actionIntentId: action },
        () => operationId,
        async (client) => {
          await client.query(
            'select participant_id from control.participant where participant_id=$1 for update',
            [participantId],
          );
          return mutateGroup(
            client,
            participantId,
            operatorId,
            { mutation: 'REMOVE_MEMBER', groupId, principalId: operatorId },
            operationId,
          );
        },
      );
      expect(removed.revokedAssignments).toBe(1);
      expect((await review()).items.find((item) => item.grant.effect.id === second)).toMatchObject({
        current: false,
        remediation: null,
        reasons: expect.arrayContaining([
          'GRANT_NOT_ACTIVE',
          'DELEGATION_NOT_CURRENT',
          'GROUP_MEMBERSHIP_OR_DIRECTORY_NOT_CURRENT',
        ]),
      });

      expect(await permits()).toBe(false);
      expect(
        (
          await admin.query(
            'select state,last_mutation_operation_id from control.assignment where assignment_id=$1',
            [assignmentId],
          )
        ).rows,
      ).toEqual([{ state: 'REVOKED', last_mutation_operation_id: operationId }]);
      expect(
        (
          await admin.query(
            'select state,last_mutation_operation_id from control.delegation where delegation_id=any($1::uuid[])',
            [[first, second]],
          )
        ).rows,
      ).toEqual([
        { state: 'REVOKED', last_mutation_operation_id: operationId },
        { state: 'REVOKED', last_mutation_operation_id: operationId },
      ]);
      expect(
        (
          await admin.query(
            "select count(*)::int n from control.revocation where target_id=$1 and reason_code='GROUP_MEMBERSHIP_REMOVED'",
            [assignmentId],
          )
        ).rows[0]!.n,
      ).toBe(1);
      await expect(
        admin.query(
          `update control.assignment set state='ACTIVE',row_version=row_version+1 where assignment_id=$1`,
          [assignmentId],
        ),
      ).rejects.toThrow('ASSIGNMENT-GROUP');
    } finally {
      await Promise.all([admin.end(), runtime.end()]);
    }
  },
  15000,
);
