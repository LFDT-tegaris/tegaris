import { execFile } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  type EnvelopeScope,
  decodeEnvelopeProposal,
  encodeEnvelopeScope,
} from '../../../packages/security-kernel/src/index.js';
import { installInitialPlatformEnvelopeScope } from '../../../scripts/operations/installation-platform-authority.mjs';
import { installInitialOperationsEnvironment } from '../../../scripts/operations/installation-generation-store.mjs';
import { readPublicOperationsSources } from '../../../scripts/operations/read-public-installation-sources.mjs';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { captureInitialRootEnvelopeProposal } from '../../../services/identity-service/src/db/identity-envelope-proposal.js';
import type { BoundAuthority } from '../../../services/identity-service/src/db/authority-fence.js';
import { typedEnvelopeCreateCandidate } from '../../../services/participant-service/src/contracts/envelope.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { participantReadbackRuntime } from './participant-readback-runtime.js';
import { digest, sha } from './public-governance-client.js';
import { envelopeActivationSigningFixture } from './envelope-activation-signing-fixture.js';
import { envelopeActivationAttemptCases } from './envelope-activation-attempt-cases.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const container = process.env.OPENPC_ENVELOPE_PROPOSAL_CONTAINER;
const integration = adminUrl && runtimeUrl && container ? it : it.skip;
const execute = promisify(execFile);
const createAction = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const submitAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';

function proposalScope(
  participantId: string,
  privacyDomainId: string,
  resources: readonly string[],
): EnvelopeScope {
  const dimensions = {
    participantIds: [participantId],
    privacyDomainIds: [privacyDomainId],
    resourceIds: [...resources].sort(),
    dataClasses: [],
    targetProfileIds: [],
    riskClasses: ['HIGH'] as ['HIGH'],
  };
  return {
    administration: { ...dimensions, actionIntentIds: [createAction] },
    runtime: {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [],
      capabilityIds: [],
    },
    validFromNs: String(BigInt(Date.now() - 60_000) * 1_000_000n),
    validUntilNs: String(BigInt(Date.now() + 3_600_000) * 1_000_000n),
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
}

async function installationInput(environmentId: string) {
  const schemaBytes = await readFile('config/schema/effective-configuration.schema.json');
  const profileBytes = await readFile('config/profiles/local.yaml');
  const sourceAuthentication = (
    await readPublicOperationsSources({
      sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
      profile: 'local',
    })
  ).custody;
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    schemaBytes,
    profileBytes,
    sourceAuthentication,
    initialBaseGenerationId: id(),
    pins: {
      issuerSpkiHex: key.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
      issuerEpoch: '1',
      issuerValidFromMs: Date.now() - 1000,
      issuerValidUntilMs: Date.now() + 300000,
      environmentId,
      profile: 'local',
      configurationSchemaDigest: `sha256:${sha(schemaBytes).toString('hex')}`,
      namedProfileDigest: `sha256:${sha(profileBytes).toString('hex')}`,
    },
  };
}

it('authenticates envelope lifecycle installation inputs before allocating PostgreSQL', async () => {
  expect(
    (await installationInput('envelope-proposal-preflight')).sourceAuthentication.version,
  ).toBe(1);
  const resources = [
    '018f0000-0000-7000-8000-000000000102',
    '018f0000-0000-7000-8000-000000000101',
  ];
  const scope = proposalScope(id(), id(), resources);
  expect(scope.administration.resourceIds).toEqual([...resources].sort());
  expect(encodeEnvelopeScope(scope).length).toBeGreaterThan(0);
});

integration(
  'preserves populated legacy envelopes and creates, submits and approves a typed proposal through real HTTP owners',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const platform = new Pool({
      connectionString: process.env.OPENPC_I02_PLATFORM_RUNTIME_DATABASE_URL,
      max: 2,
    });
    const installerUrl = new URL(adminUrl!);
    installerUrl.username = 'openpc_envelope_installer';
    installerUrl.password = randomBytes(24).toString('hex');
    const installer = new Pool({ connectionString: installerUrl.href, max: 1 });
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let ungrantedRuntime: Awaited<ReturnType<typeof participantReadbackRuntime>> | undefined;
    let signing: Awaited<ReturnType<typeof envelopeActivationSigningFixture>> | undefined;
    const participantId = id(),
      privacyDomainId = id(),
      collisionPrivacyDomainId = id(),
      envelopeId = id(),
      otherEnvelopeId = id(),
      crossEnvelopeId = id(),
      targetParticipantId = id(),
      targetPrivacyDomainId = id(),
      ungrantedPrincipalId = id(),
      platformContextId = id();
    const environmentId = `envelope-${id().slice(-12)}`;
    // Empty unsupported dimensions grant nothing. This slice never activates authority.
    const scope = proposalScope(participantId, privacyDomainId, [envelopeId, otherEnvelopeId]);
    const crossScope = {
      ...proposalScope(targetParticipantId, targetPrivacyDomainId, [crossEnvelopeId]),
      validFromNs: scope.validFromNs,
      validUntilNs: scope.validUntilNs,
    };
    const installationScope: EnvelopeScope = {
      ...scope,
      administration: {
        ...scope.administration,
        participantIds: [participantId, targetParticipantId].sort(),
        privacyDomainIds: [privacyDomainId, targetPrivacyDomainId].sort(),
        resourceIds: [envelopeId, otherEnvelopeId, crossEnvelopeId].sort(),
      },
    };
    try {
      await admin.query(
        `create role openpc_envelope_installer login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '${installerUrl.password}'`,
      );
      await admin.query('grant openpc_control_owner to openpc_envelope_installer');
      await admin.query('grant connect on database openpc_control to openpc_envelope_installer');
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Independent envelope initial trust','ACTIVE',1)`,
        [participantId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Envelope governance','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [privacyDomainId, participantId],
      );
      await admin.query(
        'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
        [participantId, privacyDomainId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
         values($1,$2,'Independent cache-isolation context','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [collisionPrivacyDomainId, participantId],
      );
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch)
        values($1,'Independent target initial trust','ACTIVE',1)`,
        [targetParticipantId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
        values($1,$2,'Target privacy','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [targetPrivacyDomainId, targetParticipantId],
      );
      await admin.query(
        'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
        [targetParticipantId, targetPrivacyDomainId],
      );
      const installationDigest = await installInitialOperationsEnvironment(
        installer,
        { participantId, privacyDomainId },
        await installationInput(environmentId),
      );
      await installInitialPlatformEnvelopeScope(installer, {
        platformContextId,
        ownerParticipantId: participantId,
        installationPrivacyDomainId: privacyDomainId,
        platformAuthorityEpoch: '1',
        environmentId,
        installationDigest,
        grantable: installationScope,
      });
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
        {
          existingScope: true,
          participantRuntime: platform,
          initialPlatformContext: { id: platformContextId, epoch: '1' },
        },
      );
      // Independent initial identity with no role, envelope or assignment.
      // This is authentication bootstrap only, before any envelope business work.
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
        values($1,$2,'PLATFORM_OPERATOR','Ungrantable initial reader','ACTIVE',1)`,
        [ungrantedPrincipalId, participantId],
      );
      await admin.query('insert into control.identity_subject(identity_subject_id) values($1)', [
        ungrantedPrincipalId,
      ]);
      await admin.query(
        'insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$1)',
        [ungrantedPrincipalId, participantId],
      );
      ungrantedRuntime = await participantReadbackRuntime({
        runtime: platform,
        identityDatabaseUrl: runtimeUrl!,
        participantId,
        privacyDomainId,
        operatorPrincipalId: ungrantedPrincipalId,
        checkerPrincipalId: fixture.governance.checker.principalId,
      });
      const ungranted = {
        ...(await ungrantedRuntime.login('operator')),
        principalId: ungrantedPrincipalId,
      };
      await admin.query(
        "update control.session set context_mode='PLATFORM',privacy_domain_id=null where session_id=$1",
        [ungranted.sessionId],
      );
      const ungrantedSession = await fetch(`${fixture.service.identityUrl}/api/v1/session`, {
        headers: { Cookie: `__Host-openpc_session=${ungranted.sessionToken}` },
      });
      expect(ungrantedSession.status).toBe(200);
      expect(await ungrantedSession.json()).toMatchObject({
        principalId: ungrantedPrincipalId,
        contextMode: 'PLATFORM',
      });
      const legacy = await admin.query(
        'select * from control.authority_envelope order by authority_envelope_id',
      );
      const column = await admin.query(
        `select attnum from pg_attribute where attrelid='control.authority_envelope'::regclass and attname='creator_participant_id'`,
      );
      const foreignKeys = await admin.query(
        `select conname,pg_get_constraintdef(oid) definition from pg_constraint where conrelid='control.authority_envelope'::regclass and contype='f' order by conname`,
      );
      await execute(
        'docker',
        [
          'exec',
          '-e',
          'PGHOST=127.0.0.1',
          '-e',
          'PGUSER=postgres',
          '-e',
          'PGDATABASE=openpc_control',
          container!,
          'sh',
          '/local/migrate.sh',
          'control',
        ],
        { timeout: 120000, maxBuffer: 1024 * 1024 },
      );
      const upgraded = await admin.query(
        'select * from control.authority_envelope order by authority_envelope_id',
      );
      expect(upgraded.rows).toEqual(
        legacy.rows.map((row) => ({
          ...row,
          representation: 'LEGACY',
          issuer_participant_id: null,
          issuer_privacy_domain_id: null,
        })),
      );
      expect(
        (
          await admin.query(
            `select attnum from pg_attribute where attrelid='control.authority_envelope'::regclass and attname='creator_participant_id'`,
          )
        ).rows,
      ).toEqual(column.rows);
      const upgradedKeys = await admin.query(
        `select conname,pg_get_constraintdef(oid) definition from pg_constraint where conrelid='control.authority_envelope'::regclass and contype='f' order by conname`,
      );
      expect(upgradedKeys.rows).toEqual(expect.arrayContaining(foreignKeys.rows));
      expect(
        (await admin.query('select count(*) from control.identity_envelope_proposal')).rows[0]
          .count,
      ).toBe('0');

      signing = await envelopeActivationSigningFixture(admin, {
        participantId,
        privacyDomainId,
        environmentId,
      });
      const { client, maker, checker } = fixture.governance;
      const review = async (
        approvalId: string,
        actor = checker,
        privacy = privacyDomainId,
        issuer = participantId,
      ) => {
        const response = await fetch(
          `${fixture!.governance.policyUrl}/api/v1/approval-requests/urn:openpc:resource:${approvalId}/candidate`,
          {
            headers: {
              'Connection': 'close',
              'Cookie': `__Host-openpc_session=${actor.sessionToken}`,
              'OpenPC-Participant-ID': `urn:openpc:participant:${issuer}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
              'OpenPC-API-Version': '1',
              'X-Request-ID': id(),
              'X-Correlation-ID': id(),
            },
          },
        );
        return {
          status: response.status,
          cacheControl: response.headers.get('cache-control'),
          body: await response.json(),
        };
      };
      const readEnvelope = async (
        actor = maker,
        target = participantId,
        privacy = privacyDomainId,
        resource = envelopeId,
      ) => {
        const response = await fetch(
          `${fixture!.service.participantUrl()}/v1/participants/${target}/envelopes/${resource}`,
          {
            headers: {
              'Authorization': `Bearer ${actor.sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
            },
          },
        );
        return {
          status: response.status,
          cacheControl: response.headers.get('cache-control'),
          body: await response.json(),
        };
      };
      expect(
        (
          await admin.query(
            `select count(*) from control.assignment assignment
        join control.authority_role role on role.participant_id=assignment.participant_id and role.role_id=assignment.role_id
        where assignment.participant_id=$1 and assignment.principal_id=any($2::uuid[]) and role.state='ACTIVE'`,
            [participantId, [maker.principalId, checker.principalId]],
          )
        ).rows[0].count,
      ).toBe('2');
      const body = {
        schema: 'pc.identity.authority-envelope-proposal',
        schemaVersion: 1,
        envelopeId,
        issuance: 'PLATFORM_ROOT',
        usable: scope,
        grantable: scope,
      };
      const candidate = { ...body, id: envelopeId, participantId, state: 'DRAFT' };
      const candidateDigest = digest(candidate);
      const key = `envelope-create-${id()}`;
      const send = async (
        approvalId = id(),
        requestedBody = body,
        requestKey = key,
        target = participantId,
      ) =>
        client.request(
          `${fixture!.service.participantUrl()}/v1/participants/${target}/envelopes`,
          maker,
          requestedBody,
          {
            'Authorization': `Bearer ${maker.sessionToken}`,
            'X-CSRF-Token': await client.csrf(
              maker,
              createAction,
              fixture!.service.participantUrl(),
            ),
            'Idempotency-Key': requestKey,
            'X-OpenPC-Aggregate-Version': '0',
            'X-OpenPC-Approval-Request-ID': approvalId,
            'OpenPC-Action-Intent-Digest': client.actionDigests.get(createAction)!,
          },
        );
      const effects = async (resource = envelopeId) =>
        (
          await admin.query(
            `select
      (select count(*) from control.identity_envelope_proposal where envelope_id=$1)::text proposals,
      (select count(*) from control.authority_envelope where authority_envelope_id=$1)::text envelopes,
      (select count(*) from control.outbox_event where aggregate_type='authority-envelope' and aggregate_id=$1)::text events,
      (select count(*) from control.idempotency_record where participant_id=any($2::uuid[]) and action_intent_id='ACT-PARTICIPANTS_READ_RESOURCE-V1')::text read_operations`,
            [resource, [participantId, targetParticipantId]],
          )
        ).rows[0];
      const staged = await send();
      expect(staged.status, JSON.stringify(staged)).toBeGreaterThanOrEqual(400);
      expect(await effects()).toEqual({
        proposals: '0',
        envelopes: '0',
        events: '0',
        read_operations: '0',
      });
      const requestApproval = (hash: string, reason: string) => ({
        actionIntentId: submitAction,
        actionIntentDigest: client.actionDigests.get(submitAction)!,
        candidateDigest: hash,
        makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
        reason,
      });
      const approve = async (ref: string, hash: string) => {
        const inputDigest = digest({
          actionIntentId: approveAction,
          approvalRequestId: ref,
          candidateDigest: hash,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        await client.stepUp(checker, approveAction, ref.slice(-36), inputDigest);
        const result = await client.policyMutation(
          checker,
          `/api/v1/approval-requests/${ref}/approve`,
          {
            targetRef: ref,
            actionIntentId: approveAction,
            actionIntentDigest: client.actionDigests.get(approveAction),
            inputDigest,
            expectedRevision: '1',
            reason: 'Independent exact-envelope review.',
          },
          '1',
        );
        expect(result.status, JSON.stringify(result)).toBe(202);
        return result;
      };
      const createApproval = await client.policyMutation(
        maker,
        '/api/v1/approval-requests',
        requestApproval(candidateDigest, 'Approve exact envelope creation.'),
      );
      expect(createApproval.status, JSON.stringify(createApproval)).toBe(202);
      const creationReview = await review(String(createApproval.body.resourceRef).slice(-36));
      expect(creationReview).toMatchObject({
        status: 200,
        cacheControl: 'no-store',
        body: { candidate, candidateDigest, runtimePermission: 'NONE' },
      });
      await approve(String(createApproval.body.resourceRef), candidateDigest);
      await client.stepUp(maker, createAction, envelopeId, candidateDigest);
      const priorDenials = fixture.service.identityDenials().length;
      const created = await send(String(createApproval.body.resourceRef).slice(-36));
      if (created.status !== 201) {
        // Discriminate the original failed CREATE without creating/replacing
        // business intent, consuming another proof, or changing authority.
        const actors = await admin.query<{ maker: BoundAuthority; checker: BoundAuthority }>(
          `select
          jsonb_build_object('principalId',c.maker_principal_id,'sessionId',c.maker_session_id,'sessionEpoch',c.maker_session_epoch::text,
            'participantEpoch',c.maker_participant_epoch::text,'principalEpoch',c.maker_principal_epoch::text,
            'assignmentId',c.maker_assignment_id,'assignmentRowVersion',c.maker_assignment_row_version::text,
            'authorityEnvelopeId',c.maker_authority_envelope_id,'authorityEpoch',c.maker_authority_epoch::text,
            'delegationEpoch',c.maker_delegation_epoch::text,'privacyDomainId',c.privacy_domain_id,
            'actionIntentId',c.action_intent_id,'resourceId',c.resource_id) maker,
          jsonb_build_object('principalId',d.approver_principal_id,'sessionId',d.approver_session_id,'sessionEpoch',d.approver_session_epoch::text,
            'participantEpoch',d.approver_participant_epoch::text,'principalEpoch',d.approver_principal_epoch::text,
            'assignmentId',d.approver_assignment_id,'assignmentRowVersion',d.approver_assignment_row_version::text,
            'authorityEnvelopeId',d.approver_authority_envelope_id,'authorityEpoch',d.approver_envelope_epoch::text,
            'delegationEpoch',d.approver_delegation_epoch::text,'privacyDomainId',d.privacy_domain_id,
            'actionIntentId',c.action_intent_id,'resourceId',c.resource_id) checker
          from control.mutation_candidate c join control.approval_request r on r.participant_id=c.participant_id and r.subject_id=c.mutation_candidate_id
          join control.approval_decision_record d on d.participant_id=r.participant_id and d.approval_request_id=r.approval_request_id
          where c.participant_id=$1 and c.resource_id=$2 and r.approval_request_id=$3`,
          [participantId, envelopeId, String(createApproval.body.resourceRef).slice(-36)],
        );
        expect(actors.rowCount).toBe(1);
        await runScopedTransaction(
          platform,
          { participantId, privacyDomainId, actionIntentId: createAction },
          id,
          async (c, operationId) => {
            const original = actors.rows[0]!;
            return captureInitialRootEnvelopeProposal(
              c,
              { participantId, privacyDomainId, actionIntentId: createAction, operationId },
              typedEnvelopeCreateCandidate.parse(candidate),
              '1',
              original.maker,
              original.checker,
            );
          },
        );
      }
      expect(
        created.status,
        JSON.stringify({
          created,
          identityDenials: fixture.service.identityDenials().slice(priorDenials),
        }),
      ).toBe(201);
      expect(created.body).toMatchObject({ id: envelopeId, state: 'DRAFT' });
      expect(created.body.semanticDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(await send(String(createApproval.body.resourceRef).slice(-36))).toEqual(created);
      const beforeReadback = await effects();
      await fixture.service.restartParticipant();
      const draft = await readEnvelope();
      expect(draft, JSON.stringify(draft)).toMatchObject({
        status: 200,
        cacheControl: 'no-store',
        body: { effect: created.body },
      });
      expect(draft.body.operationId).toMatch(/^[0-9a-f-]{36}$/u);
      // The recovery input comes only from the restarted public owner. SQL
      // inspection below is an independent encoding oracle, not client state.
      const proposalDigest: string = draft.body.effect.semanticDigest;
      for (const actor of [maker, checker]) {
        expect(await readEnvelope(actor)).toEqual(draft);
        const consumed = await review(String(createApproval.body.resourceRef).slice(-36), actor);
        expect(consumed).toMatchObject({
          status: 200,
          cacheControl: 'no-store',
          body: {
            candidate,
            candidateDigest,
            operationRef: `urn:openpc:operation:${draft.body.operationId}`,
            runtimePermission: 'NONE',
          },
        });
        expect(consumed.body.candidate).toEqual(candidate);
      }
      for (const deniedRead of [
        await readEnvelope(ungranted),
        await readEnvelope(maker, id()),
        await readEnvelope(maker, participantId, id()),
        await readEnvelope(maker, participantId, privacyDomainId, id()),
      ]) {
        expect(deniedRead.status).toBeGreaterThanOrEqual(400);
        expect(deniedRead.body.effect).toBeUndefined();
      }
      expect(await effects()).toEqual(beforeReadback);
      const stored = (
        await admin.query('select * from control.identity_envelope_proposal where envelope_id=$1', [
          envelopeId,
        ])
      ).rows[0];
      expect(stored.state).toBe('DRAFT');
      expect(`sha256:${stored.proposal_digest.toString('hex')}`).toBe(proposalDigest);
      expect(decodeEnvelopeProposal(stored.proposal_cbor)).toMatchObject({
        envelopeId,
        participantId,
        issuance: 'PLATFORM_ROOT',
      });
      // An independent finite target has a different Participant and privacy
      // domain. Issuer disclosure must not invent an issuer privacy grant in
      // the target envelope; complete scope is separately read from CREATE.
      const crossBody = {
        ...body,
        envelopeId: crossEnvelopeId,
        usable: crossScope,
        grantable: crossScope,
      };
      const crossCandidate = {
        ...crossBody,
        id: crossEnvelopeId,
        participantId: targetParticipantId,
        state: 'DRAFT',
      };
      const crossDigest = digest(crossCandidate);
      const crossKey = `envelope-cross-create-${id()}`;
      expect(
        (await send(id(), crossBody, crossKey, targetParticipantId)).status,
      ).toBeGreaterThanOrEqual(400);
      const crossApproval = await client.policyMutation(
        maker,
        '/api/v1/approval-requests',
        requestApproval(crossDigest, 'Approve the independent finite target envelope.'),
      );
      expect(crossApproval.status, JSON.stringify(crossApproval)).toBe(202);
      await approve(String(crossApproval.body.resourceRef), crossDigest);
      await client.stepUp(maker, createAction, crossEnvelopeId, crossDigest);
      const crossCreated = await send(
        String(crossApproval.body.resourceRef).slice(-36),
        crossBody,
        crossKey,
        targetParticipantId,
      );
      expect(crossCreated.status, JSON.stringify(crossCreated)).toBe(201);
      expect(crossCreated.body.privacyDomainIds).toEqual([targetPrivacyDomainId]);
      expect(
        await send(
          String(crossApproval.body.resourceRef).slice(-36),
          crossBody,
          crossKey,
          targetParticipantId,
        ),
      ).toEqual(crossCreated);
      await fixture.service.restartParticipant();
      const beforeCrossRead = await effects(crossEnvelopeId);
      for (const actor of [maker, checker]) {
        const crossRead = await readEnvelope(
          actor,
          targetParticipantId,
          privacyDomainId,
          crossEnvelopeId,
        );
        expect(crossRead, JSON.stringify(crossRead)).toMatchObject({
          status: 200,
          cacheControl: 'no-store',
          body: { effect: { ...crossCreated.body, privacyDomainIds: [] } },
        });
        const crossReview = await review(String(crossApproval.body.resourceRef).slice(-36), actor);
        expect(crossReview, JSON.stringify(crossReview)).toMatchObject({
          status: 200,
          cacheControl: 'no-store',
          body: {
            candidate: crossCandidate,
            candidateDigest: crossDigest,
            operationRef: `urn:openpc:operation:${crossRead.body.operationId}`,
            runtimePermission: 'NONE',
          },
        });
        for (const deniedRead of [
          await readEnvelope(actor, targetParticipantId, targetPrivacyDomainId, crossEnvelopeId),
          await readEnvelope(actor, participantId, privacyDomainId, crossEnvelopeId),
        ]) {
          expect(deniedRead.status).toBeGreaterThanOrEqual(400);
          expect(deniedRead.body.effect).toBeUndefined();
        }
      }
      expect(await effects(crossEnvelopeId)).toEqual(beforeCrossRead);
      // A second genuinely created DRAFT makes both challenge targets eligible;
      // denial below must come from the persisted resource binding, not lookup.
      const otherBody = { ...body, envelopeId: otherEnvelopeId };
      const otherDigest = digest({
        ...otherBody,
        id: otherEnvelopeId,
        participantId,
        state: 'DRAFT',
      });
      const otherKey = `envelope-create-${id()}`;
      expect((await send(id(), otherBody, otherKey)).status).toBeGreaterThanOrEqual(400);
      const otherApproval = await client.policyMutation(
        maker,
        '/api/v1/approval-requests',
        requestApproval(otherDigest, 'Approve an independent envelope proposal.'),
      );
      expect(otherApproval.status, JSON.stringify(otherApproval)).toBe(202);
      await approve(String(otherApproval.body.resourceRef), otherDigest);
      await client.stepUp(maker, createAction, otherEnvelopeId, otherDigest);
      expect(
        (await send(String(otherApproval.body.resourceRef).slice(-36), otherBody, otherKey)).status,
      ).toBe(201);
      const beforeSubmission = await effects();
      const submission = requestApproval(proposalDigest, 'Submit canonical typed envelope.');
      const denied = await client.policyMutation(maker, '/api/v1/approval-requests', submission);
      expect(denied.status, JSON.stringify(denied)).toBeGreaterThanOrEqual(400);
      expect(await effects()).toEqual(beforeSubmission);
      await expect(
        client.stepUp(maker, submitAction, envelopeId, digest(submission), otherEnvelopeId),
      ).rejects.toThrow();
      expect(
        (
          await admin.query(
            `select count(*) from control.mfa_challenge
        where participant_id=$1 and principal_id=$2 and action_intent_id=$3 and resource_id=$4
          and resource_digest=$5 and consumed_at is not null`,
            [
              participantId,
              maker.principalId,
              submitAction,
              envelopeId,
              Buffer.from(digest(submission).slice(7), 'hex'),
            ],
          )
        ).rows[0].count,
      ).toBe('0');
      expect(await effects()).toEqual(beforeSubmission);
      // A fresh proof over the proposal digest is still the wrong submission intent.
      await client.stepUp(maker, submitAction, envelopeId, proposalDigest);
      expect(
        (await client.policyMutation(maker, '/api/v1/approval-requests', submission)).status,
      ).toBeGreaterThanOrEqual(400);
      expect(await effects()).toEqual(beforeSubmission);
      await expect(client.stepUp(maker, submitAction, id(), digest(submission))).rejects.toThrow();
      expect(await effects()).toEqual(beforeSubmission);
      await client.stepUp(maker, submitAction, envelopeId, digest(submission));
      const proof = (
        await admin.query(
          `select mfa_challenge_id,resource_id,signer_credential_id,signer_credential_epoch
        from control.mfa_challenge where participant_id=$1 and principal_id=$2 and action_intent_id=$3
        and resource_id=$4 and resource_digest=$5 and consumed_at is not null`,
          [
            participantId,
            maker.principalId,
            submitAction,
            envelopeId,
            Buffer.from(digest(submission).slice(7), 'hex'),
          ],
        )
      ).rows;
      expect(proof).toHaveLength(1);
      expect(proof[0]).toMatchObject({ resource_id: envelopeId, signer_credential_epoch: '1' });
      expect(proof[0].signer_credential_id).toBeTruthy();
      for (const assignment of [
        'resource_id=NULL',
        'signer_credential_epoch=2',
        'consumed_at=NULL',
      ]) {
        await expect(
          admin.query(`update control.mfa_challenge set ${assignment} where mfa_challenge_id=$1`, [
            proof[0].mfa_challenge_id,
          ]),
        ).rejects.toThrow(/STEP-UP-(BINDING|VERIFICATION)-IMMUTABLE/u);
      }
      const changedIntent = await client.policyMutation(maker, '/api/v1/approval-requests', {
        ...submission,
        reason: 'A changed review reason.',
      });
      expect(changedIntent.status, JSON.stringify(changedIntent)).toBeGreaterThanOrEqual(400);
      expect(await effects()).toEqual(beforeSubmission);
      const submissions = await Promise.all([
        client.policyMutation(maker, '/api/v1/approval-requests', submission),
        client.policyMutation(maker, '/api/v1/approval-requests', submission),
      ]);
      expect(submissions.filter((result) => result.status === 202)).toHaveLength(1);
      expect(submissions.filter((result) => result.status >= 400)).toHaveLength(1);
      const submitted = submissions.find((result) => result.status === 202)!;
      expect(submitted.status, JSON.stringify(submitted)).toBe(202);
      expect(
        (
          await admin.query(
            `select used_operation_id::text from control.mfa_challenge where mfa_challenge_id=$1`,
            [proof[0].mfa_challenge_id],
          )
        ).rows,
      ).toEqual([{ used_operation_id: submitted.body.operationId }]);
      const submissionId = String(submitted.body.resourceRef).slice(-36);
      const submittedEnvelope = await readEnvelope();
      expect(submittedEnvelope, JSON.stringify(submittedEnvelope)).toMatchObject({
        status: 200,
        body: {
          operationId: submitted.body.operationId,
          effect: { id: envelopeId, state: 'SUBMITTED', semanticDigest: proposalDigest },
        },
      });
      const publicProposal = {
        schema: 'pc.identity.authority-envelope-review',
        schemaVersion: 1,
        envelopeId,
        participantId,
        semanticRevision: '1',
        participantEpoch: '1',
        authorityEpoch: '1',
        delegationEpoch: '0',
        issuance: 'PLATFORM_ROOT',
        usable: scope,
        grantable: scope,
      };
      for (const actor of [maker, checker]) {
        const currentReview = await review(submissionId, actor);
        expect(currentReview).toMatchObject({
          status: 200,
          cacheControl: 'no-store',
          body: {
            candidateDigest: proposalDigest,
            candidate: publicProposal,
            state: 'APPROVAL_REQUESTED',
            operationRef: `urn:openpc:operation:${submitted.body.operationId}`,
            approvalUsable: false,
            canRequestResume: false,
            runtimePermission: 'NONE',
          },
        });
        expect(currentReview.body.candidate).toEqual(publicProposal);
        expect(JSON.stringify(currentReview.body)).not.toContain(maker.sessionId);
      }
      for (const deniedReview of [
        await review(submissionId, checker, id()),
        await review(submissionId, checker, privacyDomainId, id()),
      ]) {
        expect(deniedReview.status).toBeGreaterThanOrEqual(400);
        expect(deniedReview.body.candidate).toBeUndefined();
      }
      const afterSubmission = await effects();
      expect(
        (await client.policyMutation(maker, '/api/v1/approval-requests', submission)).status,
      ).toBeGreaterThanOrEqual(400);
      expect(await effects()).toEqual(afterSubmission);
      const approvalResult = await approve(String(submitted.body.resourceRef), proposalDigest);
      const approvedEnvelope = await readEnvelope();
      expect(approvedEnvelope, JSON.stringify(approvedEnvelope)).toMatchObject({
        status: 200,
        body: {
          operationId: approvalResult.body.operationId,
          effect: { id: envelopeId, state: 'APPROVED', semanticDigest: proposalDigest },
        },
      });
      const finalReview = await review(submissionId);
      expect(finalReview).toMatchObject({
        status: 200,
        cacheControl: 'no-store',
        body: {
          state: 'APPROVED',
          candidate: publicProposal,
          approvalUsable: false,
          canRequestResume: false,
          runtimePermission: 'NONE',
        },
      });
      const approved = (
        await admin.query('select * from control.identity_envelope_proposal where envelope_id=$1', [
          envelopeId,
        ])
      ).rows[0];
      expect(approved).toMatchObject({
        state: 'APPROVED',
        row_version: '3',
        proposal_cbor: stored.proposal_cbor,
        proposal_digest: stored.proposal_digest,
      });
      expect(approved.submission_checker_authority.binding).toEqual(
        approved.submission_checker.authority,
      );
      expect(approved.submission_checker.stepUpChallengeId).not.toBe(
        approved.submission_maker.stepUpChallengeId,
      );
      await envelopeActivationAttemptCases({
        admin,
        platform,
        fixture,
        signing,
        envelopeId,
        environmentId,
        approve,
        collisionPrivacyDomainId,
      });
      for (const forbidden of [
        {
          sql: 'update control.identity_envelope_proposal set target_participant_id=$2 where envelope_id=$1',
          values: [envelopeId, otherEnvelopeId],
          error: 'permission denied for table identity_envelope_proposal',
        },
        {
          sql: "update control.identity_envelope_proposal set state='DRAFT',row_version=4 where envelope_id=$1",
          values: [envelopeId],
          error: 'ENVELOPE-HISTORY',
        },
        {
          sql: "update control.authority_envelope set state='ACTIVE',row_version=4,last_mutation_operation_id=$2 where authority_envelope_id=$1",
          values: [envelopeId, id()],
          error: 'ENVELOPE-SEALED-ACTIVATION-REQUIRED',
        },
      ]) {
        await expect(
          runScopedTransaction(
            platform,
            { participantId, privacyDomainId, actionIntentId: createAction },
            id,
            (scoped) => scoped.query(forbidden.sql, forbidden.values),
          ),
        ).rejects.toThrow(forbidden.error);
      }
      expect(
        (
          await admin.query(
            'select state,representation,principal_id,checker_principal_id from control.authority_envelope where authority_envelope_id=$1',
            [envelopeId],
          )
        ).rows,
      ).toEqual([
        {
          state: 'APPROVED',
          representation: 'TYPED_V1',
          principal_id: null,
          checker_principal_id: checker.principalId,
        },
      ]);
      await fixture.restartPolicy();
      await fixture.service.restartParticipant();
      expect(await readEnvelope()).toEqual(approvedEnvelope);
      expect(await review(submissionId)).toEqual(finalReview);
      expect(
        (
          await fixture.approvalRead(
            String(submitted.body.resourceRef).slice(-36),
            'checker',
            privacyDomainId,
            false,
          )
        ).status,
      ).toBe(200);
      expect(
        (
          await admin.query(
            'select state from control.identity_envelope_proposal where envelope_id=$1',
            [envelopeId],
          )
        ).rows[0].state,
      ).toBe('APPROVED');
      // Public context rotation revokes the original Platform session. That
      // history remains readable to another currently authorized issuer actor.
      const beforeRotation = await effects();
      await fixture.selectPrivacyContext('maker');
      expect(fixture.governance.maker.sessionId).not.toBe(maker.sessionId);
      expect(
        (
          await admin.query(
            'select state,revoked_reason from control.session where session_id=$1',
            [maker.sessionId],
          )
        ).rows,
      ).toEqual([{ state: 'REVOKED', revoked_reason: 'context-rotation' }]);
      const deniedAfterRotation = await readEnvelope();
      expect(deniedAfterRotation.status).toBeGreaterThanOrEqual(400);
      expect(deniedAfterRotation.body.effect).toBeUndefined();
      expect(await readEnvelope(checker)).toEqual(approvedEnvelope);
      expect(
        (await review(String(createApproval.body.resourceRef).slice(-36), checker)).body.candidate,
      ).toEqual(candidate);
      expect(await effects()).toEqual(beforeRotation);
    } finally {
      await signing?.close();
      await ungrantedRuntime?.close();
      await fixture?.close();
      await installer.end();
      await platform.end();
      await admin.end();
    }
  },
  180000,
);
