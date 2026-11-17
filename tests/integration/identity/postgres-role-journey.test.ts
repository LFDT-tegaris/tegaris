import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { participantReadbackRuntime } from './participant-readback-runtime.js';
import {
  buildPolicyService,
  HttpPolicyIdentityGateway,
} from '../../../services/module-registry/src/policy-http.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { canonicalJson } from '../../../services/module-registry/src/domain/digest.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const operatorId = '018f0000-0000-7000-8000-000000000111';
const checkerId = '018f0000-0000-7000-8000-000000000112';
const roleAction = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
const createApprovalAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
const stepUpAction = 'ACT-IDENTITY_UPDATE_STEP_UP-V1';
const sha = (value: string | Buffer) => createHash('sha256').update(value).digest();
const digest = (value: unknown) => `sha256:${sha(canonicalJson(value)).toString('hex')}`;
interface Session {
  sessionToken: string;
  sessionId: string;
}

// Initial trust contains public authenticator keys, without private bootstrap certificates.
// Every role approval, role effect, session and challenge uses its real owner.
// The public recovery journey separately exercises credential enrollment and return.
integration(
  'creates and archives roles through public approval and verified WebAuthn owners',
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
    const roleId = id();
    const restrictedPrincipalId = id();
    const sharedSubjectId = id();
    const sharedMemberId = id();
    const otherMemberId = id();
    const otherParticipantId = id();
    let restricted: Awaited<ReturnType<typeof participantReadbackRuntime>> | undefined;
    const devices = new Map<
      string,
      {
        credentialId: string;
        privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
        count: number;
      }
    >();
    try {
      // Initial directory trust for a projection regression, not acceptance of
      // cross-Participant membership linking. Its read grant below is public.
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch)
        values ($1,'Initial second membership context','ACTIVE',1)`,
        [otherParticipantId],
      );
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
        values ($1,$2,'USER','Shared subject local member','ACTIVE',1),
               ($3,$4,'USER','Shared subject other member','SUSPENDED',2)`,
        [sharedMemberId, participantId, otherMemberId, otherParticipantId],
      );
      await admin.query(`insert into control.identity_subject(identity_subject_id) values ($1)`, [
        sharedSubjectId,
      ]);
      await admin.query(
        `insert into control.participant_membership(membership_id,participant_id,identity_subject_id)
        values ($1,$2,$3),($4,$5,$3)`,
        [sharedMemberId, participantId, sharedSubjectId, otherMemberId, otherParticipantId],
      );
      // A separate initial identity starts with no authority. Its restricted
      // role-read assignment below is created through the public grant owner.
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
        values ($1,$2,'USER','Initial catalogue reader','ACTIVE',1)`,
        [restrictedPrincipalId, participantId],
      );
      // Initial trust grants the operator bounded onward delegation. All new
      // assignments/delegations and their approvals below use public owners.
      await admin.query(`update control.authority_envelope set onward_delegation_depth=2,runtime_capability_ids=ARRAY['CALL_RESULT_DISCLOSURE']
        where authority_envelope_id='018f0000-0000-7000-8000-000000000121'`);
      await admin.query(`update control.assignment set onward_delegation_depth=2,runtime_capability_ids=ARRAY['CALL_RESULT_DISCLOSURE']
        where assignment_id='018f0000-0000-7000-8000-000000000122'`);
      for (const principalId of [operatorId, checkerId]) {
        const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' });
        const credentialId = id();
        await admin.query(
          `insert into control.credential
        (credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from)
        values ($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute')`,
          [credentialId, participantId, principalId, sha(publicKey), publicKey],
        );
        devices.set(principalId, { credentialId, privateKey: keys.privateKey, count: 0 });
      }
      let maker = await service.login('operator');
      let checker = await service.login('viewer');
      let makerPrincipalId = operatorId;
      let checkerPrincipalId = checkerId;
      const actions = await admin.query<{ action_intent_id: string; digest: string }>(
        "select action_intent_id,'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent",
      );
      const actionDigests = new Map(actions.rows.map((row) => [row.action_intent_id, row.digest]));
      const origin = service.identityUrl;
      const request = async (
        url: string,
        session: Session,
        body: unknown,
        headers: Record<string, string> = {},
        method: 'POST' | 'DELETE' = 'POST',
      ) => {
        // HTTP Host must survive the test ingress hop, as it does through Envoy.
        // Node fetch replaces that header with the destination socket's host.
        return new Promise<{ status: number; body: Record<string, unknown> }>((resolve, reject) => {
          const payload = JSON.stringify(body);
          const outbound = httpRequest(
            url,
            {
              method,
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': String(Buffer.byteLength(payload)),
                'Cookie': `__Host-openpc_session=${session.sessionToken}`,
                'Origin': new URL(url).origin,
                ...headers,
              },
              signal: AbortSignal.timeout(10000),
            },
            (response) => {
              const chunks: Buffer[] = [];
              response.on('data', (chunk: Buffer) => chunks.push(chunk));
              response.on('error', reject);
              response.on('end', () => {
                try {
                  resolve({
                    status: response.statusCode!,
                    body: JSON.parse(Buffer.concat(chunks).toString()) as Record<string, unknown>,
                  });
                } catch (error) {
                  reject(error);
                }
              });
            },
          );
          outbound.on('error', reject);
          outbound.end(payload);
        });
      };
      const csrf = async (session: Session, action: string, targetOrigin: string) => {
        const value = await request(
          `${origin}/api/v1/session/csrf`,
          session,
          { actionIntentId: action },
          { Origin: targetOrigin, Host: new URL(targetOrigin).host },
        );
        expect(value.status, JSON.stringify(value.body)).toBe(200);
        return value.body.csrfToken as string;
      };
      const stepUp = async (
        session: Session,
        principalId: string,
        action: string,
        resourceId: string,
        resourceDigest: string,
        expectedStatus = 200,
      ) => {
        const token = await csrf(session, action, origin);
        const rpIdHash = `sha256:${sha(new URL(origin).hostname).toString('hex')}`;
        const challenge = await request(
          `${origin}/v1/identity/webauthn/assertion/challenge`,
          session,
          { actionIntentId: action, resourceId, resourceDigest, rpIdHash },
          { 'X-CSRF-Token': token },
        );
        expect(challenge.status, JSON.stringify(challenge.body)).toBe(200);
        const device = devices.get(principalId)!;
        const clientData = Buffer.from(
          JSON.stringify({ type: 'webauthn.get', challenge: challenge.body.challenge, origin }),
        );
        const authenticatorData = Buffer.alloc(37);
        sha(new URL(origin).hostname).copy(authenticatorData);
        authenticatorData[32] = 5;
        authenticatorData.writeUInt32BE(++device.count, 33);
        const signature = sign(
          'sha256',
          Buffer.concat([authenticatorData, sha(clientData)]),
          device.privateKey,
        );
        const version = await admin.query(
          'select row_version::text from control.session where session_id=$1',
          [session.sessionId],
        );
        const verified = await request(
          `${origin}/v1/identity/webauthn/assertion/verify`,
          session,
          {
            actionIntentId: action,
            resourceId,
            resourceDigest,
            rpIdHash,
            challenge: challenge.body.challenge,
            assertion: JSON.stringify({
              credentialId: device.credentialId,
              authenticatorData: authenticatorData.toString('base64url'),
              clientDataJson: clientData.toString('base64url'),
              signature: signature.toString('base64url'),
            }),
          },
          {
            'X-CSRF-Token': token,
            'Idempotency-Key': `step-up-${id()}`,
            'X-OpenPC-Aggregate-Version': version.rows[0].row_version,
            'OpenPC-Action-Intent-Digest': actionDigests.get(stepUpAction)!,
          },
        );
        expect(verified.status, JSON.stringify(verified.body)).toBe(expectedStatus);
      };
      const policyMutation = async (
        session: Session,
        path: string,
        body: Record<string, unknown>,
        revision?: string,
      ) => {
        const action = body.actionIntentId as string;
        return request(`${policyUrl}${path}`, session, body, {
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
          'Idempotency-Key': `role-approval-${id()}`,
          'X-CSRF-Token': await csrf(session, action, policyUrl),
          'OpenPC-Action-Intent-Digest': actionDigests.get(action)!,
          'X-OpenPC-Action-Intent-Digest': actionDigests.get(action)!,
          ...(revision === undefined
            ? {}
            : {
                'If-Match': `"${digest({ resourceId: (body.targetRef as string).slice(-36), revision })}"`,
              }),
        });
      };
      const participantMutation = async (
        path: string,
        body: unknown,
        key: string,
        revision: string,
        approvalId = '018f0000-0000-7000-8000-000000000001',
        action = roleAction,
      ) =>
        request(
          `${path.startsWith('/v1/identity/') ? service.identityUrl : service.participantUrl()}${path}`,
          maker,
          body,
          {
            ...(path.startsWith('/v1/identity/')
              ? {}
              : { Authorization: `Bearer ${maker.sessionToken}` }),
            'X-CSRF-Token': await csrf(
              maker,
              action,
              path.startsWith('/v1/identity/') ? service.identityUrl : service.participantUrl(),
            ),
            'Idempotency-Key': key,
            'X-OpenPC-Aggregate-Version': revision,
            'X-OpenPC-Approval-Request-ID': approvalId,
            'OpenPC-Action-Intent-Digest': actionDigests.get(action)!,
          },
          /\/(?:assignments|delegations)\/[0-9a-f-]{36}$/u.test(path) ? 'DELETE' : 'POST',
        );
      const prepareGoverned = async (
        path: string,
        body: unknown,
        candidate: unknown,
        resourceId: string,
        revision: string,
        expected: number | undefined,
        action = roleAction,
      ) => {
        const key = `role-journey-${id()}`;
        const candidateDigest = digest(candidate);
        const staged = await participantMutation(path, body, key, revision, undefined, action);
        expect(staged.status, `${path}: ${JSON.stringify(staged.body)}`).toBe(
          path.startsWith('/v1/identity/') ? 409 : 403,
        );
        if (path.startsWith('/v1/identity/'))
          expect(staged.body).toMatchObject({ error: { code: 'PC-IDENTITY-1005' } });
        if (path.startsWith('/v1/identity/')) {
          const getProposal = async (
            privacy = privacyDomainId,
            requestedDigest = candidateDigest,
          ) => {
            const response = await fetch(
              `${service.identityUrl}/v1/identity/principal-proposals/${requestedDigest}`,
              {
                headers: {
                  'Cookie': `__Host-openpc_session=${checker.sessionToken}`,
                  'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
                },
              },
            );
            return {
              status: response.status,
              cache: response.headers.get('cache-control'),
              body: await response.json(),
            };
          };
          const proposal = await getProposal();
          expect(proposal).toMatchObject({
            status: 200,
            cache: 'no-store',
            body: {
              candidateDigest,
              resourceId,
              expectedRevision: revision,
              proposedPrincipal: {
                principalId: resourceId,
                participantId,
                kind: 'USER',
                state: (candidate as { state: string }).state,
              },
            },
          });
          expect(JSON.stringify(proposal.body)).not.toContain('idempotency');
          expect(JSON.stringify(proposal.body)).not.toContain(maker.sessionToken);
          expect((await getProposal(id())).status).toBe(404);
          expect((await getProposal(privacyDomainId, `sha256:${'f'.repeat(64)}`)).status).toBe(404);
        }
        if (path.includes('/roles')) {
          const proposal = await service.get(
            maker.sessionToken,
            candidateDigest,
            privacyDomainId,
            'role-proposals',
          );
          expect(proposal.status, JSON.stringify(proposal.body)).toBe(200);
          expect(proposal.body).toMatchObject({
            candidateDigest,
            resourceId,
            expectedRevision: revision,
            mutation: revision === '0' ? 'CREATE' : 'ARCHIVE',
            proposedRole: {
              id: resourceId,
              participantId,
              displayName: 'Public governance auditors',
              actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
              state: revision === '0' ? 'ACTIVE' : 'ARCHIVED',
            },
          });
          expect(
            (
              await service.get(
                maker.sessionToken,
                candidateDigest,
                '018f0000-0000-7000-8000-000000000999',
                'role-proposals',
              )
            ).status,
          ).toBe(404);
          expect(
            (
              await service.get(
                maker.sessionToken,
                `sha256:${'f'.repeat(64)}`,
                privacyDomainId,
                'role-proposals',
              )
            ).status,
          ).toBe(404);
          expect(JSON.stringify(proposal.body)).not.toContain('idempotency');
          expect(JSON.stringify(proposal.body)).not.toContain(maker.sessionToken);
        }
        if (/\/(?:assignments|delegations)(?:\/|$)/u.test(path)) {
          const proposal = await service.get(
            checker.sessionToken,
            candidateDigest,
            privacyDomainId,
            'grant-proposals',
          );
          expect(
            proposal,
            `${path}: stage=${JSON.stringify(staged.body)}; identity=${JSON.stringify(service.identityDenials())}`,
          ).toMatchObject({
            status: 200,
            cacheControl: 'no-store',
            body: {
              candidateDigest,
              resourceId,
              expectedRevision: revision,
              kind: path.includes('/assignments') ? 'assignment' : 'delegation',
              mutation: revision === '0' ? 'CREATE' : 'REVOKE',
              proposedGrant: {
                id: resourceId,
                participantId,
                privacyDomainIds: [privacyDomainId],
                state: revision === '0' ? 'ACTIVE' : 'REVOKED',
              },
            },
          });
          expect(JSON.stringify(proposal.body)).not.toContain('idempotency');
          expect(JSON.stringify(proposal.body)).not.toContain('last_mutation');
          expect(
            (await service.get(checker.sessionToken, candidateDigest, id(), 'grant-proposals'))
              .status,
          ).toBe(404);
          expect(
            (
              await service.get(
                checker.sessionToken,
                `sha256:${'e'.repeat(64)}`,
                privacyDomainId,
                'grant-proposals',
              )
            ).status,
          ).toBe(404);
        }
        const created = await policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: createApprovalAction,
          actionIntentDigest: actionDigests.get(createApprovalAction),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${makerPrincipalId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerPrincipalId}`,
          reason: 'Approve this exact participant role change.',
        });
        expect(created.status, JSON.stringify(created.body)).toBe(202);
        const approvalRef = created.body.resourceRef as string;
        const approvalId = approvalRef.slice(-36);
        const decisionDigest = digest({
          actionIntentId: approveAction,
          approvalRequestId: approvalRef,
          candidateDigest,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        const decision = {
          targetRef: approvalRef,
          actionIntentId: approveAction,
          actionIntentDigest: actionDigests.get(approveAction),
          inputDigest: decisionDigest,
          expectedRevision: '1',
          reason: 'Distinct reviewer approves the bounded role change.',
        };
        await stepUp(maker, makerPrincipalId, approveAction, approvalId, decisionDigest);
        expect(
          (
            await policyMutation(
              maker,
              `/api/v1/approval-requests/${approvalRef}/approve`,
              decision,
              '1',
            )
          ).status,
        ).toBe(403);
        await stepUp(checker, checkerPrincipalId, approveAction, approvalId, decisionDigest);
        const approved = await policyMutation(
          checker,
          `/api/v1/approval-requests/${approvalRef}/approve`,
          decision,
          '1',
        );
        expect(approved.status, JSON.stringify(approved.body)).toBe(202);
        await stepUp(maker, makerPrincipalId, action, resourceId, candidateDigest);
        return async () => {
          const effect = await participantMutation(path, body, key, revision, approvalId, action);
          if (expected !== undefined)
            expect(effect.status, JSON.stringify(effect.body)).toBe(expected);
          return { key, approvalId, effect };
        };
      };
      const governed = async (...args: Parameters<typeof prepareGoverned>) =>
        (await prepareGoverned(...args))();
      const path = `/v1/participants/${participantId}/roles`;
      const body = {
        roleId,
        displayName: 'Public governance auditors',
        actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
      };
      const candidate = {
        id: roleId,
        roleId: `urn:openpc:role:${roleId}`,
        participantId,
        displayName: body.displayName,
        actionIntentIds: body.actionIntentIds,
        state: 'ACTIVE',
      };
      const created = await governed(path, body, candidate, roleId, '0', 201);
      expect(created.effect.body).toMatchObject({
        ...candidate,
        revision: '1',
        origin: 'GOVERNED',
      });
      // Simulate a caller losing the committed response: retry exactly and read the owner after restart.
      expect(await participantMutation(path, body, created.key, '0', created.approvalId)).toEqual(
        created.effect,
      );
      expect(
        (
          await participantMutation(
            path,
            { ...body, displayName: 'Changed after approval' },
            created.key,
            '0',
            created.approvalId,
          )
        ).status,
      ).toBe(403);
      const before = await service.get(maker.sessionToken, roleId, privacyDomainId, 'roles');
      expect(before).toMatchObject({
        status: 200,
        body: { effect: created.effect.body, operationId: expect.any(String) },
      });
      await service.restartParticipant();
      expect(await service.get(maker.sessionToken, roleId, privacyDomainId, 'roles')).toEqual(
        before,
      );
      const secondRoleId = id();
      await governed(
        path,
        { ...body, roleId: secondRoleId },
        { ...candidate, id: secondRoleId, roleId: `urn:openpc:role:${secondRoleId}` },
        secondRoleId,
        '0',
        201,
      );
      const catalogue = async (
        sessionToken: string,
        query: Record<string, string> = {},
        privacy = privacyDomainId,
        owner = service,
      ) => {
        const response = await fetch(
          `${owner.participantUrl()}${path}?${new URLSearchParams(query)}`,
          {
            headers: {
              'Authorization': `Bearer ${sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
            },
          },
        );
        return {
          status: response.status,
          cache: response.headers.get('cache-control'),
          body: await response.json(),
        };
      };
      const firstPage = await catalogue(maker.sessionToken, {
        search: 'PUBLIC GOVERNANCE',
        limit: '1',
      });
      expect(firstPage).toMatchObject({
        status: 200,
        cache: 'no-store',
        body: {
          items: [{ effect: { id: roleId, state: 'ACTIVE' } }],
          nextCursor: roleId,
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          observedAt: expect.any(String),
        },
      });
      const secondPage = await catalogue(maker.sessionToken, {
        search: 'PUBLIC GOVERNANCE',
        limit: '1',
        after: firstPage.body.nextCursor,
      });
      expect(secondPage.body).toMatchObject({
        items: [{ effect: { id: secondRoleId } }],
        nextCursor: null,
      });
      expect(
        (await catalogue(maker.sessionToken, { search: 'unmatched catalogue search' })).body,
      ).toMatchObject({
        items: [],
        nextCursor: null,
        authorizedEmpty: true,
        completeness: 'COMPLETE',
      });
      expect((await catalogue(maker.sessionToken, {}, id())).status).toBe(404);
      expect((await catalogue(maker.sessionToken, { limit: '0' })).status).toBe(400);
      expect(JSON.stringify(firstPage.body)).not.toContain('createdByPrincipalId');
      const readerId = id();
      const principalBody = {
        principalId: readerId,
        displayLabel: 'Governed role reader',
        kind: 'USER',
      };
      const provisioned = await governed(
        '/v1/identity/principals',
        principalBody,
        { ...principalBody, participantId, state: 'PROVISIONED', identityEpoch: '0' },
        readerId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(provisioned.effect.body).toMatchObject({
        principalId: readerId,
        state: 'PROVISIONED',
        identityEpoch: '0',
      });
      const activationPath = `/v1/identity/principals/${readerId}/activate`;
      const activated = await governed(
        activationPath,
        {},
        { principalId: readerId, state: 'ACTIVE' },
        readerId,
        '1',
        200,
      );
      expect(activated.effect.body).toMatchObject({
        principalId: readerId,
        state: 'ACTIVE',
        identityEpoch: '1',
        revision: '2',
      });
      expect(
        await participantMutation(activationPath, {}, activated.key, '1', activated.approvalId),
      ).toEqual(activated.effect);
      const readPrincipal = async (target = readerId, privacy = privacyDomainId) => {
        const response = await fetch(`${service.identityUrl}/v1/identity/principals/${target}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${maker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        });
        return {
          status: response.status,
          cache: response.headers.get('cache-control'),
          body: await response.json(),
        };
      };
      const principalCatalogue = async (
        query: Record<string, string> = {},
        sessionToken = maker.sessionToken,
        privacy = privacyDomainId,
        owner = service,
      ) => {
        const response = await fetch(
          `${owner.identityUrl}/v1/identity/principals?${new URLSearchParams(query)}`,
          {
            headers: {
              'Cookie': `__Host-openpc_session=${sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
            },
          },
        );
        return {
          status: response.status,
          cache: response.headers.get('cache-control'),
          body: await response.json(),
        };
      };
      const principals = await principalCatalogue({
        search: 'GOVERNED ROLE',
        state: 'ACTIVE',
        kind: 'USER',
      });
      expect(principals).toMatchObject({
        status: 200,
        cache: 'no-store',
        body: {
          items: [{ effect: { principalId: readerId, state: 'ACTIVE', kind: 'USER' } }],
          nextCursor: null,
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          observedAt: expect.any(String),
        },
      });
      expect(principals.body.items).toHaveLength(1);
      const pageOne = await principalCatalogue({ limit: '1' });
      expect(pageOne.status).toBe(200);
      expect(pageOne.body.items).toHaveLength(1);
      expect(pageOne.body.nextCursor).toBe(pageOne.body.items[0].effect.principalId);
      const pageTwo = await principalCatalogue({ limit: '1', after: pageOne.body.nextCursor });
      expect(pageTwo.status).toBe(200);
      expect(pageTwo.body.items[0].effect.principalId > pageOne.body.nextCursor).toBe(true);
      for (const query of [
        { search: 'unmatched principal' },
        { search: 'GOVERNED ROLE', state: 'SUSPENDED' },
        { search: '%' },
        { search: 'Shared subject other member' },
      ]) {
        expect((await principalCatalogue(query)).body).toMatchObject({
          items: [],
          nextCursor: null,
          completeness: 'COMPLETE',
          authorizedEmpty: true,
        });
      }
      expect((await principalCatalogue({}, maker.sessionToken, id())).status).toBe(404);
      expect((await principalCatalogue({ limit: '0' })).status).toBe(400);
      expect((await principalCatalogue({ unsupported: 'value' })).status).toBe(400);
      expect(JSON.stringify(principals.body)).not.toContain('createdByPrincipalId');
      const principalReadback = await readPrincipal();
      expect(principalReadback).toMatchObject({
        status: 200,
        cache: 'no-store',
        body: {
          effect: activated.effect.body,
          operationId: expect.any(String),
        },
      });
      expect((await readPrincipal(id())).status).toBe(404);
      expect((await readPrincipal(readerId, id())).status).toBe(404);
      expect(Object.keys(principalReadback.body.effect).sort()).toEqual([
        'displayLabel',
        'identityEpoch',
        'identitySubjectId',
        'kind',
        'membershipId',
        'participantId',
        'principalId',
        'revision',
        'state',
      ]);
      const readHumanIdentity = async (
        resource: 'identity-subjects' | 'memberships',
        target = readerId,
        privacy = privacyDomainId,
      ) => {
        const response = await fetch(`${service.identityUrl}/v1/identity/${resource}/${target}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${maker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        });
        return {
          status: response.status,
          cache: response.headers.get('cache-control'),
          body: await response.json(),
        };
      };
      // AF30-REQ-86DA0B827BFD2B35639D7C0C / AF30-REQ-9E65BCA89586E2A15B42B826:
      // these records come from the public provision owner, never seeded intermediate business state.
      const subjectReadback = await readHumanIdentity('identity-subjects');
      expect(subjectReadback).toMatchObject({
        status: 200,
        cache: 'no-store',
        body: {
          effect: { identitySubjectId: readerId, createdAt: expect.any(String) },
          membership: {
            principalId: readerId,
            membershipId: readerId,
            identitySubjectId: readerId,
            participantId,
            state: 'ACTIVE',
            revision: '2',
          },
        },
      });
      expect(Object.keys(subjectReadback.body.effect).sort()).toEqual([
        'createdAt',
        'identitySubjectId',
      ]);
      const membershipReadback = await readHumanIdentity('memberships');
      expect(membershipReadback).toMatchObject({
        status: 200,
        cache: 'no-store',
        body: {
          effect: {
            membershipId: readerId,
            identitySubjectId: readerId,
            participantId,
            state: 'ACTIVE',
            revision: '2',
            membershipEpoch: '1',
          },
          operationId: principalReadback.body.operationId,
        },
      });
      for (const resource of ['identity-subjects', 'memberships'] as const) {
        expect((await readHumanIdentity(resource, id())).status).toBe(404);
        expect((await readHumanIdentity(resource, readerId, id())).status).toBe(404);
      }
      const unrelatedParticipant = id();
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch)
        values ($1,'Initial isolated identity reader','ACTIVE',1)`,
        [unrelatedParticipant],
      );
      const hiddenBindings = await runScopedTransaction(
        runtime,
        {
          participantId: unrelatedParticipant,
          actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        },
        id,
        async (client) => ({
          subjects: (
            await client.query(
              `select identity_subject_id from control.identity_subject where identity_subject_id=$1`,
              [readerId],
            )
          ).rows,
          memberships: (
            await client.query(
              `select membership_id from control.participant_membership where membership_id=$1`,
              [readerId],
            )
          ).rows,
        }),
      );
      expect(hiddenBindings).toEqual({ subjects: [], memberships: [] });
      await expect(
        admin.query(`update control.principal set kind='WORKLOAD' where principal_id=$1`, [
          readerId,
        ]),
      ).rejects.toThrow('PC-IDENTITY-1002-MEMBERSHIP-KIND');
      const initialWorkload = id();
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
        values ($1,$2,'WORKLOAD','Initial non-human identity','ACTIVE',1)`,
        [initialWorkload, participantId],
      );
      await expect(
        admin.query(
          `insert into control.participant_membership(membership_id,participant_id,identity_subject_id)
        values ($1,$2,$3)`,
          [initialWorkload, participantId, readerId],
        ),
      ).rejects.toThrow('PC-IDENTITY-1002-MEMBERSHIP-KIND');
      await expect(
        admin.query(
          `update control.participant_membership set identity_subject_id=$2 where membership_id=$1`,
          [readerId, operatorId],
        ),
      ).rejects.toThrow('DATA-6020-IMMUTABLE-ROW');
      expect(await readHumanIdentity('memberships')).toEqual(membershipReadback);
      // Changed bindings fail at immutable candidate staging, before maker-checker admission.
      for (const denied of [
        await participantMutation(activationPath, {}, activated.key, '2', activated.approvalId),
        await participantMutation(
          `/v1/identity/principals/${id()}/activate`,
          {},
          activated.key,
          '1',
          activated.approvalId,
        ),
      ])
        expect(denied).toMatchObject({
          status: 403,
          body: { error: { code: 'PC-IDENTITY-1004' } },
        });
      expect(await readPrincipal()).toEqual(principalReadback);
      await service.restartIdentity();
      expect(await readPrincipal()).toEqual(principalReadback);
      expect(await readHumanIdentity('identity-subjects')).toEqual(subjectReadback);
      expect(await readHumanIdentity('memberships')).toEqual(membershipReadback);
      expect(
        await participantMutation(activationPath, {}, activated.key, '1', activated.approvalId),
      ).toEqual(activated.effect);
      const principalEvidence = await admin.query(
        `select catalog_operation_id,count(*)::int effects from control.mutation_evidence
         where participant_id=$1 and aggregate_id=$2 group by catalog_operation_id order by catalog_operation_id`,
        [participantId, readerId],
      );
      expect(principalEvidence.rows).toEqual([
        { catalog_operation_id: 'ID-OP-PRINCIPAL-ACTIVATE', effects: 1 },
        { catalog_operation_id: 'ID-OP-PRINCIPAL-PROVISION', effects: 1 },
      ]);
      const envelopeReadback = await service.get(
        maker.sessionToken,
        '018f0000-0000-7000-8000-000000000121',
        privacyDomainId,
        'envelopes',
      );
      expect(envelopeReadback).toMatchObject({
        status: 200,
        cacheControl: 'no-store',
        body: {
          effect: { state: 'ACTIVE', privacyDomainIds: [privacyDomainId] },
          operationId: null,
        },
      });
      expect(
        (
          await service.get(
            maker.sessionToken,
            '018f0000-0000-7000-8000-000000000121',
            id(),
            'envelopes',
          )
        ).status,
      ).toBe(404);
      const assignmentId = id();
      const assignmentBody = {
        assignmentId,
        principalId: readerId,
        roleId: candidate.roleId,
        authorityEnvelopeId: '018f0000-0000-7000-8000-000000000121',
        scopeDigest: digest({ roleId, assignmentId }),
        privacyDomainIds: [privacyDomainId],
        actionIntentIds: body.actionIntentIds,
        resourceIds: [roleId],
        riskClasses: ['LOW'],
        validFrom: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
        validUntil: '2030-01-01T00:00:00.000Z',
        makerCheckerRequired: true,
        stepUpRequired: true,
        onwardDelegationDepth: 0,
      };
      const assigned = await governed(
        `/v1/participants/${participantId}/assignments`,
        assignmentBody,
        {
          id: assignmentId,
          participantId,
          state: 'ACTIVE',
          delegationEpoch: '0',
          ...assignmentBody,
        },
        assignmentId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(assigned.effect.body).toMatchObject({
        id: assignmentId,
        roleId: candidate.roleId,
        state: 'ACTIVE',
      });
      // TS-ID-AUTHORIZATION: an approved candidate still cannot introduce a
      // second effective path. Denial must preserve the earlier durable grant.
      const assignmentCandidate = (
        value: Omit<typeof assignmentBody, 'roleId'> & { roleId?: string },
      ) => ({
        id: value.assignmentId,
        participantId,
        state: 'ACTIVE',
        delegationEpoch: '0',
        ...value,
      });
      const catalogueAssignment: Omit<typeof assignmentBody, 'roleId'> & { roleId?: string } = {
        ...assignmentBody,
        assignmentId: id(),
        principalId: restrictedPrincipalId,
        actionIntentIds: [
          'ACT-PARTICIPANTS_READ_COLLECTION-V1',
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        ],
        resourceIds: [participantId, roleId, sharedMemberId, 'identity-session'],
      };
      delete catalogueAssignment.roleId;
      await governed(
        `/v1/participants/${participantId}/assignments`,
        catalogueAssignment,
        assignmentCandidate(catalogueAssignment),
        catalogueAssignment.assignmentId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      // Session authority is bound to the actor's real principal resource.
      // Grant only self effective-access; principal discovery remains restricted.
      const selfContextAssignment = {
        ...catalogueAssignment,
        assignmentId: id(),
        actionIntentIds: ['ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'],
        resourceIds: [restrictedPrincipalId],
      };
      await governed(
        `/v1/participants/${participantId}/assignments`,
        selfContextAssignment,
        assignmentCandidate(selfContextAssignment),
        selfContextAssignment.assignmentId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      restricted = await participantReadbackRuntime({
        runtime,
        identityDatabaseUrl: runtimeUrl!,
        participantId,
        privacyDomainId,
        operatorPrincipalId: restrictedPrincipalId,
        checkerPrincipalId: checkerId,
      });
      const restrictedSession = await restricted.login('operator');
      const limited = await catalogue(
        restrictedSession.sessionToken,
        { search: 'Public governance' },
        privacyDomainId,
        restricted,
      );
      expect(limited.status).toBe(200);
      expect(limited.body.items.map((item: { effect: { id: string } }) => item.effect.id)).toEqual([
        roleId,
      ]);
      expect(limited.body.nextCursor).toBeNull();
      expect(JSON.stringify(limited.body)).not.toContain(secondRoleId);
      const limitedPrincipals = await principalCatalogue(
        {},
        restrictedSession.sessionToken,
        privacyDomainId,
        restricted,
      );
      expect(limitedPrincipals.status).toBe(200);
      expect(
        limitedPrincipals.body.items.map(
          (item: { effect: { principalId: string } }) => item.effect.principalId,
        ),
      ).toEqual([sharedMemberId]);
      expect(limitedPrincipals.body.nextCursor).toBeNull();
      expect(JSON.stringify(limitedPrincipals.body)).not.toContain(readerId);
      expect(JSON.stringify(limitedPrincipals.body)).not.toContain(otherMemberId);
      expect(
        (
          await principalCatalogue(
            { search: 'Governed role reader' },
            restrictedSession.sessionToken,
            privacyDomainId,
            restricted,
          )
        ).body,
      ).toMatchObject({ items: [], authorizedEmpty: true });
      const sharedReadResponse = await fetch(
        `${restricted.identityUrl}/v1/identity/identity-subjects/${sharedSubjectId}`,
        {
          headers: {
            'Cookie': `__Host-openpc_session=${restrictedSession.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          },
        },
      );
      expect(sharedReadResponse.status).toBe(200);
      const sharedRead = await sharedReadResponse.json();
      expect(sharedRead).toMatchObject({
        effect: { identitySubjectId: sharedSubjectId },
        membership: {
          membershipId: sharedMemberId,
          participantId,
          state: 'ACTIVE',
          identityEpoch: '1',
        },
      });
      expect(JSON.stringify(sharedRead)).not.toContain(otherMemberId);
      expect(JSON.stringify(sharedRead)).not.toContain(otherParticipantId);
      const otherMemberResponse = await fetch(
        `${restricted.identityUrl}/v1/identity/memberships/${otherMemberId}`,
        {
          headers: {
            'Cookie': `__Host-openpc_session=${restrictedSession.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          },
        },
      );
      expect(otherMemberResponse.status).toBe(404);
      expect(
        (
          await restricted.get(
            restrictedSession.sessionToken,
            secondRoleId,
            privacyDomainId,
            'roles',
          )
        ).status,
      ).toBe(404);
      const conflicting = { ...assignmentBody, assignmentId: id(), resourceIds: ['*'] };
      const denied = await governed(
        `/v1/participants/${participantId}/assignments`,
        conflicting,
        assignmentCandidate(conflicting),
        conflicting.assignmentId,
        '0',
        403,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(denied.effect.body).toMatchObject({ error: { code: 'PC-IDENTITY-1002' } });
      expect((await service.get(maker.sessionToken, assignmentId)).body).toMatchObject({
        effect: { id: assignmentId, state: 'ACTIVE' },
        revision: '1',
      });
      // Prepare both public approvals and exact WebAuthn bindings before racing
      // the commits. A root fence admits exactly one of the overlapping grants.
      const disjointResource = id();
      const contenders = [id(), id()].map((assignmentId) => ({
        ...assignmentBody,
        assignmentId,
        resourceIds: [disjointResource],
      }));
      const commits = [];
      for (const contender of contenders)
        commits.push(
          await prepareGoverned(
            `/v1/participants/${participantId}/assignments`,
            contender,
            assignmentCandidate(contender),
            contender.assignmentId,
            '0',
            undefined,
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
          ),
        );
      const raced = await Promise.all(commits.map((commit) => commit()));
      expect(raced.map((result) => result.effect.status).sort()).toEqual([201, 403]);
      expect(raced.find((result) => result.effect.status === 403)!.effect.body).toMatchObject({
        error: { code: 'PC-IDENTITY-1002' },
      });
      const effects = await admin.query(
        `select assignment_id from control.assignment where assignment_id=any($1::uuid[])`,
        [[conflicting.assignmentId, ...contenders.map((value) => value.assignmentId)]],
      );
      expect(effects.rowCount).toBe(1);
      const admissionEvidence = await admin.query(
        `select aggregate_id from control.mutation_evidence
          where catalog_operation_id='ID-OP-ASSIGNMENT-CREATE' and aggregate_id=any($1::uuid[])`,
        [[conflicting.assignmentId, ...contenders.map((value) => value.assignmentId)]],
      );
      expect(admissionEvidence.rows.map((row) => row.aggregate_id)).toEqual(
        effects.rows.map((row) => row.assignment_id),
      );
      const delegatedResource = id();
      const delegationBody = {
        delegationId: id(),
        parentId: '018f0000-0000-7000-8000-000000000122',
        granteeId: readerId,
        scopeDigest: digest({ delegatedResource }),
        privacyDomainIds: [privacyDomainId],
        actionIntentIds: assignmentBody.actionIntentIds,
        resourceIds: [delegatedResource],
        riskClasses: ['LOW'],
        validFrom: assignmentBody.validFrom,
        validUntil: assignmentBody.validUntil,
        makerCheckerRequired: true,
        stepUpRequired: true,
        onwardDelegationDepth: 0,
      };
      const delegateCandidate = (value: typeof delegationBody) => ({
        id: value.delegationId,
        participantId,
        grantorId: operatorId,
        state: 'ACTIVE',
        delegationEpoch: '0',
        ...value,
      });
      const delegated = await governed(
        `/v1/participants/${participantId}/delegations`,
        delegationBody,
        delegateCandidate(delegationBody),
        delegationBody.delegationId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(delegated.effect.body).toMatchObject({
        id: delegationBody.delegationId,
        state: 'ACTIVE',
      });
      const duplicateDelegation = { ...delegationBody, delegationId: id() };
      const delegationDenial = await governed(
        `/v1/participants/${participantId}/delegations`,
        duplicateDelegation,
        delegateCandidate(duplicateDelegation),
        duplicateDelegation.delegationId,
        '0',
        403,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(delegationDenial.effect.body).toMatchObject({ error: { code: 'PC-IDENTITY-1002' } });
      const delegateOverAssignment = {
        ...delegationBody,
        delegationId: id(),
        resourceIds: [roleId],
      };
      const reverseDenial = await governed(
        `/v1/participants/${participantId}/delegations`,
        delegateOverAssignment,
        delegateCandidate(delegateOverAssignment),
        delegateOverAssignment.delegationId,
        '0',
        403,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(reverseDenial.effect.body).toMatchObject({ error: { code: 'PC-IDENTITY-1002' } });
      const assignmentOverDelegate = {
        ...assignmentBody,
        assignmentId: id(),
        resourceIds: [delegatedResource],
      };
      const forwardDenial = await governed(
        `/v1/participants/${participantId}/assignments`,
        assignmentOverDelegate,
        assignmentCandidate(assignmentOverDelegate),
        assignmentOverDelegate.assignmentId,
        '0',
        403,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(forwardDenial.effect.body).toMatchObject({ error: { code: 'PC-IDENTITY-1002' } });
      const wrongParent = {
        ...delegationBody,
        delegationId: id(),
        parentId: '018f0000-0000-7000-8000-000000000132',
        resourceIds: [id()],
      };
      const parentDenial = await governed(
        `/v1/participants/${participantId}/delegations`,
        wrongParent,
        delegateCandidate(wrongParent),
        wrongParent.delegationId,
        '0',
        422,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(parentDenial.effect.body).toMatchObject({ error: { code: 'PC-IDENTITY-1003' } });
      const deniedGrantIds = [
        duplicateDelegation.delegationId,
        delegateOverAssignment.delegationId,
        assignmentOverDelegate.assignmentId,
        wrongParent.delegationId,
      ];
      expect(
        (
          await admin.query(
            `select aggregate_id from control.mutation_evidence
        where aggregate_id=any($1::uuid[])`,
            [deniedGrantIds],
          )
        ).rowCount,
      ).toBe(0);
      expect(
        (
          await admin.query(
            `select delegation_id from control.delegation
        where delegation_id=any($1::uuid[])`,
            [deniedGrantIds],
          )
        ).rowCount,
      ).toBe(0);
      expect(
        (
          await admin.query(
            `select aggregate_id from control.outbox_event
        where aggregate_type in ('assignment','delegation') and aggregate_id=any($1::uuid[])`,
            [deniedGrantIds],
          )
        ).rowCount,
      ).toBe(0);
      const concurrentResource = id();
      const delegationContenders = [id(), id()].map((delegationId) => ({
        ...delegationBody,
        delegationId,
        resourceIds: [concurrentResource],
      }));
      const delegationCommits = [];
      for (const contender of delegationContenders)
        delegationCommits.push(
          await prepareGoverned(
            `/v1/participants/${participantId}/delegations`,
            contender,
            delegateCandidate(contender),
            contender.delegationId,
            '0',
            undefined,
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
          ),
        );
      const delegationRace = await Promise.all(delegationCommits.map((commit) => commit()));
      expect(delegationRace.map((result) => result.effect.status).sort()).toEqual([201, 403]);
      expect(
        delegationRace.find((result) => result.effect.status === 403)!.effect.body,
      ).toMatchObject({ error: { code: 'PC-IDENTITY-1002' } });
      const replayAssignment = await participantMutation(
        `/v1/participants/${participantId}/assignments`,
        assignmentBody,
        assigned.key,
        '0',
        assigned.approvalId,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(replayAssignment).toEqual(assigned.effect);
      // Public two-hop delegation and cascading revocation; administrative
      // grantability is distinct from the runtime capability being delegated.
      const parentDelegation = {
        ...delegationBody,
        delegationId: id(),
        granteeId: checkerId,
        actionIntentIds: [],
        capabilityIds: ['CALL_RESULT_DISCLOSURE'],
        resourceIds: [id()],
        onwardDelegationDepth: 1,
      };
      await governed(
        `/v1/participants/${participantId}/delegations`,
        parentDelegation,
        delegateCandidate(parentDelegation),
        parentDelegation.delegationId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      [maker, checker] = [checker, maker];
      [makerPrincipalId, checkerPrincipalId] = [checkerPrincipalId, makerPrincipalId];
      const childDelegation = {
        ...parentDelegation,
        delegationId: id(),
        parentId: parentDelegation.delegationId,
        granteeId: readerId,
        onwardDelegationDepth: 0,
      };
      await governed(
        `/v1/participants/${participantId}/delegations`,
        childDelegation,
        { ...delegateCandidate(childDelegation), grantorId: checkerId },
        childDelegation.delegationId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      [maker, checker] = [checker, maker];
      [makerPrincipalId, checkerPrincipalId] = [checkerPrincipalId, makerPrincipalId];
      const childBefore = await service.get(
        maker.sessionToken,
        childDelegation.delegationId,
        privacyDomainId,
        'delegations',
      );
      expect(childBefore).toMatchObject({
        status: 200,
        body: {
          revision: '1',
          operationId: expect.any(String),
          effect: { state: 'ACTIVE', parentId: parentDelegation.delegationId },
        },
      });
      await governed(
        `/v1/participants/${participantId}/delegations/${parentDelegation.delegationId}`,
        {},
        { kind: 'delegation', targetId: parentDelegation.delegationId },
        parentDelegation.delegationId,
        '1',
        200,
      );
      expect(
        (
          await service.get(
            maker.sessionToken,
            childDelegation.delegationId,
            privacyDomainId,
            'delegations',
          )
        ).status,
      ).toBe(404);
      maker = await service.login('operator');
      checker = await service.login('viewer');
      const parentAfter = await service.get(
        maker.sessionToken,
        parentDelegation.delegationId,
        privacyDomainId,
        'delegations',
      );
      const childAfter = await service.get(
        maker.sessionToken,
        childDelegation.delegationId,
        privacyDomainId,
        'delegations',
      );
      expect(parentAfter).toMatchObject({
        status: 200,
        body: { revision: '2', effect: { state: 'REVOKED' } },
      });
      expect(childAfter).toMatchObject({
        status: 200,
        body: {
          revision: '2',
          effect: { state: 'REVOKED' },
          operationId: (parentAfter.body as { operationId: string }).operationId,
        },
      });
      expect((childAfter.body as { operationId: string }).operationId).not.toBe(
        (childBefore.body as { operationId: string }).operationId,
      );
      expect(
        (await service.get(maker.sessionToken, childDelegation.delegationId, id(), 'delegations'))
          .status,
      ).toBe(404);
      expect(
        (await service.get(maker.sessionToken, id(), privacyDomainId, 'delegations')).status,
      ).toBe(404);
      await service.restartParticipant();
      expect(
        await service.get(
          maker.sessionToken,
          childDelegation.delegationId,
          privacyDomainId,
          'delegations',
        ),
      ).toEqual(childAfter);
      const descendantRevocation = await admin.query(
        `select reason_code from control.revocation
        where target_type='delegation' and target_id=$1`,
        [childDelegation.delegationId],
      );
      expect(descendantRevocation.rows).toEqual([{ reason_code: 'ANCESTOR_REVOKED' }]);
      const archived = await governed(
        `${path}/${roleId}/archive`,
        {},
        { roleId, state: 'ARCHIVED' },
        roleId,
        '1',
        200,
      );
      expect(archived.effect.body).toMatchObject({
        effect: { state: 'ARCHIVED', revision: '2' },
        revokedAssignments: 2,
      });
      expect((await service.get(maker.sessionToken, roleId, privacyDomainId, 'roles')).status).toBe(
        404,
      );
      maker = await service.login('operator');
      checker = await service.login('viewer');
      const after = await service.get(maker.sessionToken, roleId, privacyDomainId, 'roles');
      expect(
        (await catalogue(maker.sessionToken, { search: 'Public governance', state: 'ARCHIVED' }))
          .body.items,
      ).toMatchObject([{ effect: { id: roleId, state: 'ARCHIVED' } }]);
      expect(
        (await catalogue(maker.sessionToken, { search: 'Public governance', state: 'ACTIVE' })).body
          .items,
      ).toMatchObject([{ effect: { id: secondRoleId, state: 'ACTIVE' } }]);
      expect(after).toMatchObject({ status: 200, body: { effect: archived.effect.body.effect } });
      const revoked = await service.get(maker.sessionToken, assignmentId);
      expect(revoked).toMatchObject({
        status: 200,
        body: {
          effect: { state: 'REVOKED' },
          revision: '2',
          operationId: (after.body as { operationId: string }).operationId,
        },
      });
      // TS-ID-REVOCATION: session invalidation advances the Participant epoch,
      // while unrelated active envelopes retain their delegation lineage.
      const postRevocationAssignment: Omit<typeof assignmentBody, 'roleId'> & { roleId?: string } =
        {
          ...assignmentBody,
          assignmentId: id(),
          resourceIds: [id()],
        };
      delete postRevocationAssignment.roleId;
      await stepUp(
        checker,
        checkerPrincipalId,
        'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        postRevocationAssignment.assignmentId,
        digest(assignmentCandidate(postRevocationAssignment)),
      );
      const postRevocationCreated = await governed(
        `/v1/participants/${participantId}/assignments`,
        postRevocationAssignment,
        assignmentCandidate(postRevocationAssignment),
        postRevocationAssignment.assignmentId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(postRevocationCreated.effect.body).toMatchObject({ delegationEpoch: '1' });
      const postRevocationConflict = { ...postRevocationAssignment, assignmentId: id() };
      const postRevocationDenied = await governed(
        `/v1/participants/${participantId}/assignments`,
        postRevocationConflict,
        assignmentCandidate(postRevocationConflict),
        postRevocationConflict.assignmentId,
        '0',
        403,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      expect(postRevocationDenied.effect.body).toMatchObject({
        error: { code: 'PC-IDENTITY-1002' },
      });
      // Membership removal uses the same public candidate, checker and step-up owners.
      // Existing active grants must become terminal; already revoked rows must not advance twice.
      const removePath = `/v1/identity/memberships/${readerId}/remove`;
      const oldRevoked = await service.get(maker.sessionToken, assignmentId);
      const racingGrant = { ...postRevocationAssignment, assignmentId: id(), resourceIds: [id()] };
      const grantCommit = await prepareGoverned(
        `/v1/participants/${participantId}/assignments`,
        racingGrant,
        assignmentCandidate(racingGrant),
        racingGrant.assignmentId,
        '0',
        undefined,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      const removalCommit = await prepareGoverned(
        removePath,
        {},
        { principalId: readerId, state: 'OFFBOARDED' },
        readerId,
        '2',
        200,
      );
      const [removal, racedGrant] = await Promise.all([removalCommit(), grantCommit()]);
      expect([201, 403, 409], JSON.stringify(racedGrant.effect)).toContain(
        racedGrant.effect.status,
      );
      if (racedGrant.effect.status === 409)
        expect(racedGrant.effect.body).toMatchObject({ error: { code: 'PC-IDENTITY-1001' } });
      expect(removal.effect.body).toMatchObject({
        principalId: readerId,
        state: 'OFFBOARDED',
        identityEpoch: '2',
        revision: '3',
      });
      expect((await readPrincipal()).status).toBe(404);
      maker = await service.login('operator');
      checker = await service.login('viewer');
      const removed = await readHumanIdentity('memberships');
      expect(removed).toMatchObject({
        status: 200,
        body: {
          effect: {
            membershipId: readerId,
            identitySubjectId: readerId,
            state: 'OFFBOARDED',
            revision: '3',
            membershipEpoch: '2',
          },
          operationId: expect.any(String),
        },
      });
      expect((await readHumanIdentity('identity-subjects')).body.effect).toEqual(
        subjectReadback.body.effect,
      );
      const racingReadback = await service.get(maker.sessionToken, racingGrant.assignmentId);
      if (racedGrant.effect.status === 201)
        expect(racingReadback).toMatchObject({
          status: 200,
          body: {
            effect: { state: 'REVOKED' },
            operationId: removed.body.operationId,
            revision: '2',
          },
        });
      else expect(racingReadback.status).toBe(404);
      const removedGrant = await service.get(
        maker.sessionToken,
        postRevocationAssignment.assignmentId,
      );
      expect(removedGrant).toMatchObject({
        status: 200,
        body: {
          effect: { state: 'REVOKED' },
          revision: '2',
          operationId: removed.body.operationId,
        },
      });
      expect(await service.get(maker.sessionToken, assignmentId)).toEqual(oldRevoked);
      expect(
        (
          await service.get(
            maker.sessionToken,
            delegationBody.delegationId,
            privacyDomainId,
            'delegations',
          )
        ).body,
      ).toMatchObject({ effect: { state: 'REVOKED' }, operationId: removed.body.operationId });
      await expect(
        admin.query(`update control.principal set state='ACTIVE' where principal_id=$1`, [
          readerId,
        ]),
      ).rejects.toThrow('PC-IDENTITY-1002-MEMBERSHIP-TERMINAL');
      const resurrection = await participantMutation(
        activationPath,
        {},
        `removed-reactivation-${id()}`,
        '3',
      );
      expect(resurrection).toMatchObject({
        status: 403,
        body: { error: { code: 'PC-IDENTITY-1004' } },
      });
      expect(await readHumanIdentity('memberships')).toEqual(removed);
      await service.restartIdentity();
      expect(
        (await principalCatalogue({ search: 'Governed role reader', state: 'OFFBOARDED' })).body,
      ).toMatchObject({
        items: [
          {
            effect: { principalId: readerId, state: 'OFFBOARDED' },
            operationId: removed.body.operationId,
          },
        ],
        authorizedEmpty: false,
      });
      expect(
        (await principalCatalogue({ search: 'Governed role reader', state: 'ACTIVE' })).body,
      ).toMatchObject({ items: [], authorizedEmpty: true });
      expect(await readHumanIdentity('memberships')).toEqual(removed);
      expect((await readHumanIdentity('identity-subjects')).body.effect).toEqual(
        subjectReadback.body.effect,
      );
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.mutation_evidence where aggregate_id=$1
        and catalog_operation_id='ID-OP-MEMBERSHIP-REMOVE'`,
            [readerId],
          )
        ).rows,
      ).toEqual([{ n: 1 }]);
      // Shared identity fixture: removing one membership cannot remove another Participant's membership.
      const otherBefore = (
        await admin.query(`select * from control.principal where principal_id=$1`, [otherMemberId])
      ).rows;
      await governed(
        `/v1/identity/memberships/${sharedMemberId}/remove`,
        {},
        { principalId: sharedMemberId, state: 'OFFBOARDED' },
        sharedMemberId,
        '1',
        200,
      );
      maker = await service.login('operator');
      checker = await service.login('viewer');
      expect(
        (
          await admin.query(`select * from control.principal where principal_id=$1`, [
            otherMemberId,
          ])
        ).rows,
      ).toEqual(otherBefore);
      expect((await readHumanIdentity('identity-subjects', sharedSubjectId)).body).toMatchObject({
        effect: { identitySubjectId: sharedSubjectId },
        membership: { principalId: sharedMemberId, state: 'OFFBOARDED' },
      });
      await service.restartParticipant();
      expect(await service.get(maker.sessionToken, roleId, privacyDomainId, 'roles')).toEqual(
        after,
      );
      const evidence = await admin.query(
        `select catalog_operation_id,count(*)::int effects
      from control.mutation_evidence where participant_id=$1 and aggregate_id=$2 group by catalog_operation_id`,
        [participantId, roleId],
      );
      expect(
        evidence.rows.sort((a, b) => a.catalog_operation_id.localeCompare(b.catalog_operation_id)),
      ).toEqual([
        { catalog_operation_id: 'ID-OP-ROLE-ARCHIVE', effects: 1 },
        { catalog_operation_id: 'ID-OP-ROLE-CREATE', effects: 1 },
      ]);
      // Remove an initial human member with real public onward delegation.
      // Initial credentials establish trust; both delegated grants are made through supported owners.
      const removalParent = { ...parentDelegation, delegationId: id(), resourceIds: [id()] };
      await stepUp(
        checker,
        checkerPrincipalId,
        'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        removalParent.delegationId,
        digest(delegateCandidate(removalParent)),
      );
      await governed(
        `/v1/participants/${participantId}/delegations`,
        removalParent,
        delegateCandidate(removalParent),
        removalParent.delegationId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      [maker, checker] = [checker, maker];
      [makerPrincipalId, checkerPrincipalId] = [checkerPrincipalId, makerPrincipalId];
      const removalChild = {
        ...removalParent,
        delegationId: id(),
        parentId: removalParent.delegationId,
        granteeId: restrictedPrincipalId,
        onwardDelegationDepth: 0,
      };
      await governed(
        `/v1/participants/${participantId}/delegations`,
        removalChild,
        { ...delegateCandidate(removalChild), grantorId: checkerId },
        removalChild.delegationId,
        '0',
        201,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      );
      [maker, checker] = [checker, maker];
      [makerPrincipalId, checkerPrincipalId] = [checkerPrincipalId, makerPrincipalId];
      const credentialsBefore = (
        await admin.query(
          `select credential_id,credential_epoch::text from control.credential
        where participant_id=$1 and principal_id=$2 and state='ACTIVE' order by credential_id`,
          [participantId, checkerId],
        )
      ).rows;
      expect(credentialsBefore.length).toBeGreaterThan(0);
      const checkerVersion = (await readPrincipal(checkerId)).body.effect.revision;
      await governed(
        `/v1/identity/memberships/${checkerId}/remove`,
        {},
        { principalId: checkerId, state: 'OFFBOARDED' },
        checkerId,
        checkerVersion,
        200,
      );
      maker = await service.login('operator');
      const checkerRemoved = await readHumanIdentity('memberships', checkerId);
      expect(checkerRemoved).toMatchObject({
        status: 200,
        body: { effect: { state: 'OFFBOARDED' }, operationId: expect.any(String) },
      });
      const operationId = checkerRemoved.body.operationId;
      for (const delegation of [removalParent, removalChild])
        expect(
          await service.get(
            maker.sessionToken,
            delegation.delegationId,
            privacyDomainId,
            'delegations',
          ),
        ).toMatchObject({
          status: 200,
          body: { effect: { state: 'REVOKED' }, revision: '2', operationId },
        });
      expect(
        await service.get(
          maker.sessionToken,
          '018f0000-0000-7000-8000-000000000131',
          privacyDomainId,
          'envelopes',
        ),
      ).toMatchObject({ status: 200, body: { effect: { state: 'REVOKED' }, operationId } });
      const credentialsAfter = (
        await admin.query(
          `select credential_id,credential_epoch::text,state from control.credential
        where credential_id=any($1::uuid[]) order by credential_id`,
          [credentialsBefore.map((row) => row.credential_id)],
        )
      ).rows;
      expect(credentialsAfter).toEqual(
        credentialsBefore.map((row) => ({
          credential_id: row.credential_id,
          credential_epoch: String(BigInt(row.credential_epoch) + 1n),
          state: 'REVOKED',
        })),
      );
      expect(
        (
          await admin.query(
            `select state,revoked_reason from control.session where session_id=$1`,
            [checker.sessionId],
          )
        ).rows,
      ).toEqual([{ state: 'REVOKED', revoked_reason: 'membership-removed' }]);
      await expect(service.login('viewer')).rejects.toThrow('Initial trust login failed');
      await service.restartIdentity();
      await service.restartParticipant();
      expect(await readHumanIdentity('memberships', checkerId)).toEqual(checkerRemoved);
      expect(
        await service.get(
          maker.sessionToken,
          removalChild.delegationId,
          privacyDomainId,
          'delegations',
        ),
      ).toMatchObject({ status: 200, body: { effect: { state: 'REVOKED' }, operationId } });
    } finally {
      await restricted?.close();
      await policy.close();
      await service.close();
      await Promise.all([policyPool.end(), runtime.end(), admin.end()]);
    }
  },
  60000,
);
