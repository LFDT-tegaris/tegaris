import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { invitationProofContext } from '../../../services/identity-service/src/domain/invitation-redemption.js';
import { oidcCustodyFromCookie } from '../../../services/identity-service/src/oidc-cookies.js';
import { oidcProviderFixture } from './oidc-provider-fixture.js';
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
  invitationAction,
  invitationCandidateSchema,
  type InvitationCandidate,
} from '../../../services/identity-service/src/contracts/invitation-operations.js';
import {
  fenceInvitationAuthority,
  type InvitationAuthority,
} from '../../../services/identity-service/src/domain/invitation-authority.js';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
  type BoundAuthority,
} from '../../../services/identity-service/src/db/authority-fence.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const participantId = '018f0000-0000-7000-8000-000000000101',
  privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const operatorId = '018f0000-0000-7000-8000-000000000111',
  checkerId = '018f0000-0000-7000-8000-000000000112';
const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1',
  createApproval = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';

// AF30-REQ-072C1391BF8F4D9AE1875F2D / AF30-REQ-0A468BFCE6024B9DE9C1F3A6:
// Real governed issuance/rotation/revocation and exact recipient identity-proof acceptance.
integration(
  'governs invitation issuance, token rotation and proved membership acceptance without granting authority',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const database = new URL(runtimeUrl!);
    database.username = 'openpc_participant_runtime';
    const runtime = new Pool({ connectionString: database.href });
    database.username = 'openpc_policy_runtime';
    const policyPool = new Pool({ connectionString: database.href });
    const provider = await oidcProviderFixture(participantId, id(), 'exact-invited-account', {
      membershipHints: false,
    });
    const service = await participantReadbackRuntime({
      oidc: provider,
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
      const roleId = id(),
        invitationId = id();
      // Initial role/device trust; every invitation candidate, decision and effect uses real public owners.
      await admin.query(
        `insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
      values ($1,$2,$3,'Initial review role',array['ACT-PARTICIPANTS_READ_RESOURCE-V1'],'BOOTSTRAP',$4)`,
        [roleId, participantId, `urn:openpc:role:${roleId}`, operatorId],
      );
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
      const read = async (privacy = privacyDomainId, target = invitationId) => {
        const response = await fetch(`${service.identityUrl}/v1/identity/invitations/${target}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${maker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        });
        return { status: response.status, body: await response.json() };
      };
      const send = async (
        body: InvitationCandidate | InvitationCandidate['change'],
        key: string,
        revision: string,
        approvalId?: string,
        prepare = false,
      ) => {
        const change = 'change' in body ? body.change : body;
        const action =
          change.mutation === 'CREATE'
            ? 'ACT-PARTICIPANT_CREATE_MEMBER-V1'
            : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
        return client.request(
          `${service.identityUrl}/v1/identity/invitations/${prepare ? 'prepare' : 'mutate'}`,
          maker,
          body,
          {
            'X-CSRF-Token': await client.csrf(maker, action, service.identityUrl),
            'Idempotency-Key': key,
            'X-OpenPC-Aggregate-Version': revision,
            'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
            ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
          },
        );
      };
      const prepare = async (change: InvitationCandidate['change'], revision: string) => {
        const key = `invitation-${id()}`,
          response = await send(change, key, revision, undefined, true);
        expect(response.status, JSON.stringify(response.body)).toBe(202);
        const candidate = invitationCandidateSchema.parse(response.body.candidate),
          candidateDigest = digest(candidate);
        expect(response.body.candidateDigest).toBe(candidateDigest);
        await client.stepUp(
          checker,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          change.invitationId,
          candidateDigest,
        );
        const proposal = async (query: string, privacy = privacyDomainId) => {
          const response = await fetch(
            `${service.identityUrl}/v1/identity/invitation-proposals/${candidateDigest}?${query}`,
            {
              headers: {
                'Cookie': `__Host-openpc_session=${checker.sessionToken}`,
                'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
              },
            },
          );
          return { status: response.status, body: await response.json() };
        };
        const selector = `expectedRevision=${revision}&makerPrincipalId=${operatorId}`;
        expect(await proposal(selector)).toMatchObject({
          status: 200,
          body: { candidate, candidateDigest, state: 'PROPOSED', operationId: null },
        });
        expect((await proposal(selector, id())).status).not.toBe(200);
        expect(
          (await proposal(`expectedRevision=${revision}&makerPrincipalId=${id()}`)).status,
        ).not.toBe(200);
        const created = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: createApproval,
          actionIntentDigest: client.actionDigests.get(createApproval),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${operatorId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
          reason: 'Review the exact recipient, token version and role intent.',
        });
        expect(created.status, JSON.stringify(created.body)).toBe(202);
        const approvalRef = String(created.body.resourceRef),
          approvalId = approvalRef.slice(-36);
        expect(await proposal(`approvalRequestId=${approvalId}`)).toMatchObject({
          status: 200,
          body: { candidate, approval: { approvalRequestId: approvalId } },
        });
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
            reason: 'Independent invitation review accepted.',
          },
          '1',
        );
        expect(approved.status, JSON.stringify(approved.body)).toBe(202);
        await client.stepUp(
          maker,
          invitationAction(candidate),
          change.invitationId,
          candidateDigest,
        );
        return { candidate, key, revision, approvalId };
      };
      const commit = (prepared: Awaited<ReturnType<typeof prepare>>) =>
        send(prepared.candidate, prepared.key, prepared.revision, prepared.approvalId);
      const beginProof = async (
        target: string,
        token: string,
        version = '1',
        privacy = privacyDomainId,
      ) => {
        const response = await fetch(
          `${service.identityUrl}/v1/identity/invitations/${target}/oidc/begin`,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              participantId,
              privacyDomainId: privacy,
              tokenVersion: version,
              token,
            }),
          },
        );
        return {
          status: response.status,
          body: await response.json(),
          cookie: response.headers.get('set-cookie')?.split(';')[0] ?? '',
        };
      };
      const codeFor = async (authorization: {
        transactionId: string;
        state: string;
        nonce: string;
        codeChallenge: string;
      }) => {
        const url = new URL(`${provider.issuer}/authorize`);
        url.search = new URLSearchParams({
          client_id: provider.clientId,
          redirect_uri: provider.redirectUri,
          response_type: 'code',
          scope: 'openid',
          state: authorization.state,
          nonce: authorization.nonce,
          code_challenge: authorization.codeChallenge,
          code_challenge_method: 'S256',
        }).toString();
        const response = await fetch(url, { redirect: 'manual' });
        expect(response.status).toBe(302);
        return new URL(response.headers.get('location')!).searchParams.get('code')!;
      };
      const redeem = async (
        target: string,
        started: Awaited<ReturnType<typeof beginProof>>,
        code: string,
        overrides: Record<string, string> = {},
        cookie = started.cookie,
      ) => {
        const response = await fetch(
          `${service.identityUrl}/v1/identity/invitations/${target}/oidc/callback`,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json', cookie },
            body: JSON.stringify({
              participantId,
              privacyDomainId,
              transactionId: started.body.transactionId,
              state: started.body.state,
              authorizationCode: code,
              ...overrides,
            }),
          },
        );
        return {
          status: response.status,
          body: await response.json(),
          cookie: response.headers.get('set-cookie'),
        };
      };
      const firstToken = randomBytes(32).toString('base64url'),
        secondToken = randomBytes(32).toString('base64url');
      const initial = {
        invitationId,
        mutation: 'CREATE' as const,
        displayName: 'Invited reviewer',
        recipientSubject: 'exact-invited-account',
        intendedRoleId: roleId,
        tokenDigest: `sha256:${sha(firstToken).toString('hex')}`,
        ttlSeconds: 86400,
      };
      const before = (
        await admin.query(
          `select (select count(*)::int from control.principal where participant_id=$1) principals,(select count(*)::int from control.assignment where participant_id=$1) assignments`,
          [participantId],
        )
      ).rows[0];
      expect(
        (await send({ ...initial, ttlSeconds: 899 }, `invalid-ttl-${id()}`, '0', undefined, true))
          .status,
      ).not.toBe(202);
      const created = await prepare(initial, '0');
      expect((await send(created.candidate, created.key, '0')).status).not.toBe(200);
      const creation = await commit(created);
      expect(creation.status, JSON.stringify(creation.body)).toBe(200);
      expect(creation.body).toMatchObject({
        effect: {
          invitationId,
          participantId,
          privacyDomainId,
          state: 'PENDING',
          tokenVersion: '1',
          revision: '1',
          roleIntent: { roleId, authorityGranted: false },
        },
      });
      expect((await commit(created)).body).toEqual(creation.body);
      expect((await read()).body).toEqual(creation.body);
      expect((await read(id())).status).not.toBe(200);
      expect((await read(privacyDomainId, id())).status).not.toBe(200);
      expect((await beginProof(invitationId, firstToken, '1', id())).status).toBe(401);
      expect((await beginProof(invitationId, randomBytes(32).toString('base64url'))).status).toBe(
        401,
      );
      const staleProof = await beginProof(invitationId, firstToken);
      expect(staleProof.status, JSON.stringify(staleProof.body)).toBe(200);
      const staleCode = await codeFor(staleProof.body);
      const resend = await prepare(
        {
          invitationId,
          mutation: 'RESEND',
          tokenDigest: `sha256:${sha(secondToken).toString('hex')}`,
          ttlSeconds: 900,
        },
        '1',
      );
      const rotation = await commit(resend);
      expect(rotation.status, JSON.stringify(rotation.body)).toBe(200);
      expect(rotation.body).toMatchObject({
        effect: { tokenVersion: '2', revision: '2', state: 'PENDING' },
      });
      const exchangesBeforeRotation = provider.tokenExchanges();
      expect((await redeem(invitationId, staleProof, staleCode)).status).toBe(401);
      expect(provider.tokenExchanges()).toBe(exchangesBeforeRotation);
      expect((await beginProof(invitationId, firstToken)).status).toBe(401);
      const tokens = (
        await admin.query(
          `select token_version::text version,encode(token_digest,'hex') digest from control.participant_invitation_token where invitation_id=$1 order by token_version`,
          [invitationId],
        )
      ).rows;
      expect(tokens).toEqual([
        { version: '1', digest: sha(firstToken).toString('hex') },
        { version: '2', digest: sha(secondToken).toString('hex') },
      ]);
      const reuse = await prepare(
        { invitationId, mutation: 'RESEND', tokenDigest: initial.tokenDigest, ttlSeconds: 900 },
        '2',
      );
      expect((await commit(reuse)).status).not.toBe(200);
      expect((await read()).body).toEqual(rotation.body);
      const revoked = await commit(await prepare({ invitationId, mutation: 'REVOKE' }, '2'));
      expect(revoked.status, JSON.stringify(revoked.body)).toBe(200);
      expect(revoked.body).toMatchObject({
        effect: { state: 'REVOKED', tokenVersion: '2', revision: '3' },
      });
      expect((await beginProof(invitationId, secondToken, '2')).status).toBe(401);
      await service.restartIdentity();
      expect((await read()).body).toEqual(revoked.body);
      expect(
        (
          await send(
            { invitationId, mutation: 'RESEND', tokenDigest: initial.tokenDigest, ttlSeconds: 900 },
            `terminal-resend-${id()}`,
            '3',
            undefined,
            true,
          )
        ).status,
      ).not.toBe(202);
      // Retained expired-history diagnostic. No clock changes or waiting; this fixture does
      // not claim public issuance/acceptance. Renewal itself uses the real governed owner.
      const expiredId = id(),
        expiredOperation = id();
      const issuedAt = new Date(Date.now() - 30 * 60_000),
        expiresAt = new Date(issuedAt.getTime() + 900_000);
      const expiredFixture = await admin.connect();
      try {
        await expiredFixture.query('begin');
        await expiredFixture.query(
          `insert into control.participant_invitation
          (invitation_id,participant_id,privacy_domain_id,display_name,recipient_issuer,recipient_subject,recipient_audience,intended_role_id,created_by_principal_id,expires_at,last_mutation_operation_id,created_at,updated_at)
          values ($1,$2,$3,'Expired retained invitation',$4,'expired-recipient',$5,$6,$7,$8,$9,$10,$10)`,
          [
            expiredId,
            participantId,
            privacyDomainId,
            created.candidate.issuer,
            created.candidate.audience,
            roleId,
            operatorId,
            expiresAt,
            expiredOperation,
            issuedAt,
          ],
        );
        await expiredFixture.query(
          `insert into control.participant_invitation_token
          (participant_id,privacy_domain_id,invitation_id,token_version,token_digest,ttl_seconds,expires_at,operation_id,created_at)
          values ($1,$2,$3,1,$4,900,$5,$6,$7)`,
          [
            participantId,
            privacyDomainId,
            expiredId,
            sha(randomBytes(32)),
            expiresAt,
            expiredOperation,
            issuedAt,
          ],
        );
        await expiredFixture.query('commit');
      } catch (error) {
        await expiredFixture.query('rollback');
        throw error;
      } finally {
        expiredFixture.release();
      }
      expect(await read(privacyDomainId, expiredId)).toMatchObject({
        status: 200,
        body: { effect: { state: 'EXPIRED', tokenVersion: '1' } },
      });
      const renewed = await commit(
        await prepare(
          {
            invitationId: expiredId,
            mutation: 'RESEND',
            tokenDigest: `sha256:${sha(randomBytes(32)).toString('hex')}`,
            ttlSeconds: 900,
          },
          '1',
        ),
      );
      expect(renewed).toMatchObject({
        status: 200,
        body: {
          effect: { invitationId: expiredId, state: 'PENDING', tokenVersion: '2', revision: '2' },
        },
      });
      const after = (
        await admin.query(
          `select (select count(*)::int from control.principal where participant_id=$1) principals,(select count(*)::int from control.assignment where participant_id=$1) assignments`,
          [participantId],
        )
      ).rows[0];
      expect(after).toEqual(before);
      const stored = await admin.query(
        `select record.input_digest,record.result_payload from control.idempotency_record record
         join control.mutation_evidence evidence on evidence.participant_id=record.participant_id and evidence.operation_id=record.operation_id
         where record.participant_id=$1 and evidence.aggregate_type='participant-invitation' and evidence.aggregate_id=$2`,
        [participantId, invitationId],
      );
      expect(stored.rows).toHaveLength(3);
      expect(JSON.stringify(stored.rows)).not.toContain(firstToken);
      expect(JSON.stringify(stored.rows)).not.toContain(secondToken);
      await expect(
        admin.query(
          `update control.participant_invitation_token set token_digest=$2 where invitation_id=$1`,
          [invitationId, sha('changed')],
        ),
      ).rejects.toThrow();
      const provenance = (
        await admin.query<{ issuance_authority: InvitationAuthority; operation_id: string }>(
          `select issuance_authority,operation_id from control.participant_invitation_token where invitation_id=$1 and token_version=2`,
          [expiredId],
        )
      ).rows[0]!;
      expect(provenance.issuance_authority.authorities).toHaveLength(4);
      expect(JSON.stringify(provenance.issuance_authority)).not.toContain('sessionId');
      expect(JSON.stringify(provenance.issuance_authority)).not.toContain('sessionEpoch');
      const missingProvenance = await admin.connect();
      try {
        await missingProvenance.query('begin');
        const operationId = id();
        await missingProvenance.query(
          `update control.participant_invitation set token_version=3,row_version=row_version+1,last_mutation_operation_id=$2 where invitation_id=$1`,
          [expiredId, operationId],
        );
        await expect(
          missingProvenance.query(
            `insert into control.participant_invitation_token(participant_id,privacy_domain_id,invitation_id,token_version,token_digest,ttl_seconds,expires_at,operation_id)
           select participant_id,privacy_domain_id,invitation_id,token_version,$2,900,expires_at,last_mutation_operation_id
           from control.participant_invitation where invitation_id=$1`,
            [expiredId, sha(randomBytes(32))],
          ),
        ).rejects.toThrow('PC-IDENTITY-1005-INVITATION-ISSUANCE-AUTHORITY');
      } finally {
        await missingProvenance.query('rollback');
        missingProvenance.release();
      }
      const authority = provenance.issuance_authority;
      const makerGrant = authority.authorities[0]!.grant;
      const originalApproval = (
        await admin.query<{ maker_authority: BoundAuthority }>(
          `select maker_authority from control.approval_request where approval_request_id=$1`,
          [authority.approvalRequestId],
        )
      ).rows[0]!.maker_authority;
      // Fault-state diagnostics exercise the real runtime role and fence, always rolled back.
      // They establish the durable authority component, not the still-open public redemption journey.
      const probe = async (
        fault?: (connection: PoolClient) => Promise<unknown>,
        ordinary = false,
      ) => {
        const connection = await admin.connect();
        try {
          await connection.query('begin');
          await fault?.(connection);
          await connection.query('set local role openpc_identity_runtime');
          await connection.query(
            `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`,
            [participantId, privacyDomainId, id(), 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
          );
          if (ordinary) await fenceBoundAuthorities(connection, participantId, [originalApproval]);
          else
            await fenceInvitationAuthority(
              connection,
              participantId,
              privacyDomainId,
              provenance.operation_id,
              authority,
            );
        } finally {
          await connection.query('rollback');
          connection.release();
        }
      };
      await expect(probe()).resolves.toBeUndefined();
      const expiredIssuance = async (connection: PoolClient) => {
        await connection.query(
          `update control.approval_request set expires_at=clock_timestamp()-interval '1 second' where approval_request_id=$1`,
          [authority.approvalRequestId],
        );
        await connection.query(
          `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='invitation-diagnostic-logout' where participant_id=$1 and principal_id=any($2::uuid[])`,
          [participantId, [operatorId, checkerId]],
        );
      };
      await expect(probe(expiredIssuance)).resolves.toBeUndefined();
      await expect(probe(expiredIssuance, true)).rejects.toThrow(AuthorityFenceError);
      for (const signer of authority.signers) {
        await expect(
          probe((connection) =>
            connection.query(
              `update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1`,
              [signer.credentialId],
            ),
          ),
        ).rejects.toThrow('PC-IDENTITY-1005');
        await expect(
          probe((connection) =>
            connection.query(
              `update control.principal set authority_epoch=authority_epoch+1 where participant_id=$1 and principal_id=$2`,
              [participantId, signer.principalId],
            ),
          ),
        ).rejects.toThrow(AuthorityFenceError);
      }
      await expect(
        probe((connection) =>
          connection.query(
            `update control.assignment set row_version=row_version+1 where participant_id=$1 and assignment_id=$2`,
            [participantId, makerGrant.assignmentId],
          ),
        ),
      ).rejects.toThrow(AuthorityFenceError);
      await expect(
        probe((connection) =>
          connection.query(
            `update control.authority_envelope set authority_epoch=authority_epoch+1 where participant_id=$1 and authority_envelope_id=$2`,
            [participantId, makerGrant.authorityEnvelopeId],
          ),
        ),
      ).rejects.toThrow(AuthorityFenceError);
      await expect(
        probe((connection) =>
          connection.query(
            `update control.privacy_domain set row_version=row_version+1 where participant_id=$1 and privacy_domain_id=$2`,
            [participantId, privacyDomainId],
          ),
        ),
      ).rejects.toThrow(AuthorityFenceError);
      // AF30-REQ-338DF65FA7B18E051BB94825: real governed issuance to exact OIDC proof,
      // durable membership acceptance and restart readback. Role activation remains separate.
      const acceptedId = id(),
        acceptedToken = randomBytes(32).toString('base64url');
      const acceptedCreation = await commit(
        await prepare(
          {
            ...initial,
            invitationId: acceptedId,
            displayName: 'Proved invited reviewer',
            tokenDigest: `sha256:${sha(acceptedToken).toString('hex')}`,
          },
          '0',
        ),
      );
      expect(acceptedCreation.status, JSON.stringify(acceptedCreation.body)).toBe(200);
      const wrongSubject = await beginProof(acceptedId, acceptedToken);
      expect(wrongSubject.status, JSON.stringify(wrongSubject.body)).toBe(200);
      const wrongCode = await codeFor(wrongSubject.body);
      provider.setSubject('another-person');
      expect((await redeem(acceptedId, wrongSubject, wrongCode)).status).toBe(401);
      provider.setSubject('exact-invited-account');
      expect((await read(privacyDomainId, acceptedId)).body.effect.state).toBe('PENDING');
      expect(
        (
          await admin.query(
            'select 1 from control.participant_invitation_acceptance where invitation_id=$1',
            [acceptedId],
          )
        ).rowCount,
      ).toBe(0);
      const validProof = await beginProof(acceptedId, acceptedToken);
      expect(validProof.status, JSON.stringify(validProof.body)).toBe(200);
      const validCode = await codeFor(validProof.body);
      const beforeInvalid = provider.tokenExchanges();
      expect(
        (await redeem(acceptedId, validProof, validCode, { state: 'wrong-state' })).status,
      ).toBe(401);
      expect(
        (await redeem(acceptedId, validProof, validCode, { privacyDomainId: id() })).status,
      ).toBe(401);
      expect((await redeem(acceptedId, validProof, validCode, {}, '')).status).toBe(401);
      expect(provider.tokenExchanges()).toBe(beforeInvalid);
      const sessionSubstitution = await fetch(`${service.identityUrl}/v1/identity/oidc/callback`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'cookie': validProof.cookie.replace(
            '__Host-openpc_invitation_oidc',
            '__Host-openpc_oidc',
          ),
        },
        body: JSON.stringify({
          transactionId: validProof.body.transactionId,
          state: validProof.body.state,
          authorizationCode: validCode,
        }),
      });
      expect(sessionSubstitution.status).toBe(401);
      expect(provider.tokenExchanges()).toBe(beforeInvalid);
      const accepted = await redeem(acceptedId, validProof, validCode);
      expect(accepted.status, JSON.stringify(accepted.body)).toBe(201);
      expect(accepted.cookie).toBeNull();
      expect(accepted.body).toMatchObject({
        invitationId: acceptedId,
        participantId,
        privacyDomainId,
        state: 'ACCEPTED',
        tokenVersion: '1',
        membershipStateAtAcceptance: 'PROVISIONED',
        roleIntent: { roleId, authorityGranted: false },
      });
      expect(accepted.body).not.toHaveProperty('identitySubjectId');
      const exchangesAfterAcceptance = provider.tokenExchanges();
      for (const retry of await Promise.all([
        redeem(acceptedId, validProof, validCode),
        redeem(acceptedId, validProof, validCode),
      ])) {
        expect(retry.status).toBe(200);
        expect(retry.body).toEqual(accepted.body);
      }
      expect((await redeem(acceptedId, validProof, 'different-code')).status).toBe(401);
      expect(provider.tokenExchanges()).toBe(exchangesAfterAcceptance);
      expect((await beginProof(acceptedId, acceptedToken)).status).toBe(401);
      const durable = await read(privacyDomainId, acceptedId);
      expect(durable.body.effect).toMatchObject({
        state: 'ACCEPTED',
        revision: '2',
        operationId: accepted.body.operationId,
        acceptance: {
          membershipId: accepted.body.membershipId,
          acceptedAt: accepted.body.acceptedAt,
        },
      });
      const effects = (
        await admin.query(
          `select principal.state,
        (select count(*)::int from control.assignment where participant_id=$1 and principal_id=$2) assignments,
        (select count(*)::int from control.session where participant_id=$1 and principal_id=$2) sessions,
        (select count(*)::int from control.mutation_evidence where operation_id=$3 and evidence_role='IDENTITY_PROOF_INPUT') proofs,
        (select count(*)::int from control.outbox_event where aggregate_type='invitation-redemption' and aggregate_id=$4) events
        from control.principal principal where participant_id=$1 and principal_id=$2`,
          [participantId, accepted.body.membershipId, accepted.body.operationId, acceptedId],
        )
      ).rows[0];
      expect(effects).toEqual({
        state: 'PROVISIONED',
        assignments: 0,
        sessions: 0,
        proofs: 1,
        events: 1,
      });
      await service.restartIdentity();
      expect((await redeem(acceptedId, validProof, validCode)).body).toEqual(accepted.body);
      expect((await read(privacyDomainId, acceptedId)).body).toEqual(durable.body);
      expect(provider.tokenExchanges()).toBe(exchangesAfterAcceptance);
      // Rolled-back deadline diagnostic after real public acceptance. Historical receipt
      // retrieval needs exact custody, state and code, but cannot repeat an expired proof.
      const deadline = await admin.connect();
      try {
        await deadline.query('begin');
        await deadline.query(
          'alter table control.oidc_transaction disable trigger invitation_oidc_custody',
        );
        await deadline.query(
          `update control.oidc_transaction set created_at=clock_timestamp()-interval '10 minutes',
          expires_at=clock_timestamp()-interval '5 minutes' where transaction_id=$1`,
          [validProof.body.transactionId],
        );
        await deadline.query(
          'alter table control.oidc_transaction enable trigger invitation_oidc_custody',
        );
        await deadline.query('set local role openpc_identity_runtime');
        await deadline.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PARTICIPANT_CREATE_MEMBER-V1',true)`,
          [participantId, privacyDomainId, id()],
        );
        const request = {
          participantId,
          privacyDomainId,
          invitationId: acceptedId,
          transactionId: validProof.body.transactionId,
          state: validProof.body.state,
          authorizationCode: validCode,
        };
        const custody = oidcCustodyFromCookie(validProof.cookie, 'INVITATION')!.custody;
        expect(await invitationProofContext(deadline, request, custody, provider)).toEqual({
          receipt: accepted.body,
        });
        await expect(
          invitationProofContext(
            deadline,
            { ...request, authorizationCode: 'wrong-code' },
            custody,
            provider,
          ),
        ).rejects.toThrow('PC-AUTH-0002');
      } finally {
        await deadline.query('rollback');
        deadline.release();
      }
      // Independent invitations for the same verified identity serialize at the Participant
      // owner and reuse the one local membership. Neither creates additional access.
      const siblings = [];
      for (const suffix of ['One', 'Two']) {
        const siblingId = id(),
          token = randomBytes(32).toString('base64url');
        const created = await commit(
          await prepare(
            {
              ...initial,
              invitationId: siblingId,
              displayName: `Concurrent recipient ${suffix}`,
              tokenDigest: `sha256:${sha(token).toString('hex')}`,
            },
            '0',
          ),
        );
        expect(created.status, JSON.stringify(created.body)).toBe(200);
        const proof = await beginProof(siblingId, token);
        expect(proof.status, JSON.stringify(proof.body)).toBe(200);
        siblings.push({ siblingId, proof, code: await codeFor(proof.body) });
      }
      const simultaneous = await Promise.all(
        siblings.map(({ siblingId, proof, code }) => redeem(siblingId, proof, code)),
      );
      for (const outcome of simultaneous) {
        expect(outcome.status, JSON.stringify(outcome.body)).toBe(201);
        expect(outcome.body.membershipId).toBe(accepted.body.membershipId);
      }
      const localIdentity = (
        await admin.query(
          `select count(*)::int members from control.participant_membership membership
        join control.identity_oidc_binding binding on binding.identity_subject_id=membership.identity_subject_id
        where membership.participant_id=$1 and binding.issuer=$2 and binding.subject=$3 and binding.audience=$4`,
          [participantId, provider.issuer, 'exact-invited-account', provider.clientId],
        )
      ).rows[0];
      expect(localIdentity.members).toBe(1);
      const kept = (
        await admin.query(
          'select to_jsonb(receipt) receipt from control.participant_invitation_acceptance receipt where invitation_id=$1',
          [acceptedId],
        )
      ).rows;
      expect(JSON.stringify(kept)).not.toContain(acceptedToken);
      expect(JSON.stringify(kept)).not.toContain(validCode);
    } finally {
      await provider.close();
      await policy.close();
      await service.close();
      await Promise.all([runtime.end(), policyPool.end(), admin.end()]);
    }
  },
  60_000,
);
