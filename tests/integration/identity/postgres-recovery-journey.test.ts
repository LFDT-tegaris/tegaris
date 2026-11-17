import { generateKeyPairSync } from 'node:crypto';
import { recoveryWorkbenchClient } from './recovery-workbench-client.js';
import { Pool } from 'pg';
import { z } from 'zod';
import { oidcProviderFixture } from './oidc-provider-fixture.js';
import { createUnattestedTestRegistration } from './hardware-authenticator.js';
import { expect, it } from 'vitest';
import { participantReadbackRuntime } from './participant-readback-runtime.js';
import {
  publicGovernanceClient,
  sha,
  digest,
  type TestAuthenticator,
  type GovernanceActor,
} from './public-governance-client.js';
import {
  buildPolicyService,
  HttpPolicyIdentityGateway,
} from '../../../services/module-registry/src/policy-http.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  encodeIdentityCredentialPayload,
  signIdentityCredentialCoseSign1Es256,
} from '../../../packages/security-kernel/src/index.js';
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const stepUpAction = 'ACT-IDENTITY_UPDATE_STEP_UP-V1';

// Initial identities, credentials and envelopes establish trust only.
// Qualification, custody decisions, recovery execution and review use public owners.
integration(
  'executes two-custodian recovery, denies premature authority, and restores one authenticator with restart-safe readback',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const database = new URL(runtimeUrl!);
    database.username = 'openpc_participant_runtime';
    const runtime = new Pool({ connectionString: database.href });
    database.username = 'openpc_policy_runtime';
    const policyPool = new Pool({ connectionString: database.href });
    const participantId = id(),
      privacyDomainId = id(),
      operatorId = id(),
      checkerId = id(),
      executorId = id(),
      subjectId = id();
    const actorIds = [operatorId, checkerId, executorId, subjectId];
    const devices = new Map<string, TestAuthenticator>(),
      envelopes = new Map<string, string>(),
      assignments = new Map<string, string>();
    const oidc = await oidcProviderFixture(participantId, subjectId);
    const service = await participantReadbackRuntime({
      runtime,
      identityDatabaseUrl: runtimeUrl!,
      participantId,
      privacyDomainId,
      operatorPrincipalId: operatorId,
      checkerPrincipalId: checkerId,
      oidc,
    });
    const extra = await participantReadbackRuntime({
      runtime,
      identityDatabaseUrl: runtimeUrl!,
      participantId,
      privacyDomainId,
      operatorPrincipalId: executorId,
      checkerPrincipalId: subjectId,
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
    let workbench: Awaited<ReturnType<typeof recoveryWorkbenchClient>> | undefined;
    try {
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch,root_privacy_domain_id) values ($1,'Public recovery journey','ACTIVE',1,$2)`,
        [participantId, privacyDomainId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values ($1,$2,'Recovery context','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE')`,
        [privacyDomainId, participantId],
      );
      for (const principalId of actorIds)
        await admin.query(
          `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values ($1,$2,'USER',$1::uuid::text,'ACTIVE',1)`,
          [principalId, participantId],
        );
      const intents = [
        action,
        stepUpAction,
        'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        'ACT-PARTICIPANTS_READ_COLLECTION-V1',
        'ACT-IDENTITY_CREATE_SESSION-V1',
        'ACT-IDENTITY_DELETE_SESSION-V1',
        'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        'ACT-POLICY_APPROVE_REQUEST-V1',
        'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
        'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
        'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
      ];
      for (const principalId of actorIds) {
        const envelopeId = id(),
          assignmentId = id();
        envelopes.set(principalId, envelopeId);
        assignments.set(principalId, assignmentId);
        await admin.query(
          `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
      values ($1,$2,$3,$3,$4,1,0,'ACTIVE',clock_timestamp()-interval '1 hour',$5,$6,$7,$8,$9,array['*'],array['LOW','HIGH'],true,true,0)`,
          [
            envelopeId,
            participantId,
            principalId,
            principalId === checkerId ? operatorId : checkerId,
            Buffer.from('initial-trust'),
            sha(envelopeId),
            Buffer.alloc(0),
            [privacyDomainId],
            intents,
          ],
        );
        await admin.query(
          `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state,created_by_principal_id)
      values ($1,$2,$3,$4,0,$5,$6,$7,array['*'],array['LOW','HIGH'],true,true,0,tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),'ACTIVE',$3)`,
          [
            assignmentId,
            participantId,
            principalId,
            envelopeId,
            sha(assignmentId),
            [privacyDomainId],
            intents,
          ],
        );
      }
      for (const principalId of [...actorIds]) {
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
        const certificate = encodeIdentityCredentialPayload({
          participantId: `urn:openpc:participant:${participantId}`,
          principalId: `urn:openpc:principal:${principalId}`,
          authorityEpoch: '1',
          issuedAt: new Date(Date.now() - 60000).toISOString().replace('Z', '000Z'),
          expiresAt: new Date(Date.now() + 3600000).toISOString().replace('Z', '000Z'),
        });
        const signed = signIdentityCredentialCoseSign1Es256(
          keys.privateKey.export({ type: 'pkcs8', format: 'der' }),
          publicKey,
          certificate,
        );
        const approvalId = id();
        const envelopeId = envelopes.get(principalId)!;
        const assignmentId = assignments.get(principalId)!;
        await admin.query(
          `insert into control.approval_request
        (approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,subject_id,
         subject_digest,subject_version,maker_principal_id,required_approvals,state,expires_at)
        values ($1,$2,$3,$4,'LOCAL_IDENTITY_CREDENTIAL_BOOTSTRAP',$5,$6,1,$7,1,'APPROVED',clock_timestamp()+interval '1 hour')`,
          [
            approvalId,
            participantId,
            privacyDomainId,
            stepUpAction,
            credentialId,
            sha(certificate),
            principalId,
          ],
        );
        await admin.query(
          `insert into control.approval_decision_record
        (participant_id,privacy_domain_id,approval_request_id,approver_principal_id,approver_principal_epoch,
         approver_authority_envelope_id,approver_envelope_epoch,approver_assignment_id,signer_credential_id,
         aggregate_version,candidate_digest,decision,decision_digest,evidence_cbor,cose_sign1)
        values ($1,$2,$3,$4,1,$5,1,$6,$7,1,$8,'APPROVE',$9,$10,$11)`,
          [
            participantId,
            privacyDomainId,
            approvalId,
            principalId,
            envelopeId,
            assignmentId,
            credentialId,
            sha(certificate),
            sha(Buffer.concat([sha(certificate), certificate])),
            certificate,
            signed,
          ],
        );
      }

      // The executor's pre-enrolled hardware provenance is initial external trust.
      await admin.query(
        `insert into control.hardware_authenticator(credential_id,participant_id,principal_id,profile_id,profile_digest,aaguid,attestation_digest) values ($1,$2,$3,'initial-external-test-trust',$4,$3,$4)`,
        [
          devices.get(executorId)!.credentialId,
          participantId,
          executorId,
          digest('initial-hardware'),
        ],
      );
      await admin.query(
        `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from) values ($1,$2,'OIDC_SUBJECT',$3,$2::uuid::text,$4,'ACTIVE',1,clock_timestamp()-interval '1 hour')`,
        [participantId, subjectId, oidc.issuer, oidc.clientId],
      );
      const oidcLogin = async (authTime?: string) => {
        const start = await fetch(`${service.identityUrl}/v1/identity/oidc/begin`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}',
        });
        expect(start.status).toBe(200);
        const started = await start.json();
        const authorization = new URL(`${oidc.issuer}/authorize`);
        authorization.search = new URLSearchParams({
          response_type: 'code',
          client_id: started.clientId,
          redirect_uri: started.redirectUri,
          state: started.state,
          nonce: started.nonce,
          code_challenge: started.codeChallenge,
          code_challenge_method: 'S256',
          ...(authTime === undefined ? {} : { auth_time: authTime }),
        }).toString();
        const redirect = await fetch(authorization, { redirect: 'manual' });
        expect(redirect.status).toBe(302);
        const location = new URL(redirect.headers.get('location')!);
        const callback = await fetch(`${service.identityUrl}/v1/identity/oidc/callback`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Cookie': start.headers.get('set-cookie')!.split(';')[0]!,
          },
          body: JSON.stringify({
            transactionId: started.transactionId,
            state: location.searchParams.get('state'),
            authorizationCode: location.searchParams.get('code'),
          }),
        });
        return {
          status: callback.status,
          body: await callback.json(),
          sessionToken: callback.headers
            .get('set-cookie')
            ?.split(';')[0]
            ?.slice('__Host-openpc_session='.length),
        };
      };
      const maker: GovernanceActor = {
        ...(await service.login('operator')),
        principalId: operatorId,
      };
      const checker: GovernanceActor = {
        ...(await service.login('viewer')),
        principalId: checkerId,
      };
      let executor: GovernanceActor = {
        ...(await extra.login('operator')),
        principalId: executorId,
      };
      const originalLogin = await oidcLogin();
      expect(originalLogin.status, JSON.stringify(originalLogin.body)).toBe(201);
      const subject: GovernanceActor = {
        sessionToken: originalLogin.sessionToken!,
        sessionId: originalLogin.sessionToken!.split('.')[1]!,
        principalId: subjectId,
      };
      const client = await publicGovernanceClient({
        admin,
        identityUrl: service.identityUrl,
        policyUrl,
        participantId,
        privacyDomainId,
        devices,
      });
      workbench = await recoveryWorkbenchClient({
        identityUrl: service.identityUrl,
        policyUrl,
        internalToken: service.identityInternalToken,
        directory: service.directory,
        operatorId,
        publicClient: client,
      });
      const governed = async (...args: Parameters<typeof client.prepare>) => {
        const prepared = await workbench!.prepare(...args);
        const result = await prepared.commit();
        expect(result.status, JSON.stringify(result.body)).toBeLessThan(300);
        return { ...prepared, result };
      };
      const qualification = {
        principalId: executorId,
        credentialId: devices.get(executorId)!.credentialId,
        principalEpoch: '1',
        credentialEpoch: '1',
      };
      await governed(
        maker,
        checker,
        '/v1/identity/recovery-principals',
        qualification,
        qualification,
        executorId,
        '0',
      );
      executor = { ...(await extra.login('operator')), principalId: executorId };
      const recoveryId = id(),
        purposeDigest = digest('Recover subject after authenticator loss');
      const body = {
        recoveryId,
        subjectId,
        recoveryPrincipalId: executorId,
        custodianPrincipalIds: [operatorId, checkerId],
        purposeDigest,
        actionIntentId: action,
      };
      await governed(
        maker,
        checker,
        '/v1/identity/recoveries',
        body,
        { ...body, participantId },
        recoveryId,
        '0',
      );
      const read = async (target = recoveryId, privacy = privacyDomainId, actor = maker) => {
        const response = await fetch(`${service.identityUrl}/v1/identity/recoveries/${target}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${actor.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        });
        return { status: response.status, body: await response.json() };
      };
      expect((await read()).body).toMatchObject({ effect: { state: 'REQUESTED' } });
      expect((await read(recoveryId, id())).status).toBe(404);
      const approvalBody = { purposeDigest },
        approvalCandidate = { recoveryId, purposeDigest };
      await governed(
        maker,
        checker,
        `/v1/identity/recoveries/${recoveryId}/approve`,
        approvalBody,
        approvalCandidate,
        recoveryId,
        '1',
      );
      expect((await read()).body).toMatchObject({ effect: { state: 'CUSTODIAN_ONE_APPROVED' } });
      const premature = await client.mutation(
        executor,
        `/v1/identity/recoveries/${recoveryId}/complete`,
        {},
        `premature-${id()}`,
        '2',
      );
      expect(premature).toMatchObject({
        status: 403,
        body: { error: { code: 'PC-IDENTITY-1007' } },
      });
      expect((await read()).body.effect.state).toBe('CUSTODIAN_ONE_APPROVED');

      await governed(
        checker,
        maker,
        `/v1/identity/recoveries/${recoveryId}/approve`,
        approvalBody,
        approvalCandidate,
        recoveryId,
        '2',
      );
      const deniedChallenge = async (resourceId: string, resourceDigest: string) => {
        const response = await client.request(
          `${service.identityUrl}/v1/identity/webauthn/assertion/challenge`,
          executor,
          {
            actionIntentId: action,
            resourceId,
            resourceDigest,
            rpIdHash: `sha256:${sha(new URL(service.identityUrl).hostname).toString('hex')}`,
          },
          { 'X-CSRF-Token': await client.csrf(executor, action, service.identityUrl) },
        );
        expect(response).toMatchObject({
          status: 403,
          body: { error: { code: 'PC-IDENTITY-1007' } },
        });
      };
      const completionDigest = digest({ recoveryId, state: 'COMPLETED' });
      await deniedChallenge(recoveryId, completionDigest); // No approved completion candidate.
      const completed = await governed(
        executor,
        checker,
        `/v1/identity/recoveries/${recoveryId}/complete`,
        {},
        { recoveryId, state: 'COMPLETED' },
        recoveryId,
        '3',
        async () => {
          await deniedChallenge(recoveryId, digest('another purpose'));
          await deniedChallenge(subjectId, completionDigest);
        },
      );
      expect(completed.result.body).toMatchObject({
        truthState: 'SUCCESS',
        readback: {
          effect: {
            state: 'COMPLETED',
            subjectEpoch: '1',
            replacementState: 'AWAITING_ENROLLMENT',
          },
        },
      });
      expect(await completed.commit()).toEqual(completed.result);
      const result = await read();
      expect(result.body).toMatchObject({
        effect: { state: 'COMPLETED', postReviewStatus: 'REQUIRED' },
      });
      const old = await admin.query(`select state from control.session where session_id=$1`, [
        subject.sessionId,
      ]);
      expect(old.rows[0].state).toBe('REVOKED');
      const keys = await admin.query(
        `select state,credential_epoch::text from control.credential where principal_id=$1`,
        [subjectId],
      );
      expect(keys.rows).toHaveLength(2);
      expect(keys.rows).toEqual(
        expect.arrayContaining([
          { state: 'REVOKED', credential_epoch: '2' },
          { state: 'ACTIVE', credential_epoch: '2' },
        ]),
      );
      await service.restartIdentity();
      expect(await read()).toEqual(result);
      expect(result.body.effect.replacementState).toBe('AWAITING_ENROLLMENT');
      const prematureNote = 'Attempt review before the replacement authenticator exists.';
      const prematureReview = await client.prepare(
        maker,
        checker,
        `/v1/identity/recoveries/${recoveryId}/post-review`,
        { note: prematureNote },
        { recoveryId, note: prematureNote },
        recoveryId,
        '4',
      );
      expect(await prematureReview.commit()).toMatchObject({
        status: 403,
        body: { error: { code: 'PC-IDENTITY-1007' } },
      });
      expect((await read()).body.effect.postReviewStatus).toBe('REQUIRED');

      for (const authTime of [
        'missing',
        String(Math.floor(Date.parse(result.body.effect.completedAt) / 1000) - 1),
      ]) {
        const denied = await oidcLogin(authTime);
        expect(denied.status, JSON.stringify(denied.body)).toBe(401);
      }
      // auth_time is whole-second precision; authenticate after the complete recovery second.
      const until =
        Math.ceil(Date.parse(result.body.effect.completedAt) / 1000) * 1000 - Date.now();
      if (until >= 0) await new Promise((resolve) => setTimeout(resolve, until + 20));
      const returned = await oidcLogin();
      expect(returned.status, JSON.stringify(returned.body)).toBe(201);
      const returning: GovernanceActor = {
        principalId: subjectId,
        sessionToken: returned.sessionToken!,
        sessionId: returned.sessionToken!.split('.')[1]!,
      };
      const token = await client.csrf(returning, stepUpAction, service.identityUrl);
      const options = await client.request(
        `${service.identityUrl}/v1/identity/webauthn/initial-registration/options`,
        returning,
        {},
        { 'X-CSRF-Token': token },
      );
      expect(options.status, JSON.stringify(options.body)).toBe(201);
      const readEnrollment = async (
        actor = returning,
        enrollmentId = options.body.enrollmentId,
      ) => {
        const response = await fetch(
          `${service.identityUrl}/v1/identity/webauthn/enrollments/${enrollmentId}`,
          {
            headers: { Cookie: `__Host-openpc_session=${actor.sessionToken}` },
          },
        );
        expect(response.headers.get('cache-control')).toBe('no-store');
        return { status: response.status, body: await response.json() };
      };
      expect(await readEnrollment()).toMatchObject({
        status: 200,
        body: { state: 'PENDING', credential: null, principalEpoch: '2' },
      });
      expect((await readEnrollment(maker)).status).toBe(404);
      expect((await readEnrollment(returning, id())).status).toBe(404);
      for (const deniedToken of [subject.sessionToken, `${id()}.${returning.sessionId}`]) {
        const denied = await fetch(
          `${service.identityUrl}/v1/identity/webauthn/enrollments/${options.body.enrollmentId}`,
          {
            headers: { Cookie: `__Host-openpc_session=${deniedToken}` },
          },
        );
        expect(denied.status).toBe(401);
      }
      const replacementKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const registration = createUnattestedTestRegistration(
        Buffer.from(
          z.object({ publicKey: z.object({ challenge: z.string() }) }).parse(options.body).publicKey
            .challenge,
          'base64url',
        ).toString(),
        service.identityUrl,
        new URL(service.identityUrl).hostname,
        replacementKeys.publicKey,
      );
      const enrollmentBody = { enrollmentId: options.body.enrollmentId, response: registration };
      const registered = await client.request(
        `${service.identityUrl}/v1/identity/webauthn/initial-registration/complete`,
        returning,
        enrollmentBody,
        { 'X-CSRF-Token': token },
      );
      expect(registered.status, JSON.stringify(registered.body)).toBe(201);
      const enrollmentRead = await readEnrollment();
      expect(enrollmentRead).toMatchObject({
        status: 200,
        body: {
          state: 'COMPLETED',
          principalId: subjectId,
          participantId,
          principalEpoch: '2',
          credential: {
            credentialId: registered.body.credentialId,
            credentialEpoch: '1',
            active: true,
          },
        },
      });
      expect(Object.keys(enrollmentRead.body).sort()).toEqual([
        'completedAt',
        'credential',
        'enrollmentId',
        'expiresAt',
        'participantId',
        'principalEpoch',
        'principalId',
        'state',
      ]);
      await service.restartIdentity();
      expect(await readEnrollment()).toEqual(enrollmentRead);
      expect(
        (
          await client.request(
            `${service.identityUrl}/v1/identity/webauthn/initial-registration/complete`,
            returning,
            enrollmentBody,
            { 'X-CSRF-Token': token },
          )
        ).status,
      ).toBe(401);
      expect(
        (
          await client.request(
            `${service.identityUrl}/v1/identity/webauthn/initial-registration/options`,
            returning,
            {},
            { 'X-CSRF-Token': token },
          )
        ).status,
      ).toBe(401);
      devices.set(subjectId, {
        credentialId: z.uuid().parse(registered.body.credentialId),
        externalCredentialId: registration.id,
        privateKey: replacementKeys.privateKey,
        count: 1,
      });
      await client.stepUp(
        returning,
        'ACT-IDENTITY_CREATE_SESSION-V1',
        participantId,
        digest({ participantId, privacyDomainId }),
      );
      const selected = await client.request(
        `${service.identityUrl}/api/v1/session/context`,
        returning,
        { participantId, privacyDomainId },
        {
          'X-CSRF-Token': await client.csrf(
            returning,
            'ACT-IDENTITY_CREATE_SESSION-V1',
            service.identityUrl,
          ),
        },
      );
      expect(selected.status, JSON.stringify(selected.body)).toBe(201);
      expect(selected.body).toMatchObject({
        principalId: subjectId,
        contextMode: 'PARTICIPANT',
        authorityEpoch: '2',
      });
      expect((await read()).body.effect.replacementState).toBe('ENROLLED');
      expect((await read()).body.operationId).toBe(result.body.operationId);
      const registeredRead = await read();
      await service.restartIdentity();
      expect(await read()).toEqual(registeredRead);
      const note = 'Confirmed revoked credentials, new subject epoch and complete evidence.';
      await governed(
        maker,
        checker,
        `/v1/identity/recoveries/${recoveryId}/post-review`,
        { note },
        { recoveryId, note },
        recoveryId,
        '5',
      );
      expect((await read()).body).toMatchObject({
        effect: { state: 'COMPLETED', postReviewStatus: 'REVIEWED' },
      });
      const recoveredChecker: GovernanceActor = {
        principalId: subjectId,
        sessionId: selected.body.sessionId as string,
        sessionToken: selected.body.sessionToken as string,
      };
      expect(await readEnrollment(recoveredChecker)).toEqual(enrollmentRead);
      await governed(
        maker,
        recoveredChecker,
        `/v1/identity/recovery-principals/${executorId}/revoke`,
        {},
        { principalId: executorId, state: 'REVOKED' },
        executorId,
        '1',
      );
    } finally {
      await workbench?.close();
      await oidc.close();
      await policy.close();
      await extra.close();
      await service.close();
      await Promise.all([admin.end(), runtime.end(), policyPool.end()]);
    }
  },
  60000,
);
