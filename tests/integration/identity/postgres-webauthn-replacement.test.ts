import { generateKeyPairSync, sign } from 'node:crypto';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { participantReadbackRuntime } from './participant-readback-runtime.js';
import {
  publicGovernanceClient,
  sha,
  digest,
  type TestAuthenticator,
  type GovernanceActor,
} from './public-governance-client.js';
import { createUnattestedTestRegistration } from './hardware-authenticator.js';
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

// Only initial trust is provisioned. Replacement, approvals and evidence use real owners.
integration(
  'replaces one authenticator through governed public owners with denial, replay and restart-safe readback',
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
      outsiderId = id();
    const actorIds = [operatorId, checkerId, outsiderId];
    const devices = new Map<string, TestAuthenticator>(),
      envelopes = new Map<string, string>(),
      assignments = new Map<string, string>();
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
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch,root_privacy_domain_id) values ($1,'Authenticator replacement journey','ACTIVE',1,$2)`,
        [participantId, privacyDomainId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values ($1,$2,'Credential context','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE')`,
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

      const maker: GovernanceActor = {
        ...(await service.login('operator')),
        principalId: operatorId,
      };
      const checker: GovernanceActor = {
        ...(await service.login('viewer')),
        principalId: checkerId,
      };
      const client = await publicGovernanceClient({
        admin,
        identityUrl: service.identityUrl,
        policyUrl,
        participantId,
        privacyDomainId,
        devices,
      });
      const origin = service.identityUrl;
      const oldCredentialId = devices.get(operatorId)!.credentialId;
      const intentRows = await admin.query<{ action_intent_id: string; digest: string }>(
        "select action_intent_id,'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent",
      );
      const actionDigests = new Map(
        intentRows.rows.map((row) => [row.action_intent_id, row.digest]),
      );
      const read = async (actor: GovernanceActor, path: string, privacy = privacyDomainId) => {
        const response = await fetch(`${origin}${path}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${actor.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        });
        return { status: response.status, body: await response.json() };
      };
      const inventory = await read(maker, '/v1/identity/webauthn/credentials');
      expect(inventory.status, JSON.stringify(inventory.body)).toBe(200);
      expect(inventory.body.items).toEqual([
        expect.objectContaining({ credentialId: oldCredentialId, active: true }),
      ]);
      expect(JSON.stringify(inventory.body)).not.toMatch(/public_key|publicKey|attestation|cose/);
      expect((await read(maker, '/v1/identity/webauthn/credentials', id())).status).not.toBe(200);
      const start = async (actor: GovernanceActor, credentialId: string) =>
        client.request(
          `${origin}/v1/identity/webauthn/replacement/options`,
          actor,
          { replacedCredentialId: credentialId },
          { 'X-CSRF-Token': await client.csrf(actor, stepUpAction, origin) },
        );
      expect((await start(checker, oldCredentialId)).status).toBe(401);
      const options = await start(maker, oldCredentialId);
      expect(options.status, JSON.stringify(options.body)).toBe(201);
      const enrollmentId = options.body.enrollmentId as string;
      const publicKey = options.body.publicKey as { challenge: string };
      const newKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const registration = createUnattestedTestRegistration(
        Buffer.from(publicKey.challenge, 'base64url').toString(),
        origin,
        new URL(origin).hostname,
        newKeys.publicKey,
      );
      const payload = { enrollmentId, response: registration };
      const complete = async (
        actor = maker,
        body: unknown = payload,
        extra: Record<string, string> = {},
      ) =>
        client.request(`${origin}/v1/identity/webauthn/replacement/complete`, actor, body, {
          'X-CSRF-Token': await client.csrf(actor, action, origin),
          ...extra,
        });
      expect((await complete(checker)).status).toBe(401);
      const wrongOrigin = createUnattestedTestRegistration(
        Buffer.from(publicKey.challenge, 'base64url').toString(),
        'https://other.example',
        new URL(origin).hostname,
        newKeys.publicKey,
      );
      expect((await complete(maker, { enrollmentId, response: wrongOrigin })).status).toBe(401);
      const prepared = await complete();
      expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
      const candidateDigest = prepared.body.candidateDigest as string;
      const revision = prepared.body.expectedRevision as string;
      const key = `replacement-${id()}`;
      const mutationHeaders = {
        'Idempotency-Key': key,
        'X-OpenPC-Aggregate-Version': revision,
        'OpenPC-Action-Intent-Digest': actionDigests.get(action)!,
      };
      const staged = await complete(maker, payload, mutationHeaders);
      expect(staged.status, JSON.stringify(staged.body)).toBe(202);
      const detailPath = `/v1/identity/webauthn-proposals/${candidateDigest}?expectedRevision=${revision}&makerPrincipalId=${operatorId}`;
      const detail = await read(checker, detailPath);
      expect(detail.status, JSON.stringify(detail.body)).toBe(200);
      expect(detail.body).toMatchObject({
        resourceId: oldCredentialId,
        makerPrincipalId: operatorId,
        candidate: { enrollmentId, replacedCredentialId: oldCredentialId },
      });
      expect(digest(detail.body.candidate)).toBe(candidateDigest);
      expect((await read(checker, detailPath, id())).status).toBe(404);
      expect((await read(checker, detailPath.replace(operatorId, checkerId))).status).toBe(404);
      const policyMutation = async (
        actor: GovernanceActor,
        path: string,
        body: Record<string, unknown>,
        version?: string,
      ) =>
        client.request(`${policyUrl}${path}`, actor, body, {
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
          'Idempotency-Key': `credential-approval-${id()}`,
          'X-CSRF-Token': await client.csrf(actor, body.actionIntentId as string, policyUrl),
          'OpenPC-Action-Intent-Digest': actionDigests.get(body.actionIntentId as string)!,
          'X-OpenPC-Action-Intent-Digest': actionDigests.get(body.actionIntentId as string)!,
          ...(version
            ? {
                'If-Match': `"${digest({ resourceId: (body.targetRef as string).slice(-36), revision: version })}"`,
              }
            : {}),
        });
      const createAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
      const created = await policyMutation(maker, '/api/v1/approval-requests', {
        actionIntentId: createAction,
        actionIntentDigest: actionDigests.get(createAction),
        candidateDigest,
        makerSubjectRef: `urn:openpc:resource:${operatorId}`,
        checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
        reason: 'Replace the current authenticator after a device upgrade.',
      });
      expect(created.status, JSON.stringify(created.body)).toBe(202);
      const approvalRef = created.body.resourceRef as string,
        approvalId = approvalRef.slice(-36);
      const boundDetail = await read(
        checker,
        `/v1/identity/webauthn-proposals/${candidateDigest}?approvalRequestId=${approvalId}`,
      );
      expect(boundDetail.body.approval).toMatchObject({
        approvalRequestId: approvalId,
        reason: 'Replace the current authenticator after a device upgrade.',
      });
      const commitHeaders = { ...mutationHeaders, 'X-OpenPC-Approval-Request-ID': approvalId };
      expect((await complete(maker, payload, commitHeaders)).status).not.toBe(201);
      const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
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
        reason: 'Independently verified the exact new authenticator fingerprint.',
      };
      // Self-approval is denied before an authenticator challenge is issued.
      const selfApprovalChallenge = await client.request(
        `${origin}/v1/identity/webauthn/assertion/challenge`,
        maker,
        {
          actionIntentId: approveAction,
          resourceId: approvalId,
          resourceDigest: decisionDigest,
          rpIdHash: `sha256:${sha(new URL(origin).hostname).toString('hex')}`,
        },
        { 'X-CSRF-Token': await client.csrf(maker, approveAction, origin) },
      );
      expect(selfApprovalChallenge).toMatchObject({
        status: 403,
        body: { error: { code: 'PC-IDENTITY-1002' } },
      });
      expect(
        (
          await policyMutation(
            maker,
            `/api/v1/approval-requests/${approvalRef}/approve`,
            decision,
            '1',
          )
        ).status,
      ).not.toBe(202);
      await client.stepUp(checker, approveAction, approvalId, decisionDigest);
      const approved = await policyMutation(
        checker,
        `/api/v1/approval-requests/${approvalRef}/approve`,
        decision,
        '1',
      );
      expect(approved.status, JSON.stringify(approved.body)).toBe(202);
      await client.stepUp(maker, action, oldCredentialId, candidateDigest);
      const versions = await admin.query(
        'select row_version::text,credential_epoch::text from control.credential where credential_id=$1',
        [oldCredentialId],
      );
      expect(BigInt(versions.rows[0].row_version)).toBeGreaterThan(BigInt(revision));
      expect(versions.rows[0].credential_epoch).toBe(revision);
      expect(
        (await complete(maker, payload, { ...commitHeaders, 'X-OpenPC-Aggregate-Version': '99' }))
          .status,
      ).not.toBe(201);
      const committed = await complete(maker, payload, commitHeaders);
      expect(committed.status, JSON.stringify(committed.body)).toBe(201);
      const newId = committed.body.credentialId as string;
      const resultPath = `/v1/identity/webauthn/enrollments/${enrollmentId}`;
      const result = await read(maker, resultPath);
      expect(result.body).toMatchObject({
        state: 'COMPLETED',
        credential: { credentialId: newId, active: true, credentialEpoch: '2' },
      });
      expect((await read(checker, resultPath)).status).not.toBe(200);
      await service.restartIdentity();
      expect((await read(maker, resultPath)).body).toEqual(result.body);
      expect((await complete(maker, payload, commitHeaders)).status).not.toBe(201);
      const after = await read(maker, '/v1/identity/webauthn/credentials');
      expect(after.body.items).toHaveLength(2);
      expect(after.body.items).toContainEqual(
        expect.objectContaining({ credentialId: oldCredentialId, active: false, state: 'REVOKED' }),
      );
      expect(after.body.items).toContainEqual(
        expect.objectContaining({
          credentialId: newId,
          active: true,
          replacedCredentialId: oldCredentialId,
        }),
      );
      const challenge = await client.request(
        `${origin}/v1/identity/webauthn/assertion/challenge`,
        maker,
        {
          actionIntentId: action,
          resourceId: oldCredentialId,
          resourceDigest: candidateDigest,
          rpIdHash: `sha256:${sha(new URL(origin).hostname).toString('hex')}`,
        },
        { 'X-CSRF-Token': await client.csrf(maker, action, origin) },
      );
      expect(challenge.status).toBe(200);
      expect(challenge.body.credentialIds).not.toContain(oldCredentialId);
      expect(challenge.body.credentialIds).toContain(registration.id);
      const oldDevice = devices.get(operatorId)!;
      const clientData = Buffer.from(
        JSON.stringify({ type: 'webauthn.get', challenge: challenge.body.challenge, origin }),
      );
      const authData = Buffer.alloc(37);
      sha(new URL(origin).hostname).copy(authData);
      authData[32] = 5;
      authData.writeUInt32BE(++oldDevice.count, 33);
      const sessionVersion = await admin.query(
        'select row_version::text from control.session where session_id=$1',
        [maker.sessionId],
      );
      const deniedOld = await client.request(
        `${origin}/v1/identity/webauthn/assertion/verify`,
        maker,
        {
          actionIntentId: action,
          resourceId: oldCredentialId,
          resourceDigest: candidateDigest,
          rpIdHash: `sha256:${sha(new URL(origin).hostname).toString('hex')}`,
          challenge: challenge.body.challenge,
          assertion: JSON.stringify({
            credentialId: oldCredentialId,
            authenticatorData: authData.toString('base64url'),
            clientDataJson: clientData.toString('base64url'),
            signature: sign(
              'sha256',
              Buffer.concat([authData, sha(clientData)]),
              oldDevice.privateKey,
            ).toString('base64url'),
          }),
        },
        {
          'X-CSRF-Token': await client.csrf(maker, action, origin),
          'Idempotency-Key': `old-authenticator-${id()}`,
          'X-OpenPC-Aggregate-Version': sessionVersion.rows[0].row_version,
          'OpenPC-Action-Intent-Digest': actionDigests.get(stepUpAction)!,
        },
      );
      expect(deniedOld.status).toBe(401);
      devices.set(operatorId, {
        credentialId: newId,
        externalCredentialId: registration.id,
        privateKey: newKeys.privateKey,
        count: 1,
      });
      await client.stepUp(maker, action, oldCredentialId, candidateDigest);
      const effects = await admin.query(
        'select count(*)::int count from control.credential where participant_id=$1 and rotated_from_credential_id=$2',
        [participantId, oldCredentialId],
      );
      expect(effects.rows[0].count).toBe(1);
    } finally {
      await policy.close();
      await service.close();
      await Promise.all([admin.end(), runtime.end(), policyPool.end()]);
    }
  },
  60000,
);
