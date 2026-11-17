import { participantLifecycleReadback } from '../../../services/participant-service/src/contracts/participant-lifecycle.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import {
  canonicalAbiBytes,
  selectorFor,
} from '../../../services/control-api/src/configuration/contract-assets.js';
import { createPrivateKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { chromium } from '@playwright/test';
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

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const participantId = '018f0000-0000-7000-8000-000000000101',
  privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const makerId = '018f0000-0000-7000-8000-000000000711',
  checkerId = '018f0000-0000-7000-8000-000000000712';
const createAction = 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
  approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1',
  approvalAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';

// REQ-SR01-B0-REQ-FLOWREQ-PARTICIPANT-CREATE / REQ-SR01-B0-LEDGER-SEM-219.
integration(
  'hands an empty Participant to its proved first administrator through real governed HTTP owners',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const runtime = new Pool({
      connectionString: process.env.OPENPC_I02_PLATFORM_RUNTIME_DATABASE_URL,
    });
    const database = new URL(runtimeUrl!);
    database.username = 'openpc_policy_runtime';
    const policyPool = new Pool({ connectionString: database.href });
    const provider = await oidcProviderFixture(
      participantId,
      id(),
      'first-administrator-recipient',
      { membershipHints: false },
    );
    const service = await participantReadbackRuntime({
      runtime,
      identityDatabaseUrl: runtimeUrl!,
      participantId,
      privacyDomainId,
      operatorPrincipalId: makerId,
      checkerPrincipalId: checkerId,
      oidc: provider,
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
    const browser = await chromium.launch({ headless: true });
    const contractFixtures: Awaited<ReturnType<typeof contractAdministrationFixture>>[] = [];
    const platformContextId = id();
    try {
      // Initial Platform trust only. No candidate, approval, invitation, membership or acceptance state is seeded.
      await admin.query(
        `insert into control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version)
         values($1,$2,'ACTIVE',17,1)`,
        [platformContextId, participantId],
      );
      const devices = new Map<string, TestAuthenticator>();
      for (const principalId of [makerId, checkerId]) {
        const envelopeId = id(),
          assignmentId = id(),
          initialTrust = Buffer.from(`initial-platform-custodian:${principalId}`);
        await admin.query(
          `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'PLATFORM_OPERATOR',$3,'ACTIVE',1)`,
          [principalId, participantId, principalId],
        );
        await admin.query('insert into control.identity_subject(identity_subject_id) values($1)', [
          principalId,
        ]);
        await admin.query(
          'insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$1)',
          [principalId, participantId],
        );
        await admin.query(
          `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
        values($1,$2,$3,$3,1,0,'ACTIVE',clock_timestamp()-interval '1 hour',$4,$5,$4,$6,ARRAY(select action_intent_id from control.action_intent),ARRAY['*'],ARRAY['LOW','STANDARD','HIGH'],true,true,0,$7,17)`,
          [
            envelopeId,
            participantId,
            principalId,
            initialTrust,
            sha(initialTrust),
            [privacyDomainId],
            platformContextId,
          ],
        );
        await admin.query(
          `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
        values($1,$2,$3,$4,0,$5,tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),'ACTIVE',$3,$6,ARRAY(select action_intent_id from control.action_intent),ARRAY['*'],ARRAY['LOW','STANDARD','HIGH'],true,true,0)`,
          [
            assignmentId,
            participantId,
            principalId,
            envelopeId,
            sha(initialTrust),
            [privacyDomainId],
          ],
        );
        const key = generateKeyPairSync('ec', { namedCurve: 'P-256' }),
          publicKey = key.publicKey.export({ type: 'spki', format: 'der' }),
          credentialId = id();
        await admin.query(
          `insert into control.credential(credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from)
        values($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute')`,
          [credentialId, participantId, principalId, sha(publicKey), publicKey],
        );
        devices.set(principalId, { credentialId, privateKey: key.privateKey, count: 0 });
      }
      const transferSource = await contractAdministrationFixture(admin, runtimeUrl!, id(), id());
      contractFixtures.push(transferSource);
      const transferTarget = await contractAdministrationFixture(admin, runtimeUrl!, id(), id());
      contractFixtures.push(transferTarget);
      // Pre-existing contract installation is the transfer precondition. Its registration owner retains prior accepted coverage.
      // No transfer proposal, approval, epoch change, or successor contract state is seeded.
      const oldContract = id(),
        oldBinding = id(),
        oldAbi = id(),
        existingAbi = [
          {
            type: 'function',
            name: 'balanceOf',
            inputs: [{ name: 'account', type: 'address' }],
            outputs: [{ name: 'balance', type: 'uint256' }],
            stateMutability: 'view',
          },
        ];
      const transactionPolicy = {
        version: 1,
        allowedTransactionTypes: [0, 1, 2],
        maximumValue: `0x${'ff'.repeat(32)}`,
        maximumGasLimit: '18446744073709551615',
        maximumFeePerGas: `0x${'ff'.repeat(32)}`,
        maximumPriorityFeePerGas: `0x${'00'.repeat(32)}`,
        maximumRawTransactionBytes: 131072,
        maximumCalldataBytes: 32768,
        maximumAccessListAddresses: 128,
        maximumAccessListStorageKeys: 1024,
      };
      const abiDigest = `sha256:${sha(canonicalAbiBytes(existingAbi)).toString('hex')}`,
        baselineDigest = digest({ installation: 'existing-contract-administration' });
      await admin.query(
        `insert into control.abi_artifact(abi_artifact_id,participant_id,privacy_domain_id,provenance_source,provenance_locator,provenance_retrieved_at,
        provenance_source_digest,canonical_abi,abi_digest,policy_generation_digest,canonical_abi_bytes) values($1,$2,$3,'LOCAL_FIXTURE','fixture://existing-contract',clock_timestamp(),$4,$5,$6,$4,$7)`,
        [
          oldAbi,
          transferSource.participantId,
          transferSource.privacyDomainId,
          baselineDigest,
          JSON.stringify(existingAbi),
          abiDigest,
          canonicalAbiBytes(existingAbi),
        ],
      );
      await admin.query(
        `insert into control.logical_contract_asset(logical_contract_id,participant_id,privacy_domain_id,logical_name,display_name,policy_generation_digest)
        values($1,$2,$3,'existing-contract','Existing governed contract',$4)`,
        [oldContract, transferSource.participantId, transferSource.privacyDomainId, baselineDigest],
      );
      await admin.query(
        `insert into control.contract_runtime_binding(runtime_binding_id,participant_id,privacy_domain_id,logical_contract_id,chain_id,network_id,
        genesis_digest,contract_address,code_digest,abi_artifact_id,abi_version,policy_generation_digest,state,transaction_policy)
        values($1,$2,$3,$4,'31337','local',$5,'0x1111111111111111111111111111111111111111',$5,$6,'1.0.0',$5,'BOUND',$7::jsonb)`,
        [
          oldBinding,
          transferSource.participantId,
          transferSource.privacyDomainId,
          oldContract,
          baselineDigest,
          oldAbi,
          JSON.stringify(transactionPolicy),
        ],
      );
      const maker = { ...(await service.login('operator')), principalId: makerId },
        checker = { ...(await service.login('viewer')), principalId: checkerId };
      // The isolated initial-trust login helper starts in Participant context; establish the Platform fixture before business work.
      await admin.query(
        "update control.session set context_mode='PLATFORM',privacy_domain_id=null where session_id=any($1::uuid[])",
        [[maker.sessionId, checker.sessionId]],
      );
      const client = await publicGovernanceClient({
        admin,
        identityUrl: service.identityUrl,
        policyUrl,
        participantId,
        privacyDomainId,
        devices,
      });
      const metadata = await fetch(
        `${service.participantUrl()}/v1/participants/bootstrap-metadata`,
        { headers: { Authorization: `Bearer ${maker.sessionToken}` } },
      );
      expect(metadata.status, await metadata.clone().text()).toBe(200);
      expect(await metadata.json()).toMatchObject({
        participantId,
        privacyDomainId,
        actionIntentDigest: client.actionDigests.get(createAction),
      });
      const createTarget = async () => {
        const target = id(),
          privacy = id(),
          invitationId = id(),
          token = randomBytes(32).toString('base64url');
        const candidate = {
          participantId: target,
          displayName: 'First administrator acceptance',
          idempotencyKey: `first-admin-${id()}`,
          firstAdministrator: {
            mandateId: id(),
            invitationId,
            privacyDomainId: privacy,
            roleId: id(),
            authorityEnvelopeId: id(),
            assignmentId: id(),
            displayName: 'First administrator',
            recipientIssuer: provider.issuer,
            recipientSubject: 'first-administrator-recipient',
            recipientAudience: provider.clientId,
            tokenDigest: `sha256:${sha(token).toString('hex')}`,
            actionIntentIds: [
              'ACT-PARTICIPANTS_READ_RESOURCE-V1',
              'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
              'ACT-IDENTITY_CREATE_SESSION-V1',
              'ACT-IDENTITY_UPDATE_STEP_UP-V1',
              'ACT-PARTICIPANT_CREATE_MEMBER-V1',
              'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
              'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
              'ACT-POLICY_APPROVE_REQUEST-V1',
            ],
            configuration: { 'participant.first_admin_invite_ttl': 86400000 },
          },
        };
        const send = async (approvalId = id()) =>
          client.request(`${service.participantUrl()}/v1/participants`, maker, candidate, {
            'Authorization': `Bearer ${maker.sessionToken}`,
            'X-CSRF-Token': await client.csrf(maker, createAction, service.participantUrl()),
            'Idempotency-Key': candidate.idempotencyKey,
            'X-OpenPC-Aggregate-Version': '0',
            'X-OpenPC-Approval-Request-ID': approvalId,
            'OpenPC-Action-Intent-Digest': client.actionDigests.get(createAction)!,
          });
        const staged = await client.request(
          `${service.participantUrl()}/v1/participants/prepare`,
          maker,
          candidate,
          {
            'Authorization': `Bearer ${maker.sessionToken}`,
            'X-CSRF-Token': await client.csrf(maker, createAction, service.participantUrl()),
            'Idempotency-Key': candidate.idempotencyKey,
            'X-OpenPC-Aggregate-Version': '0',
            'OpenPC-Action-Intent-Digest': client.actionDigests.get(createAction)!,
          },
        );
        expect(staged.status, JSON.stringify(staged)).toBe(202);
        const candidateDigest = digest(candidate);
        const proposed = await admin.query(
          'select state from control.mutation_candidate where participant_id=$1 and candidate_digest=$2',
          [participantId, Buffer.from(candidateDigest.slice(7), 'hex')],
        );
        expect(proposed.rows, JSON.stringify(staged)).toEqual([{ state: 'PROPOSED' }]);
        const approval = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: approvalAction,
          actionIntentDigest: client.actionDigests.get(approvalAction),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${makerId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
          reason: 'Independent review of bounded first administration.',
        });
        expect(approval.status, JSON.stringify(approval)).toBe(202);
        const approvalRef = String(approval.body.resourceRef),
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
            reason: 'Accept exact first-administrator scope.',
          },
          '1',
        );
        expect(approved.status, JSON.stringify(approved)).toBe(202);
        await client.stepUp(maker, createAction, target, candidateDigest);
        const created = await send(approvalId);
        expect(created.status, JSON.stringify(created)).toBe(201);
        const proposalRead = await fetch(
          `${service.participantUrl()}/v1/participants/bootstrap-proposals/${target}/${encodeURIComponent(candidateDigest)}`,
          {
            headers: {
              'Authorization': `Bearer ${maker.sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
            },
          },
        );
        expect(proposalRead.status, await proposalRead.clone().text()).toBe(200);
        expect(await proposalRead.json()).toMatchObject({
          candidateDigest,
          state: 'CONSUMED',
          candidate,
        });
        expect(
          (
            await admin.query(
              'select state,authority_epoch::text from control.participant where participant_id=$1',
              [target],
            )
          ).rows,
        ).toEqual([{ state: 'PROVISIONING', authority_epoch: '0' }]);
        return {
          target,
          privacy,
          invitationId,
          token,
          candidate,
          created,
          candidateDigest,
          approvalId,
          send,
        };
      };
      let { target, privacy, invitationId, token, candidate } = await createTarget();
      const ceremonyOrigin = service.identityUrl.replace('127.0.0.1', 'localhost');
      const post = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
        const response = await fetch(
          `${path.endsWith('/first-administrator') ? ceremonyOrigin : service.identityUrl}${path}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...headers },
            body: JSON.stringify(body),
          },
        );
        return {
          status: response.status,
          body: await response.json(),
          cookie: response.headers.get('set-cookie')?.split(';')[0] ?? '',
        };
      };
      const authorizationCode = async (start: {
        state: string;
        nonce: string;
        codeChallenge: string;
      }) => {
        const authorization = new URL(`${provider.issuer}/authorize`);
        authorization.search = new URLSearchParams({
          client_id: provider.clientId,
          redirect_uri: provider.redirectUri,
          response_type: 'code',
          scope: 'openid',
          state: start.state,
          nonce: start.nonce,
          code_challenge: start.codeChallenge,
          code_challenge_method: 'S256',
        }).toString();
        const response = await fetch(authorization, { redirect: 'manual' });
        return new URL(response.headers.get('location')!).searchParams.get('code')!;
      };
      let invitationToken = token,
        invitationVersion = '1';
      const invitationProof = async () => {
        const start = await post(`/v1/identity/invitations/${invitationId}/oidc/begin`, {
          participantId: target,
          privacyDomainId: privacy,
          tokenVersion: invitationVersion,
          token: invitationToken,
        });
        expect(start.status, JSON.stringify(start)).toBe(200);
        return post(
          `/v1/identity/invitations/${invitationId}/oidc/callback`,
          {
            participantId: target,
            privacyDomainId: privacy,
            transactionId: start.body.transactionId,
            state: start.body.state,
            authorizationCode: await authorizationCode(start.body),
          },
          { Cookie: start.cookie },
        );
      };
      expect(
        (
          await post(`/v1/identity/invitations/${invitationId}/oidc/begin`, {
            participantId: target,
            privacyDomainId,
            tokenVersion: '1',
            token,
          })
        ).status,
      ).not.toBe(200);
      expect(
        (
          await post(`/v1/identity/invitations/${invitationId}/oidc/begin`, {
            participantId: target,
            privacyDomainId: privacy,
            tokenVersion: '1',
            token: randomBytes(32).toString('base64url'),
          })
        ).status,
      ).not.toBe(200);
      provider.setSubject('wrong-recipient');
      expect((await invitationProof()).status).not.toBe(201);
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.principal where participant_id=$1',
            [target],
          )
        ).rows,
      ).toEqual([{ count: 0 }]);
      const lifecycleRead = async () => {
        const response = await fetch(
          `${service.participantUrl()}/v1/participants/${target}/first-administrator`,
          {
            headers: {
              'Authorization': `Bearer ${maker.sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
            },
          },
        );
        expect(response.status, await response.clone().text()).toBe(200);
        return response.json();
      };
      const lifecycleChange = async (
        change: { mutation: 'ROTATE'; tokenDigest: string } | { mutation: 'REVOKE' },
      ) => {
        const current = await lifecycleRead(),
          action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
        const candidate = {
          participantId: target,
          mandateId: current.mandateId,
          invitationId,
          custodyGeneration: current.custodyGeneration,
          tokenVersion: current.tokenVersion,
          expectedRevision: current.revision,
          idempotencyKey: `first-admin-custody-${id()}`,
          change,
        };
        const call = async (kind: 'prepare' | 'mutate', approvalId?: string) =>
          client.request(
            `${service.participantUrl()}/v1/participants/${target}/first-administrator/${kind}`,
            maker,
            candidate,
            {
              'Authorization': `Bearer ${maker.sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
              'X-CSRF-Token': await client.csrf(maker, action, service.participantUrl()),
              'Idempotency-Key': candidate.idempotencyKey,
              'X-OpenPC-Aggregate-Version': current.revision,
              'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
              ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
            },
          );
        const staged = await call('prepare');
        expect(staged.status, JSON.stringify(staged)).toBe(202);
        const candidateDigest = digest(candidate);
        const created = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: approvalAction,
          actionIntentDigest: client.actionDigests.get(approvalAction),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${makerId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
          reason: 'Change bounded first-administrator custody without extending its deadline.',
        });
        expect(created.status, JSON.stringify(created)).toBe(202);
        const ref = String(created.body.resourceRef),
          approvalId = ref.slice(-36),
          decisionDigest = digest({
            actionIntentId: approveAction,
            approvalRequestId: ref,
            candidateDigest,
            expectedRevision: '1',
            decision: 'APPROVE',
          });
        await client.stepUp(checker, approveAction, approvalId, decisionDigest);
        const decision = await client.policyMutation(
          checker,
          `/api/v1/approval-requests/${ref}/approve`,
          {
            targetRef: ref,
            actionIntentId: approveAction,
            actionIntentDigest: client.actionDigests.get(approveAction),
            inputDigest: decisionDigest,
            expectedRevision: '1',
            reason: 'Preserve recipient, role and original acceptance deadline.',
          },
          '1',
        );
        expect(decision.status, JSON.stringify(decision)).toBe(202);
        await client.stepUp(maker, action, target, candidateDigest);
        const changed = await call('mutate', approvalId);
        expect(changed.status, JSON.stringify(changed)).toBe(200);
        expect(changed.body.result).toMatchObject({ expiresAt: current.expiresAt });
        expect((await call('mutate', approvalId)).body).toEqual(changed.body);
        return changed.body.result;
      };
      provider.setSubject('first-administrator-recipient');
      let proof = await invitationProof();
      expect(proof.status, JSON.stringify(proof)).toBe(201);
      const priorProof = proof,
        priorMembership = proof.body.membershipId;
      const nextToken = randomBytes(32).toString('base64url');
      const rotated = await lifecycleChange({
        mutation: 'ROTATE',
        tokenDigest: `sha256:${sha(nextToken).toString('hex')}`,
      });
      expect(rotated).toMatchObject({ state: 'ACTIVE', custodyGeneration: '2', tokenVersion: '2' });
      expect(
        (
          await post(
            `/v1/identity/invitations/${invitationId}/first-administrator`,
            { participantId: target, privacyDomainId: privacy, request: { command: 'READ' } },
            {
              Authorization: `Bearer ${priorProof.body.bootstrap.sessionToken}`,
              Origin: ceremonyOrigin,
            },
          )
        ).status,
      ).not.toBe(200);
      expect(
        (
          await post(`/v1/identity/invitations/${invitationId}/oidc/begin`, {
            participantId: target,
            privacyDomainId: privacy,
            tokenVersion: '1',
            token,
          })
        ).status,
      ).not.toBe(200);
      invitationToken = nextToken;
      invitationVersion = '2';
      proof = await invitationProof();
      expect(proof.body.membershipId).toBe(priorMembership);

      expect(proof.status, JSON.stringify(proof)).toBe(201);
      const custodyToken = proof.body.bootstrap.sessionToken as string;
      expect(proof.body.roleIntent.authorityGranted).toBe(false);
      const ceremony = async (request: unknown, sessionToken = custodyToken) =>
        post(
          `/v1/identity/invitations/${invitationId}/first-administrator`,
          { participantId: target, privacyDomainId: privacy, request },
          { Authorization: `Bearer ${sessionToken}`, Origin: ceremonyOrigin },
        );
      expect((await ceremony({ command: 'READ' }, maker.sessionToken)).status).not.toBe(200);
      const ordinary = await post(
        '/internal/v1/local/session/validate',
        { sessionToken: custodyToken },
        { Authorization: `Bearer ${service.identityInternalToken}` },
      );
      expect(ordinary.status).not.toBe(200);
      const context = await browser.newContext(),
        page = await context.newPage(),
        cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable', { enableUI: false });
      const virtual = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          ctap2Version: 'ctap2_1',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          automaticPresenceSimulation: true,
          isUserVerified: true,
        },
      });
      await page.goto(ceremonyOrigin);
      const options = await ceremony({ command: 'ENROLL_OPTIONS' });
      expect(options.status, JSON.stringify(options)).toBe(200);
      const registration = await page.evaluate(async (publicKey) => {
        const credential = (await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(publicKey),
        })) as PublicKeyCredential;
        return credential.toJSON();
      }, options.body.publicKey);
      const enrolled = await ceremony({
        command: 'ENROLL_COMPLETE',
        enrollmentId: options.body.enrollmentId,
        response: registration,
      });
      expect(enrolled.status, JSON.stringify(enrolled)).toBe(200);
      const accept = await ceremony({ command: 'ACCEPT_OPTIONS' });
      expect(accept.status, JSON.stringify(accept)).toBe(200);
      const assertion = await page.evaluate(async (value) => {
        const from = (text: string) =>
          Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), (c) =>
            c.charCodeAt(0),
          );
        const to = (data: ArrayBuffer) =>
          btoa(String.fromCharCode(...new Uint8Array(data)))
            .replaceAll('+', '-')
            .replaceAll('/', '_')
            .replace(/=+$/u, '');
        const credential = (await navigator.credentials.get({
          publicKey: {
            challenge: from(value.challenge),
            rpId: value.rpId,
            allowCredentials: value.credentialIds.map((id: string) => ({
              type: 'public-key' as const,
              id: from(id),
            })),
            userVerification: 'required',
          },
        })) as PublicKeyCredential;
        const response = credential.response as AuthenticatorAssertionResponse;
        return JSON.stringify({
          credentialId: credential.id,
          authenticatorData: to(response.authenticatorData),
          clientDataJson: to(response.clientDataJSON),
          signature: to(response.signature),
        });
      }, accept.body);
      const request = {
        command: 'ACCEPT',
        intentDigest: accept.body.intentDigest,
        challenge: accept.body.challenge,
        assertion,
      };
      expect(
        (await ceremony({ ...request, intentDigest: `sha256:${'00'.repeat(32)}` })).status,
      ).not.toBe(200);
      expect((await ceremony({ ...request, challenge: 'X'.repeat(43) })).status).not.toBe(200);
      const concurrent = await Promise.all([ceremony(request), ceremony(request)]);
      const accepted = concurrent.find((value) => value.status === 200)!;
      expect(accepted, JSON.stringify(concurrent)).toBeDefined();
      expect(
        concurrent.every((value) => [200, 401, 403].includes(value.status)),
        JSON.stringify(concurrent),
      ).toBe(true);
      expect(accepted.body).toMatchObject({
        state: 'ACCEPTED',
        membershipState: 'ACTIVE',
        platformBootstrapAuthority: 'CLOSED',
        participantEpoch: '1',
      });
      expect(
        (
          await admin.query(
            `select platform_context_id,platform_authority_epoch::text from control.authority_envelope
         where participant_id=$1`,
            [target],
          )
        ).rows,
      ).toEqual([{ platform_context_id: platformContextId, platform_authority_epoch: '17' }]);
      await service.restartIdentity();
      expect((await ceremony(request)).body).toEqual(accepted.body);
      expect((await ceremony({ command: 'READ' })).body).toEqual(accepted.body);
      expect((await ceremony({ command: 'ACCEPT_OPTIONS' })).status).not.toBe(200);
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.assignment where participant_id=$1',
            [target],
          )
        ).rows,
      ).toEqual([{ count: 1 }]);
      expect(
        (
          await admin.query(
            'select state from control.participant_bootstrap_custody where participant_id=$1',
            [target],
          )
        ).rows,
      ).toEqual([{ state: 'ACCEPTED' }]);
      expect(
        (await ceremony({ ...request, intentDigest: `sha256:${'11'.repeat(32)}` })).status,
      ).not.toBe(200);
      const platformRead = await fetch(
        `${service.participantUrl()}/v1/participants/${target}/assignments/${candidate.firstAdministrator.assignmentId}`,
        {
          headers: {
            'Authorization': `Bearer ${maker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        },
      );
      expect(platformRead.status).not.toBe(200);
      const loginStart = await post('/api/v1/session/oidc/authorization', {
        participantId: target,
      });
      expect(loginStart.status, JSON.stringify(loginStart)).toBe(200);
      const login = await post(
        '/api/v1/session/oidc/callback',
        {
          transactionId: loginStart.body.transactionId,
          state: loginStart.body.state,
          authorizationCode: await authorizationCode(loginStart.body),
        },
        { Cookie: loginStart.cookie },
      );
      expect(login.status, JSON.stringify(login)).toBe(201);
      const sessionToken = login.cookie.split('=')[1]!;
      const recipient = {
        sessionToken,
        sessionId: sessionToken.split('.')[1]!,
        principalId: proof.body.membershipId,
      };
      const keys = await cdp.send('WebAuthn.getCredentials', {
        authenticatorId: virtual.authenticatorId,
      });
      const device = keys.credentials.find(
        (value) =>
          Buffer.from(value.credentialId, 'base64').toString('base64url') === registration.id,
      )!;
      devices.set(recipient.principalId, {
        credentialId: enrolled.body.credentialId,
        externalCredentialId: registration.id,
        privateKey: createPrivateKey({
          key: Buffer.from(device.privateKey, 'base64'),
          format: 'der',
          type: 'pkcs8',
        }),
        count: device.signCount,
      });
      const recipientClient = await publicGovernanceClient({
        admin,
        identityUrl: ceremonyOrigin,
        policyUrl,
        participantId: target,
        privacyDomainId: privacy,
        devices,
      });
      const selection = { participantId: target, privacyDomainId: privacy };
      await recipientClient.stepUp(
        recipient,
        'ACT-IDENTITY_CREATE_SESSION-V1',
        target,
        digest(selection),
      );
      const selected = await recipientClient.request(
        `${ceremonyOrigin}/api/v1/session/context`,
        recipient,
        selection,
        {
          'X-CSRF-Token': await recipientClient.csrf(
            recipient,
            'ACT-IDENTITY_CREATE_SESSION-V1',
            ceremonyOrigin,
          ),
        },
      );
      expect(selected.status, JSON.stringify(selected)).toBe(201);
      const activeToken = String(selected.body.sessionToken);
      const read = await fetch(
        `${service.participantUrl()}/v1/participants/${target}/assignments/${candidate.firstAdministrator.assignmentId}`,
        {
          headers: {
            'Authorization': `Bearer ${activeToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        },
      );
      expect(read.status, await read.text()).toBe(200);
      // Participant lifecycle is distinct from member offboarding.
      const participantLifecycleRead = async () => {
        const response = await fetch(
          `${service.participantUrl()}/v1/participants/${target}/lifecycle?privacyDomainId=${privacy}`,
          {
            headers: {
              'Authorization': `Bearer ${maker.sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
            },
          },
        );
        expect(response.status, await response.clone().text()).toBe(200);
        return response.json();
      };
      const prepareParticipantLifecycle = async (
        mutation: 'ARCHIVE' | 'RESTORE' | 'SHRINK' | 'TRANSFER',
        extra: Record<string, unknown> = {},
      ) => {
        const current = await participantLifecycleRead(),
          action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
        const change = {
          participantId: target,
          privacyDomainId: privacy,
          expectedRevision: current.revision,
          expectedEpoch: current.epoch,
          mutation,
          ...extra,
          reason: 'Govern exact Participant authority without reviving historical grants.',
          idempotencyKey: `participant-lifecycle-${id()}`,
        };
        const call = (kind: 'prepare' | 'mutate', approvalId?: string) =>
          client.csrf(maker, action, service.participantUrl()).then((csrf) =>
            client.request(
              `${service.participantUrl()}/v1/participants/${target}/lifecycle/${kind}`,
              maker,
              change,
              {
                'Authorization': `Bearer ${maker.sessionToken}`,
                'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
                'X-CSRF-Token': csrf,
                'Idempotency-Key': change.idempotencyKey,
                'X-OpenPC-Aggregate-Version': change.expectedRevision,
                'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
                ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
              },
            ),
          );
        const staged = await call('prepare');
        expect(staged.status, JSON.stringify(staged)).toBe(202);
        expect((await call('mutate')).status).not.toBe(200);
        const candidateDigest = digest(change);
        const ownApproval = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: approvalAction,
          actionIntentDigest: client.actionDigests.get(approvalAction),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${makerId}`,
          checkerSubjectRef: `urn:openpc:resource:${makerId}`,
          reason: change.reason,
        });
        expect(ownApproval.status).not.toBe(202);
        const created = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: approvalAction,
          actionIntentDigest: client.actionDigests.get(approvalAction),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${makerId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
          reason: change.reason,
        });
        expect(created.status, JSON.stringify(created)).toBe(202);
        const ref = String(created.body.resourceRef),
          approvalId = ref.slice(-36),
          decisionDigest = digest({
            actionIntentId: approveAction,
            approvalRequestId: ref,
            candidateDigest,
            expectedRevision: '1',
            decision: 'APPROVE',
          });
        await client.stepUp(checker, approveAction, approvalId, decisionDigest);
        const decision = await client.policyMutation(
          checker,
          `/api/v1/approval-requests/${ref}/approve`,
          {
            targetRef: ref,
            actionIntentId: approveAction,
            actionIntentDigest: client.actionDigests.get(approveAction),
            inputDigest: decisionDigest,
            expectedRevision: '1',
            reason: change.reason,
          },
          '1',
        );
        expect(decision.status, JSON.stringify(decision)).toBe(202);
        expect((await call('mutate', approvalId)).status).not.toBe(200);
        await client.stepUp(maker, action, target, candidateDigest);
        return { current, commit: () => call('mutate', approvalId) };
      };
      const shrink = await prepareParticipantLifecycle('SHRINK', {
        envelopeIds: [candidate.firstAdministrator.authorityEnvelopeId],
      });
      const shrunk = await shrink.commit();
      expect(shrunk.status, JSON.stringify(shrunk)).toBe(200);
      expect(shrunk.body.result).toMatchObject({
        state: 'ACTIVE',
        lifecycleState: 'LIVE',
        epoch: String(BigInt(shrink.current.epoch) + 1n),
      });
      expect((await shrink.commit()).body).toEqual(shrunk.body);
      const archive = await prepareParticipantLifecycle('ARCHIVE');
      // A genuine OIDC session-creation callback races the archive transaction.
      const racingStart = await post('/api/v1/session/oidc/authorization', {
        participantId: target,
      });
      expect(racingStart.status).toBe(200);
      const racingCode = await authorizationCode(racingStart.body);
      const [archived, racingLogin] = await Promise.all([
        archive.commit(),
        post(
          '/api/v1/session/oidc/callback',
          {
            transactionId: racingStart.body.transactionId,
            state: racingStart.body.state,
            authorizationCode: racingCode,
          },
          { Cookie: racingStart.cookie },
        ),
      ]);
      expect(archived.status, JSON.stringify(archived)).toBe(200);
      expect(archived.body.result).toMatchObject({
        state: 'SUSPENDED',
        lifecycleState: 'ARCHIVED',
        epoch: String(BigInt(archive.current.epoch) + 1n),
      });
      expect((await archive.commit()).body).toEqual(archived.body);
      expect([201, 401, 403, 404].includes(racingLogin.status), JSON.stringify(racingLogin)).toBe(
        true,
      );
      expect(
        (
          await admin.query(
            "select count(*)::int count from control.session where participant_id=$1 and state='ACTIVE'",
            [target],
          )
        ).rows,
      ).toEqual([{ count: 0 }]);
      await service.restartIdentity();
      expect(await participantLifecycleRead()).toEqual(archived.body.result);
      const deniedRead = await fetch(
        `${service.participantUrl()}/v1/participants/${target}/assignments/${candidate.firstAdministrator.assignmentId}`,
        {
          headers: {
            'Authorization': `Bearer ${activeToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        },
      );
      expect(deniedRead.status).not.toBe(200);
      const restore = await prepareParticipantLifecycle('RESTORE'),
        restored = await restore.commit();
      expect(restored.status, JSON.stringify(restored)).toBe(200);
      expect(restored.body.result).toMatchObject({
        state: 'ACTIVE',
        lifecycleState: 'LIVE',
        archivedAt: null,
        epoch: String(BigInt(participantLifecycleReadback.parse(archived.body.result).epoch) + 1n),
      });
      expect((await restore.commit()).body).toEqual(restored.body);
      expect((await archive.commit()).status).not.toBe(200);
      await service.restartIdentity();
      expect(await participantLifecycleRead()).toEqual(restored.body.result);
      for (const table of ['assignment', 'delegation', 'authority_envelope', 'session']) {
        expect(
          (
            await admin.query(
              `select count(*)::int count from control.${table} where participant_id=$1 and state='ACTIVE'`,
              [target],
            )
          ).rows,
        ).toEqual([{ count: 0 }]);
      }
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.participant_lifecycle_transition where participant_id=$1',
            [target],
          )
        ).rows,
      ).toEqual([{ count: 3 }]);
      expect(
        (
          await admin.query(
            "select count(*)::int count from control.outbox_event where participant_id=$1 and event_type='openpc.identity.participant.epoch.advanced.v1'",
            [target],
          )
        ).rows,
      ).toEqual([{ count: 3 }]);
      const priorTarget = target,
        priorPrivacy = privacy;
      target = transferSource.participantId;
      privacy = transferSource.privacyDomainId;
      const beforeTransferRead = await transferSource.read(
        `contract-runtime-bindings/urn:openpc:resource:${oldBinding}`,
      );
      expect(beforeTransferRead.status, JSON.stringify(beforeTransferRead)).toBe(200);
      expect(beforeTransferRead.body.transactionPolicy).toEqual(transactionPolicy);
      await expect(
        admin.query(
          'update control.contract_runtime_binding set transaction_policy=null where runtime_binding_id=$1',
          [oldBinding],
        ),
      ).rejects.toThrow('PC-AUTH-0002-TRANSACTION-POLICY-IMMUTABLE');
      const definitionResponse = await fetch(
        `${service.participantUrl()}/v1/participants/${target}/lifecycle/contracts/${oldContract}?privacyDomainId=${privacy}`,
        {
          headers: {
            'Authorization': `Bearer ${maker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          },
        },
      );
      expect(definitionResponse.status, await definitionResponse.clone().text()).toBe(200);
      const definition = await definitionResponse.json(),
        newContract = id();
      const transfer = await prepareParticipantLifecycle('TRANSFER', {
        logicalContractId: oldContract,
        contentDigest: definition.contentDigest,
        successorParticipantId: transferTarget.participantId,
        successorPrivacyDomainId: transferTarget.privacyDomainId,
        successorLogicalContractId: newContract,
        expectedSuccessorEpoch: '1',
      });
      const transferred = await transfer.commit();
      expect(transferred.status, JSON.stringify(transferred)).toBe(200);
      expect(participantLifecycleReadback.parse(transferred.body.result).transfer).toMatchObject({
        logicalContractId: oldContract,
        successorLogicalContractId: newContract,
        successorParticipantId: transferTarget.participantId,
        successorEpoch: '2',
      });
      expect((await transfer.commit()).body).toEqual(transferred.body);
      expect(
        (await transferSource.read(`contract-runtime-bindings/urn:openpc:resource:${oldBinding}`))
          .status,
      ).not.toBe(200);
      const binding = participantLifecycleReadback.parse(transferred.body.result).transfer!
        .bindings[0]!;
      expect(
        (
          await transferTarget.read(
            `contract-runtime-bindings/urn:openpc:resource:${binding.successorBindingId}`,
          )
        ).status,
      ).not.toBe(200);
      await transferSource.refresh();
      await transferTarget.refresh();
      expect(
        (await transferSource.read(`contract-runtime-bindings/urn:openpc:resource:${oldBinding}`))
          .body.state,
      ).toBe('QUARANTINED');
      const successorRead = await transferTarget.read(
        `contract-runtime-bindings/urn:openpc:resource:${binding.successorBindingId}`,
      );
      expect(successorRead.status, JSON.stringify(successorRead)).toBe(200);
      expect(successorRead.body.state).toBe('BOUND');
      expect(successorRead.body.transactionPolicy).toEqual(transactionPolicy);
      expect(
        (await transferTarget.read(`contract-runtime-bindings/urn:openpc:resource:${oldBinding}`))
          .status,
      ).not.toBe(200);
      await transferSource.create(
        'contract-method-policies',
        'ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1',
        {
          runtimeBindingId: `urn:openpc:resource:${oldBinding}`,
          abiArtifactId: `urn:openpc:resource:${oldAbi}`,
          abiDigest,
          canonicalSignature: 'balanceOf(address)',
          selector: selectorFor('balanceOf(address)'),
          effect: 'READ',
          requiredRoles: ['former-owner'],
          approvalRequirement: 'MAKER_CHECKER',
          mfaRequirement: 'WEBAUTHN',
          environments: ['LOCAL'],
          rpcMethodPolicyDigest: baselineDigest,
          nestedCallSetDigest: baselineDigest,
        },
        0,
      );
      await service.restartIdentity();
      expect(await participantLifecycleRead()).toEqual(transferred.body.result);
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.contract_administration_transfer where operation_id=$1',
            [transferred.body.operationId],
          )
        ).rows,
      ).toEqual([{ count: 1 }]);
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.assignment where participant_id=$1',
            [transferTarget.participantId],
          )
        ).rows,
      ).toEqual([{ count: 2 }]);
      target = priorTarget;
      privacy = priorPrivacy;
      // Adversarial persisted-state tests: no business intermediate state is seeded.
      const forged = await admin.connect();
      try {
        await forged.query('begin');
        await forged.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',true)",
          [participantId, privacyDomainId, id()],
        );
        const other = id(),
          operation = id(),
          mandate = id(),
          invitation = id();
        const substitution = {
          ...candidate.firstAdministrator,
          mandateId: mandate,
          invitationId: invitation,
          recipientSubject: 'substituted-recipient',
        };
        await forged.query(
          "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Forged target','PROVISIONING',0)",
          [other],
        );
        await forged.query(
          `insert into control.participant_bootstrap_custody(mandate_id,participant_id,participant_epoch,platform_participant_id,maker_principal_id,checker_principal_id,invitation_id,first_admin_invite_ttl_ms,configuration_digest,candidate,candidate_digest,issuance_authority,created_operation_id,created_at,expires_at)
          select $1,$2,0,platform_participant_id,maker_principal_id,checker_principal_id,$3,first_admin_invite_ttl_ms,configuration_digest,$4,$5,jsonb_set(issuance_authority,'{operationId}',to_jsonb($6::text)),$6::uuid,created_at,expires_at
          from control.participant_bootstrap_custody where participant_id=$7`,
          [
            mandate,
            other,
            invitation,
            substitution,
            Buffer.from(digest(substitution).slice(7), 'hex'),
            operation,
            target,
          ],
        );
        await expect(
          forged.query('set constraints control.bootstrap_provenance immediate'),
        ).rejects.toThrow('BOOTSTRAP-SOURCE-PROVENANCE');
      } finally {
        await forged.query('rollback');
        forged.release();
      }
      await admin.query(
        `update control.session set issued_at=issued_at-interval '13 hours',last_seen_at=last_seen_at-interval '13 hours',idle_expires_at=idle_expires_at-interval '13 hours',absolute_expires_at=absolute_expires_at-interval '13 hours',row_version=row_version+1 where participant_id=$1 and session_id=$2`,
        [target, custodyToken.split('.')[1]],
      );
      expect((await ceremony({ command: 'READ' })).status).not.toBe(200);
      // A separate empty Participant exercises terminal revocation through the same public owners.
      ({ target, privacy, invitationId, token, candidate } = await createTarget());
      invitationToken = token;
      invitationVersion = '1';
      provider.setSubject('first-administrator-recipient');
      const revokedProof = await invitationProof();
      expect(revokedProof.status).toBe(201);
      const revoked = await lifecycleChange({ mutation: 'REVOKE' });
      expect(revoked).toMatchObject({
        state: 'CANCELLED',
        custodyGeneration: '1',
        tokenVersion: '1',
      });
      expect(
        (
          await post(
            `/v1/identity/invitations/${invitationId}/first-administrator`,
            { participantId: target, privacyDomainId: privacy, request: { command: 'READ' } },
            {
              Authorization: `Bearer ${revokedProof.body.bootstrap.sessionToken}`,
              Origin: ceremonyOrigin,
            },
          )
        ).status,
      ).not.toBe(200);
      expect(
        (
          await post(`/v1/identity/invitations/${invitationId}/oidc/begin`, {
            participantId: target,
            privacyDomainId: privacy,
            tokenVersion: '1',
            token,
          })
        ).status,
      ).not.toBe(200);
      expect(
        (
          await admin.query(
            `select state,authority_epoch::text,(select count(*)::int from control.assignment where participant_id=$1) grants from control.participant where participant_id=$1`,
            [target],
          )
        ).rows,
      ).toEqual([{ state: 'PROVISIONING', authority_epoch: '0', grants: 0 }]);
      // Fault injection only: loss of the original signer's authority must deny an already-proved recipient.
      ({ target, privacy, invitationId, token, candidate } = await createTarget());
      invitationToken = token;
      invitationVersion = '1';
      const sourceProof = await invitationProof();
      expect(sourceProof.status).toBe(201);
      await admin.query(
        "update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1",
        [devices.get(makerId)!.credentialId],
      );
      expect(
        (
          await post(
            `/v1/identity/invitations/${invitationId}/first-administrator`,
            { participantId: target, privacyDomainId: privacy, request: { command: 'READ' } },
            {
              Authorization: `Bearer ${sourceProof.body.bootstrap.sessionToken}`,
              Origin: ceremonyOrigin,
            },
          )
        ).status,
      ).not.toBe(200);
      expect(
        (
          await post(`/v1/identity/invitations/${invitationId}/oidc/begin`, {
            participantId: target,
            privacyDomainId: privacy,
            tokenVersion: '1',
            token,
          })
        ).status,
      ).not.toBe(200);
      expect(
        (
          await admin.query(
            `select state,authority_epoch::text,(select count(*)::int from control.assignment where participant_id=$1) grants from control.participant where participant_id=$1`,
            [target],
          )
        ).rows,
      ).toEqual([{ state: 'PROVISIONING', authority_epoch: '0', grants: 0 }]);
    } finally {
      for (const fixture of contractFixtures.reverse()) await fixture.close();
      await browser.close();
      await policy.close();
      await service.close();
      await provider.close();
      await runtime.end();
      await policyPool.end();
      await admin.end();
    }
  },
  180000,
);
