import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { invitationCandidateSchema } from '../../../services/identity-service/src/contracts/invitation-operations.js';
import {
  governedInitialEnrollmentProfileSchema,
  type GovernedInitialEnrollmentAccount,
} from '../../../services/identity-service/src/domain/governed-initial-enrollment.js';
import {
  canonicalAuthorizationJson,
  canonicalAuthorizationDigestBytes,
} from '../../../services/identity-service/src/contracts/authorization.js';
import {
  buildPolicyService,
  HttpPolicyIdentityGateway,
} from '../../../services/module-registry/src/policy-http.js';
import { qualifyGovernedEnrollment } from './governed-initial-enrollment-fixture.js';
import { closeFixtureResources } from './close-fixture-resources.js';
import { participantReadbackRuntime } from './participant-readback-runtime.js';
import { oidcProviderFixture } from './oidc-provider-fixture.js';
import { createHardwareAuthenticatorEmulator } from './hardware-authenticator.js';
import {
  publicGovernanceClient,
  digest,
  sha,
  type TestAuthenticator,
} from './public-governance-client.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const participantId = '018f0000-0000-7000-8000-000000000101',
  privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const makerId = '018f0000-0000-7000-8000-000000000111',
  checkerId = '018f0000-0000-7000-8000-000000000112';
const update = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';

integration(
  'enrolls only three governed identities through real OIDC, independent approvals and durable factual receipts without ordinary access',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const db = new URL(runtimeUrl!);
    db.username = 'openpc_participant_runtime';
    const runtime = new Pool({ connectionString: db.href });
    db.username = 'openpc_policy_runtime';
    const policyPool = new Pool({ connectionString: db.href });
    let provider: Awaited<ReturnType<typeof oidcProviderFixture>> | undefined;
    let hardware: ReturnType<typeof createHardwareAuthenticatorEmulator> | undefined;
    let service: Awaited<ReturnType<typeof participantReadbackRuntime>> | undefined;
    let policy: ReturnType<typeof buildPolicyService> | undefined;
    let primaryFailure: { error: unknown } | undefined;
    try {
      const activeProvider = await oidcProviderFixture(participantId, id(), 'enrollment-person-0', {
        membershipHints: false,
      });
      provider = activeProvider;
      const origin = 'https://enrollment.example.test';
      const oidc = { ...activeProvider, redirectUri: `${origin}/callback` };
      const activeHardware = createHardwareAuthenticatorEmulator();
      hardware = activeHardware;
      const activeService = await participantReadbackRuntime({
        runtime,
        identityDatabaseUrl: runtimeUrl!,
        participantId,
        privacyDomainId,
        operatorPrincipalId: makerId,
        checkerPrincipalId: checkerId,
        oidc,
        localQaFixture: true,
        hardwareAttestationProfile: activeHardware.profile,
        preserveMaterial: true,
      });
      service = activeService;
      const activePolicy = buildPolicyService({
        pool: policyPool,
        identityGateway: new HttpPolicyIdentityGateway(
          activeService.identityUrl,
          activeService.identityInternalToken,
        ),
        trustedArtifactSigners: [],
        internalToken: activeService.identityInternalToken,
      });
      policy = activePolicy;
      const policyUrl = await activePolicy.listen({ host: '127.0.0.1', port: 0 });
      const roleId = id();
      // Initial operator trust only. Recipient invitations, acceptance, activation,
      // login and credentials must all pass the real public owners below.
      await admin.query(
        `insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
      values($1,$2,$3,'Initial enrollment review',array['ACT-PARTICIPANTS_READ_RESOURCE-V1'],'BOOTSTRAP',$4)`,
        [roleId, participantId, `urn:openpc:role:${roleId}`, makerId],
      );
      const devices = new Map<string, TestAuthenticator>();
      for (const principalId of [makerId, checkerId]) {
        const key = generateKeyPairSync('ec', { namedCurve: 'P-256' }),
          publicKey = key.publicKey.export({ type: 'spki', format: 'der' }),
          credentialId = id();
        await admin.query(
          `insert into control.credential(credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from)
        values($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute')`,
          [credentialId, participantId, principalId, sha(publicKey), publicKey],
        );
        await writeFile(
          join(activeService.directory, `initial-authenticator-${principalId}.private.der`),
          key.privateKey.export({ type: 'pkcs8', format: 'der' }),
          { mode: 0o600, flag: 'wx' },
        );
        devices.set(principalId, { credentialId, privateKey: key.privateKey, count: 0 });
      }
      const maker = { ...(await activeService.login('operator')), principalId: makerId },
        checker = { ...(await activeService.login('viewer')), principalId: checkerId };
      const client = await publicGovernanceClient({
        admin,
        identityUrl: activeService.identityUrl,
        policyUrl,
        participantId,
        privacyDomainId,
        devices,
      });
      const approval = async (candidateDigest: string, resourceId: string, action: string) => {
        const create = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
          approve = 'ACT-POLICY_APPROVE_REQUEST-V1';
        const opened = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: create,
          actionIntentDigest: client.actionDigests.get(create),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${makerId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
          reason: 'Review the exact first-enrollment membership change.',
        });
        expect(opened.status, JSON.stringify(opened.body)).toBe(202);
        const ref = String(opened.body.resourceRef),
          approvalId = ref.slice(-36);
        const decisionDigest = digest({
          actionIntentId: approve,
          approvalRequestId: ref,
          candidateDigest,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        await client.stepUp(checker, approve, approvalId, decisionDigest);
        const decision = await client.policyMutation(
          checker,
          `/api/v1/approval-requests/${ref}/approve`,
          {
            targetRef: ref,
            actionIntentId: approve,
            actionIntentDigest: client.actionDigests.get(approve),
            inputDigest: decisionDigest,
            expectedRevision: '1',
            reason: 'Independent review accepted.',
          },
          '1',
        );
        expect(decision.status, JSON.stringify(decision.body)).toBe(202);
        await client.stepUp(maker, action, resourceId, candidateDigest);
        return approvalId;
      };
      const codeFor = async (authorization: {
        state: string;
        nonce: string;
        codeChallenge: string;
      }) => {
        const url = new URL(`${activeProvider.issuer}/authorize`);
        url.search = new URLSearchParams({
          client_id: activeProvider.clientId,
          redirect_uri: oidc.redirectUri,
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
      const accounts: GovernedInitialEnrollmentAccount[] = [];
      for (let n = 0; n < 3; n++) {
        const invitationId = id(),
          token = randomBytes(32).toString('base64url'),
          subject = `enrollment-person-${n}`;
        activeProvider.setSubject(subject);
        const change = {
          invitationId,
          mutation: 'CREATE',
          displayName: `Enrollment ${n}`,
          recipientSubject: subject,
          intendedRoleId: roleId,
          tokenDigest: `sha256:${sha(token).toString('hex')}`,
          ttlSeconds: 3600,
        };
        const action = 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
          key = `enrollment-invitation-${id()}`;
        const send = async (body: unknown, approvalId?: string, prepare = false) =>
          client.request(
            `${activeService.identityUrl}/v1/identity/invitations/${prepare ? 'prepare' : 'mutate'}`,
            maker,
            body,
            {
              'X-CSRF-Token': await client.csrf(maker, action, activeService.identityUrl),
              'Idempotency-Key': key,
              'X-OpenPC-Aggregate-Version': '0',
              'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
              ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
            },
          );
        const prepared = await send(change, undefined, true);
        expect(prepared.status, JSON.stringify(prepared.body)).toBe(202);
        const candidate = invitationCandidateSchema.parse(prepared.body.candidate);
        const issued = await send(
          candidate,
          await approval(digest(candidate), invitationId, action),
        );
        expect(issued.status, JSON.stringify(issued.body)).toBe(200);
        const begin = await fetch(
          `${activeService.identityUrl}/v1/identity/invitations/${invitationId}/oidc/begin`,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ participantId, privacyDomainId, tokenVersion: '1', token }),
          },
        );
        expect(begin.status).toBe(200);
        const started = await begin.json();
        const accepted = await fetch(
          `${activeService.identityUrl}/v1/identity/invitations/${invitationId}/oidc/callback`,
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'cookie': begin.headers.get('set-cookie')!.split(';')[0]!,
            },
            body: JSON.stringify({
              participantId,
              privacyDomainId,
              transactionId: started.transactionId,
              state: started.state,
              authorizationCode: await codeFor(started),
            }),
          },
        );
        expect(accepted.status, JSON.stringify(await accepted.clone().json())).toBe(201);
        const membership = await accepted.json();
        const principalId = String(membership.membershipId),
          activationDigest = digest({ principalId, state: 'ACTIVE' }),
          activationKey = `enrollment-activation-${id()}`;
        const revision = String(
          (
            await admin.query(
              'select row_version::text from control.principal where participant_id=$1 and principal_id=$2',
              [participantId, principalId],
            )
          ).rows[0].row_version,
        );
        const activate = async (approvalId?: string) =>
          client.request(
            `${activeService.identityUrl}/v1/identity/principals/${principalId}/activate`,
            maker,
            {},
            {
              'X-CSRF-Token': await client.csrf(maker, update, activeService.identityUrl),
              'Idempotency-Key': activationKey,
              'X-OpenPC-Aggregate-Version': revision,
              'OpenPC-Action-Intent-Digest': client.actionDigests.get(update)!,
              ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
            },
          );
        const staged = await activate('018f0000-0000-7000-8000-000000000001');
        expect(staged.status, JSON.stringify(staged.body)).toBe(409);
        expect(staged.body).toMatchObject({ error: { code: 'PC-IDENTITY-1005' } });
        const active = await activate(await approval(activationDigest, principalId, update));
        expect(active.status, JSON.stringify(active.body)).toBe(200);
        // Read only the original committed facts to prepare the operator profile.
        const fact = (
          await admin.query(
            `select principal.authority_epoch::text principal_epoch,participant.authority_epoch::text participant_epoch,
        membership.identity_subject_id,accepted.operation_id acceptance_operation_id,activation.operation_id activation_operation_id,
        'sha256:'||encode(activation.evidence_digest,'hex') activation_evidence_digest,
        'sha256:'||encode(accepted.evidence_digest,'hex') acceptance_evidence_digest,
        'sha256:'||encode(verification.evidence_digest,'hex') maker_evidence_digest
        from control.principal principal join control.participant participant using(participant_id)
        join control.participant_membership membership on membership.participant_id=principal.participant_id and membership.membership_id=principal.principal_id
        join control.participant_invitation_acceptance accepted on accepted.membership_id=membership.membership_id and accepted.invitation_id=$3
        join control.mutation_evidence activation on activation.participant_id=principal.participant_id and activation.aggregate_id=principal.principal_id and activation.catalog_operation_id='ID-OP-PRINCIPAL-ACTIVATE'
        join control.mutation_evidence verification on verification.participant_id=activation.participant_id and verification.mfa_challenge_id=activation.mfa_challenge_id and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
        where principal.participant_id=$1 and principal.principal_id=$2`,
            [participantId, principalId, invitationId],
          )
        ).rows[0];
        accounts.push({
          participantId,
          privacyDomainId,
          principalId,
          identitySubjectId: fact.identity_subject_id,
          principalEpoch: fact.principal_epoch,
          participantEpoch: fact.participant_epoch,
          issuer: activeProvider.issuer,
          subject,
          audience: activeProvider.clientId,
          invitationId,
          invitationVersion: '1',
          acceptanceOperationId: fact.acceptance_operation_id,
          activationOperationId: fact.activation_operation_id,
          activationDigest,
          activationEvidenceDigest: fact.activation_evidence_digest,
          acceptanceEvidenceDigest: fact.acceptance_evidence_digest,
          makerVerificationEvidenceDigest: fact.maker_evidence_digest,
          kind: n === 0 ? 'EXECUTOR' : 'CUSTODIAN',
        });
      }
      const profile = governedInitialEnrollmentProfileSchema.parse({
        schema: 'pc.identity.governed-initial-enrollment-profile',
        schemaVersion: 1,
        purpose: 'FIRST_AUTHENTICATOR_ONLY',
        profile: 'LOCAL_QA',
        origin,
        validFrom: new Date().toISOString(),
        validUntil: new Date(Date.now() + 3600000).toISOString(),
        accounts,
      });
      const profileDigest = canonicalAuthorizationDigestBytes(profile);
      const owner = await admin.connect();
      try {
        await owner.query('begin');
        await owner.query('set local role openpc_control_owner');
        await owner.query("select set_config('openpc.local_qa_runtime','1',true)");
        await owner.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-IDENTITY_UPDATE_STEP_UP-V1',true)",
          [participantId, privacyDomainId, id()],
        );
        await owner.query(
          `insert into control.governed_initial_enrollment_profile(profile_digest,participant_id,privacy_domain_id,document,document_bytes,valid_from,valid_until)
        values($1,$2,$3,$4::jsonb,$5,$6,$7)`,
          [
            profileDigest,
            participantId,
            privacyDomainId,
            JSON.stringify(profile),
            Buffer.from(canonicalAuthorizationJson(profile)),
            profile.validFrom,
            profile.validUntil,
          ],
        );
        await owner.query('commit');
      } catch (error) {
        await owner.query('rollback');
        throw error;
      } finally {
        owner.release();
      }
      await activeService.configureGovernedInitialEnrollment(profile);
      await activeService.restartIdentity();
      await qualifyGovernedEnrollment({
        admin,
        activeService,
        activeProvider,
        profile,
        client,
        codeFor,
        hardware: activeHardware,
        makerProbeSessionId: maker.sessionId,
        originalCredentialIds: new Map(
          [...devices].map(([principalId, device]) => [principalId, device.credentialId]),
        ),
      });
    } catch (error) {
      primaryFailure = { error };
      throw error;
    } finally {
      await closeFixtureResources(
        [
          async () => {
            await policy?.close();
          },
          async () => {
            await service?.close();
          },
          async () => {
            await provider?.close();
          },
          async () => {
            await policyPool.end();
          },
          async () => {
            await runtime.end();
          },
          async () => {
            await admin.end();
          },
        ],
        primaryFailure,
      );
      // Failed external attestation material stays beside the retained native
      // database and Identity trust so a later diagnosis can verify original bytes.
      if (!primaryFailure) hardware?.dispose();
    }
  },
  180000,
);
