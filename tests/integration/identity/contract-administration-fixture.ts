import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Pool } from 'pg';
import Fastify from 'fastify';
import { closeFixtureResources } from './close-fixture-resources.js';
import { expect } from 'vitest';
import { participantReadbackRuntime } from './participant-readback-runtime.js';
import {
  publicGovernanceClient,
  digest,
  sha,
  type TestAuthenticator,
} from './public-governance-client.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  buildPolicyService,
  HttpPolicyIdentityGateway,
} from '../../../services/module-registry/src/policy-http.js';
import { registerConfigurationRoutes } from '../../../services/control-api/src/configuration/http.js';
import { createLocalConfigurationAuthorizer } from '../../../services/control-api/src/configuration/local-authorizer.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import type { ConfigurationBusinessEvidence } from '../../../services/control-api/src/configuration/persistence/business-receipt-writer.js';
import type { NotificationEndpointOwners } from '../../../services/control-api/src/notifications/endpoint-owner-contract.js';
import type { IdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import type { ProtectedProofKeys } from '../../../services/control-api/src/evidence/protected-crypto.js';

/** Initial Participant trust only. Transfer proposals, approvals and effects use their HTTP owners. */
export async function contractAdministrationFixture(
  admin: Pool,
  databaseUrl: string,
  participantId: string,
  privacyDomainId: string,
  options: {
    existingScope?: boolean;
    /** Initial human trust shape; never changes an admitted principal. */
    principalKind?: 'USER' | 'PLATFORM_OPERATOR';
    /** One initial Participant role for a native policy's requiredRoles. */
    initialParticipantRole?: boolean;
    /** Separate initial source-read authority for a later public workload grant. */
    initialRuntimeSourceReadTrust?: boolean;
    workloadIssuer?: Parameters<typeof participantReadbackRuntime>[0]['workloadIssuer'];
    participantRuntime?: Pool;
    configurationRuntime?: Pool;
    businessEvidence?: ConfigurationBusinessEvidence;
    moduleReleaseCatalog?: Parameters<typeof buildPolicyService>[0]['moduleReleaseCatalog'];
    trustedArtifactSigners?: Parameters<typeof buildPolicyService>[0]['trustedArtifactSigners'];
    artifactCompilerSigner?: Parameters<typeof buildPolicyService>[0]['artifactCompilerSigner'];
    resourceIds?: readonly string[];
    initialPrivacyDomainIds?: readonly string[];
    /** Independently installed initial trust; never retrofit retained envelopes. */
    initialPlatformContext?: { id: string; epoch: string };
    protectedProofKeys?: ProtectedProofKeys;
    /** Trusted test composition, never an HTTP body or a substitute authorizer.
     * The factory receives the existing real scoped pool and Identity verifier. */
    notificationEndpointOwners?: (
      pool: Pool,
      verifier: IdentityRuntimeVerifier,
    ) => NotificationEndpointOwners;
  } = {},
) {
  const makerId = id(),
    checkerId = id(),
    devices = new Map<string, TestAuthenticator>();
  if (options.initialParticipantRole && options.initialPlatformContext)
    throw new Error('Initial Participant and Platform roles require separate fixtures');
  if (options.initialRuntimeSourceReadTrust && !options.initialParticipantRole)
    throw new Error('Initial source trust requires its separate Participant role fixture');
  const participantRoleId = options.initialParticipantRole ? id() : undefined;
  const sourceEnvelopeId = options.initialRuntimeSourceReadTrust ? id() : undefined;
  const initialPrivacyDomainIds = options.initialPrivacyDomainIds ?? [privacyDomainId];
  expect(initialPrivacyDomainIds).toContain(privacyDomainId);
  if (!options.existingScope) {
    await admin.query(
      `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Contract administration initial trust','ACTIVE',1)`,
      [participantId],
    );
    await admin.query(
      `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
    values($1,$2,'Contract administration','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
      [privacyDomainId, participantId],
    );
    await admin.query(
      'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
      [participantId, privacyDomainId],
    );
  } else {
    const scope = await admin.query(
      `select 1 from control.participant participant join control.privacy_domain privacy
      on privacy.participant_id=participant.participant_id where participant.participant_id=$1 and privacy.privacy_domain_id=$2
      and participant.state='ACTIVE' and participant.archived_at is null and privacy.state='ACTIVE'`,
      [participantId, privacyDomainId],
    );
    expect(scope.rowCount).toBe(1);
  }
  for (const principal of [makerId, checkerId]) {
    await admin.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1::uuid,$2,$3,$1::uuid::text,'ACTIVE',1)`,
      [
        principal,
        participantId,
        options.initialPlatformContext ? 'PLATFORM_OPERATOR' : (options.principalKind ?? 'USER'),
      ],
    );
    await admin.query('insert into control.identity_subject(identity_subject_id) values($1)', [
      principal,
    ]);
    await admin.query(
      'insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$1)',
      [principal, participantId],
    );
  }
  if (participantRoleId) {
    await admin.query(
      `insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,created_by_principal_id)
      values($1,$2,$3,'Initial Participant administrator',ARRAY(select action_intent_id from control.action_intent),$4)`,
      [participantRoleId, participantId, `urn:openpc:role:${participantRoleId}`, makerId],
    );
  }
  for (const principal of [makerId, checkerId]) {
    const envelope = id(),
      trust = Buffer.from(`contract-administration-initial-trust:${principal}`),
      key = generateKeyPairSync('ec', { namedCurve: 'P-256' }),
      publicKey = key.publicKey.export({ type: 'spki', format: 'der' }),
      credential = id();
    const roleId = options.initialPlatformContext ? id() : participantRoleId;
    if (roleId && options.initialPlatformContext) {
      await admin.query(
        `insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,created_by_principal_id)
        values($1,$2,$3,'Initial Platform custodian',ARRAY(select action_intent_id from control.action_intent),$4)`,
        [roleId, participantId, `urn:openpc:role:${roleId}`, principal],
      );
    }
    await admin.query(
      `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,authority_epoch,delegation_epoch,state,
      valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
      values($1,$2,$3,$7,$8,1,0,'ACTIVE',clock_timestamp()-interval '1 hour',$4,$5,$4,$6,ARRAY(select action_intent_id from control.action_intent where not ($12::boolean and action_intent_id='ACT-RUNTIME_READ_RPC-V1')),$9,ARRAY['LOW','STANDARD','HIGH'],true,true,0,$10,$11)`,
      [
        envelope,
        participantId,
        principal,
        trust,
        sha(trust),
        initialPrivacyDomainIds,
        makerId,
        checkerId,
        options.resourceIds ?? ['*'],
        options.initialPlatformContext?.id ?? null,
        options.initialPlatformContext?.epoch ?? null,
        Boolean(sourceEnvelopeId && principal === makerId),
      ],
    );
    await admin.query(
      `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,valid_during,state,
      created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id)
      values($1,$2,$3,$4,0,$5,tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),'ACTIVE',$3,$6,ARRAY(select action_intent_id from control.action_intent where not ($9::boolean and action_intent_id='ACT-RUNTIME_READ_RPC-V1')),$7,ARRAY['LOW','STANDARD','HIGH'],true,true,0,$8)`,
      [
        id(),
        participantId,
        principal,
        envelope,
        sha(trust),
        initialPrivacyDomainIds,
        options.resourceIds ?? ['*'],
        roleId ? `urn:openpc:role:${roleId}` : null,
        Boolean(sourceEnvelopeId && principal === makerId),
      ],
    );
    await admin.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from)
      values($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute')`,
      [credential, participantId, principal, sha(publicKey), publicKey],
    );
    devices.set(principal, { credentialId: credential, privateKey: key.privateKey, count: 0 });
  }
  if (sourceEnvelopeId) {
    // Initial human trust only, before any service or business call. The
    // maker's administration path excludes this action, leaving one source
    // path. Actual workload permission still requires the public grant owner.
    const trust = Buffer.from(`runtime-source-read-initial-trust:${makerId}`);
    await admin.query(
      `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
      authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,
      privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
      values($1,$2,$3,$3,$4,1,0,'ACTIVE',clock_timestamp()-interval '1 hour',$5,$6,$5,$7,
      ARRAY['ACT-RUNTIME_READ_RPC-V1'],ARRAY['*'],ARRAY['LOW'],false,false,0)`,
      [sourceEnvelopeId, participantId, makerId, checkerId, trust, sha(trust), [privacyDomainId]],
    );
    await admin.query(
      `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
      scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,
      risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id)
      values($1,$2,$3,$4,0,$5,tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),'ACTIVE',$3,$6,
      ARRAY['ACT-RUNTIME_READ_RPC-V1'],ARRAY['*'],ARRAY['LOW'],false,false,0,$7)`,
      [
        id(),
        participantId,
        makerId,
        sourceEnvelopeId,
        sha(trust),
        [privacyDomainId],
        `urn:openpc:role:${participantRoleId}`,
      ],
    );
    const sourcePaths = await admin.query(
      `select count(*)::int n from control.assignment assignment
      join control.authority_envelope envelope using(participant_id,authority_envelope_id)
      where assignment.participant_id=$1 and assignment.principal_id=$2
      and assignment.state='ACTIVE' and envelope.state='ACTIVE'
      and 'ACT-RUNTIME_READ_RPC-V1'=any(assignment.action_intent_ids)
      and 'ACT-RUNTIME_READ_RPC-V1'=any(envelope.action_intent_ids)`,
      [participantId, makerId],
    );
    expect(sourcePaths.rows).toEqual([{ n: 1 }]);
  }
  const pool = new Pool({ connectionString: databaseUrl }),
    policyDatabase = new URL(databaseUrl);
  policyDatabase.username = 'openpc_policy_runtime';
  const policyPool = new Pool({ connectionString: policyDatabase.href });
  const service = await participantReadbackRuntime({
    runtime: options.participantRuntime ?? pool,
    identityDatabaseUrl: databaseUrl,
    participantId,
    privacyDomainId,
    operatorPrincipalId: makerId,
    checkerPrincipalId: checkerId,
    workloadIssuer: options.workloadIssuer,
  });
  const identityRuntimeVerifier = createLocalIdentityRuntimeVerifier([
    await readFile(`${service.directory}/public.der`),
  ]);
  const policyOptions = {
    pool: policyPool,
    identityGateway: new HttpPolicyIdentityGateway(
      service.identityUrl,
      service.identityInternalToken,
    ),
    trustedArtifactSigners: options.trustedArtifactSigners ?? [],
    artifactCompilerSigner: options.artifactCompilerSigner,
    moduleReleaseCatalog: options.moduleReleaseCatalog,
    internalToken: service.identityInternalToken,
    identityRuntimeVerifier,
  };
  let policy = buildPolicyService(policyOptions);
  const policyUrl = await policy.listen({ host: '127.0.0.1', port: 0 });
  let app = Fastify({ logger: { level: 'warn' } });
  const configurationOptions = {
    protectedProofKeys: options.protectedProofKeys,
    businessEvidence: options.businessEvidence,
    pool: options.configurationRuntime ?? pool,
    authorizer: createLocalConfigurationAuthorizer(
      service.identityUrl,
      service.identityInternalToken,
      privacyDomainId,
    ),
    identityRuntimeVerifier,
    notificationEndpointOwners: options.notificationEndpointOwners?.(pool, identityRuntimeVerifier),
  };
  registerConfigurationRoutes(app, configurationOptions);
  let url = await app.listen({ host: '127.0.0.1', port: 0 });
  const client = await publicGovernanceClient({
    admin,
    identityUrl: service.identityUrl,
    policyUrl,
    participantId,
    privacyDomainId,
    devices,
  });
  let maker = { ...(await service.login('operator')), principalId: makerId },
    checker = { ...(await service.login('viewer')), principalId: checkerId };
  if (options.initialPlatformContext) {
    // The local development login owner starts in Participant context. Establish
    // independent initial Platform sessions before any business operation, as
    // in the existing first-administrator fixture. This is not an OIDC journey.
    await admin.query(
      "update control.session set context_mode='PLATFORM',privacy_domain_id=null where session_id=any($1::uuid[])",
      [[maker.sessionId, checker.sessionId]],
    );
  }
  const refresh = async () => {
    maker = { ...(await service.login('operator')), principalId: makerId };
    checker = { ...(await service.login('viewer')), principalId: checkerId };
  };
  const approvalRead = async (
    approvalId: string,
    actor: 'maker' | 'checker' = 'maker',
    privacy = privacyDomainId,
    candidate = true,
    overrides: Record<string, string> = {},
  ) => {
    const response = await fetch(
      `${policyUrl}/api/v1/approval-requests/urn:openpc:resource:${approvalId}${candidate ? '/candidate' : ''}`,
      {
        headers: {
          'Connection': 'close',
          'Cookie': `__Host-openpc_session=${(actor === 'maker' ? maker : checker).sessionToken}`,
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          'OpenPC-API-Version': '1',
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
          ...overrides,
        },
      },
    );
    return { status: response.status, body: await response.json() };
  };
  const approveCandidate = async (hash: string, review?: (approvalId: string) => Promise<void>) => {
    const approvalAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
      approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
    const proposed = await client.policyMutation(maker, '/api/v1/approval-requests', {
      actionIntentId: approvalAction,
      actionIntentDigest: client.actionDigests.get(approvalAction),
      candidateDigest: hash,
      makerSubjectRef: `urn:openpc:resource:${makerId}`,
      checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
      reason: 'Approve exact contract administration.',
    });
    expect(proposed.status, JSON.stringify(proposed)).toBe(202);
    const ref = String(proposed.body.resourceRef),
      approvalId = ref.slice(-36),
      decision = digest({
        actionIntentId: approveAction,
        approvalRequestId: ref,
        candidateDigest: hash,
        expectedRevision: '1',
        decision: 'APPROVE',
      });
    await review?.(approvalId);
    await client.stepUp(checker, approveAction, approvalId, decision);
    const approved = await client.policyMutation(
      checker,
      `/api/v1/approval-requests/${ref}/approve`,
      {
        targetRef: ref,
        actionIntentId: approveAction,
        actionIntentDigest: client.actionDigests.get(approveAction),
        inputDigest: decision,
        expectedRevision: '1',
        reason: 'Independent approval of the stored contract definition.',
      },
      '1',
    );
    expect(approved.status, JSON.stringify(approved)).toBe(202);
    return approvalId;
  };
  const mutationRequest = (
    path: string,
    action: string,
    fields: Record<string, unknown>,
    method: 'POST' | 'PATCH' = 'POST',
    actor: 'maker' | 'checker' = 'maker',
    owner: 'configuration' | 'policy' = 'configuration',
  ) => {
    const destination = owner === 'policy' ? policyUrl : url;
    const body = {
        ...fields,
        actionIntentId: action,
        actionIntentDigest: client.actionDigests.get(action),
        reason: 'Govern the exact contract definition.',
      },
      hash = digest(body),
      key = `contract-definition-${id()}`;
    const call = async (payload: Record<string, unknown> = body, proposalOnly = false) =>
      client.request(
        `${destination}/api/v1/${path}${proposalOnly ? '/proposals' : ''}`,
        actor === 'maker' ? maker : checker,
        payload,
        {
          'Cookie': `__Host-openpc_session=${(actor === 'maker' ? maker : checker).sessionToken}`,
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          'OpenPC-API-Version': '1',
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
          'Idempotency-Key': key,
          'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
          'X-OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
          ...(fields.expectedRevision === undefined
            ? {}
            : {
                'If-Match': `"${digest({ resourceId: path.split('/')[1]?.slice(-36), revision: fields.expectedRevision })}"`,
              }),
          'X-CSRF-Token': await client.csrf(
            actor === 'maker' ? maker : checker,
            action,
            destination,
          ),
        },
        method,
      );
    return { body, hash, key, call };
  };
  const prepareMutation = async (
    path: string,
    action: string,
    fields: Record<string, unknown>,
    publicCandidateReadback = false,
    owner: 'configuration' | 'policy' = 'configuration',
  ) => {
    const { body, hash, key, call } = mutationRequest(path, action, fields, 'POST', 'maker', owner);
    const staged = await call(body, publicCandidateReadback);
    if (publicCandidateReadback)
      expect(staged).toMatchObject({
        status: 200,
        body: { candidateDigest: hash, runtimePermission: 'NONE' },
      });
    expect(staged.status, JSON.stringify(staged)).not.toBe(202);
    let resource: string;
    const approvalId = await approveCandidate(
      hash,
      publicCandidateReadback
        ? async (approval) => {
            const review = await approvalRead(approval, 'checker');
            expect(review, JSON.stringify(review)).toMatchObject({
              status: 200,
              body: {
                candidateDigest: hash,
                actionIntentId: action,
                state: 'APPROVAL_REQUESTED',
                operationRef: null,
                runtimePermission: 'NONE',
              },
            });
            resource = String(review.body.resourceRef).slice(-36);
          }
        : undefined,
    );
    if (!publicCandidateReadback) {
      // Legacy fixture consumers retain read-only discovery until their public view is supported.
      const candidate = await admin.query<{ resource_id: string }>(
        'select resource_id from control.mutation_candidate where participant_id=$1 and candidate_digest=$2 and idempotency_key=$3',
        [participantId, Buffer.from(hash.slice(7), 'hex'), key],
      );
      expect(candidate.rowCount, JSON.stringify(staged)).toBe(1);
      resource = candidate.rows[0]!.resource_id;
    }
    return {
      resourceId: resource!,
      approvalId,
      idempotencyKey: key,
      body,
      commit: call,
      propose: () => call(body, true),
      stepUp: () => client.stepUp(maker, action, resource, hash),
    };
  };
  const create = async (
    path: string,
    action: string,
    fields: Record<string, unknown>,
    expected = 202,
  ) => {
    const prepared = await prepareMutation(path, action, fields);
    await prepared.stepUp();
    const committed = await prepared.commit();
    if (expected === 0) expect(committed.status, JSON.stringify(committed)).not.toBe(202);
    else expect(committed.status, JSON.stringify(committed)).toBe(expected);
    return committed;
  };
  const createWalletBinding = async (
    chainId: string,
    walletAddress: string,
    subjectId = makerId,
  ) => {
    const walletBindingId = id(),
      action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
    const input = { walletBindingId, subjectId, chainId, walletAddress };
    const change = async (revoke: boolean) => {
      const fields = revoke ? { walletBindingId } : input;
      const key = `native-value-wallet-${id()}`,
        revision = revoke ? '1' : '0';
      const hash = digest(
        revoke ? { walletBindingId, state: 'REVOKED' } : { ...input, participantId },
      );
      const prepared = await client.mutation(
        maker,
        '/v1/identity/wallet-bindings/prepare',
        { ...fields, mutation: revoke ? 'REVOKE' : 'CREATE' },
        key,
        revision,
      );
      expect(prepared, JSON.stringify(prepared)).toMatchObject({
        status: 202,
        body: { candidateDigest: hash },
      });
      const approvalId = await approveCandidate(hash);
      await client.stepUp(maker, action, walletBindingId, hash);
      const committed = await client.mutation(
        maker,
        revoke
          ? `/v1/identity/wallet-bindings/${walletBindingId}/revoke`
          : '/v1/identity/wallet-bindings',
        revoke ? {} : input,
        key,
        revision,
        approvalId,
      );
      expect(committed.status, JSON.stringify(committed)).toBe(revoke ? 200 : 201);
      return committed;
    };
    await change(false);
    return { walletBindingId, actorPrincipalId: subjectId, revoke: () => change(true) };
  };
  return {
    participantId,
    privacyDomainId,
    makerId,
    initialParticipantRoleId: participantRoleId
      ? `urn:openpc:role:${participantRoleId}`
      : undefined,
    initialRuntimeSourceEnvelopeId: sourceEnvelopeId,
    identityRuntimeVerifier,
    governance: {
      client,
      devices,
      policyUrl,
      get maker() {
        return maker;
      },
      get checker() {
        return checker;
      },
    },
    createWalletBinding,
    create,
    prepareCreation: prepareMutation,
    prepareMutation,
    ordinaryMutation: mutationRequest,
    preparePolicyMutation: (path: string, action: string, fields: Record<string, unknown>) =>
      prepareMutation(path, action, fields, true, 'policy'),
    get configurationUrl() {
      return url;
    },
    async readPolicyResource(path: string, actor: 'maker' | 'checker' = 'maker') {
      const response = await fetch(`${policyUrl}/api/v1/${path}`, {
        headers: {
          'Cookie': `__Host-openpc_session=${(actor === 'maker' ? maker : checker).sessionToken}`,
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          'OpenPC-API-Version': '1',
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
        },
        signal: AbortSignal.timeout(10000),
      });
      return { status: response.status, body: await response.json(), headers: response.headers };
    },
    async selectPrivacyContext(
      actor: 'maker' | 'checker' = 'maker',
      options: { freshStepUp?: boolean } = {},
    ) {
      const session = actor === 'maker' ? maker : checker;
      const selection = { participantId, privacyDomainId };
      if (options.freshStepUp) {
        await client.stepUp(
          session,
          'ACT-IDENTITY_CREATE_SESSION-V1',
          privacyDomainId,
          digest(selection),
        );
      }
      const selected = await client.request(
        `${service.identityUrl}/api/v1/session/context`,
        session,
        selection,
        {
          'X-CSRF-Token': await client.csrf(
            session,
            'ACT-IDENTITY_CREATE_SESSION-V1',
            service.identityUrl,
          ),
        },
      );
      expect(selected, JSON.stringify(selected)).toMatchObject({
        status: 201,
        body: { participantId, privacyDomainId, contextMode: 'PARTICIPANT' },
      });
      expect(selected.body.sessionToken).toBeTypeOf('string');
      const scopedSession = {
        principalId: session.principalId,
        sessionToken: String(selected.body.sessionToken),
        sessionId: String(selected.body.sessionId),
      };
      if (actor === 'maker') maker = scopedSession;
      else checker = scopedSession;
    },
    approvalRead,
    approveCandidate,
    /** Exact service ingress used by the public BFF. The internal token is
     * trusted fixture composition; current session/scope/role admission and
     * native policy evaluation remain enforced by the real service owner. */
    simulatePolicyVersion(policyVersionId: string, request: Record<string, unknown>) {
      return client.request(
        `${policyUrl}/internal/v1/policy-simulations`,
        maker,
        { sessionToken: maker.sessionToken, policyVersionId, request },
        {
          'Authorization': `Bearer ${service.identityInternalToken}`,
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
        },
      );
    },
    attemptMutation: (
      path: string,
      action: string,
      fields: Record<string, unknown>,
      method: 'POST' | 'PATCH' = 'POST',
    ) => mutationRequest(path, action, fields, method).call(),
    refresh,
    service,
    async restartConfiguration(businessEvidence = configurationOptions.businessEvidence) {
      configurationOptions.businessEvidence = businessEvidence;
      await app.close();
      app = Fastify({ logger: { level: 'warn' } });
      registerConfigurationRoutes(app, configurationOptions);
      url = await app.listen({ host: '127.0.0.1', port: 0 });
    },
    async restartPolicy() {
      await policy.close();
      policy = buildPolicyService(policyOptions);
      await policy.listen({ host: '127.0.0.1', port: Number(new URL(policyUrl).port) });
    },
    async read(path: string, headers: Record<string, string> = {}) {
      const response = await fetch(`${url}/api/v1/${path}`, {
        headers: {
          'Cookie': `__Host-openpc_session=${maker.sessionToken}`,
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          'OpenPC-API-Version': '1',
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
          ...headers,
        },
      });
      return { status: response.status, body: await response.json(), headers: response.headers };
    },
    async close() {
      await closeFixtureResources([
        () => app.close(),
        () => policy.close(),
        () => service.close(),
        () => pool.end(),
        () => policyPool.end(),
      ]);
    },
  };
}
