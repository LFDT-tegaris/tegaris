import { generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:https';
import type { TLSSocket } from 'node:tls';
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
import { DirectoryProfileRegistry } from '../../../services/identity-service/src/domain/directory-profiles.js';
import { directoryPrepared } from '../../../apps/admin-web/lib/directory-workflow.js';
import { directoryGroupObservationSchema } from '../../../services/identity-service/src/contracts/directory-group-observation.js';
import { directoryGroupCandidateSchema } from '../../../services/participant-service/src/contracts/directory-group-operations.js';
import { authorizeLocalPolicyAction } from '../../../services/identity-service/src/domain/policy-authorization.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { createHttpScimDirectorySource } from '../../../services/identity-service/src/domain/http-scim-directory-source.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { oidcProviderFixture } from './oidc-provider-fixture.js';
import {
  scimListSchemaUrn,
  scimUserSchemaUrn,
  scimGroupSchemaUrn,
} from '../../../services/identity-service/src/domain/scim-directory-source.js';
import {
  directoryCandidateSchema,
  directoryCandidateAction,
  type DirectoryConnectorChange,
  type DirectoryReconcileRequest,
} from '../../../services/identity-service/src/contracts/directory-operations.js';

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

// User joiner/leaver journey through the Identity services.
// TARCH-COM-021: registered mTLS observations; TARCH-FAIL-029: source failure cannot infer deletion.
// Includes approved direct group projection; explicit deletion and access review remain open.
// Registered settings remain security-approved. Connector presence never creates local authority.
integration(
  'governs directory registration, settings, exact review, suspension and durable terminal retirement',
  async () => {
    const admin = new Pool({ connectionString: adminUrl }),
      database = new URL(runtimeUrl!);
    const identityPool = new Pool({ connectionString: runtimeUrl });
    database.username = 'openpc_participant_runtime';
    const runtime = new Pool({ connectionString: database.href });
    database.username = 'openpc_policy_runtime';
    const policyPool = new Pool({ connectionString: database.href });
    const profileId = id(),
      connectorId = id(),
      foreignProfileId = id();
    const tls = await runtimeSnapshotTlsFixture(`urn:openpc:directory-profile:${profileId}`);
    const principalId = id(),
      externalId = `external-${id()}`;
    const oidc = await oidcProviderFixture(participantId, principalId, externalId);
    let providerStatus = 200,
      omitted = false;
    const externalUser = {
      schemas: [scimUserSchemaUrn],
      id: externalId,
      userName: 'external@example.invalid',
      displayName: 'External source name',
      active: true,
      meta: { resourceType: 'User', version: 'W/"1"', lastModified: new Date().toISOString() },
      roles: ['platform-admin'],
    };
    const externalGroupId = `group-${id()}`;
    const externalGroup: {
      schemas: string[];
      id: string;
      displayName: string;
      members?: { value: string; type?: string }[];
      meta: { resourceType: string; version: string; lastModified: string };
      roles: string[];
    } = {
      schemas: [scimGroupSchemaUrn],
      id: externalGroupId,
      displayName: 'External approvers',
      members: [{ value: externalId, type: 'User' }],
      meta: { resourceType: 'Group', version: 'W/"1"', lastModified: new Date().toISOString() },
      roles: ['platform-admin'],
    };
    let groupRequests = 0,
      groupStatus = 200;
    let holdGroup: (() => void) | undefined, releaseGroup: (() => void) | undefined;
    const provider = createServer(
      {
        cert: tls.server.certificate,
        key: tls.server.privateKey,
        ca: tls.server.ca,
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
      },
      (request, response) => {
        const peer = request.socket as TLSSocket;
        if (!peer.authorized || !peer.getPeerCertificate().raw.equals(tls.parsed.raw)) {
          response.writeHead(403);
          response.end();
          return;
        }
        if (request.url?.startsWith('/scim/v2/Groups/')) {
          groupRequests++;
          const respond = () => {
            response.writeHead(groupStatus, {
              'content-type': 'application/scim+json',
              'etag': externalGroup.meta.version,
            });
            response.end(JSON.stringify(externalGroup));
          };
          if (holdGroup) {
            releaseGroup = () => {
              releaseGroup = undefined;
              respond();
            };
            holdGroup();
            holdGroup = undefined;
          } else respond();
          return;
        }
        response.writeHead(providerStatus, { 'content-type': 'application/scim+json' });
        response.end(
          JSON.stringify({
            schemas: [scimListSchemaUrn],
            totalResults: omitted ? 0 : 1,
            startIndex: 1,
            itemsPerPage: omitted ? 0 : 1,
            Resources: omitted ? [] : [externalUser],
          }),
        );
      },
    );
    await new Promise<void>((resolve) => provider.listen(0, '127.0.0.1', resolve));
    const address = provider.address();
    if (!address || typeof address === 'string') throw new Error('SCIM fixture not listening');
    const source = createHttpScimDirectorySource({
      profileId,
      baseUrl: `https://127.0.0.1:${address.port}/scim/v2`,
      certificate: tls.certificate,
      privateKey: tls.privateKey,
      trustCa: tls.server.ca,
    });
    const foreignSource = createHttpScimDirectorySource({
      profileId: foreignProfileId,
      baseUrl: 'https://127.0.0.1:1/other-tenant/scim/v2',
      certificate: tls.certificate,
      privateKey: tls.privateKey,
      trustCa: tls.server.ca,
    });
    const directoryProfiles = new DirectoryProfileRegistry(
      [
        {
          participantId,
          source,
          oidcIssuer: oidc.issuer,
          oidcClientId: oidc.clientId,
          subjectMapping: 'SCIM_ID',
        },
        {
          participantId: id(),
          source: foreignSource,
          oidcIssuer: 'https://foreign.example.invalid',
          oidcClientId: 'foreign',
          subjectMapping: 'SCIM_ID',
        },
      ],
      { localOidcIssuer: oidc.issuer },
    );
    const service = await participantReadbackRuntime({
      runtime,
      identityDatabaseUrl: runtimeUrl!,
      participantId,
      privacyDomainId,
      operatorPrincipalId: operatorId,
      checkerPrincipalId: checkerId,
      directoryProfiles,
      oidc,
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
      const otherMakerSession = { ...(await service.login('operator')), principalId: operatorId };
      const read = async (path: string, session = maker, privacy = privacyDomainId) => {
        const response = await fetch(`${service.identityUrl}/v1/identity/${path}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${session.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        });
        return { status: response.status, body: await response.json() };
      };
      const availableProfiles = await read('directory-profiles');
      expect(availableProfiles.status).toBe(200);
      expect(
        availableProfiles.body.profiles.map((value: { profileId: string }) => value.profileId),
      ).toEqual([profileId]);
      expect(JSON.stringify(availableProfiles.body)).not.toMatch(
        /privateKey|certificate|secret:\/\//u,
      );
      expect((await read('directory-profiles', maker, id())).status).toBe(404);
      const send = async (
        body: unknown,
        key: string,
        revision: string,
        approvalId?: string,
        prepare = false,
      ) => {
        const reconcile = typeof body === 'object' && body !== null && 'mode' in body;
        const intent =
          reconcile && body.mode === 'PROVISION' ? 'ACT-PARTICIPANT_CREATE_MEMBER-V1' : action;
        return client.request(
          `${service.identityUrl}/v1/identity/${reconcile ? 'directory-reconciliation' : 'directory-connectors'}/${prepare ? 'prepare' : 'mutate'}`,
          maker,
          body,
          {
            'X-CSRF-Token': await client.csrf(maker, intent, service.identityUrl),
            'Idempotency-Key': key,
            'X-OpenPC-Aggregate-Version': revision,
            'OpenPC-Action-Intent-Digest': client.actionDigests.get(intent)!,
            ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
          },
        );
      };
      const approveDigest = async (candidateDigest: string, resourceId: string, intent: string) => {
        const created = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: createApproval,
          actionIntentDigest: client.actionDigests.get(createApproval),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${operatorId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
          reason: 'Review the exact registered connector and approved settings.',
        });
        expect(created.status, JSON.stringify(created.body)).toBe(202);
        const approvalRef = String(created.body.resourceRef),
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
            reason: 'Independent directory review accepted.',
          },
          '1',
        );
        expect(approved.status, JSON.stringify(approved.body)).toBe(202);
        await client.stepUp(maker, intent, resourceId, candidateDigest);
        return approvalId;
      };
      const prepare = async (
        change: DirectoryConnectorChange | DirectoryReconcileRequest,
        revision: string,
      ) => {
        const key = `directory-${id()}`,
          prepared = await send(change, key, revision, undefined, true);
        expect(prepared.status, JSON.stringify(prepared.body)).toBe(202);
        // Exercise the actual BFF reader against both public owner response variants.
        expect(directoryPrepared.parse(prepared.body).candidateDigest).toBe(
          prepared.body.candidateDigest,
        );
        const candidate = directoryCandidateSchema.parse(prepared.body.candidate),
          candidateDigest = String(prepared.body.candidateDigest);
        expect(candidateDigest).toBe(digest(candidate));
        await client.stepUp(
          checker,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          change.connectorId,
          candidateDigest,
        );
        const proposalPath = `directory-proposals/${candidateDigest}?expectedRevision=${revision}&makerPrincipalId=${operatorId}`;
        expect(await read(proposalPath, checker)).toMatchObject({
          status: 200,
          body: { candidate, state: 'PROPOSED', operationId: null },
        });
        expect((await read(proposalPath, checker, id())).status).not.toBe(200);
        const approvalId = await approveDigest(
          candidateDigest,
          change.connectorId,
          directoryCandidateAction(candidate),
        );
        return { candidate, key, revision, approvalId, candidateDigest };
      };
      const commit = async (prepared: Awaited<ReturnType<typeof prepare>>) => {
        const resourceId =
          'change' in prepared.candidate
            ? prepared.candidate.change.connectorId
            : prepared.candidate.connectorId;
        const intent = directoryCandidateAction(prepared.candidate);
        await client.stepUp(maker, intent, resourceId, prepared.candidateDigest);
        // A newer proof from another session must not replace this session's authority.
        await client.stepUp(otherMakerSession, intent, resourceId, prepared.candidateDigest);
        return send(prepared.candidate, prepared.key, prepared.revision, prepared.approvalId);
      };
      const initial = {
        mutation: 'CREATE' as const,
        connectorId,
        profileId,
        displayName: 'Directory A',
        massChangeThreshold: 5,
        externalGroupFreshnessSeconds: 900,
      };
      expect(
        (await send({ ...initial, profileId: foreignProfileId }, id(), '0', undefined, true))
          .status,
      ).not.toBe(202);
      for (const invalid of [
        { massChangeThreshold: 101 },
        { massChangeThreshold: 0.5 },
        { externalGroupFreshnessSeconds: 59 },
        { externalGroupFreshnessSeconds: 86401 },
        { privateKey: 'inline-secret-forbidden' },
      ])
        expect(
          (await send({ ...initial, ...invalid }, id(), '0', undefined, true)).status,
        ).not.toBe(202);
      const prepared = await prepare(initial, '0');
      expect((await send(prepared.candidate, prepared.key, '0')).status).not.toBe(200);
      const created = await commit(prepared);
      expect(created.status, JSON.stringify(created.body)).toBe(200);
      expect(created.body).toMatchObject({
        effect: {
          connectorId,
          profileId,
          state: 'ACTIVE',
          revision: '1',
          massChangeThreshold: 5,
          externalGroupFreshnessSeconds: 900,
        },
      });
      expect(await commit(prepared)).toEqual(created);
      const groupPath = `directory-connectors/${connectorId}/groups/${encodeURIComponent(externalGroupId)}/observation`;
      const observed = await read(groupPath);
      expect(observed.status, JSON.stringify(observed.body)).toBe(200);
      const observation = directoryGroupObservationSchema.parse(observed.body);
      expect(observation).toMatchObject({
        participantId,
        connectorId,
        connectorRevision: '1',
        externalGroupFreshnessSeconds: 900,
        source: { id: externalGroupId, members: [{ id: externalId, type: 'User' }] },
      });
      expect(Date.parse(observation.freshUntil) - Date.parse(observation.observedAt)).toBe(900_000);
      expect(JSON.stringify(observation)).not.toMatch(
        /platform-admin|privateKey|certificate|secret:\/\//u,
      );
      const countBeforeDeniedRead = groupRequests;
      expect((await read(groupPath, maker, id())).status).toBe(404);
      expect(
        (await read(`directory-connectors/${id()}/groups/${externalGroupId}/observation`)).status,
      ).toBe(404);
      expect(groupRequests).toBe(countBeforeDeniedRead);
      const groupMembers = externalGroup.members;
      for (const unresolved of [
        undefined,
        [{ value: externalId }],
        [{ value: externalId, type: 'Group' }],
        [
          { value: externalId, type: 'User' },
          { value: externalId, type: 'User' },
        ],
      ]) {
        externalGroup.members = unresolved;
        expect((await read(groupPath)).body.error).toMatchObject({ code: 'PC-AUTH-0002' });
      }
      externalGroup.members = [];
      expect((await read(groupPath)).body).toMatchObject({ source: { members: [] } });
      externalGroup.members = [
        { value: 'z-external', type: 'User' },
        { value: 'A-external', type: 'User' },
      ];
      expect((await read(groupPath)).body.source.members).toEqual([
        { id: 'A-external', type: 'User' },
        { id: 'z-external', type: 'User' },
      ]);
      externalGroup.members = groupMembers;
      for (const status of [404, 503]) {
        groupStatus = status;
        expect((await read(groupPath)).body.error).toMatchObject({ code: 'PC-AUTH-0002' });
      }
      groupStatus = 200;
      externalGroup.id = 'different-group';
      expect((await read(groupPath)).body.error).toMatchObject({ code: 'PC-AUTH-0002' });
      externalGroup.id = externalGroupId;
      const modifiedAt = externalGroup.meta.lastModified;
      externalGroup.meta.lastModified = new Date(Date.now() + 60_000).toISOString();
      expect((await read(groupPath)).body.error).toMatchObject({ code: 'PC-AUTH-0002' });
      externalGroup.meta.lastModified = modifiedAt;
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.authority_group where participant_id=$1',
            [participantId],
          )
        ).rows[0].count,
      ).toBe(0);
      const before = await admin.query(
        'select count(*)::int count from control.assignment where participant_id=$1',
        [participantId],
      );
      const settings = {
        mutation: 'CONFIGURE' as const,
        connectorId,
        displayName: 'Directory B',
        massChangeThreshold: 0,
        externalGroupFreshnessSeconds: 60,
      };
      const first = await prepare(settings, '1'),
        stale = await prepare({ ...settings, displayName: 'Stale settings' }, '1');
      const heldRequest = new Promise<void>((resolve) => {
        holdGroup = resolve;
      });
      const pendingObservation = read(groupPath);
      await heldRequest;
      expect((await commit(first)).status).toBe(200);
      releaseGroup!();
      expect((await pendingObservation).body.error).toMatchObject({ code: 'PC-IDENTITY-1001' });
      expect((await read(groupPath)).body).toMatchObject({
        connectorRevision: '2',
        externalGroupFreshnessSeconds: 60,
      });
      expect((await commit(stale)).status).not.toBe(200);
      expect((await read(`directory-connectors/${connectorId}`)).body).toMatchObject({
        effect: {
          displayName: 'Directory B',
          revision: '2',
          massChangeThreshold: 0,
          externalGroupFreshnessSeconds: 60,
        },
      });
      const membership = { externalId, principalId, displayName: `Directory user ${principalId}` };
      const provision = await prepare(
        { connectorId, mode: 'PROVISION', members: [membership] },
        '2',
      );
      expect(provision.candidate).toMatchObject({
        mode: 'PROVISION',
        reviewClass: 'MASS_CHANGE',
        managedMembers: 0,
        changedMembers: 1,
      });
      expect(JSON.stringify(provision.candidate)).not.toContain('platform-admin');
      if ('change' in provision.candidate) throw new Error('Expected reconciliation candidate');
      for (const forged of [
        { ...provision.candidate, reviewClass: 'ORDINARY' as const },
        { ...provision.candidate, observedAt: new Date(Date.now() - 3600_000).toISOString() },
      ]) {
        const forgedKey = `forged-directory-${id()}`,
          forgedDigest = digest(forged);
        expect((await send(forged, forgedKey, '2')).status).not.toBe(200);
        const forgedApproval = await approveDigest(
          forgedDigest,
          connectorId,
          directoryCandidateAction(forged),
        );
        expect((await send(forged, forgedKey, '2', forgedApproval)).status).not.toBe(200);
        expect(
          (
            await admin.query(
              'select count(*)::int count from control.principal where principal_id=$1',
              [principalId],
            )
          ).rows[0].count,
        ).toBe(0);
      }
      const provisioned = await commit(provision);
      expect(provisioned.status, JSON.stringify(provisioned.body)).toBe(200);
      expect(provisioned.body).toMatchObject({
        effect: {
          connector: { revision: '3' },
          members: [{ principalId, state: 'PROVISIONED', revision: '1', externalId }],
        },
      });
      providerStatus = 503;
      expect(await commit(provision)).toEqual(provisioned);
      providerStatus = 200;
      expect(
        await read(`directory-connectors/${connectorId}/members/${encodeURIComponent(externalId)}`),
      ).toMatchObject({
        status: 200,
        body: {
          binding: { externalId, principalId, state: 'LINKED', providerVersion: 'W/"1"' },
          membership: { state: 'PROVISIONED' },
        },
      });
      expect(
        (
          await read(
            `directory-connectors/${connectorId}/members/${encodeURIComponent(externalId)}`,
            maker,
            id(),
          )
        ).status,
      ).not.toBe(200);
      await expect(
        admin.query(
          'update control.directory_member set principal_id=$3,row_version=row_version+1 where participant_id=$1 and connector_id=$2',
          [participantId, connectorId, operatorId],
        ),
      ).rejects.toThrow(/DIRECTORY-MEMBER-TRANSITION/);
      expect(await read(`principals/${principalId}`)).toMatchObject({
        status: 200,
        body: {
          effect: {
            state: 'PROVISIONED',
            identitySubjectId: principalId,
            membershipId: principalId,
          },
        },
      });
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.assignment where participant_id=$1 and principal_id=$2',
            [participantId, principalId],
          )
        ).rows[0].count,
      ).toBe(0);
      const unchanged = await prepare(
        { connectorId, mode: 'RECONCILE', members: [membership] },
        '3',
      );
      expect(unchanged.candidate).toMatchObject({
        reviewClass: 'ORDINARY',
        managedMembers: 1,
        changedMembers: 0,
      });
      expect((await commit(unchanged)).body).toMatchObject({
        effect: {
          connector: { revision: '4' },
          members: [{ state: 'PROVISIONED', revision: '1' }],
        },
      });
      providerStatus = 503;
      expect(
        (
          await send(
            { connectorId, mode: 'RECONCILE', members: [membership] },
            id(),
            '4',
            undefined,
            true,
          )
        ).status,
      ).not.toBe(202);
      providerStatus = 200;
      omitted = true;
      expect(
        (
          await send(
            { connectorId, mode: 'RECONCILE', members: [membership] },
            id(),
            '4',
            undefined,
            true,
          )
        ).status,
      ).not.toBe(202);
      omitted = false;
      expect((await read(`principals/${principalId}`)).body).toMatchObject({
        effect: { state: 'PROVISIONED', revision: '1' },
      });
      const renamed = { ...membership, displayName: `Renamed directory user ${principalId}` };
      externalUser.meta = {
        ...externalUser.meta,
        version: 'W/"2"',
        lastModified: new Date().toISOString(),
      };
      const drifted = await prepare({ connectorId, mode: 'RECONCILE', members: [renamed] }, '4');
      externalUser.meta = {
        ...externalUser.meta,
        version: 'W/"3"',
        lastModified: new Date().toISOString(),
      };
      expect((await commit(drifted)).status).not.toBe(200);
      expect(
        (await commit(await prepare({ connectorId, mode: 'RECONCILE', members: [renamed] }, '4')))
          .body,
      ).toMatchObject({ effect: { connector: { revision: '5' }, members: [{ revision: '2' }] } });
      const oidcLogin = async () => {
        const start = await fetch(`${service.identityUrl}/v1/identity/oidc/begin`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}',
        });
        expect(start.status).toBe(200);
        const started = await start.json(),
          authorization = new URL(`${oidc.issuer}/authorize`);
        authorization.search = new URLSearchParams({
          response_type: 'code',
          client_id: started.clientId,
          redirect_uri: started.redirectUri,
          state: started.state,
          nonce: started.nonce,
          code_challenge: started.codeChallenge,
          code_challenge_method: 'S256',
        }).toString();
        const redirect = await fetch(authorization, { redirect: 'manual' }),
          location = new URL(redirect.headers.get('location')!);
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
          cookie: callback.headers.get('set-cookie')?.split(';')[0],
        };
      };
      expect((await oidcLogin()).status).not.toBe(201);
      const activationKey = `activate-directory-${id()}`,
        activationDigest = digest({ principalId, state: 'ACTIVE' });
      const activate = async (approvalId?: string) =>
        client.request(
          `${service.identityUrl}/v1/identity/principals/${principalId}/activate`,
          maker,
          {},
          {
            'X-CSRF-Token': await client.csrf(maker, action, service.identityUrl),
            'Idempotency-Key': activationKey,
            'X-OpenPC-Aggregate-Version': '2',
            'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
            ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
          },
        );
      // Existing principal ingress stages a candidate but refuses the write until actual approval.
      expect((await activate()).status).not.toBe(200);
      const activated = await activate(await approveDigest(activationDigest, principalId, action));
      expect(activated.status, JSON.stringify(activated.body)).toBe(200);
      expect(activated.body).toMatchObject({ state: 'ACTIVE', revision: '3' });
      let userSession = await oidcLogin();
      expect(userSession.status, JSON.stringify(userSession.body)).toBe(201);
      const localGroupId = id();
      const participantPath = () => `${service.participantUrl()}/v1/participants/${participantId}`;
      const groupSend = async (
        suffix: string,
        body: unknown,
        key: string,
        revision: string,
        approvalId?: string,
        intent = action,
      ) =>
        client.request(`${participantPath()}/${suffix}`, maker, body, {
          'Authorization': `Bearer ${maker.sessionToken}`,
          'X-CSRF-Token': await client.csrf(maker, intent, service.participantUrl()),
          'Idempotency-Key': key,
          'X-OpenPC-Aggregate-Version': revision,
          'OpenPC-Action-Intent-Digest': client.actionDigests.get(intent)!,
          ...(approvalId ? { 'X-OpenPC-Approval-Request-ID': approvalId } : {}),
        });
      const localRead = async (suffix: string, actor = maker) => {
        const response = await fetch(`${participantPath()}/${suffix}`, {
          headers: {
            'Authorization': `Bearer ${actor.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          },
        });
        return { status: response.status, body: await response.json() };
      };
      const createLocalGroup = {
          mutation: 'CREATE',
          groupId: localGroupId,
          groupName: 'Approved directory group',
        },
        groupKey = id();
      const groupPrepared = await groupSend('groups/prepare', createLocalGroup, groupKey, '0');
      expect(groupPrepared.status, JSON.stringify(groupPrepared.body)).toBe(202);
      expect(
        (
          await groupSend(
            'groups/mutate',
            createLocalGroup,
            groupKey,
            '0',
            await approveDigest(String(groupPrepared.body.candidateDigest), localGroupId, action),
          )
        ).status,
      ).toBe(200);
      const prepareGroupMapping = async (
        mutation: 'MAP_DIRECTORY' | 'REFRESH_DIRECTORY',
        revision: string,
      ) => {
        const key = `directory-group-${id()}`;
        const prepared = await groupSend(
          'directory-groups/prepare',
          { mutation, groupId: localGroupId, connectorId, externalGroupId },
          key,
          revision,
        );
        expect(prepared.status, JSON.stringify(prepared.body)).toBe(202);
        const candidate = directoryGroupCandidateSchema.parse(prepared.body.candidate);
        expect(prepared.body.candidateDigest).toBe(digest(candidate));
        expect(
          await localRead(
            `group-proposals/${digest(candidate)}?expectedRevision=${revision}&makerPrincipalId=${operatorId}`,
            checker,
          ),
        ).toMatchObject({ status: 200, body: { candidate } });
        const approvalId = await approveDigest(digest(candidate), localGroupId, action);
        return {
          candidate,
          commit: () => groupSend('directory-groups/mutate', candidate, key, revision, approvalId),
        };
      };
      externalGroup.members = [{ value: 'unbound-external-user', type: 'User' }];
      expect(
        (
          await groupSend(
            'directory-groups/prepare',
            { mutation: 'MAP_DIRECTORY', groupId: localGroupId, connectorId, externalGroupId },
            id(),
            '1',
          )
        ).status,
      ).not.toBe(202);
      externalGroup.members = [{ value: externalId, type: 'User' }];
      const mappingPrepared = await prepareGroupMapping('MAP_DIRECTORY', '1');
      expect(mappingPrepared.candidate).toMatchObject({
        reviewClass: 'MASS_CHANGE',
        managedMembers: 0,
        changedMembers: 1,
        members: [{ principalId, externalId }],
      });
      const mapped = await mappingPrepared.commit();
      expect(mapped.status, JSON.stringify(mapped.body)).toBe(200);
      expect(mapped.body).toMatchObject({
        group: { effect: { revision: '2' }, members: [{ principalId, current: true }] },
        mapping: { connectorId, externalGroupId, fresh: true, revision: '1' },
      });
      groupStatus = 503;
      expect(await mappingPrepared.commit()).toEqual(mapped);
      groupStatus = 200;
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.assignment where participant_id=$1 and principal_id=$2',
            [participantId, principalId],
          )
        ).rows[0].count,
      ).toBe(0);
      const manualChange = {
          mutation: 'ADD_MEMBER',
          groupId: localGroupId,
          principalId: operatorId,
        },
        manualKey = id();
      const manualPrepared = await groupSend('groups/prepare', manualChange, manualKey, '2');
      expect(manualPrepared.status).toBe(202);
      expect(
        (
          await groupSend(
            'groups/mutate',
            manualChange,
            manualKey,
            '2',
            await approveDigest(String(manualPrepared.body.candidateDigest), localGroupId, action),
          )
        ).status,
      ).toBe(403);
      const makeGroupGrant = async () => {
        const assignmentId = id(),
          key = id(),
          intent = 'ACT-PARTICIPANT_CREATE_MEMBER-V1';
        const body = {
          assignmentId,
          principalId,
          groupId: localGroupId,
          authorityEnvelopeId: '018f0000-0000-7000-8000-000000000121',
          scopeDigest: digest(assignmentId),
          privacyDomainIds: [privacyDomainId],
          actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1', 'ACT-IDENTITY_CREATE_SESSION-V1'],
          capabilityIds: [],
          resourceIds: [assignmentId, participantId],
          riskClasses: ['LOW'],
          validFrom: new Date().toISOString(),
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
        expect(
          (
            await groupSend(
              'assignments',
              body,
              key,
              '0',
              '018f0000-0000-7000-8000-000000000001',
              intent,
            )
          ).status,
        ).toBe(403);
        const approvalId = await approveDigest(digest(candidate), assignmentId, intent);
        return {
          assignmentId,
          commit: () => groupSend('assignments', body, key, '0', approvalId, intent),
        };
      };
      const groupGrant = await makeGroupGrant();
      expect((await groupGrant.commit()).status).toBe(201);
      // Grant creation advances the user's delegation lineage. Obtain a new
      // OIDC session instead of reusing the pre-grant session's stale epoch.
      userSession = await oidcLogin();
      expect(userSession.status).toBe(201);
      const groupPermits = async () =>
        (
          await admin.query(
            'select openpc.assignment_group_permits(participant_id,authority_group_id,principal_id,valid_during) allowed from control.assignment where assignment_id=$1',
            [groupGrant.assignmentId],
          )
        ).rows[0].allowed;
      expect(await groupPermits()).toBe(true);
      const expiresAt = Date.parse(mappingPrepared.candidate.observation.freshUntil);
      const policyContext = () =>
        authorizeLocalPolicyAction(
          identityPool,
          new IdentityKernel(new PostgresIdentityRepository(identityPool)),
          {
            sessionToken: userSession.cookie!.slice(userSession.cookie!.indexOf('=') + 1),
            privacyDomainId,
            actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
            resourceId: participantId,
            stepUpRequired: false,
            allowPlatformContextSelection: true,
          },
        );
      // Initial context-selection authority uses the real OIDC platform session
      // and approved grant. This is not WebAuthn or completed context selection.
      expect((await policyContext()).authorityValidUntil?.getTime()).toBe(expiresAt);
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, expiresAt - Date.now() + 50)));
      expect(await groupPermits()).toBe(false);
      await expect(policyContext()).rejects.toMatchObject({ code: 'PC-IDENTITY-1002' });
      expect(await localRead(`directory-groups/${localGroupId}`)).toMatchObject({
        status: 200,
        body: { mapping: { fresh: false }, group: { members: [{ current: false }] } },
      });
      expect((await (await makeGroupGrant()).commit()).status).toBe(403);
      const refreshed = await prepareGroupMapping('REFRESH_DIRECTORY', '2');
      expect(refreshed.candidate).toMatchObject({ reviewClass: 'ORDINARY', changedMembers: 0 });
      expect((await refreshed.commit()).status).toBe(200);
      expect(await groupPermits()).toBe(true);
      externalGroup.members = [];
      externalGroup.meta = {
        ...externalGroup.meta,
        version: 'W/"2"',
        lastModified: new Date().toISOString(),
      };
      const removeProjection = await prepareGroupMapping('REFRESH_DIRECTORY', '3');
      expect(removeProjection.candidate).toMatchObject({
        reviewClass: 'MASS_CHANGE',
        changedMembers: 1,
      });
      externalGroup.members = [{ value: externalId, type: 'User' }];
      expect((await removeProjection.commit()).status).toBe(409);
      externalGroup.members = [];
      const removedProjection = await removeProjection.commit();
      expect(removedProjection.status, JSON.stringify(removedProjection.body)).toBe(200);
      expect(removedProjection.body).toMatchObject({
        revokedAssignments: 1,
        mapping: { revision: '3' },
        group: { effect: { revision: '4' }, members: [{ current: false, state: 'REVOKED' }] },
      });
      Object.assign(maker, await service.login('operator'));
      Object.assign(checker, await service.login('viewer'));
      Object.assign(otherMakerSession, await service.login('operator'));
      userSession = await oidcLogin();
      expect(userSession.status).toBe(201);
      await service.restartParticipant();
      await service.restartIdentity();
      expect(await localRead(`directory-groups/${localGroupId}`)).toMatchObject({
        status: 200,
        body: {
          mapping: { connectorId, externalGroupId, revision: '3' },
          group: { members: [{ state: 'REVOKED' }] },
        },
      });
      expect(await localRead(`assignments/${groupGrant.assignmentId}`)).toMatchObject({
        status: 200,
        body: { effect: { groupId: localGroupId, state: 'REVOKED' } },
      });
      await expect(
        admin.query('delete from control.directory_group_mapping where authority_group_id=$1', [
          localGroupId,
        ]),
      ).rejects.toThrow('DIRECTORY-GROUP-TOMBSTONE');
      externalGroup.members = [{ value: externalId, type: 'User' }];
      externalGroup.meta = {
        ...externalGroup.meta,
        version: 'W/"3"',
        lastModified: new Date().toISOString(),
      };
      externalUser.active = false;
      externalUser.meta = {
        ...externalUser.meta,
        version: 'W/"4"',
        lastModified: new Date().toISOString(),
      };
      const disabled = await commit(
        await prepare({ connectorId, mode: 'RECONCILE', members: [renamed] }, '5'),
      );
      expect(disabled.status, JSON.stringify(disabled.body)).toBe(200);
      expect(disabled.body).toMatchObject({
        effect: { connector: { revision: '6' }, members: [{ state: 'OFFBOARDED', revision: '4' }] },
      });
      expect(
        (
          await fetch(`${service.identityUrl}/api/v1/session`, {
            headers: { Cookie: userSession.cookie! },
          })
        ).status,
      ).not.toBe(200);
      expect((await oidcLogin()).status).not.toBe(201);
      // Offboarding invalidates Participant authority snapshots; every actor authenticates again.
      Object.assign(maker, await service.login('operator'));
      Object.assign(checker, await service.login('viewer'));
      Object.assign(otherMakerSession, await service.login('operator'));
      expect(
        (
          await admin.query(
            'select state,external_id,principal_id from control.directory_member where participant_id=$1 and connector_id=$2',
            [participantId, connectorId],
          )
        ).rows,
      ).toEqual([{ state: 'OFFBOARDED', external_id: externalId, principal_id: principalId }]);
      await service.restartIdentity();
      expect((await read(groupPath)).body).toMatchObject({
        connectorId,
        connectorRevision: '6',
        source: { id: externalGroupId },
      });
      expect((await read(`principals/${principalId}`)).body).toMatchObject({
        effect: { state: 'OFFBOARDED', revision: '4' },
      });
      expect(
        await read(`directory-connectors/${connectorId}/members/${encodeURIComponent(externalId)}`),
      ).toMatchObject({
        status: 200,
        body: {
          binding: { state: 'OFFBOARDED', externalId, principalId },
          membership: { state: 'OFFBOARDED', revision: '4' },
        },
      });
      externalUser.active = true;
      externalUser.meta = {
        ...externalUser.meta,
        version: 'W/"5"',
        lastModified: new Date().toISOString(),
      };
      expect(
        (await commit(await prepare({ connectorId, mode: 'RECONCILE', members: [renamed] }, '6')))
          .status,
      ).not.toBe(200);
      expect(
        (await commit(await prepare({ mutation: 'SUSPEND', connectorId }, '6'))).body,
      ).toMatchObject({ effect: { state: 'SUSPENDED', revision: '7' } });
      const beforeSuspendedRead = groupRequests;
      expect((await read(groupPath)).body.error).toMatchObject({ code: 'PC-IDENTITY-1002' });
      expect(groupRequests).toBe(beforeSuspendedRead);
      expect(
        (await commit(await prepare({ mutation: 'RESUME', connectorId }, '7'))).body,
      ).toMatchObject({ effect: { state: 'ACTIVE', revision: '8' } });
      expect((await read(groupPath)).status).toBe(200);
      const retirement = await prepare({ mutation: 'RETIRE', connectorId }, '8'),
        retired = await commit(retirement);
      expect(retired.body).toMatchObject({ effect: { state: 'RETIRED', revision: '9' } });
      const beforeRetiredRead = groupRequests;
      expect((await read(groupPath)).body.error).toMatchObject({ code: 'PC-IDENTITY-1002' });
      expect(groupRequests).toBe(beforeRetiredRead);
      await service.restartIdentity();
      expect(await commit(retirement)).toEqual(retired);
      expect(
        await read(
          `directory-proposals/${retirement.candidateDigest}?approvalRequestId=${retirement.approvalId}`,
          checker,
        ),
      ).toMatchObject({
        status: 200,
        body: {
          state: 'CONSUMED',
          operationId: (retired.body.effect as { operationId: string }).operationId,
        },
      });
      expect(
        (await commit(await prepare({ mutation: 'RESUME', connectorId }, '9'))).status,
      ).not.toBe(200);
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.assignment where participant_id=$1',
            [participantId],
          )
        ).rows,
      ).toEqual([{ count: before.rows[0].count + 1 }]);
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.directory_member where participant_id=$1',
            [participantId],
          )
        ).rows[0].count,
      ).toBe(1);
      await expect(
        admin.query('delete from control.directory_connector where connector_id=$1', [connectorId]),
      ).rejects.toThrow(/DIRECTORY-TOMBSTONE/);
      await expect(
        admin.query(
          'update control.directory_connector set profile_id=$2,row_version=row_version+1 where connector_id=$1',
          [connectorId, id()],
        ),
      ).rejects.toThrow(/DIRECTORY-TRANSITION/);
    } finally {
      releaseGroup?.();
      await policy.close();
      await service.close();
      source.close();
      foreignSource.close();
      provider.closeAllConnections();
      await new Promise<void>((resolve) => provider.close(() => resolve()));
      await oidc.close();
      await tls.close();
      await policyPool.end();
      await identityPool.end();
      await runtime.end();
      await admin.end();
    }
  },
  240_000,
);
