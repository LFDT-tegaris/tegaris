import { generateKeyPairSync } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool, type PoolClient } from 'pg';
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
import { createLocalIdentityRuntimeCryptoAdapter } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { RuntimeSnapshotPublisher } from '../../../services/identity-service/src/domain/runtime-snapshot-publisher.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
  type AuthenticatedWorkloadIdentity,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { decodeIdentityAuthContextAssertionPayload } from '../../../packages/security-kernel/src/index.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const operatorId = '018f0000-0000-7000-8000-000000000111';
const checkerId = '018f0000-0000-7000-8000-000000000112';
const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
const createApproval = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';

// REQ-SR01-B0-REQ-SCRREQ-WALLETBINDING-DETAIL and RTP-060 association owner.
// Public wallet and delegation owners feed the real Rust admission consumer.
// Provider submission, installed policy and complete target acceptance remain separate.
integration(
  'governs wallet binding creation and revocation without granting invocation authority',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const database = new URL(runtimeUrl!);
    database.username = 'openpc_participant_runtime';
    const runtime = new Pool({ connectionString: database.href, max: 2 });
    database.username = 'openpc_policy_runtime';
    const policyPool = new Pool({ connectionString: database.href, max: 2 });
    const identityPool = new Pool({ connectionString: runtimeUrl, max: 2 });
    let tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>> | undefined;
    let workloadApp: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
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
        const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' });
        const credentialId = id();
        await admin.query(
          `insert into control.credential(credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from)
        values($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute')`,
          [credentialId, participantId, principalId, sha(publicKey), publicKey],
        );
        devices.set(principalId, { credentialId, privateKey: keys.privateKey, count: 0 });
      }
      // Initial runtime grantability is independent of the management grant.
      // The workload's wallet and delegations below are created by public owners.
      const roleId = `urn:openpc:role:${id()}`;
      const runtimeEnvelopeId = id(),
        runtimeAssignmentId = id();
      const runtimeValidFrom = new Date(Date.now() - 60_000).toISOString();
      await admin.query(
        `insert into control.authority_role
          (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
         values($1,$2,$3,'Initial transaction authority',ARRAY[]::text[],'BOOTSTRAP',$4)`,
        [roleId.slice(-36), participantId, roleId, operatorId],
      );
      await admin.query(
        `insert into control.authority_envelope
          (authority_envelope_id,participant_id,principal_id,maker_principal_id,authority_epoch,delegation_epoch,state,
           valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
           maker_checker_required,step_up_required,onward_delegation_depth,runtime_capability_ids)
         values($1,$2,$3,$3,1,1,'ACTIVE',$4,$5,$6,$5,$7,ARRAY[]::text[],ARRAY['*'],ARRAY['LOW'],false,false,1,
           ARRAY['SIGNED_TRANSACTION_SUBMISSION','OPERATION_STATUS_DISCLOSURE'])`,
        [
          runtimeEnvelopeId,
          participantId,
          operatorId,
          runtimeValidFrom,
          Buffer.from([0x80]),
          sha(runtimeEnvelopeId),
          [privacyDomainId],
        ],
      );
      await admin.query(
        `insert into control.assignment
          (assignment_id,participant_id,principal_id,role_id,authority_envelope_id,delegation_epoch,scope_digest,
           privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
           onward_delegation_depth,valid_during,state,created_by_principal_id,runtime_capability_ids)
         values($1,$2,$3,$4,$5,1,$6,$7,ARRAY[]::text[],ARRAY['*'],ARRAY['LOW'],false,false,1,
           tstzrange($8,null,'[)'),'ACTIVE',$3,ARRAY['SIGNED_TRANSACTION_SUBMISSION','OPERATION_STATUS_DISCLOSURE'])`,
        [
          runtimeAssignmentId,
          participantId,
          operatorId,
          roleId,
          runtimeEnvelopeId,
          sha(runtimeAssignmentId),
          [privacyDomainId],
          runtimeValidFrom,
        ],
      );
      // Initial workload identity is test trust; no wallet binding or approval is seeded.
      const subjectId = id();
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Wallet-bound workload','ACTIVE',1)`,
        [subjectId, participantId],
      );
      const workloadId = `urn:openpc:workload:${id()}`;
      const uriSan = `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`;
      tls = await runtimeSnapshotTlsFixture(uriSan);
      const publicKey = await readFile(join(service.directory, 'public.der'));
      const crypto = createLocalIdentityRuntimeCryptoAdapter({
        activePrivateKeyPkcs8Der: await readFile(join(service.directory, 'private.der')),
        activePublicKeySpkiDer: publicKey,
        trustedPublicKeysSpkiDer: [publicKey],
      });
      const publisher = new RuntimeSnapshotPublisher(
        crypto,
        {
          profileId: 'pc.identity.r1.workload-mtls',
          profileVersion: 1n,
          applicability: [1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1],
          profileClass: 1,
          signerId: 'local-test-identity',
        },
        {
          scope: ['local-wallet-test', 'local-test-ca', 'TLS1.3-X509'],
          state: { caDigest: sha(tls.server.ca).toString('hex') },
        },
      );
      workloadApp = buildLocalWorkloadMtlsService(
        identityPool,
        new IdentityKernel(
          new PostgresIdentityRepository(identityPool, systemClock, crypto, publisher),
        ),
        tls.server,
      );
      const workloadUrl = await workloadApp.listen({ host: '127.0.0.1', port: 0 });
      const certificatePublicKey = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
          public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
         values($1,$2,$3,'WORKLOAD_MTLS','local-test-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          id(),
          participantId,
          subjectId,
          uriSan,
          workloadId,
          sha(certificatePublicKey),
          certificatePublicKey,
          sha(tls.parsed.raw),
          new Date(tls.parsed.validFrom),
          new Date(tls.parsed.validTo),
        ],
      );
      const targetRuntimeId = id();
      // This downstream wallet test establishes initial target trust only; it
      // does not claim authenticated discovery or runtime activation acceptance.
      const targetFixture = await admin.connect();
      try {
        await targetFixture.query('begin');
        await targetFixture.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',true)",
          [participantId, privacyDomainId, id()],
        );
        await targetFixture.query(
          `insert into control.runtime_target(runtime_target_id,participant_id,privacy_domain_id,state,observed_at,policy_generation_digest)
           values($1,$2,$3,'DISCOVERED',clock_timestamp(),$4)`,
          [
            targetRuntimeId,
            participantId,
            privacyDomainId,
            digest('wallet association test target'),
          ],
        );
        await targetFixture.query('commit');
      } finally {
        await targetFixture.query('rollback');
        targetFixture.release();
      }
      const publish = async (grantCount = 0) => {
        const authenticated = await tls!.post(`${workloadUrl}/internal/v1/workload/authenticate`, {
          runtimeContext: { privacyDomainId, targetRuntimeId },
        });
        expect(authenticated.status, JSON.stringify(authenticated.body)).toBe(200);
        const identity = authenticated.body as AuthenticatedWorkloadIdentity;
        const snapshotId = identity.runtime!.snapshotId;
        const snapshot = (
          await admin.query<{
            manifest_payload: Buffer;
            manifest_cose: Buffer;
            manifest_digest: Buffer;
            profile_payload: Buffer;
            profile_cose: Buffer;
            profile_digest: Buffer;
            issued_at_ns: string;
          }>('select * from control.identity_runtime_snapshot where snapshot_id=$1', [snapshotId])
        ).rows[0]!;
        const content = (
          await admin.query<{ content_kind: string; content_digest: Buffer; payload: Buffer }>(
            'select * from control.identity_runtime_snapshot_content where snapshot_id=$1 order by ordinal',
            [snapshotId],
          )
        ).rows;
        const projection = JSON.parse(
          content.find((c) => c.content_kind === 'ROLE_ASSIGNMENTS')!.payload.toString(),
        ) as {
          wallet_bindings: unknown[];
          paths: unknown[];
        };
        expect(projection.paths.length).toBe(grantCount);
        return {
          wallets: projection.wallet_bindings,
          vector: decodeIdentityAuthContextAssertionPayload(
            Buffer.from(identity.runtime!.assertionPayload, 'base64'),
          ).authorityVectorDigest,
          publication: {
            manifest_payload: snapshot.manifest_payload.toString('hex'),
            manifest_cose: snapshot.manifest_cose.toString('hex'),
            manifest_digest: snapshot.manifest_digest.toString('hex'),
            profile_payload: snapshot.profile_payload.toString('hex'),
            profile_cose: snapshot.profile_cose.toString('hex'),
            profile_digest: snapshot.profile_digest.toString('hex'),
            verification_time_ns: (BigInt(snapshot.issued_at_ns) + 1_000_000n).toString(),
            assertion_payload: Buffer.from(identity.runtime!.assertionPayload, 'base64').toString(
              'hex',
            ),
            assertion_cose: Buffer.from(identity.runtime!.assertionCoseSign1, 'base64').toString(
              'hex',
            ),
            shards: content
              .filter((c) => c.content_kind === 'SHARD')
              .map((c) => c.payload.toString('hex')),
            content: content.map((c) => ({
              digest: c.content_digest.toString('hex'),
              payload: c.payload.toString('hex'),
            })),
          },
        };
      };
      const empty = await publish();
      expect(empty.wallets).toEqual([]);
      const maker = { ...(await service.login('operator')), principalId: operatorId };
      const checker = { ...(await service.login('viewer')), principalId: checkerId };
      const client = await publicGovernanceClient({
        admin,
        identityUrl: service.identityUrl,
        policyUrl,
        participantId,
        privacyDomainId,
        devices,
      });
      const base = '/v1/identity/wallet-bindings';
      const input = {
        walletBindingId: id(),
        subjectId,
        chainId: '1',
        walletAddress: '0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f',
      };
      const attemptDatabaseForgery = async (
        change: (connection: PoolClient, operationId: string) => Promise<unknown>,
        rejection: string,
      ) => {
        const connection = await admin.connect();
        try {
          await connection.query('begin');
          await connection.query('set local role openpc_identity_runtime');
          const operationId = id();
          await connection.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)",
            [participantId, privacyDomainId, operationId, action],
          );
          await expect(
            (async () => {
              await change(connection, operationId);
              await connection.query('commit');
            })(),
          ).rejects.toThrow(rejection);
        } finally {
          await connection.query('rollback');
          connection.release();
        }
      };
      // Even the runtime SQL role cannot fabricate an approved association.
      await attemptDatabaseForgery(
        (connection, operationId) =>
          connection.query(
            `insert into control.wallet_binding(wallet_binding_id,participant_id,privacy_domain_id,
             subject_id,chain_id,wallet_address,state,binding_epoch,row_version,last_operation_id)
           values($1,$2,$3,$4,1,$5,'ACTIVE',1,1,$6)`,
            [id(), participantId, privacyDomainId, subjectId, input.walletAddress, operationId],
          ),
        'WALLET-BINDING-PROVENANCE',
      );
      const read = async (resourceId = input.walletBindingId, privacy = privacyDomainId) => {
        const response = await fetch(
          `${service.identityUrl}${base}/${resourceId}?privacyDomainId=${privacy}`,
          { headers: { Cookie: `__Host-openpc_session=${maker.sessionToken}` } },
        );
        return { status: response.status, body: await response.json() };
      };
      const approveCandidate = async (
        candidateDigest: string,
        intent: string,
        resourceId: string,
      ) => {
        const requested = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: createApproval,
          actionIntentDigest: client.actionDigests.get(createApproval),
          candidateDigest,
          makerSubjectRef: `urn:openpc:resource:${operatorId}`,
          checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
          reason: 'Approve the exact scoped wallet or submission-grant candidate.',
        });
        expect(requested.status, JSON.stringify(requested.body)).toBe(202);
        const reference = requested.body.resourceRef as string;
        const approvalId = reference.slice(-36);
        const decisionDigest = digest({
          actionIntentId: approveAction,
          approvalRequestId: reference,
          candidateDigest,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        await client.stepUp(checker, approveAction, approvalId, decisionDigest);
        const approved = await client.policyMutation(
          checker,
          `/api/v1/approval-requests/${reference}/approve`,
          {
            targetRef: reference,
            actionIntentId: approveAction,
            actionIntentDigest: client.actionDigests.get(approveAction),
            inputDigest: decisionDigest,
            expectedRevision: '1',
            reason: 'Independent review of the exact candidate.',
          },
          '1',
        );
        expect(approved.status, JSON.stringify(approved.body)).toBe(202);
        await client.stepUp(maker, intent, resourceId, candidateDigest);
        return approvalId;
      };
      const initialKey = `wallet-binding-${id()}`;
      const prepare = async (mutation: 'CREATE' | 'REVOKE', revision: string) => {
        const body = mutation === 'CREATE' ? input : { walletBindingId: input.walletBindingId };
        const candidate =
          mutation === 'CREATE'
            ? { ...input, participantId }
            : { walletBindingId: input.walletBindingId, state: 'REVOKED' };
        const candidateDigest = digest(candidate);
        const key = mutation === 'CREATE' ? initialKey : `wallet-binding-${id()}`;
        const prepared = await client.mutation(
          maker,
          `${base}/prepare`,
          { ...body, mutation },
          key,
          revision,
        );
        expect(prepared, JSON.stringify(prepared)).toMatchObject({
          status: 202,
          body: { candidateDigest, expectedRevision: revision },
        });
        const approvalId = await approveCandidate(candidateDigest, action, input.walletBindingId);
        return {
          key,
          approvalId,
          commit: () =>
            client.mutation(
              maker,
              mutation === 'CREATE' ? base : `${base}/${input.walletBindingId}/revoke`,
              mutation === 'CREATE' ? input : {},
              key,
              revision,
              approvalId,
            ),
        };
      };
      expect(
        (await client.mutation(maker, base, input, initialKey, '0')).status,
      ).toBeGreaterThanOrEqual(400);
      expect(
        (await admin.query('select count(*)::int count from control.wallet_binding')).rows[0].count,
      ).toBe(0);
      const creation = await prepare('CREATE', '0');
      const altered = await client.mutation(
        maker,
        base,
        { ...input, walletAddress: `0x${'36'.repeat(20)}` },
        creation.key,
        '0',
        creation.approvalId,
      );
      expect(altered.status).toBeGreaterThanOrEqual(400);
      expect(
        (await admin.query('select count(*)::int count from control.wallet_binding')).rows[0].count,
      ).toBe(0);
      const created = await creation.commit();
      expect(created, JSON.stringify(created)).toMatchObject({
        status: 201,
        body: {
          ...input,
          participantId,
          privacyDomainId,
          state: 'ACTIVE',
          bindingEpoch: '1',
          revision: '1',
          permissionEffect: 'NONE_WITHOUT_EFFECTIVE_AUTHORITY',
        },
      });
      expect(await creation.commit()).toEqual(created);
      const active = await publish();
      expect(active.vector).not.toEqual(empty.vector);
      expect(active.wallets).toEqual([
        {
          wallet_binding_id: input.walletBindingId,
          participant_id: participantId,
          privacy_domain_id: privacyDomainId,
          subject_id: subjectId,
          chain_id: '1',
          wallet_address: input.walletAddress,
          state: 'ACTIVE',
          binding_epoch: '1',
          row_version: '1',
        },
      ]);
      await attemptDatabaseForgery(
        (connection, operationId) =>
          connection.query(
            `update control.wallet_binding set wallet_address=$2,last_operation_id=$3
             where wallet_binding_id=$1`,
            [input.walletBindingId, `0x${'36'.repeat(20)}`, operationId],
          ),
        'WALLET-BINDING-TRANSITION',
      );
      await attemptDatabaseForgery(
        (connection, operationId) =>
          connection.query(
            `update control.wallet_binding set state='REVOKED',binding_epoch=2,row_version=2,
             last_operation_id=$2 where wallet_binding_id=$1`,
            [input.walletBindingId, operationId],
          ),
        'WALLET-BINDING-PROVENANCE',
      );
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.assignment where principal_id=$1',
            [subjectId],
          )
        ).rows[0].count,
      ).toBe(0);
      expect((await read()).body).toEqual(created.body);
      const hidden = await read(input.walletBindingId, id());
      const absent = await read(id(), id());
      expect(hidden.status).toBe(absent.status);
      expect(hidden.status).toBeGreaterThanOrEqual(400);
      await service.restartIdentity();
      expect((await read()).body).toEqual(created.body);
      const runtimeBindingId = id();
      const grantAction = 'ACT-PARTICIPANT_CREATE_MEMBER-V1';
      const delegationId = id();
      const baseDelegation = {
        delegationId,
        parentId: runtimeAssignmentId,
        granteeId: subjectId,
        scopeDigest: digest({ runtimeBindingId }),
        privacyDomainIds: [privacyDomainId],
        actionIntentIds: [],
        capabilityIds: ['SIGNED_TRANSACTION_SUBMISSION'],
        resourceIds: [runtimeBindingId],
        riskClasses: ['LOW'],
        validFrom: new Date(Date.now() - 60_000).toISOString(),
        validUntil: '2030-01-01T00:00:00.000Z',
        makerCheckerRequired: false,
        stepUpRequired: false,
        onwardDelegationDepth: 0,
      };
      const grantSubmission = async (delegation: typeof baseDelegation) => {
        const grantCandidate = {
          id: delegation.delegationId,
          participantId,
          grantorId: operatorId,
          state: 'ACTIVE',
          delegationEpoch: '0',
          ...delegation,
        };
        const grantKey = `wallet-submission-grant-${id()}`;
        const grant = async (approvalId = '018f0000-0000-7000-8000-000000000001') =>
          client.request(
            `${service.participantUrl()}/v1/participants/${participantId}/delegations`,
            maker,
            delegation,
            {
              'Authorization': `Bearer ${maker.sessionToken}`,
              'X-CSRF-Token': await client.csrf(maker, grantAction, service.participantUrl()),
              'Idempotency-Key': grantKey,
              'X-OpenPC-Aggregate-Version': '0',
              'X-OpenPC-Approval-Request-ID': approvalId,
              'OpenPC-Action-Intent-Digest': client.actionDigests.get(grantAction)!,
            },
          );
        expect((await grant()).status).toBe(403);
        const grantProposal = await service.get(
          checker.sessionToken,
          digest(grantCandidate),
          privacyDomainId,
          'grant-proposals',
        );
        expect(grantProposal).toMatchObject({
          status: 200,
          body: { candidateDigest: digest(grantCandidate) },
        });
        const grantApproval = await approveCandidate(
          digest(grantCandidate),
          grantAction,
          delegation.delegationId,
        );
        const granted = await grant(grantApproval);
        expect(granted, JSON.stringify(granted)).toMatchObject({
          status: 201,
          body: { state: 'ACTIVE' },
        });
        expect(await grant(grantApproval)).toEqual(granted);
      };
      await grantSubmission(baseDelegation);
      const conditionalRuntimeBindingId = id();
      await grantSubmission({
        ...baseDelegation,
        delegationId: id(),
        scopeDigest: digest({ conditionalRuntimeBindingId }),
        resourceIds: [conditionalRuntimeBindingId],
        makerCheckerRequired: true,
        stepUpRequired: true,
      });
      const submissionGranted = await publish(2);
      expect(submissionGranted.vector).not.toEqual(active.vector);
      // A separate operation-scoped status grant cannot authorize submission,
      // selector reads or provider receipt disclosure.
      await grantSubmission({
        ...baseDelegation,
        delegationId: id(),
        scopeDigest: digest({ ownedOperationStatus: true }),
        capabilityIds: ['OPERATION_STATUS_DISCLOSURE'],
        resourceIds: ['*'],
      });
      const statusGranted = await publish(3);
      const revocation = await prepare('REVOKE', '1');
      const revoked = await revocation.commit();
      expect(revoked, JSON.stringify(revoked)).toMatchObject({
        status: 200,
        body: {
          state: 'REVOKED',
          bindingEpoch: '2',
          revision: '2',
          permissionEffect: 'NONE_WITHOUT_EFFECTIVE_AUTHORITY',
        },
      });
      expect(await revocation.commit()).toEqual(revoked);
      expect(
        (
          await admin.query(
            'select authority_epoch::text from control.principal where principal_id=$1',
            [subjectId],
          )
        ).rows[0].authority_epoch,
      ).toBe('2');
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.assignment where principal_id=$1',
            [subjectId],
          )
        ).rows[0].count,
      ).toBe(0);
      await service.restartIdentity();
      expect((await read()).body).toEqual(revoked.body);
      const withdrawn = await publish(3);
      expect(withdrawn.vector).not.toEqual(active.vector);
      expect(withdrawn.wallets).toEqual([
        {
          wallet_binding_id: input.walletBindingId,
          participant_id: participantId,
          privacy_domain_id: privacyDomainId,
          subject_id: subjectId,
          chain_id: '1',
          wallet_address: input.walletAddress,
          state: 'REVOKED',
          binding_epoch: '2',
          row_version: '2',
        },
      ]);
      const output = process.env.OPENPC_ASTRA07_WALLET_PUBLICATION_FIXTURE;
      if (output)
        await writeFile(
          output,
          JSON.stringify({
            participant_id: participantId,
            privacy_domain_id: privacyDomainId,
            target_runtime_id: targetRuntimeId,
            principal_id: subjectId,
            role_id: roleId,
            wallet_binding_id: input.walletBindingId,
            runtime_binding_id: runtimeBindingId,
            conditional_runtime_binding_id: conditionalRuntimeBindingId,
            submission_granted: submissionGranted.publication,
            status_granted: statusGranted.publication,
            identity_public_key: publicKey.toString('hex'),
            certificate_pem: tls.certificate.toString(),
            uri_san: uriSan,
            empty: empty.publication,
            active: active.publication,
            revoked: withdrawn.publication,
          }),
          { mode: 0o600 },
        );
      expect(
        (
          await admin.query(
            "select count(*)::int count from control.mutation_evidence where aggregate_type='wallet-binding' and aggregate_id=$1",
            [input.walletBindingId],
          )
        ).rows[0].count,
      ).toBe(2);
    } finally {
      await workloadApp?.close();
      await tls?.close();
      await identityPool.end();
      await policy.close();
      await service.close();
      await policyPool.end();
      await runtime.end();
      await admin.end();
    }
  },
  120_000,
);
