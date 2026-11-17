import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { digest } from './public-governance-client.js';
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

integration(
  'prepares real scoped provider and wallet candidates without confusing resource catalogue and effect aggregate',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const configurationUrl = new URL(runtimeUrl!);
    configurationUrl.username = 'openpc_configuration_runtime';
    const configuration = new Pool({ connectionString: configurationUrl.href, max: 2 });
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      const participantId = id(),
        privacyDomainId = id();
      expect((await configuration.query('select current_user role')).rows[0].role).toBe(
        'openpc_configuration_runtime',
      );
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
        { configurationRuntime: configuration },
      );
      const { client } = fixture.governance;
      for (const actor of ['maker', 'checker'] as const) {
        await client.stepUp(
          fixture.governance[actor],
          'ACT-IDENTITY_CREATE_SESSION-V1',
          participantId,
          digest({ participantId, privacyDomainId }),
        );
        await fixture.selectPrivacyContext(actor);
      }
      const { maker, checker } = fixture.governance;
      const provider = fixture.ordinaryMutation(
        'provider-profiles',
        'ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${participantId}`,
          chainId: '92870',
          endpointSecretRef: `urn:openpc:secret:${id()}`,
          behaviorFingerprint: digest('external provider expected behavior'),
        },
      );
      const staged = await provider.call(provider.body, true);
      expect(staged, JSON.stringify(staged)).toMatchObject({
        status: 200,
        body: { candidateDigest: provider.hash, runtimePermission: 'NONE', expectedRevision: '0' },
      });
      expect(await provider.call(provider.body, true)).toEqual(staged);
      const walletBody = {
        walletBindingId: id(),
        subjectId: maker.principalId,
        chainId: '92870',
        walletAddress: `0x${'ab'.repeat(20)}`,
      };
      const walletCandidate = { ...walletBody, participantId };
      const key = `setup-wallet-${id()}`;
      const prepared = await client.mutation(
        maker,
        '/v1/identity/wallet-bindings/prepare',
        { mutation: 'CREATE', ...walletBody },
        key,
        '0',
      );
      expect(prepared, JSON.stringify(prepared)).toMatchObject({
        status: 202,
        body: {
          candidateDigest: digest(walletCandidate),
          expectedRevision: '0',
          resourceId: walletBody.walletBindingId,
        },
      });
      expect(
        await client.mutation(
          maker,
          '/v1/identity/wallet-bindings/prepare',
          { mutation: 'CREATE', ...walletBody },
          key,
          '0',
        ),
      ).toEqual(prepared);
      const rows = await admin.query(
        `select catalog_operation_id,resource_type,operation_class,resource_id::text,expected_revision::text,candidate_document from control.mutation_candidate where participant_id=$1 order by catalog_operation_id`,
        [participantId],
      );
      expect(rows.rows).toEqual([
        {
          catalog_operation_id: 'CFG-OP-CREATE-PROVIDER-PROFILE',
          resource_type: 'provider-profiles',
          operation_class: 'CREATE',
          resource_id: String(staged.body.resourceRef).slice(-36),
          expected_revision: '0',
          candidate_document: provider.body,
        },
        {
          catalog_operation_id: 'ID-OP-WALLET-BINDING-CREATE',
          resource_type: 'participant',
          operation_class: 'UPDATE',
          resource_id: walletBody.walletBindingId,
          expected_revision: '0',
          candidate_document: walletCandidate,
        },
      ]);
      for (const [candidate, action, resource] of [
        [provider.body, provider.body.actionIntentId, String(staged.body.resourceRef).slice(-36)],
        [walletCandidate, 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', walletBody.walletBindingId],
      ] as const) {
        const requested = await client.policyMutation(maker, '/api/v1/approval-requests', {
          actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
          actionIntentDigest: client.actionDigests.get('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'),
          candidateDigest: digest(candidate),
          makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
          checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
          reason: 'Review the exact setup candidate.',
        });
        expect(requested.status, JSON.stringify(requested)).toBe(202);
        const approvalId = String(requested.body.resourceRef).slice(-36);
        const review = await fixture.approvalRead(approvalId, 'checker');
        expect(review, JSON.stringify(review)).toMatchObject({
          status: 200,
          body: {
            actionIntentId: action,
            candidate,
            candidateDigest: digest(candidate),
            resourceRef: `urn:openpc:resource:${resource}`,
            runtimePermission: 'NONE',
            state: 'APPROVAL_REQUESTED',
            operationRef: null,
          },
        });
        const foreignPrivacy = await fixture.approvalRead(approvalId, 'checker', id());
        expect([403, 404]).toContain(foreignPrivacy.status);
        expect(JSON.stringify(foreignPrivacy.body)).not.toContain('walletAddress');
        const anonymous = await fixture.approvalRead(approvalId, 'checker', privacyDomainId, true, {
          Cookie: '',
        });
        expect([401, 403, 404]).toContain(anonymous.status);
        await fixture.restartPolicy();
        expect((await fixture.approvalRead(approvalId, 'checker')).body).toEqual(review.body);
      }
      for (const table of ['provider_profile', 'runtime_target', 'wallet_binding'])
        expect(
          (
            await admin.query(
              `select count(*)::int n from control.${table} where participant_id=$1`,
              [participantId],
            )
          ).rows[0].n,
        ).toBe(0);
      const runtime = fixture.ordinaryMutation(
        'runtime-targets',
        'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${participantId}`,
          desiredGenerationDigest: null,
          activeGenerationDigest: null,
          xdsVersionDigest: null,
          observedAt: '2026-09-28T00:00:00.000000Z',
        },
      );
      const injected = await runtime.call({
        ...runtime.body,
        activeGenerationDigest: digest('fake'),
      });
      expect(injected.status).toBe(400);
      const discovered = await runtime.call();
      expect(discovered.status, JSON.stringify(discovered)).toBe(202);
      const read = await fixture.read(`runtime-targets/${String(discovered.body.resourceRef)}`);
      expect(read, JSON.stringify(read)).toMatchObject({
        status: 200,
        body: {
          desiredGenerationDigest: null,
          activeGenerationDigest: null,
          xdsVersionDigest: null,
          state: 'OFFLINE',
        },
      });
      expect(await runtime.call()).toEqual(discovered);
      await fixture.restartConfiguration();
      expect(
        (await fixture.read(`runtime-targets/${String(discovered.body.resourceRef)}`)).body,
      ).toEqual(read.body);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.mutation_candidate where participant_id=$1',
            [participantId],
          )
        ).rows[0].n,
      ).toBe(2);
    } finally {
      await fixture?.close();
      await configuration.end();
      await admin.end();
    }
  },
  120000,
);
