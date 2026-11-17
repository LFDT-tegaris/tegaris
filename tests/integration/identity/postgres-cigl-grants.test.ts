import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  canonicalAbiBytes,
  selectorFor,
} from '../../../services/control-api/src/configuration/contract-assets.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const createAction = 'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1';
const updateAction = 'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1';

// UF-CIGL-003/004 grant-owner segment. Initial trust includes an existing method
// installation; every grant, review, approval and status transition is public.
// This does not establish fresh contract registration or profile activation.
integration(
  'governs shared method grants with exact approval, immutable history and revocation',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const participantId = id(),
      privacyDomainId = id();
    const fixture = await contractAdministrationFixture(
      admin,
      runtimeUrl!,
      participantId,
      privacyDomainId,
    );
    let other: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      const abiId = id(),
        contractId = id(),
        bindingId = id(),
        methodId = id();
      const signature = 'transfer(address,uint256)',
        selector = selectorFor(signature);
      const abi = [
        {
          type: 'function',
          name: 'transfer',
          inputs: [
            { name: 'to', type: 'address' },
            { name: 'amount', type: 'uint256' },
          ],
          outputs: [],
          stateMutability: 'nonpayable',
        },
      ];
      const bytes = canonicalAbiBytes(abi),
        provenance = sha256('pre-existing CIGL method installation');
      await admin.query(
        `insert into control.abi_artifact(abi_artifact_id,participant_id,privacy_domain_id,provenance_source,
      provenance_locator,provenance_retrieved_at,provenance_source_digest,canonical_abi_bytes,canonical_abi,abi_digest,policy_generation_digest)
      values($1,$2,$3,'LOCAL_FIXTURE','fixture://existing-cigl-method',clock_timestamp(),$4,$5,$6,$7,$4)`,
        [
          abiId,
          participantId,
          privacyDomainId,
          provenance,
          bytes,
          JSON.stringify(abi),
          sha256(bytes),
        ],
      );
      await admin.query(
        `insert into control.logical_contract_asset(logical_contract_id,participant_id,privacy_domain_id,logical_name,display_name,policy_generation_digest)
      values($1,$2,$3,'existing-cigl-method','Existing CIGL method',$4)`,
        [contractId, participantId, privacyDomainId, provenance],
      );
      await admin.query(
        `insert into control.contract_runtime_binding(runtime_binding_id,participant_id,privacy_domain_id,logical_contract_id,
      chain_id,network_id,genesis_digest,contract_address,code_digest,abi_artifact_id,abi_version,policy_generation_digest)
      values($1,$2,$3,$4,'92870','isolated-testnet',$5,$6,$5,$7,'1.0.0',$5)`,
        [
          bindingId,
          participantId,
          privacyDomainId,
          contractId,
          provenance,
          `0x${'11'.repeat(20)}`,
          abiId,
        ],
      );
      await admin.query(
        `insert into control.contract_method_policy(contract_method_policy_id,participant_id,privacy_domain_id,runtime_binding_id,abi_artifact_id,
      canonical_signature,selector,effect,required_roles,approval_requirement,mfa_requirement,environments,rpc_method_policy_digest,nested_call_set_digest,policy_generation_digest)
      values($1,$2,$3,$4,$5,$6,$7,'WRITE',ARRAY['role:caller'],'NONE','NONE',ARRAY['TEST'],$8,$8,$8)`,
        [
          methodId,
          participantId,
          privacyDomainId,
          bindingId,
          abiId,
          signature,
          selector,
          provenance,
        ],
      );
      const definition = {
        runtimeBindingId: `urn:openpc:resource:${bindingId}`,
        selector,
        subject: { kind: 'ANY_AUTHENTICATED' },
        surface: 'RAW_SUBMISSION',
        effect: 'ALLOW',
      };
      const input = {
        definition,
        expectedRuntimeBindingRevision: '1',
        expectedMethodRevision: '1',
      };
      const prepared = await fixture.prepareCreation('cigl-grants', createAction, input, true);
      const proposal = await fixture.approvalRead(prepared.approvalId, 'checker');
      expect(proposal).toMatchObject({
        status: 200,
        body: {
          candidate: prepared.body,
          redactedFields: [],
          state: 'APPROVED',
          resourceRef: `urn:openpc:resource:${prepared.resourceId}`,
          operationRef: null,
        },
      });
      expect((await fixture.approvalRead(prepared.approvalId, 'checker', id())).status).toBe(403);
      expect(
        (
          await fixture.approvalRead(prepared.approvalId, 'checker', privacyDomainId, true, {
            Cookie: '',
          })
        ).status,
      ).toBe(403);
      const ordinary = await fixture.approvalRead(
        prepared.approvalId,
        'checker',
        privacyDomainId,
        false,
      );
      expect(Object.keys(ordinary.body).sort()).toEqual([
        'actionIntentId',
        'approvalRequestId',
        'candidateDigest',
        'checkerSubjectRef',
        'createdAt',
        'makerSubjectRef',
        'revision',
        'state',
        'updatedAt',
      ]);
      expect((await prepared.commit()).status).toBe(403);
      expect(
        (await prepared.commit({ ...prepared.body, definition: { ...definition, effect: 'DENY' } }))
          .status,
      ).toBe(412);
      expect(
        (await admin.query('select count(*)::int n from control.cigl_method_access_grants')).rows[0]
          .n,
      ).toBe(0);
      await prepared.stepUp();
      // A proposal retry must never execute, even with approval and fresh MFA.
      expect(await prepared.propose()).toMatchObject({
        status: 200,
        body: {
          resourceRef: `urn:openpc:resource:${prepared.resourceId}`,
          runtimePermission: 'NONE',
        },
      });
      expect(
        (await admin.query('select count(*)::int n from control.cigl_method_access_grants')).rows[0]
          .n,
      ).toBe(0);
      const committed = await prepared.commit();
      expect(committed.status, JSON.stringify(committed)).toBe(202);
      // A client that lost the mutation response discovers the original command
      // through its retained public approval, without reissuing the mutation.
      const consumed = await fixture.approvalRead(prepared.approvalId);
      expect(consumed).toMatchObject({
        status: 200,
        body: {
          state: 'CONSUMED',
          operationRef: `urn:openpc:operation:${committed.body.operationId}`,
          candidate: prepared.body,
        },
      });
      for (const replay of await Promise.all([prepared.commit(), prepared.commit()]))
        expect(replay).toEqual(committed);
      const path = `cigl-grants/${committed.body.resourceRef}`;
      const initial = await fixture.read(path);
      expect(initial.status, JSON.stringify(initial)).toBe(200);
      expect(initial.body).toMatchObject({
        definition,
        status: 'DISABLED',
        revision: '1',
        runtimePermission: 'NONE_WITHOUT_CURRENT_PROFILE',
        publicationOperationId: committed.body.operationId,
        runtimeBindingRevision: '1',
        methodRevision: '1',
      });
      const activate = await fixture.prepareMutation(`${path}/status`, updateAction, {
        targetRef: committed.body.resourceRef,
        expectedRevision: '1',
        status: 'ACTIVE',
      });
      expect((await activate.commit()).status).toBe(403);
      await activate.stepUp();
      const activated = await activate.commit();
      expect(activated.status, JSON.stringify(activated)).toBe(202);
      expect((await fixture.read(path)).body).toMatchObject({
        definition,
        status: 'ACTIVE',
        revision: '2',
        runtimePermission: 'NONE_WITHOUT_CURRENT_PROFILE',
      });
      expect((await fixture.read(path)).body.grantDigest).not.toBe(initial.body.grantDigest);

      const denied = await fixture.create('cigl-grants', createAction, {
        ...input,
        definition: { ...definition, effect: 'DENY' },
      });
      const denyPath = `cigl-grants/${denied.body.resourceRef}`;
      await fixture.create(`${denyPath}/status`, updateAction, {
        targetRef: denied.body.resourceRef,
        expectedRevision: '1',
        status: 'ACTIVE',
      });
      const denyRead = await fixture.read(denyPath);
      expect(denyRead.body).toMatchObject({ status: 'ACTIVE', definition: { effect: 'DENY' } });
      // Even an independently approved stale proposal cannot change the row.
      await fixture.create(
        `${path}/status`,
        updateAction,
        {
          targetRef: committed.body.resourceRef,
          expectedRevision: '1',
          status: 'DISABLED',
        },
        412,
      );
      expect(
        await fixture.attemptMutation(`${path}/status`, updateAction, {
          targetRef: denied.body.resourceRef,
          expectedRevision: '2',
          status: 'DISABLED',
        }),
      ).toMatchObject({ status: 400, body: { truthState: 'FAILED' } });
      for (const changed of [
        { ...input, expectedMethodRevision: '2' },
        { ...input, definition: { ...definition, selector: '0xdeadbeef' } },
        { ...input, definition: { ...definition, subject: { kind: 'PARTICIPANT', id: id() } } },
        {
          ...input,
          definition: { ...definition, subject: { kind: 'ROLE', id: `urn:openpc:role:${id()}` } },
        },
      ])
        await fixture.create('cigl-grants', createAction, changed, 403);

      // The SQL role/context and a correct digest cannot manufacture an approved
      // candidate or its committed receipt. Null fields fail before provenance.
      const client = await admin.connect();
      const rejectSql = async (
        query: string,
        values: unknown[],
        action: string,
        pattern: RegExp,
      ) => {
        try {
          await client.query('begin');
          await client.query('set local role openpc_configuration_runtime');
          await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
            participantId,
            privacyDomainId,
            id(),
            action,
          ]);
          await expect(
            (async () => {
              await client.query(query, values);
              await client.query('commit');
            })(),
          ).rejects.toThrow(pattern);
        } finally {
          await client.query('rollback');
        }
      };
      try {
        const insert = `insert into control.cigl_method_access_grants(grant_id,participant_id,privacy_domain_id,runtime_binding_id,selector,
        binding_revision,method_revision,definition,status,grant_digest,publication_operation_id,publication_authority_digest)
        values($1,$2,$3,$4,$5,1,1,$6::jsonb,'DISABLED',$7,current_setting('openpc.operation_id')::uuid,$8)`;
        for (const document of [
          definition,
          { ...definition, effect: null },
          { ...definition, subject: null },
        ]) {
          const forgedId = id();
          const digest = sha256({
            ...document,
            grantId: forgedId,
            runtimeBindingId: bindingId,
            selector: [...Buffer.from(selector.slice(2), 'hex')],
            status: 'DISABLED',
          });
          await rejectSql(
            insert,
            [
              forgedId,
              participantId,
              privacyDomainId,
              bindingId,
              selector,
              JSON.stringify(document),
              digest,
              sha256('forged'),
            ],
            createAction,
            document === definition ? /CIGL-GRANT-PROVENANCE/ : /CIGL-GRANT-(DEFINITION|REFERENCE)/,
          );
        }
        await rejectSql(
          'delete from control.cigl_method_access_grants where grant_id=$1',
          [prepared.resourceId],
          updateAction,
          /permission denied|CIGL-GRANT-HISTORY/,
        );
        await rejectSql(
          "update control.cigl_method_access_grants set definition=jsonb_set(definition,'{effect}','\"DENY\"') where grant_id=$1",
          [prepared.resourceId],
          updateAction,
          /CIGL-GRANT-IMMUTABLE|CIGL-GRANT/,
        );
        await rejectSql(
          'delete from control.cigl_grant_history where grant_id=$1',
          [prepared.resourceId],
          updateAction,
          /permission denied|CIGL-GRANT-HISTORY/,
        );
        await client.query('begin');
        await client.query('set local role openpc_configuration_runtime');
        await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          participantId,
          id(),
          id(),
          createAction,
        ]);
        expect(
          (await client.query('select 1 from control.cigl_method_access_grants')).rowCount,
        ).toBe(0);
        expect((await client.query('select 1 from control.cigl_grant_history')).rowCount).toBe(0);
        await client.query('rollback');
      } finally {
        await client.query('rollback');
        client.release();
      }

      // Adversarial source drift cannot prevent a revocation, and cannot make a
      // subsequent activation under the formerly reviewed source revision valid.
      await admin.query(
        'update control.contract_method_policy set revision=revision+1 where contract_method_policy_id=$1',
        [methodId],
      );
      const revoke = await fixture.prepareMutation(`${path}/status`, updateAction, {
        targetRef: committed.body.resourceRef,
        expectedRevision: '2',
        status: 'DISABLED',
      });
      await revoke.stepUp();
      const revoked = await revoke.commit();
      expect(revoked.status, JSON.stringify(revoked)).toBe(202);
      for (const replay of await Promise.all([revoke.commit(), revoke.commit()]))
        expect(replay).toEqual(revoked);
      const finalRead = await fixture.read(path);
      expect(finalRead.body).toMatchObject({ status: 'DISABLED', revision: '3', definition });
      expect(await fixture.read(denyPath)).toEqual(denyRead);
      const inventory = await fixture.read('cigl-grants?limit=1&sort=updatedAt');
      expect(inventory.status, JSON.stringify(inventory)).toBe(200);
      expect(inventory.body).toMatchObject({
        total: '2',
        authorizedEmpty: false,
        items: [denyRead.body],
      });
      const next = await fixture.read(
        `cigl-grants?limit=1&sort=updatedAt&cursor=${inventory.body.nextCursor}`,
      );
      expect(next.body).toMatchObject({ total: '2', items: [finalRead.body], nextCursor: null });
      const activeDenies = await fixture.read('cigl-grants?filter=effect:eq:DENY');
      expect(activeDenies.body).toMatchObject({ total: '1', items: [denyRead.body] });
      await fixture.create(
        `${path}/status`,
        updateAction,
        { targetRef: committed.body.resourceRef, expectedRevision: '3', status: 'ACTIVE' },
        403,
      );
      expect(await fixture.read(path)).toEqual(finalRead);
      await fixture.restartConfiguration();
      await fixture.restartPolicy();
      expect(await fixture.approvalRead(prepared.approvalId)).toEqual(consumed);
      expect(await fixture.read(path)).toEqual(finalRead);
      expect(await revoke.commit()).toEqual(revoked);
      expect(await activate.commit()).toEqual(activated);
      expect(await fixture.read(path)).toEqual(finalRead);
      for (const table of ['cigl_grant_history', 'mutation_evidence', 'outbox_event']) {
        const column = table === 'cigl_grant_history' ? 'grant_id' : 'aggregate_id';
        expect(
          (
            await admin.query(`select count(*)::int n from control.${table} where ${column}=$1`, [
              prepared.resourceId,
            ])
          ).rows[0].n,
        ).toBe(3);
      }
      other = await contractAdministrationFixture(admin, runtimeUrl!, id(), id());
      expect((await other.approvalRead(prepared.approvalId)).status).toBe(404);
      expect((await other.read(path)).status).toBe(403);
      expect((await other.read('cigl-grants')).body).toMatchObject({
        items: [],
        total: '0',
        authorizedEmpty: true,
      });
      // Migration0041 USER resolution stays in ordinary R1 owner acceptance,
      // independent of the deferred administration CLI. Identity-only bootstrap
      // supplies a workload counterexample; all grant transitions remain public.
      const workloadId = id();
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
         values($1,$2,'WORKLOAD','USER subject counterexample','ACTIVE',1)`,
        [workloadId, participantId],
      );
      for (const [scope, subjectId, allowed] of [
        [participantId, fixture.makerId, true],
        [other.participantId, fixture.makerId, false],
        [participantId, other.makerId, false],
        [participantId, workloadId, false],
        [participantId, id(), false],
        [participantId, 'malformed', false],
      ] as const) {
        const result = await admin.query(
          'select openpc.cigl_subject_current($1::uuid,$2::jsonb) allowed',
          [scope, JSON.stringify({ kind: 'USER', id: subjectId })],
        );
        expect(result.rows[0].allowed).toBe(allowed);
      }
      const userGrant = await fixture.prepareCreation('cigl-grants', createAction, {
        ...input,
        expectedMethodRevision: '2',
        definition: { ...definition, subject: { kind: 'USER', id: fixture.makerId } },
      });
      await userGrant.stepUp();
      const userCommitted = await userGrant.commit();
      expect(userCommitted.status, JSON.stringify(userCommitted)).toBe(202);
      expect(await userGrant.commit()).toEqual(userCommitted);
      const userPath = `cigl-grants/${userCommitted.body.resourceRef}`;
      const userBefore = await fixture.read(userPath);
      expect(userBefore.body).toMatchObject({ status: 'DISABLED', revision: '1' });
      const stale = await fixture.prepareMutation(`${userPath}/status`, updateAction, {
        targetRef: userCommitted.body.resourceRef,
        expectedRevision: '9999',
        status: 'ACTIVE',
      });
      await stale.stepUp();
      expect(await stale.commit()).toMatchObject({
        status: 412,
        body: { code: 'PC-DATA-6007' },
      });
      expect(await fixture.read(userPath)).toEqual(userBefore);
      expect((await fixture.approvalRead(stale.approvalId)).body.operationRef).toBeNull();
      await fixture.restartConfiguration();
      expect(await fixture.read(userPath)).toEqual(userBefore);
    } finally {
      await other?.close();
      await fixture.close();
      await admin.end();
    }
  },
  120_000,
);
