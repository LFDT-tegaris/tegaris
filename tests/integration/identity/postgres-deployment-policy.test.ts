import { keccak_256 } from '@noble/hashes/sha3.js';
import { writeFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { canonicalAbiBytes } from '../../../services/control-api/src/configuration/contract-assets.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import type { DeploymentPolicyDefinition } from '../../../services/control-api/src/configuration/deployment/policy-contract.js';
import { loadPolicyDeploymentInputs } from '../../../services/module-registry/src/db/deployment-policy-inputs.js';
import {
  compilePolicySemantics,
  validatePolicySemantics,
} from '../../../services/module-registry/src/domain/policy-semantics.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const action = 'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1';
const zero = `0x${'00'.repeat(32)}`;

// DEPLOY-PROFILE-CONTRACT-003: deployment-policy publication.
// Initial trust includes a pre-existing ABI registry/factory installation. All
// deployment publication, approval and WebAuthn transitions below are real HTTP.
// This does not establish runtime profile activation, a deployment intent or send.
integration(
  'publishes immutable deployment definitions through exact approval and WebAuthn',
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
    const workerUrl = new URL(runtimeUrl!);
    workerUrl.username = 'openpc_configuration_runtime';
    const runtime = new Pool({ connectionString: workerUrl.href, max: 2 });
    try {
      const abiId = id(),
        factoryAbiId = id(),
        factoryAssetId = id(),
        factoryBindingId = id();
      const provenance = sha256('existing deployment source registry');
      for (const [artifactId, abi] of [
        [abiId, []],
        [
          factoryAbiId,
          [
            {
              type: 'function',
              name: 'deploy',
              stateMutability: 'nonpayable',
              inputs: [
                { name: 'init', type: 'bytes' },
                { name: 'salt', type: 'bytes32' },
              ],
              outputs: [],
            },
          ],
        ],
      ] as const) {
        const bytes = canonicalAbiBytes(abi);
        await admin.query(
          `insert into control.abi_artifact(abi_artifact_id,participant_id,privacy_domain_id,provenance_source,
       provenance_locator,provenance_retrieved_at,provenance_source_digest,canonical_abi_bytes,canonical_abi,abi_digest,policy_generation_digest)
       values($1,$2,$3,'LOCAL_FIXTURE','fixture://existing-deployment-registry',clock_timestamp(),$4,$5,$6,$7,$4)`,
          [
            artifactId,
            participantId,
            privacyDomainId,
            provenance,
            bytes,
            JSON.stringify(abi),
            sha256(bytes),
          ],
        );
      }
      const genesis = sha256('local genesis');
      await admin.query(
        `insert into control.logical_contract_asset(logical_contract_id,participant_id,privacy_domain_id,
      logical_name,display_name,policy_generation_digest) values($1,$2,$3,'existing-factory','Existing factory',$4)`,
        [factoryAssetId, participantId, privacyDomainId, provenance],
      );
      await admin.query(
        `insert into control.contract_runtime_binding(runtime_binding_id,participant_id,privacy_domain_id,
     logical_contract_id,chain_id,network_id,genesis_digest,contract_address,code_digest,abi_artifact_id,abi_version,policy_generation_digest)
     values($1,$2,$3,$4,'1','ethereum',$5,$6,$7,$8,'1.0.0',$9)`,
        [
          factoryBindingId,
          participantId,
          privacyDomainId,
          factoryAssetId,
          genesis,
          `0x${'11'.repeat(20)}`,
          sha256(Buffer.from('6000', 'hex')),
          factoryAbiId,
          provenance,
        ],
      );
      const definition: DeploymentPolicyDefinition = {
        schemaVersion: '1.0.0',
        profileId: 'reference:direct',
        profileVersion: '1.0.0',
        assuranceLevel: 'A0',
        creationEvidence: 'COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1',
        chainId: '1',
        networkId: 'ethereum',
        genesisDigest: genesis,
        abiArtifactId: `urn:openpc:resource:${abiId}`,
        artifact: {
          mode: 'EXACT_INIT_CODE',
          initCode: '0x6001600c60003960016000f300',
          runtimeCodeHash: `0x${Buffer.from(keccak_256(Buffer.from([0]))).toString('hex')}`,
        },
        route: { mechanism: 'TRANSACTION_CREATE' },
        allowedSenders: [`0x${'22'.repeat(20)}`],
        requiredRoles: ['role:deployer'],
        approvalRequirement: 'MAKER_CHECKER',
        webauthnRequired: true,
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        transactionPolicy: {
          version: 1,
          allowedTransactionTypes: [0, 1, 2],
          maximumValue: zero,
          maximumGasLimit: '1000000',
          maximumFeePerGas: `0x${'00'.repeat(31)}ff`,
          maximumPriorityFeePerGas: zero,
          maximumRawTransactionBytes: 131072,
          maximumCalldataBytes: 32768,
          maximumAccessListAddresses: 128,
          maximumAccessListStorageKeys: 1024,
        },
      };
      const prepared = await fixture.prepareCreation('deployment-policies', action, { definition });
      expect((await prepared.commit()).status).toBe(403);
      expect(
        (
          await admin.query(
            'select count(*)::integer n from control.deployment_policy where participant_id=$1',
            [participantId],
          )
        ).rows[0]?.n,
      ).toBe(0);
      const changed = structuredClone(definition);
      changed.allowedSenders = [`0x${'33'.repeat(20)}`];
      expect(await prepared.commit({ ...prepared.body, definition: changed })).toMatchObject({
        status: 412,
        body: { code: 'PC-DATA-6007' },
      });
      await prepared.stepUp();
      const committed = await prepared.commit();
      expect(committed.status, JSON.stringify(committed)).toBe(202);
      expect(committed.body).toMatchObject({
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        resourceRef: `urn:openpc:resource:${prepared.resourceId}`,
      });
      // Lost caller acknowledgement does not allocate a second publication or approval.
      expect(await prepared.commit()).toEqual(committed);
      const path = `deployment-policies/${committed.body.resourceRef}`;
      const read = await fixture.read(path);
      expect(read.status).toBe(200);
      expect(read.body).toMatchObject({
        definition,
        state: 'STAGED',
        publicationOperationId: committed.body.operationId,
        definitionDigest: sha256(definition),
        initCodeHash: `0x${Buffer.from(keccak_256(Buffer.from(definition.artifact.initCode.slice(2), 'hex'))).toString('hex')}`,
        runtimePermission: 'REQUIRES_EFFECTIVE_POLICY_AND_LIVE_AUTHORITY',
      });
      expect(
        (
          await admin.query(
            `select count(*)::integer n from control.mutation_evidence where participant_id=$1 and aggregate_id=$2`,
            [participantId, prepared.resourceId],
          )
        ).rows[0]?.n,
      ).toBe(1);
      expect(
        (
          await admin.query(
            `select count(*)::integer n from control.outbox_event where participant_id=$1 and aggregate_id=$2`,
            [participantId, prepared.resourceId],
          )
        ).rows[0]?.n,
      ).toBe(1);
      expect(
        (
          await admin.query(
            'select count(*)::integer n from control.deployment_address_reservation where participant_id=$1',
            [participantId],
          )
        ).rows[0]?.n,
      ).toBe(0);
      await fixture.restartConfiguration();
      expect(await fixture.read(path)).toEqual(read);
      other = await contractAdministrationFixture(admin, runtimeUrl!, id(), id());
      expect((await other.read(path)).status).toBe(403);

      const factory: DeploymentPolicyDefinition = {
        ...definition,
        profileId: 'reference:factory',
        route: {
          mechanism: 'CREATE2',
          runtimeBindingId: `urn:openpc:resource:${factoryBindingId}`,
          canonicalSignature: 'deploy(bytes,bytes32)',
          codeHash: `0x${Buffer.from(keccak_256(Buffer.from('6000', 'hex'))).toString('hex')}`,
          adapterDigest: sha256('closed factory adapter'),
          arguments: 'INIT_CODE_SALT',
          saltNamespaceDigest: sha256('local namespace'),
          saltTransform: 'IDENTITY',
        },
      };
      const factoryPublication = await fixture.create('deployment-policies', action, {
        definition: factory,
      });
      expect(
        (await fixture.read(`deployment-policies/${factoryPublication.body.resourceRef}`)).body
          .definition,
      ).toEqual(factory);
      // Compiler/module bindings here are component fixtures. Publication is real;
      // this does not stand in for governed module/policy release or activation.
      const { document } = validatePolicySemantics({
        schemaVersion: '1.0.0',
        participantId,
        privacyDomainId,
        moduleBindings: [
          'pc.policy.rpc-surface',
          'pc.policy.deployment',
          'pc.deployment.governance',
        ].map((moduleId) => ({
          moduleId,
          semanticVersion: '1.0.0',
          manifestDigest: sha256(moduleId),
          configurationDigest: sha256({}),
        })),
        rpcPolicies: [
          {
            schemaVersion: '1.0.0',
            participantId,
            privacyDomainId,
            rules: [
              {
                method: 'eth_sendRawTransaction',
                effect: 'ALLOW',
                requiredRoles: ['role:deployer'],
              },
            ],
          },
        ],
        contractPolicies: [],
        deploymentPolicies: [
          { deploymentPolicyId: prepared.resourceId, definitionDigest: sha256(definition) },
          {
            deploymentPolicyId: String(factoryPublication.body.resourceRef).slice(-36),
            definitionDigest: sha256(factory),
          },
        ],
        requiredFacts: [
          {
            candidateId: 'component:chain',
            generationId: 'component:generation',
            factDigest: sha256('component fact'),
          },
        ],
      });
      const compilerClient = await runtime.connect();
      try {
        await compilerClient.query('begin');
        await compilerClient.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,false)`,
          [participantId, privacyDomainId, id(), 'ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1'],
        );
        const admitted = await loadPolicyDeploymentInputs(compilerClient, document);
        expect(admitted).toHaveLength(2);
        compilePolicySemantics(document, [], 'workload:deployment', admitted);
        expect(() =>
          compilePolicySemantics(
            document,
            [],
            'workload:deployment',
            admitted.map((policy) => ({ ...policy, initCodeHash: zero })),
          ),
        ).toThrow('PC-POLICY-2003');
        await expect(
          loadPolicyDeploymentInputs(compilerClient, {
            ...document,
            deploymentPolicies: [
              {
                deploymentPolicyId: prepared.resourceId,
                definitionDigest: sha256('changed definition'),
              },
            ],
          }),
        ).rejects.toMatchObject({
          code: 'PC-POLICY-2003',
          detail: 'deployment publication binding rejected',
        });
        const output = process.env.OPENPC_ASTRA08_DEPLOYMENT_PUBLICATION_FIXTURE;
        if (output)
          await writeFile(
            output,
            JSON.stringify({ document, admitted, workloadId: 'workload:deployment' }),
          );
      } finally {
        await compilerClient.query('rollback');
        compilerClient.release();
      }
      for (const denied of [
        { ...factory, profileId: 'reference:wrong-chain', chainId: '2' },
        { ...definition, profileId: 'reference:expired', expiresAt: '2000-01-01T00:00:00.000Z' },
        {
          ...definition,
          profileId: 'reference:missing-abi',
          abiArtifactId: `urn:openpc:resource:${id()}`,
        },
      ]) {
        await fixture.create('deployment-policies', action, { definition: denied }, 0);
      }
      expect(
        (
          await admin.query(
            'select count(*)::integer n from control.deployment_policy where participant_id=$1',
            [participantId],
          )
        ).rows[0]?.n,
      ).toBe(2);

      // Independently approved competing publications cannot reuse a profile version.
      const competing = { ...definition, profileId: 'reference:competing' };
      const first = await fixture.prepareCreation('deployment-policies', action, {
        definition: competing,
      });
      const second = await fixture.prepareCreation('deployment-policies', action, {
        definition: { ...competing, allowedSenders: [`0x${'33'.repeat(20)}`] },
      });
      await first.stepUp();
      await second.stepUp();
      const raced = await Promise.all([first.commit(), second.commit()]);
      expect(raced.map((result) => result.status).sort()).toEqual([202, 412]);
      const winner = raced[0]!.status === 202 ? first : second;
      const winnerResult = raced.find((result) => result.status === 202)!;
      expect(await winner.commit()).toEqual(winnerResult);
      expect(
        (
          await admin.query(
            `select count(*)::integer n from control.deployment_policy where participant_id=$1 and definition->>'profileId'=$2`,
            [participantId, competing.profileId],
          )
        ).rows[0]?.n,
      ).toBe(1);

      const client = await runtime.connect();
      try {
        await client.query('begin');
        await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
          participantId,
          privacyDomainId,
          id(),
          action,
        ]);
        await expect(
          client.query(
            `update control.deployment_policy set definition=jsonb_set(definition,'{profileId}','"reference:altered"') where deployment_policy_id=$1`,
            [prepared.resourceId],
          ),
        ).rejects.toThrow('PC-DATA-6004');
        await client.query('rollback');
        const forgedId = id(),
          forgedOperationId = id();
        await client.query('begin');
        await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
          participantId,
          privacyDomainId,
          forgedOperationId,
          action,
        ]);
        await client.query(
          `with source as (select *,jsonb_set(definition,'{profileId}','"reference:forged"') forged from control.deployment_policy where deployment_policy_id=$1)
        insert into control.deployment_policy(deployment_policy_id,participant_id,privacy_domain_id,definition,definition_digest,artifact_digest,init_code_hash,
         abi_artifact_id,abi_digest,factory_runtime_binding_id,publication_operation_id,publication_authority_digest)
        select $2,participant_id,privacy_domain_id,forged,'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(forged),'UTF8')),'hex'),
         artifact_digest,init_code_hash,abi_artifact_id,abi_digest,factory_runtime_binding_id,$3,publication_authority_digest from source`,
          [prepared.resourceId, forgedId, forgedOperationId],
        );
        await expect(client.query('commit')).rejects.toThrow(
          'PC-AUTH-0002-DEPLOYMENT-PUBLICATION-PROVENANCE',
        );
        await client.query('rollback');
      } finally {
        client.release();
      }
    } finally {
      await other?.close();
      await fixture.close();
      await runtime.end();
      await admin.end();
    }
  },
  60_000,
);
