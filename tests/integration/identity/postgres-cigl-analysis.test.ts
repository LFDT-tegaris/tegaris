import { createECDH } from 'node:crypto';
import { readFile, writeFile, rename, access } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { canonicalAbiBytes } from '../../../services/control-api/src/configuration/contract-assets.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';

const root = process.env.OPENPC_ASTRA05_DECISION_OWNER_ROOT;
const integration = root && process.env.OPENPC_CIGL_PUBLIC_ANALYSIS ? it : it.skip;
const createAction = 'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1';
const updateAction = 'ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1';
const reviewAction = 'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1';
async function waitFile(name: string) {
  const path = join(root!, name),
    deadline = Date.now() + 25_000;
  for (;;) {
    try {
      await access(path);
      return await readFile(path);
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !('code' in error) ||
        error.code !== 'ENOENT' ||
        Date.now() >= deadline
      )
        throw error;
      await setTimeout(30);
    }
  }
}
interface Source {
  participantId: string;
  privacyDomainId: string;
  targetRuntimeId: string;
  runtimeBindingId: string;
  contractMethodPolicyId: string;
  workloadId: string;
  capsuleDigest: string;
  policyGenerationDigest: string;
  transactionHash: string;
  verificationKey: string;
  installedPolicies: {
    configured_identity: { contract_method_policy_id: string; runtime_binding_id: string };
    artifact: {
      chain_id: string;
      network_id: string;
      genesis_digest: string;
      contract_address: number[];
      code_digest: string;
      abi_digest: string;
      canonical_signature: string;
      selector: number[];
      policy_version: string;
      method_required_roles: string[];
    };
  }[];
}

/** Existing target/method installation is bootstrap context, including its
 * matching observed capsule. Analysis jobs, approvals, acquisition and imports
 * are real. No test helper signs an analysis or seeds its business result. */
async function installExistingContext(admin: Pool, s: Source) {
  const p = s.participantId,
    d = s.privacyDomainId,
    g = s.policyGenerationDigest,
    // Fleet retains the proposal identity in its generation/work/observation,
    // while the active target identifies the resulting signed capsule.
    proposalDigest = sha256({ purpose: 'existing-analysis-proposal', target: s.targetRuntimeId });
  expect(proposalDigest).not.toBe(s.capsuleDigest);
  const abiId = id(),
    contractId = id(),
    providerId = id(),
    indexerId = id(),
    planId = id(),
    generationId = id(),
    workId = id(),
    operationId = id();
  const abi = [
    {
      type: 'function',
      name: 'balanceOf',
      inputs: [{ name: 'owner', type: 'address' }],
      outputs: [{ name: 'balance', type: 'uint256' }],
      stateMutability: 'view',
    },
  ];
  const bytes = canonicalAbiBytes(abi);
  await admin.query(
    `insert into control.abi_artifact(abi_artifact_id,participant_id,privacy_domain_id,provenance_source,provenance_locator,
    provenance_retrieved_at,provenance_source_digest,canonical_abi_bytes,canonical_abi,abi_digest,policy_generation_digest)
    values($1,$2,$3,'LOCAL_FIXTURE','fixture://existing-analysis-target',clock_timestamp(),$4,$5,$6,$7,$4)`,
    [
      abiId,
      p,
      d,
      g,
      bytes,
      JSON.stringify(abi),
      `sha256:${s.installedPolicies[0]!.artifact.abi_digest}`,
    ],
  );
  await admin.query(
    `insert into control.logical_contract_asset(logical_contract_id,participant_id,privacy_domain_id,logical_name,display_name,policy_generation_digest)
    values($1,$2,$3,'analysis-baseline','Analysis baseline',$4)`,
    [contractId, p, d, g],
  );
  for (const installed of s.installedPolicies) {
    const policy = installed.artifact,
      identity = installed.configured_identity;
    const [, rpc, nested] = policy.policy_version.split(':');
    await admin.query(
      `insert into control.contract_runtime_binding(runtime_binding_id,participant_id,privacy_domain_id,logical_contract_id,chain_id,network_id,
      genesis_digest,contract_address,code_digest,abi_artifact_id,abi_version,policy_generation_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'1.0.0',$11)`,
      [
        identity.runtime_binding_id,
        p,
        d,
        contractId,
        policy.chain_id,
        policy.network_id,
        `sha256:${policy.genesis_digest}`,
        `0x${Buffer.from(policy.contract_address).toString('hex')}`,
        `sha256:${policy.code_digest}`,
        abiId,
        g,
      ],
    );
    await admin.query(
      `insert into control.contract_method_policy(contract_method_policy_id,participant_id,privacy_domain_id,runtime_binding_id,abi_artifact_id,
      canonical_signature,selector,effect,required_roles,approval_requirement,mfa_requirement,environments,rpc_method_policy_digest,nested_call_set_digest,policy_generation_digest,state)
      values($1,$2,$3,$4,$5,$6,$7,'WRITE',$8,'NONE','NONE',ARRAY['TEST'],$9,$10,$11,'ACTIVE')`,
      [
        identity.contract_method_policy_id,
        p,
        d,
        identity.runtime_binding_id,
        abiId,
        policy.canonical_signature,
        `0x${Buffer.from(policy.selector).toString('hex')}`,
        policy.method_required_roles,
        `sha256:${rpc}`,
        `sha256:${nested}`,
        g,
      ],
    );
  }
  await admin.query(
    `update control.runtime_target set state='ACTIVE_MATCHED',desired_generation_digest=$2,active_generation_digest=$2,policy_generation_digest=$3 where runtime_target_id=$1`,
    [s.targetRuntimeId, s.capsuleDigest, g],
  );
  await admin.query(
    `insert into control.provider_profile(provider_profile_id,participant_id,privacy_domain_id,chain_id,endpoint_secret_ref,behavior_fingerprint,policy_generation_digest)
    values($1,$2,$3,'1',$5,$4,$4)`,
    [providerId, p, d, g, `urn:openpc:secret:${providerId}`],
  );
  await admin.query(
    `insert into control.indexer_profile(indexer_profile_id,participant_id,privacy_domain_id,engine,engine_version,method_profile_digest,policy_generation_digest)
    values($1,$2,$3,'CLIENT_INDEXER','1.0.0',$4,$4)`,
    [indexerId, p, d, g],
  );
  await admin.query(
    `insert into control.projection_plan(projection_plan_id,participant_id,privacy_domain_id,indexer_profile_id,plan_digest,readiness,policy_generation_digest)
    values($1,$2,$3,$4,$5,'READY',$5)`,
    [planId, p, d, indexerId, g],
  );
  await admin.query(
    `insert into control.runtime_configuration_generation(runtime_configuration_generation_id,participant_id,privacy_domain_id,runtime_target_id,provider_profile_id,
    projection_plan_id,generation_digest,policy_generation_digest,state) values($1,$2,$3,$4,$5,$6,$7,$8,'ACTIVE')`,
    [generationId, p, d, s.targetRuntimeId, providerId, planId, proposalDigest, g],
  );
  await admin.query(
    `insert into control.configuration_work(configuration_work_id,participant_id,privacy_domain_id,operation_id,work_kind,resource_id,input_digest,configuration_digest,
    runtime_configuration_generation_id,runtime_target_id,generation_digest,policy_generation_digest,xds_version_digest,
    state,completed_at,result_receipt,result_receipt_digest,result_event_id)
    values($1,$2,$3,$4,'RUNTIME_ACTIVATION',$5,$6,$6,$7,$5,$9,$8,$6,'COMPLETED',clock_timestamp(),'{}',$6,uuidv7())`,
    [
      workId,
      p,
      d,
      operationId,
      s.targetRuntimeId,
      s.capsuleDigest,
      generationId,
      g,
      proposalDigest,
    ],
  );
  await admin.query(
    `insert into control.runtime_activation_observation(runtime_activation_observation_id,participant_id,privacy_domain_id,configuration_work_id,operation_id,execution_attempt_id,
    runtime_configuration_generation_id,runtime_target_id,generation_digest,capsule_digest,xds_version_digest,activation_receipt,activation_receipt_digest)
    values($1,$2,$3,$4,$5,$6,$7,$8,$10,$9,$9,'{}',$9)`,
    [
      id(),
      p,
      d,
      workId,
      operationId,
      id(),
      generationId,
      s.targetRuntimeId,
      s.capsuleDigest,
      proposalDigest,
    ],
  );
  return { proposalDigest };
}

integration(
  'retains only exact live target analysis through public approval and restart readback',
  async () => {
    const admin = new Pool({ connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL, max: 2 });
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const priorKeys = process.env.OPENPC_CIGL_ANALYSIS_TARGET_KEYS_FILE;
    const priorProfileKey = process.env.OPENPC_CIGL_PROFILE_PUBLIC_KEY_FILE;
    try {
      const source = JSON.parse((await waitFile('analysis-request.json')).toString()) as Source;
      const keysFile = join(root!, 'analysis-target-keys.json');
      const keys = JSON.stringify({ [source.targetRuntimeId]: source.verificationKey });
      await writeFile(keysFile, keys, { mode: 0o600 });
      process.env.OPENPC_CIGL_ANALYSIS_TARGET_KEYS_FILE = keysFile;
      const profileKeyFile = join(root!, 'profile-signer-key.txt');
      const signer = createECDH('prime256v1');
      signer.setPrivateKey(Buffer.alloc(32, 94));
      const profileKey = signer.getPublicKey('hex', 'compressed');
      await writeFile(profileKeyFile, profileKey, { mode: 0o600 });
      process.env.OPENPC_CIGL_PROFILE_PUBLIC_KEY_FILE = profileKeyFile;
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        source.participantId,
        source.privacyDomainId,
        { existingScope: true },
      );
      const { proposalDigest } = await installExistingContext(admin, source);
      // Fail at the source-role boundary before starting trace acquisition.
      // The real publication worker must be able to lock the authority root
      // under FORCE RLS without gaining Participant mutation privileges.
      const publicationPreflight = await admin.connect();
      try {
        await publicationPreflight.query('begin');
        await publicationPreflight.query('set local role openpc_control_worker');
        await publicationPreflight.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)",
          [source.participantId, source.privacyDomainId, id()],
        );
        await publicationPreflight.query('select openpc.lock_cigl_publication_participant()');
        expect(
          (
            await publicationPreflight.query(
              "select has_table_privilege(current_user,'control.participant','UPDATE') allowed",
            )
          ).rows[0].allowed,
        ).toBe(false);
      } finally {
        await publicationPreflight.query('rollback');
        publicationPreflight.release();
      }
      const definition = {
        targetRuntimeId: `urn:openpc:resource:${source.targetRuntimeId}`,
        expectedGenerationDigest: source.capsuleDigest,
        runtimeBindingId: `urn:openpc:resource:${source.runtimeBindingId}`,
        contractMethodPolicyId: `urn:openpc:resource:${source.contractMethodPolicyId}`,
        expectedRuntimeBindingRevision: '1',
        expectedMethodRevision: '1',
        workloadId: source.workloadId,
        transactionHash: source.transactionHash,
        expiresInSeconds: 300,
      };
      await fixture.create(
        'cigl-analyses',
        createAction,
        { definition: { ...definition, expectedGenerationDigest: proposalDigest } },
        403,
      );
      const prepared = await fixture.prepareCreation('cigl-analyses', createAction, { definition });
      expect((await prepared.commit()).status).toBe(403);
      expect(
        (
          await prepared.commit({
            ...prepared.body,
            definition: { ...definition, transactionHash: `0x${'00'.repeat(32)}` },
          })
        ).status,
      ).toBe(412);
      await prepared.stepUp();
      const created = await prepared.commit();
      expect(created.status, JSON.stringify(created)).toBe(202);
      expect(await prepared.commit()).toEqual(created);
      const path = `cigl-analyses/${created.body.resourceRef}`;
      const initial = await fixture.read(path);
      expect(initial.body).toMatchObject({
        definition,
        state: 'OPEN',
        revision: '1',
        runtimePermission: 'NONE',
        observation: null,
        capsuleDigest: source.capsuleDigest,
      });
      const pending = join(root!, 'analysis-job.pending');
      await writeFile(pending, JSON.stringify(initial.body), { mode: 0o600 });
      await rename(pending, join(root!, 'analysis-job.json'));
      const signedBytes = await waitFile('analysis-receipt.json');
      const signedReceipt = `0x${signedBytes.toString('hex')}`;
      const tampered = JSON.parse(signedBytes.toString());
      tampered.claims.transactionHash = Array(32).fill(0);
      await fixture.create(
        `${path}/observation`,
        updateAction,
        {
          targetRef: created.body.resourceRef,
          expectedRevision: '1',
          signedReceipt: `0x${Buffer.from(JSON.stringify(tampered)).toString('hex')}`,
        },
        400,
      );
      expect((await fixture.read(path)).body).toMatchObject({
        state: 'OPEN',
        revision: '1',
        observation: null,
      });
      const observe = await fixture.prepareMutation(`${path}/observation`, updateAction, {
        targetRef: created.body.resourceRef,
        expectedRevision: '1',
        signedReceipt,
      });
      expect((await observe.commit()).status).toBe(403);
      await observe.stepUp();
      const accepted = await observe.commit();
      expect(accepted.status, JSON.stringify(accepted)).toBe(202);
      for (const replay of await Promise.all([observe.commit(), observe.commit()]))
        expect(replay).toEqual(accepted);
      let read = await fixture.read(path);
      expect(read.status, JSON.stringify(read)).toBe(200);
      expect(read.body).toMatchObject({
        state: 'OBSERVED',
        revision: '2',
        runtimePermission: 'NONE',
        observation: { authority: 'OBSERVATION_ONLY', unresolvedCount: 0 },
      });
      expect(read.body.observation.actions).toHaveLength(1);
      expect(JSON.stringify(read.body)).not.toContain('signedTransaction');
      const review = {
        analysisDigest: read.body.observation.analysisDigest,
        actions: read.body.observation.actions.map((action: { actionDigest: string }) => ({
          actionDigest: action.actionDigest,
          maximumValue: Array(32).fill(0) as number[],
        })),
        program: null,
      };
      const reviewFields = { targetRef: created.body.resourceRef, expectedRevision: '2', review };
      for (const wrong of [
        { ...review, actions: [] },
        { ...review, actions: [...review.actions, ...review.actions] },
        { ...review, analysisDigest: sha256('other analysis') },
        { ...review, program: { forged: true } },
      ])
        await fixture.create(
          `${path}/review`,
          reviewAction,
          { ...reviewFields, review: wrong },
          400,
        );
      const reviewed = await fixture.prepareMutation(`${path}/review`, reviewAction, reviewFields);
      expect((await reviewed.commit()).status).toBe(403);
      expect(
        (await reviewed.commit({ ...reviewed.body, review: { ...review, actions: [] } })).status,
      ).toBe(412);
      await reviewed.stepUp();
      const reviewReceipt = await reviewed.commit();
      expect(reviewReceipt.status, JSON.stringify(reviewReceipt)).toBe(202);
      for (const replay of await Promise.all([reviewed.commit(), reviewed.commit()]))
        expect(replay).toEqual(reviewReceipt);
      read = await fixture.read(path);
      expect(read.body).toMatchObject({
        state: 'REVIEWED',
        revision: '3',
        runtimePermission: 'NONE',
        review: { definition: review, digest: sha256(review), profileCompilation: 'PENDING' },
      });
      // Shared method grants remain independent public aggregates. Fleet must
      // capture ALLOW, DENY and disabled rows without selecting only an allow.
      const interaction = read.body.observation.analysis.interactions[0];
      const grants: string[] = [];
      for (const [effect, status] of [
        ['ALLOW', 'ACTIVE'],
        ['DENY', 'ACTIVE'],
        ['ALLOW', 'DISABLED'],
      ] as const) {
        const grant = await fixture.create('cigl-grants', 'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1', {
          definition: {
            runtimeBindingId: `urn:openpc:resource:${interaction.resolution.runtimeBindingId}`,
            selector: `0x${Buffer.from(interaction.selector).toString('hex')}`,
            subject:
              status === 'DISABLED'
                ? { kind: 'ANY_AUTHENTICATED' }
                : { kind: 'WORKLOAD', id: source.workloadId },
            surface: 'RAW_SUBMISSION',
            effect,
          },
          expectedRuntimeBindingRevision: '1',
          expectedMethodRevision: '1',
        });
        expect(grant.body.resourceRef).toBeTypeOf('string');
        grants.push(String(grant.body.resourceRef));
        if (status === 'ACTIVE')
          await fixture.create(
            `cigl-grants/${grant.body.resourceRef}/status`,
            'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1',
            { targetRef: grant.body.resourceRef, expectedRevision: '1', status },
          );
      }
      await writeFile(
        join(root!, 'profile-review.pending'),
        JSON.stringify({
          analysisId: prepared.resourceId,
          reviewDigest: read.body.review.digest,
          profileId: String(read.body.review.profile.profileId).slice(
            'urn:openpc:resource:'.length,
          ),
          grants,
        }),
        { mode: 0o600 },
      );
      await rename(join(root!, 'profile-review.pending'), join(root!, 'profile-review.json'));
      await waitFile('profile-compilation-passed');
      read = await fixture.read(path);
      expect(read.body.review).toMatchObject({
        profileCompilation: 'COMPILED',
        profile: {
          state: 'COMPILED',
          runtimePermission: 'NONE',
          result: { methodCount: 2, grantCount: 3 },
          currentSources: {
            targetRuntimeId: definition.targetRuntimeId,
            installedCapsuleDigest: source.capsuleDigest,
          },
        },
      });
      const operation = await fixture.read(`operations/${reviewReceipt.body.operationId}`);
      expect(operation.body).toMatchObject({ state: 'SUCCEEDED', truthState: 'SUCCESS' });
      await writeFile(profileKeyFile, '');
      expect((await fixture.read(path)).status).toBe(409);
      expect((await fixture.read(`operations/${reviewReceipt.body.operationId}`)).status).toBe(409);
      await writeFile(profileKeyFile, profileKey);
      await fixture.restartConfiguration();
      expect(await fixture.read(path)).toEqual(read);
      expect(await observe.commit()).toEqual(accepted);
      expect((await reviewed.commit()).body).toMatchObject({
        operationId: reviewReceipt.body.operationId,
        state: 'SUCCEEDED',
      });
      await writeFile(keysFile, '{}');
      expect(await fixture.read(path)).toMatchObject({
        status: 409,
        body: { code: 'PC-FACT-4001', truthState: 'UNKNOWN' },
      });
      expect(await prepared.commit()).toEqual(created);
      expect(await observe.commit()).toEqual(accepted);
      await writeFile(keysFile, keys);
      expect(await fixture.read(path)).toEqual(read);
      const second = await fixture.create('cigl-analyses', createAction, {
        definition: { ...definition, expiresInSeconds: 301 },
      });
      await fixture.create(
        `cigl-analyses/${second.body.resourceRef}/observation`,
        updateAction,
        { targetRef: second.body.resourceRef, expectedRevision: '1', signedReceipt },
        400,
      );
      // Database role/context and copied cryptographic bytes cannot fabricate
      // the independently approved command, provenance or terminal history.
      const sqlClient = await admin.connect();
      const rejectSql = async (
        query: string,
        values: unknown[],
        action: string,
        pattern: RegExp,
      ) => {
        try {
          await sqlClient.query('begin');
          await sqlClient.query('set local role openpc_configuration_runtime');
          await sqlClient.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)",
            [source.participantId, source.privacyDomainId, id(), action],
          );
          await expect(
            (async () => {
              await sqlClient.query(query, values);
              await sqlClient.query('commit');
            })(),
          ).rejects.toThrow(pattern);
        } finally {
          await sqlClient.query('rollback');
        }
      };
      try {
        const profileId = String(read.body.review.profile.profileId).slice(-36);
        for (const query of [
          'delete from control.cigl_profile_version where profile_id=$1',
          "update control.cigl_profile_version set state='PENDING' where profile_id=$1",
          'delete from control.cigl_profile_grant_source where profile_id=$1',
          'delete from control.cigl_profile_method_source where profile_id=$1',
          'delete from control.cigl_profile_dependency_path where profile_id=$1',
        ])
          await rejectSql(query, [profileId], reviewAction, /permission denied|CIGL-PROFILE/);
        const retained = await sqlClient.query<{ profile_cbor: Buffer }>(
          'select profile_cbor from control.cigl_profile_version where profile_id=$1 and revision=1',
          [profileId],
        );
        const corrupt = async (bytes: Buffer) => {
          await sqlClient.query('begin');
          try {
            await sqlClient.query('set local session_replication_role=replica');
            await sqlClient.query(
              'update control.cigl_profile_version set profile_cbor=$2 where profile_id=$1 and revision=1',
              [profileId, bytes],
            );
            await sqlClient.query('commit');
          } catch (error) {
            await sqlClient.query('rollback');
            throw error;
          }
        };
        // Simulate privileged storage corruption; ordinary runtime roles cannot
        // perform this write. Readback must still verify the retained bytes.
        try {
          await corrupt(Buffer.from('corrupt profile'));
          expect((await fixture.read(path)).status).toBe(409);
          expect((await fixture.read(`operations/${reviewReceipt.body.operationId}`)).status).toBe(
            409,
          );
        } finally {
          await corrupt(retained.rows[0]!.profile_cbor);
        }
        expect(await fixture.read(path)).toEqual(read);
        await rejectSql(
          `insert into control.cigl_analysis(analysis_id,participant_id,privacy_domain_id,runtime_target_id,runtime_binding_id,
          contract_method_policy_id,definition,creation_operation_id,publication_operation_id,publication_authority_digest,expires_at)
          values($1,$2,$3,$4,$5,$6,$7::jsonb,current_setting('openpc.operation_id')::uuid,current_setting('openpc.operation_id')::uuid,$8,clock_timestamp())`,
          [
            id(),
            source.participantId,
            source.privacyDomainId,
            source.targetRuntimeId,
            source.runtimeBindingId,
            source.contractMethodPolicyId,
            JSON.stringify(definition),
            sha256('forged'),
          ],
          createAction,
          /CIGL-ANALYSIS-PROVENANCE/,
        );
        await rejectSql(
          `update control.cigl_analysis set state='OBSERVED',revision=2,signed_receipt=$2,receipt_digest=$3,analysis_digest=$4,
          publication_operation_id=current_setting('openpc.operation_id')::uuid,publication_authority_digest=$5 where analysis_id=$1`,
          [
            String(second.body.resourceRef).slice(-36),
            signedBytes,
            sha256(signedBytes),
            read.body.observation.analysisDigest,
            sha256('forged'),
          ],
          updateAction,
          /CIGL-ANALYSIS-PROVENANCE/,
        );
        await rejectSql(
          `update control.cigl_analysis set definition=jsonb_set(definition,'{transactionHash}',to_jsonb($2::text)),
          publication_operation_id=current_setting('openpc.operation_id')::uuid where analysis_id=$1`,
          [prepared.resourceId, `0x${'ff'.repeat(32)}`],
          updateAction,
          /CIGL-ANALYSIS-IMMUTABLE/,
        );
        await rejectSql(
          'delete from control.cigl_analysis where analysis_id=$1',
          [prepared.resourceId],
          updateAction,
          /permission denied|CIGL-ANALYSIS-HISTORY/,
        );
      } finally {
        sqlClient.release();
      }
      // Import exact backend-derived paths through the existing governed grant
      // owner. Profile compilation itself continues to confer no permission.
      const grantUpdate = 'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1';
      const rootMethod = source.installedPolicies.find(
        (m) => m.configured_identity.contract_method_policy_id === source.contractMethodPolicyId,
      )!;
      const upstream = await fixture.create('cigl-grants', 'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1', {
        definition: {
          runtimeBindingId: definition.runtimeBindingId,
          selector: `0x${Buffer.from(rootMethod.artifact.selector).toString('hex')}`,
          subject: { kind: 'WORKLOAD', id: source.workloadId },
          surface: 'RAW_SUBMISSION',
          effect: 'ALLOW',
        },
        expectedRuntimeBindingRevision: '1',
        expectedMethodRevision: '1',
      });
      const sourceRef = String(upstream.body.resourceRef);
      const paths = read.body.review.profile.result.dependencyPaths as {
        actionDigest: string;
        ordinal: number;
      }[];
      expect(paths.length).toBeGreaterThan(0);
      const epoch = (
        await admin.query<{ epoch: string }>(
          'select authority_epoch::text epoch from control.participant where participant_id=$1',
          [source.participantId],
        )
      ).rows[0]!.epoch;
      const bundle = {
        profileId: read.body.review.profile.profileId,
        profileRevision: '1',
        profileDigest: read.body.review.profile.result.profileDigest,
        graphDigest: read.body.observation.analysisDigest,
        policyGenerationDigest: source.policyGenerationDigest,
        participantEpoch: epoch,
        capability: 'EXECUTE_TRANSACTION',
        dependencies: paths.map((p) => ({
          actionDigest: `sha256:${p.actionDigest}`,
          grant: { kind: 'SHARED', grantId: grants[0], expectedRevision: '2' },
        })),
      };
      const importInput = {
        targetRef: sourceRef,
        expectedRevision: '1',
        status: 'ACTIVE',
        dependencyBundle: bundle,
      };
      // A matching ALLOW never neutralizes the already-active same-subject DENY.
      const imported = await fixture.prepareCreation(
        `cigl-grants/${sourceRef}/status`,
        grantUpdate,
        importInput,
      );
      await imported.stepUp();
      expect((await imported.commit()).status).toBe(400);
      expect((await fixture.read(`cigl-grants/${sourceRef}`)).body).toMatchObject({
        status: 'DISABLED',
        revision: '1',
      });
      await fixture.create(`cigl-grants/${grants[1]}/status`, grantUpdate, {
        targetRef: grants[1],
        expectedRevision: '2',
        status: 'DISABLED',
      });
      await fixture.create(`cigl-grants/${grants[2]}/status`, grantUpdate, {
        targetRef: grants[2],
        expectedRevision: '1',
        status: 'ACTIVE',
      });
      for (const [dependencyBundle, status] of [
        [{ ...bundle, dependencies: [] }, 400],
        [{ ...bundle, capability: 'SIMULATE_CALL' }, 412],
        [{ ...bundle, profileRevision: '999' }, 412],
        [{ ...bundle, participantEpoch: (BigInt(epoch) + 1n).toString() }, 412],
        [{ ...bundle, graphDigest: sha256('other graph') }, 412],
        [{ ...bundle, policyGenerationDigest: sha256('other epoch') }, 412],
        [
          {
            ...bundle,
            dependencies: [
              ...bundle.dependencies,
              { actionDigest: sha256('extra action'), grant: { kind: 'GENERATE' } },
            ],
          },
          400,
        ],
        [
          {
            ...bundle,
            dependencies: bundle.dependencies.map((d) => ({
              ...d,
              grant: { kind: 'SHARED', grantId: grants[2], expectedRevision: '2' },
            })),
          },
          400,
        ],
        [
          {
            ...bundle,
            dependencies: bundle.dependencies.map((d) => ({
              ...d,
              grant: {
                kind: 'SHARED',
                grantId: `urn:openpc:resource:${id()}`,
                expectedRevision: '1',
              },
            })),
          },
          412,
        ],
        [
          {
            ...bundle,
            dependencies: bundle.dependencies.map((d) => ({
              ...d,
              grant: { ...d.grant, expectedRevision: '1' },
            })),
          },
          412,
        ],
      ] as const) {
        const attempted = await fixture.prepareCreation(
          `cigl-grants/${sourceRef}/status`,
          grantUpdate,
          { ...importInput, dependencyBundle },
        );
        await attempted.stepUp();
        const denied = await attempted.commit();
        expect(denied.status, JSON.stringify(denied)).toBe(status);
        expect(denied.body.code).toBe(status === 400 ? 'PC-DATA-6004' : 'PC-DATA-6007');
        expect((await fixture.read(`cigl-grants/${sourceRef}`)).body).toMatchObject({
          status: 'DISABLED',
          revision: '1',
        });
      }
      await imported.stepUp();
      const importReceipt = await imported.commit();
      expect(importReceipt.status, JSON.stringify(importReceipt)).toBe(202);
      expect(await imported.commit()).toEqual(importReceipt);
      const outgoing = `cigl-grant-dependencies?filter=${encodeURIComponent(`sourceGrantId:eq:${sourceRef}`)}`;
      let claims = await fixture.read(outgoing);
      expect(claims.status, JSON.stringify(claims)).toBe(200);
      expect(claims.body.items).toHaveLength(paths.length);
      expect(claims.body.items[0]).toMatchObject({
        state: 'ACTIVE',
        ownership: 'UPSTREAM_SOURCE_GRANT',
        requiredGrantId: grants[0],
        requiredGrantOrigin: 'SHARED',
      });
      const claimSql = await admin.connect();
      try {
        for (const query of [
          'update control.cigl_method_grant_dependency_claims set required_grant_id=$2 where claim_id=$1',
          "update control.cigl_method_grant_dependency_claims set state='RELEASED',released_operation_id=$2,released_at=clock_timestamp() where claim_id=$1",
          'delete from control.cigl_method_grant_dependency_claims where claim_id=$1 and required_grant_id<>$2',
        ]) {
          await claimSql.query('begin');
          await claimSql.query('set local role openpc_configuration_runtime');
          await claimSql.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)",
            [source.participantId, source.privacyDomainId, id(), grantUpdate],
          );
          await expect(
            (async () => {
              await claimSql.query(query, [String(claims.body.items[0].claimId).slice(-36), id()]);
              await claimSql.query('commit');
            })(),
          ).rejects.toThrow(/permission denied|CIGL-DEPENDENCY/);
          await claimSql.query('rollback');
        }
      } finally {
        await claimSql.query('rollback');
        claimSql.release();
      }
      await fixture.restartConfiguration();
      expect((await fixture.read(outgoing)).body.items).toEqual(claims.body.items);
      await fixture.create(`cigl-grants/${sourceRef}/status`, grantUpdate, {
        targetRef: sourceRef,
        expectedRevision: '2',
        status: 'DISABLED',
      });
      expect((await fixture.read(`cigl-grants/${grants[0]}`)).body).toMatchObject({
        status: 'ACTIVE',
        revision: '2',
        origin: 'SHARED',
      });
      claims = await fixture.read(outgoing);
      expect(
        claims.body.items.every((claim: { state: string }) => claim.state === 'RELEASED'),
      ).toBe(true);
      // Generated authority has an explicit upstream owner and becomes disabled
      // when its last reference is removed. Its history is retained.
      const generatedBundle = {
        ...bundle,
        dependencies: paths.map((p) => ({
          actionDigest: `sha256:${p.actionDigest}`,
          grant: { kind: 'GENERATE' },
        })),
      };
      await fixture.create(`cigl-grants/${sourceRef}/status`, grantUpdate, {
        targetRef: sourceRef,
        expectedRevision: '3',
        status: 'ACTIVE',
        dependencyBundle: generatedBundle,
      });
      claims = await fixture.read(outgoing);
      const generatedClaim = claims.body.items.find(
        (claim: { state: string }) => claim.state === 'ACTIVE',
      );
      expect(generatedClaim).toMatchObject({
        requiredGrantOrigin: 'GENERATED',
        sourceGrantRevision: '4',
      });
      const generatedRef = String(generatedClaim.requiredGrantId);
      const incoming = await fixture.read(
        `cigl-grant-dependencies?filter=${encodeURIComponent(`requiredGrantId:eq:${generatedRef}`)}`,
      );
      expect(incoming.body.items).toHaveLength(paths.length);
      await fixture.create(
        `cigl-grants/${generatedRef}/status`,
        grantUpdate,
        { targetRef: generatedRef, expectedRevision: '1', status: 'DISABLED' },
        403,
      );
      // Replacing an upstream bundle releases its former claims but retains
      // generated authority while the new exact bundle still references it.
      await fixture.create(`cigl-grants/${sourceRef}/status`, grantUpdate, {
        targetRef: sourceRef,
        expectedRevision: '4',
        status: 'ACTIVE',
        dependencyBundle: {
          ...bundle,
          dependencies: paths.map((p) => ({
            actionDigest: `sha256:${p.actionDigest}`,
            grant: { kind: 'SHARED', grantId: generatedRef, expectedRevision: '1' },
          })),
        },
      });
      expect((await fixture.read(`cigl-grants/${generatedRef}`)).body).toMatchObject({
        status: 'ACTIVE',
        revision: '1',
        origin: 'GENERATED',
      });
      await fixture.create(`cigl-grants/${sourceRef}/status`, grantUpdate, {
        targetRef: sourceRef,
        expectedRevision: '5',
        status: 'DISABLED',
      });
      expect((await fixture.read(`cigl-grants/${generatedRef}`)).body).toMatchObject({
        origin: 'GENERATED',
        status: 'DISABLED',
        revision: '2',
      });
      await fixture.restartConfiguration();
      expect((await fixture.read(`cigl-grants/${generatedRef}`)).body).toMatchObject({
        origin: 'GENERATED',
        status: 'DISABLED',
        revision: '2',
      });
      const publicationFixture = fixture;
      const publicationView = await fixture.read(path);
      expect(publicationView.body.review.profile.currentSources).toMatchObject({
        targetRuntimeId: definition.targetRuntimeId,
        installedCapsuleDigest: source.capsuleDigest,
        participantEpoch: epoch,
      });
      expect(publicationView.body.review.profile.currentSources.grantSourcesDigest).not.toBe(
        read.body.review.profile.currentSources.grantSourcesDigest,
      );
      const publicationSources = await Promise.all(
        [...grants, generatedRef].map(async (grantRef) => {
          const current = (await publicationFixture.read(`cigl-grants/${grantRef}`)).body;
          return {
            grantId: grantRef.slice('urn:openpc:resource:'.length),
            revision: current.revision,
            digest: String(current.grantDigest).slice('sha256:'.length),
          };
        }),
      );
      await writeFile(
        join(root!, 'profile-publication.pending'),
        JSON.stringify({
          participantEpoch: epoch,
          grants: publicationSources,
          grantSourcesDigest: publicationView.body.review.profile.currentSources.grantSourcesDigest,
        }),
        { mode: 0o600 },
      );
      await rename(
        join(root!, 'profile-publication.pending'),
        join(root!, 'profile-publication.json'),
      );
      await waitFile('profile-publication-passed');
      expect((await fixture.read(path)).body.review.profile.result).toEqual(
        read.body.review.profile.result,
      );
      const profile = publicationView.body.review.profile;
      const activationPath = `runtime-targets/${definition.targetRuntimeId}/cigl-profiles`;
      const activationAction = 'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1';
      const activationInput = {
        targetRef: definition.targetRuntimeId,
        expectedRevision: profile.currentSources.targetRevision,
        expectedGenerationDigest: source.capsuleDigest,
        participantEpoch: epoch,
        profiles: [
          {
            profileId: profile.profileId,
            profileRevision: profile.revision,
            profileDigest: profile.result.profileDigest,
            compilationArtifactDigest: profile.result.artifactDigest,
            grantSourcesDigest: profile.currentSources.grantSourcesDigest,
          },
        ],
      };
      await fixture.create(
        activationPath,
        activationAction,
        {
          ...activationInput,
          profiles: [
            { ...activationInput.profiles[0], grantSourcesDigest: sha256('stale grant set') },
          ],
        },
        412,
      );
      // A new policy generation is never caller authority. An absent/foreign
      // occurrence cannot dispatch work or replace the installed policy.
      const workCount = await admin.query(
        `select count(*)::text count from control.configuration_work where work_kind='RUNTIME_ACTIVATION'`,
      );
      await fixture.create(
        activationPath,
        activationAction,
        {
          ...activationInput,
          policyRenewal: {
            activationOccurrenceRef: `urn:openpc:resource:${id()}`,
            expectedRevision: '1',
            policyGenerationDigest: sha256('unapproved renewal'),
          },
        },
        412,
      );
      expect(
        (
          await admin.query(
            `select count(*)::text count from control.configuration_work where work_kind='RUNTIME_ACTIVATION'`,
          )
        ).rows,
      ).toEqual(workCount.rows);
      const activate = await fixture.prepareCreation(
        activationPath,
        activationAction,
        activationInput,
      );
      expect((await activate.commit()).status).toBe(403);
      await activate.stepUp();
      expect(
        (await activate.commit({ ...activate.body, participantEpoch: String(Number(epoch) + 1) }))
          .status,
      ).toBe(412);
      const queued = await activate.commit();
      expect(queued.status, JSON.stringify(queued)).toBe(202);
      expect(await activate.commit()).toEqual(queued);
      const activationWork = await admin.query(
        `select generation.generation_digest,generation.cigl_profile_selection,work.configuration_work_id,generation.runtime_configuration_generation_id,
        generation.state,work.state work_state,work.configuration_digest,work.predecessor_digest,work.input_digest
        from control.runtime_configuration_generation generation join control.configuration_work work
        on work.runtime_configuration_generation_id=generation.runtime_configuration_generation_id
        where work.operation_id=$1`,
        [queued.body.operationId],
      );
      expect(activationWork.rowCount).toBe(1);
      expect(activationWork.rows[0]).toMatchObject({
        state: 'ACTIVATING',
        work_state: 'PENDING',
        predecessor_digest: source.capsuleDigest,
        input_digest: sha256(activate.body),
        cigl_profile_selection: { participantEpoch: epoch, profiles: activationInput.profiles },
        generation_digest: sha256({
          purpose: 'openpc.runtime.cigl-profile-selection.v1',
          baseCapsuleDigest: source.capsuleDigest,
          selection: { participantEpoch: epoch, profiles: activationInput.profiles },
        }),
      });
      const targetPath = `runtime-targets/${definition.targetRuntimeId}`;
      const staging = await fixture.read(targetPath);
      expect(staging.body).toMatchObject({
        state: 'STAGING',
        activeGenerationDigest: source.capsuleDigest,
        desiredGenerationDigest: activationWork.rows[0].generation_digest,
      });
      await fixture.restartConfiguration();
      expect(await fixture.read(targetPath)).toEqual(staging);
      expect(await activate.commit()).toEqual(queued);
      await expect(
        admin.query(
          `update control.runtime_configuration_generation
        set cigl_profile_selection=null where generation_digest=$1`,
          [activationWork.rows[0].generation_digest],
        ),
      ).rejects.toMatchObject({ message: 'PC-DATA-6004-CIGL-ACTIVATION-IMMUTABLE' });
      await expect(
        admin.query(
          `update control.runtime_configuration_generation
        set policy_generation_digest=$2 where generation_digest=$1`,
          [activationWork.rows[0].generation_digest, sha256('unapproved policy')],
        ),
      ).rejects.toMatchObject({ message: 'PC-DATA-6004-CIGL-ACTIVATION-IMMUTABLE' });
      await expect(
        admin.query(
          `update control.runtime_configuration_generation
        set state='ACTIVE' where generation_digest=$1`,
          [activationWork.rows[0].generation_digest],
        ),
      ).rejects.toMatchObject({ message: 'PC-AUTH-0002-CIGL-ACTIVATION-EFFECT' });
      await expect(
        admin.query(
          `update control.configuration_work set configuration_digest=$2
        where configuration_work_id=$1`,
          [activationWork.rows[0].configuration_work_id, sha256('unapproved configuration')],
        ),
      ).rejects.toMatchObject({ message: 'PC-DATA-6004-CIGL-ACTIVATION-WORK-IMMUTABLE' });
      expect(await fixture.read(targetPath)).toEqual(staging);
      await writeFile(
        join(root!, 'profile-activation-queued.pending'),
        JSON.stringify({
          workId: activationWork.rows[0].configuration_work_id,
          generationId: activationWork.rows[0].runtime_configuration_generation_id,
          generationDigest: activationWork.rows[0].generation_digest,
        }),
      );
      await rename(
        join(root!, 'profile-activation-queued.pending'),
        join(root!, 'profile-activation-queued.json'),
      );
      await waitFile('profile-activation-composed');
      const selectedGrant = (await fixture.read(`cigl-grants/${grants[0]}`)).body;
      expect(selectedGrant.status).toBe('ACTIVE');
      await fixture.create(`cigl-grants/${grants[0]}/status`, grantUpdate, {
        targetRef: grants[0],
        expectedRevision: selectedGrant.revision,
        status: 'DISABLED',
      });
      await writeFile(
        join(root!, 'profile-grant-source-changed'),
        'Governed shared grant revocation',
      );
      await waitFile('profile-grant-invalidation-derived');
      await admin.query(
        'update control.runtime_target set desired_generation_digest=$2 where runtime_target_id=$1',
        [source.targetRuntimeId, sha256('changed generation')],
      );
      expect((await fixture.read(path)).body.review.profile.currentSources).toBeNull();
      await fixture.create(
        'cigl-analyses',
        createAction,
        { definition: { ...definition, expiresInSeconds: 302 } },
        403,
      );
      const retainedAfterDrift = structuredClone(read);
      retainedAfterDrift.body.review.profile.currentSources = null;
      expect(await fixture.read(path)).toEqual(retainedAfterDrift);
      await writeFile(join(root!, 'profile-stale-ready'), 'Current desired generation changed');
      await waitFile('profile-stale-passed');
      await admin.query(
        "update control.runtime_target set state='ACTIVE_MATCHED',active_generation_digest=$2,desired_generation_digest=$2 where runtime_target_id=$1",
        [source.targetRuntimeId, sha256('unobserved replacement capsule')],
      );
      expect(await fixture.read(path)).toEqual(retainedAfterDrift);
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect((await foreign.read(path)).status).not.toBe(200);
      expect((await foreign.read(outgoing)).body.items).toEqual([]);
      expect(
        (
          await admin.query(
            "select count(*)::int n from control.cigl_analysis where state='REVIEWED'",
          )
        ).rows[0].n,
      ).toBe(1);
      for (const table of ['mutation_evidence', 'outbox_event'])
        expect(
          (
            await admin.query(
              `select count(*)::int n from control.${table} where aggregate_id=$1`,
              [prepared.resourceId],
            )
          ).rows[0].n,
        ).toBe(table === 'outbox_event' ? 4 : 3);
      const runtime = new Pool({
        connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
        max: 1,
      });
      try {
        await expect(
          runtime.query('delete from control.cigl_analysis where analysis_id=$1', [
            prepared.resourceId,
          ]),
        ).rejects.toThrow();
      } finally {
        await runtime.end();
      }
    } catch (error) {
      await writeFile(
        join(root!, 'analysis-api-failed'),
        error instanceof Error
          ? (error.stack ?? error.message)
          : 'Public analysis prerequisite failed',
        { mode: 0o600 },
      );
      throw error;
    } finally {
      if (priorProfileKey === undefined) delete process.env.OPENPC_CIGL_PROFILE_PUBLIC_KEY_FILE;
      else process.env.OPENPC_CIGL_PROFILE_PUBLIC_KEY_FILE = priorProfileKey;
      if (priorKeys === undefined) delete process.env.OPENPC_CIGL_ANALYSIS_TARGET_KEYS_FILE;
      else process.env.OPENPC_CIGL_ANALYSIS_TARGET_KEYS_FILE = priorKeys;
      await foreign?.close();
      await fixture?.close();
      await admin.end();
    }
  },
  90_000,
);
