import assert from 'node:assert/strict';
import { prepareVisibilityPolicy, checkEffectiveVisibility } from './typed-visibility-policy.mjs';
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { encodeCbor } from '../../../packages/security-kernel/src/business-transition/cbor.ts';
import { pcCbor1 } from '../../../services/module-registry/src/domain/digest.ts';
import {
  encodePolicyArtifactPayload,
  policyArtifactCoseContext,
} from '../../../services/module-registry/src/domain/policy-artifact.ts';
import { validatePolicySemantics } from '../../../services/module-registry/src/domain/policy-semantics.ts';
import { simulateDeployment } from './deployment-policy-journey.mjs';
import {
  assertPolicyModuleBindings,
  loadPolicyContractInputs,
} from '../../../services/module-registry/src/db/policy-inputs.ts';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const policyId = '018f0000-0000-7000-8000-000000000920';
const role = 'urn:openpc:role:018f0000-0000-7000-8000-000000000801';
const rpc = (method) => ({
  schemaVersion: '1.0.0',
  participantId,
  privacyDomainId,
  rules: [{ method, effect: 'ALLOW', requiredRoles: [role] }],
});
const [mode, root, evidence, container, sessionToken, fixtureRevision = '0'] =
  process.argv.slice(2);
assert.match(fixtureRevision, /^(0|[1-9][0-9]{0,2})$/u);
const load = async (name) => JSON.parse(await readFile(join(evidence, name), 'utf8'));
const save = (name, value) => writeFile(join(evidence, name), JSON.stringify(value));
const hash = (value) => createHash('sha256').update(value).digest();
if (mode === 'state-read-recovery') {
  await prepareVisibilityPolicy(root, evidence, true, true, 'typed-policy-inputs.json');
} else if (mode === 'state-read-prepare' || mode === 'state-read-browser') {
  await prepareVisibilityPolicy(root, evidence, mode === 'state-read-browser', true);
} else if (mode === 'visibility-prepare' || mode === 'visibility-browser') {
  await prepareVisibilityPolicy(root, evidence, mode === 'visibility-browser');
} else if (mode === 'visibility-effective' || mode === 'visibility-inactive') {
  await checkEffectiveVisibility(
    evidence,
    sessionToken,
    mode === 'visibility-effective' ? 'ACTIVE' : 'UNAVAILABLE',
  );
} else if (mode === 'rpc-digest') {
  process.stdout.write(`sha256:${pcCbor1(rpc('eth_call')).digest.toString('hex')}`);
} else {
  const call = (path, body, expected = 201, scope = {}) => {
    const result = JSON.parse(
      execFileSync(
        'docker',
        [
          'exec',
          '-i',
          container,
          'node',
          '--input-type=module',
          '-e',
          `
      import fs from 'node:fs';
      const input = JSON.parse(fs.readFileSync(0,'utf8'));
      const response = await fetch('http://127.0.0.1:3002'+input.path,{method:'POST',headers:{
        'authorization':'Bearer '+fs.readFileSync('/run/secrets/policy_internal_token','utf8').trim(),
        'content-type':'application/json','x-request-id':input.requestId,
        'openpc-participant-id':'urn:openpc:participant:'+input.participantId,
        'openpc-privacy-domain-id':'urn:openpc:privacy-domain:'+input.privacyDomainId
      },body:JSON.stringify(input.body)});
      process.stdout.write(JSON.stringify({status:response.status,body:await response.json()}));
    `,
        ],
        {
          encoding: 'utf8',
          input: JSON.stringify({
            path,
            body,
            participantId,
            privacyDomainId,
            ...scope,
            requestId: execFileSync(
              process.execPath,
              ['tests/integration/local-runtime/configuration-fixture.mjs', 'uuidv7'],
              { encoding: 'utf8' },
            ),
          }),
        },
      ),
    );
    assert.equal(result.status, expected, JSON.stringify(result));
    return result.body;
  };
  if (mode === 'source-simulate') {
    const input = await load('typed-policy-inputs.json');
    const version = await load('typed-policy-version.json');
    const body = {
      sessionToken,
      policyVersionId: version.resourceRef.split(':').at(-1),
      request: input.sourceRequest,
    };
    const result = call('/internal/v1/policy-simulations', body);
    assert.equal(result.authorityLabel, 'SIMULATION_ONLY');
    assert.equal(result.evaluation.truthState, 'SUCCESS');
    assert.equal(
      call('/internal/v1/policy-simulations', {
        ...body,
        request: { ...body.request, dataClass: 'FULL_BLOCK_TRANSACTIONS' },
      }).evaluation.truthState,
      'DENIED',
    );
    await save('typed-policy-simulation.json', result);
  } else if (mode === 'visibility-simulate') {
    const input = await load('typed-policy-inputs.json');
    const version = await load('typed-policy-version.json');
    const body = {
      sessionToken,
      policyVersionId: version.resourceRef.split(':').at(-1),
      request: input.visibilityRequest,
    };
    const result = call('/internal/v1/policy-simulations', body);
    assert.equal(result.authorityLabel, 'SIMULATION_ONLY');
    assert.equal(result.evaluation.truthState, 'SUCCESS');
    assert.deepEqual(call('/internal/v1/policy-simulations', body), result);
    const denied = call('/internal/v1/policy-simulations', {
      ...body,
      request: { ...body.request, purpose: 'UNAUTHORIZED_PURPOSE' },
    });
    assert.equal(denied.evaluation.truthState, 'DENIED');
    await save('typed-policy-simulation.json', result);
  } else if (mode === 'prepare' || mode === 'prepare-browser' || mode === 'prepare-b') {
    const semanticVersion =
      mode === 'prepare-browser'
        ? '4.1.0'
        : mode === 'prepare-b'
          ? '5.0.0'
          : `4.0.${fixtureRevision}`;
    const pool = new Pool({
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_control',
      password: (await readFile(join(root, 'control_pg_password.txt'), 'utf8')).trim(),
      max: 1,
    });
    let moduleBindings;
    try {
      moduleBindings = (
        await pool.query(
          `select version.module_id as "moduleId", version.semantic_version as "semanticVersion",
        'sha256:'||encode(version.manifest_digest,'hex') as "manifestDigest",
        'sha256:'||encode(configuration.configuration_digest,'hex') as "configurationDigest"
        from control.module_installation installation join control.module_version version using(module_version_id)
        join control.module_configuration_generation configuration using(module_installation_id)
        where installation.participant_id=$1 and installation.privacy_domain_id=$2 and installation.state='ENABLED'
          and version.release_payload_cbor is not null and configuration.active=true
        order by version.module_id`,
          [participantId, privacyDomainId],
        )
      ).rows;
    } finally {
      await pool.end();
    }
    assert.equal(moduleBindings.length, 25);
    const readMethod = await load('configuration-contract-read-resource.json');
    const readMethodB =
      mode === 'prepare-b' || process.env.OPENPC_LOCAL_RUNTIME_CIGL_ONLY === '1'
        ? await load('configuration-contract-read-b-resource.json')
        : undefined;
    const writeMethod = await load('configuration-contract-method-resource.json');
    const deployment = await load('configuration-deployment-policy-resource.json');
    assert.equal(deployment.state, 'STAGED');
    const deployments = [deployment];
    if (process.env.OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY === '1')
      for (const mechanism of ['CREATE', 'CREATE2', 'CREATE3'])
        deployments.push(await load(`configuration-deployment-${mechanism}-policy-resource.json`));
    const fact = await load('typed-policy-fact.json');
    assert.equal(fact.outcome, 'PRESENT');
    const document = {
      schemaVersion: '1.0.0',
      participantId,
      privacyDomainId,
      moduleBindings,
      rpcPolicies: [
        rpc('eth_call'),
        rpc('eth_sendRawTransaction'),
        ...(process.env.OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY === '1' ||
        process.env.OPENPC_LOCAL_RUNTIME_CIGL_ONLY === '1'
          ? [rpc('pc_getOperationStatus')]
          : []),
      ],
      contractPolicies: (mode === 'prepare-browser'
        ? [readMethod]
        : mode === 'prepare-b'
          ? [readMethodB, writeMethod]
          : process.env.OPENPC_LOCAL_RUNTIME_CIGL_ONLY === '1'
            ? [readMethod, writeMethod, readMethodB]
            : [readMethod, writeMethod]
      ).map((value) => {
        assert.ok(value);
        return {
          contractMethodPolicyId: value.contractMethodPolicyId.split(':').at(-1),
          revision: value.revision,
        };
      }),
      ...(mode === 'prepare-browser'
        ? {}
        : {
            deploymentPolicies: deployments
              .map((value) => ({
                deploymentPolicyId: value.deploymentPolicyId.split(':').at(-1),
                definitionDigest: value.definitionDigest,
              }))
              .sort((a, b) => a.deploymentPolicyId.localeCompare(b.deploymentPolicyId)),
          }),
      requiredFacts: [
        {
          candidateId: fact.candidateId,
          generationId: fact.generationId,
          factDigest: `sha256:${Buffer.from(fact.factDigest).toString('hex')}`,
        },
      ],
    };
    const semantic = validatePolicySemantics(document);
    const dependency = pcCbor1(moduleBindings).digest;
    const reader = new Pool({
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_policy_runtime',
      password: (await readFile(join(root, 'policy_runtime_db_password.txt'), 'utf8')).trim(),
      max: 2,
    });
    const readerClient = await reader.connect();
    const contender = await reader.connect();
    try {
      await readerClient.query('begin');
      await readerClient.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',true)",
        [participantId, privacyDomainId],
      );
      assert.equal(
        (
          await readerClient.query(
            "select has_table_privilege(current_user,'control.module_installation','UPDATE') as mutable",
          )
        ).rows[0].mutable,
        false,
      );
      await assertPolicyModuleBindings(readerClient, document, dependency);
      const inputs = await loadPolicyContractInputs(readerClient, document);
      assert.equal(inputs.length, document.contractPolicies.length);
      for (const input of inputs) {
        const resource = [readMethod, readMethodB, writeMethod]
          .filter(Boolean)
          .find((value) => value.contractMethodPolicyId.split(':').at(-1) === input.assetId);
        assert.ok(resource);
        assert.equal(input.runtimeBindingId, resource.runtimeBindingId.split(':').at(-1));
      }
      await contender.query('begin');
      const lock = `module-admission:${participantId}:${privacyDomainId}`;
      assert.equal(
        (
          await contender.query(
            'select pg_try_advisory_xact_lock(hashtextextended($1,0)) as acquired',
            [lock],
          )
        ).rows[0].acquired,
        false,
      );
      await readerClient.query('rollback');
      assert.equal(
        (
          await contender.query(
            'select pg_try_advisory_xact_lock(hashtextextended($1,0)) as acquired',
            [lock],
          )
        ).rows[0].acquired,
        true,
      );
    } finally {
      await Promise.allSettled([readerClient.query('rollback'), contender.query('rollback')]);
      readerClient.release();
      contender.release();
      await reader.end();
    }
    const schema = hash('OpenPC typed RPC/contract/argument policy semantic document v1');
    const payload = encodePolicyArtifactPayload({
      participantId: `urn:openpc:participant:${participantId}`,
      privacyDomainId: `urn:openpc:privacy-domain:${privacyDomainId}`,
      policySetId: `urn:openpc:policy-set:${policyId}`,
      semanticVersion,
      policySchemaDigest: schema,
      semanticDigest: semantic.digest,
      dependencyClosureDigest: dependency,
      semanticBytesDigest: semantic.digest,
    });
    const key = createPrivateKey(
      await readFile(join(root, 'policy_artifact_signer_private_key.pem')),
    );
    const publicKey = createPublicKey(key).export({ format: 'der', type: 'spki' });
    const protectedBytes = encodeCbor(
      new Map([
        [1, -7],
        [3, 'application/openpc+cbor'],
        [4, hash(publicKey)],
        [1001, policyArtifactCoseContext.schemaId],
        [1002, policyArtifactCoseContext.purpose],
      ]),
    );
    const signature = sign(
      'sha256',
      encodeCbor(['Signature1', protectedBytes, Buffer.alloc(0), payload]),
      { key, dsaEncoding: 'ieee-p1363' },
    );
    const cose = Buffer.concat([
      Buffer.from([0xd2]),
      encodeCbor([protectedBytes, new Map(), payload, signature]),
    ]);
    const body = {
      sessionToken,
      policyId,
      semanticVersion,
      semanticDocument: document,
      semanticCbor: semantic.bytes.toString('base64'),
      policySchemaDigest: `sha256:${schema.toString('hex')}`,
      dependencyClosureDigest: `sha256:${dependency.toString('hex')}`,
      payloadCbor: payload.toString('base64'),
      coseSign1: cose.toString('base64'),
    };
    await save(
      mode === 'prepare-browser'
        ? 'typed-policy-browser-artifact.json'
        : mode === 'prepare-b'
          ? 'typed-policy-b-artifact.json'
          : 'typed-policy-artifact.json',
      call('/internal/v1/policy-artifacts', body),
    );
    const forged = structuredClone(body);
    forged.semanticDocument.desiredEffect = 'ALLOW';
    call('/internal/v1/policy-artifacts', forged, 422);
    await save(
      mode === 'prepare-browser'
        ? 'typed-policy-browser-inputs.json'
        : mode === 'prepare-b'
          ? 'typed-policy-b-inputs.json'
          : 'typed-policy-inputs.json',
      {
        semanticVersion,
        semanticDigest: `sha256:${semantic.digest.toString('hex')}`,
        dependencyDigest: body.dependencyClosureDigest,
        readId: document.contractPolicies[0].contractMethodPolicyId,
        writeId: document.contractPolicies[1]?.contractMethodPolicyId,
      },
    );
  } else {
    const authoritySnapshot = async () => {
      const pool = new Pool({
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: 'openpc_control',
        password: (await readFile(join(root, 'control_pg_password.txt'), 'utf8')).trim(),
        max: 1,
      });
      try {
        return (
          await pool.query(`select
          (select count(*)::text from control.policy_generation) as generations,
          (select count(*)::text from control.policy_activation) as activations`)
        ).rows;
      } finally {
        await pool.end();
      }
    };
    const authorityBefore = await authoritySnapshot();
    const policyB = mode === 'simulate-b' || mode === 'restart-b';
    const input = await load(policyB ? 'typed-policy-b-inputs.json' : 'typed-policy-inputs.json');
    const version = await load(
      policyB ? 'typed-policy-b-version.json' : 'typed-policy-version.json',
    );
    const policyVersionId = version.resourceRef.split(':').at(-1);
    const request = {
      contractMethodPolicyId: input.readId,
      method: 'eth_call',
      calldata: '0x70a08231' + '0'.repeat(24) + (policyB ? '2'.repeat(40) : '1'.repeat(40)),
    };
    const body = { sessionToken, policyVersionId, request };
    const path = '/internal/v1/policy-simulations';
    const response = call(path, body);
    assert.equal(response.authorityLabel, 'SIMULATION_ONLY');
    assert.equal(response.evaluation.truthState, mode === 'reorg' ? 'STALE' : 'SUCCESS');
    assert.equal('inputBytes' in response.evaluation, false);
    assert.equal('resultBytes' in response.evaluation, false);
    if (mode === 'simulate' || mode === 'simulate-b') {
      await save(
        policyB ? 'typed-policy-b-simulation.json' : 'typed-policy-simulation.json',
        response,
      );
      assert.deepEqual(
        call(path, body),
        response,
        'same owner inputs must replay the durable simulation',
      );
      for (const injected of [
        { context: { effect: 'ALLOW' } },
        { roles: [role] },
        { currentFactDigest: input.semanticDigest },
      ])
        call(path, { ...body, ...injected }, 422);
      const selectorDenied = call(path, {
        ...body,
        request: { ...request, calldata: '0xffffffff' + request.calldata.slice(10) },
      });
      assert.equal(selectorDenied.evaluation.truthState, 'DENIED');
      const argumentDenied = call(path, {
        ...body,
        request: {
          ...request,
          calldata: '0x70a08231' + '0'.repeat(24) + (policyB ? '1'.repeat(40) : '2'.repeat(40)),
        },
      });
      assert.equal(argumentDenied.evaluation.truthState, 'DENIED');
      const methodDenied = call(path, {
        ...body,
        request: { ...request, method: 'eth_sendRawTransaction' },
      });
      assert.equal(methodDenied.evaluation.truthState, 'DENIED');
      const governed = call(path, {
        ...body,
        request: {
          contractMethodPolicyId: input.writeId,
          method: 'eth_sendRawTransaction',
          calldata: '0xa9059cbb' + '0'.repeat(24) + '1'.repeat(40) + '0'.repeat(63) + '1',
        },
      });
      if (process.env.OPENPC_LOCAL_RUNTIME_CIGL_ONLY === '1') {
        const method = await load('configuration-contract-method-resource.json');
        assert.equal(method.approvalRequirement, 'NONE');
        assert.equal(method.mfaRequirement, 'NONE');
        assert.equal(governed.authorityLabel, 'SIMULATION_ONLY');
        assert.equal(governed.evaluation.truthState, 'SUCCESS');
      } else {
        assert.equal(
          governed.evaluation.truthState,
          'DENIED',
          'missing genuine approval and step-up deny writes',
        );
      }
      call(path, body, 403, { privacyDomainId: '018f0000-0000-7000-8000-000000000202' });
      call(path, body, 403, { participantId: '018f0000-0000-7000-8000-000000000102' });
    } else if (mode === 'restart' || mode === 'restart-b') {
      assert.deepEqual(
        response,
        await load(policyB ? 'typed-policy-b-simulation.json' : 'typed-policy-simulation.json'),
      );
    } else if (mode !== 'reorg') {
      throw Error('unknown typed policy journey mode');
    }
    await simulateDeployment({ load, save, call, body, mode, policyB });
    assert.deepEqual(
      await authoritySnapshot(),
      authorityBefore,
      'simulation must not activate authority',
    );
    process.stdout.write(`OPENPC_TYPED_POLICY_${mode.toUpperCase()}|PASS\n`);
  }
}
