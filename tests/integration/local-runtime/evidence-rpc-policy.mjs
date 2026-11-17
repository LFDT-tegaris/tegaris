import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import { withTransactionBrowser } from './transaction-workbench-browser.mjs';
import { simulateSourcePolicy } from './policy-source-browser.mjs';
import {
  importPolicyDocument,
  openPolicySimulation,
  selectPolicyVersion,
} from './evaluation-ui-browser.mjs';
import { responseIds } from '../../../apps/admin-web/app/api/v1/ui/local-runtime.ts';
import { pcCbor1 } from '../../../services/module-registry/src/domain/digest.ts';
import {
  validatePolicySemantics,
  compilePolicySemantics,
} from '../../../services/module-registry/src/domain/policy-semantics.ts';
import {
  assertPolicyModuleBindings,
  loadPolicyContractInputs,
} from '../../../services/module-registry/src/db/policy-inputs.ts';

async function selectContractSimulationAuthority(maker, evidenceRoot) {
  const load = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
  const discovery = await load('discovery-credential-input.json');
  const assignment = await load('rpc-assignment-readback.json');
  assert.equal(assignment.state, 'ACTIVE');
  const workload = maker.getByRole('combobox', { name: 'Workload', exact: true });
  const verify = maker.getByRole('button', {
    name: 'Verify authenticator and load assignments',
    exact: true,
  });
  await expect
    .poll(async () => (await verify.isVisible()) || (await workload.isEnabled()))
    .toBe(true);
  if (await verify.isVisible()) {
    const [response] = await Promise.all([
      maker.waitForResponse(
        (value) =>
          value.request().method() === 'POST' && value.url().endsWith('/webauthn/assertion/verify'),
      ),
      verify.click(),
    ]);
    assert.ok(response.ok(), 'Catalogue authenticator verification must succeed');
  }
  await expect(workload).toBeEnabled();
  await workload.selectOption(discovery.workloadId ?? `urn:openpc:workload:${discovery.targetId}`);
  await maker
    .getByRole('combobox', { name: 'Role assignment', exact: true })
    .selectOption(assignment.id);
}

async function prepareContractSimulation(secretRoot, evidenceRoot) {
  const generation = Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2);
  assert.ok(Number.isSafeInteger(generation) && generation >= 2);
  const suffix = generation === 2 ? '' : `-${generation}`;
  const input = JSON.parse(
    await readFile(join(evidenceRoot, `rpc-source${suffix}-policy-input.json`), 'utf8'),
  );
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot,
      privacyDomainId: input.privacyDomainId,
      reuseSessions: true,
      route: '/configure/policies',
      readyHeading:
        process.env.OPENPC_EVALUATION_UI === '1'
          ? 'Create a policy version'
          : 'Compose and simulate policy',
      artifacts: join(
        evidenceRoot,
        'rpc-catalogue-browser',
        new Date().toISOString().replaceAll(':', '-'),
      ),
    },
    async ({ maker }) => {
      await openPolicySimulation(maker);
      await selectContractSimulationAuthority(maker, evidenceRoot);
    },
  );
  process.stdout.write(
    'OPENPC_RPC_POLICY|PASS|catalogue-preflight|exact-assignment|before-fact-window\n',
  );
}

export async function authorRpcPolicy({ secretRoot, evidenceRoot, family = 'rpc', browser }) {
  assert.ok(['source', 'rpc'].includes(family));
  const generation = Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2);
  assert.ok(Number.isSafeInteger(generation) && generation >= 2);
  const sourcePrefix = `rpc-source${generation === 2 ? '' : `-${generation}`}`;
  const rpcPrefix = `rpc-policy${generation === 2 ? '' : `-${generation}`}`;
  const prefix = family === 'source' ? `${sourcePrefix}-policy` : rpcPrefix;
  const load = async (name) => JSON.parse(await readFile(join(evidenceRoot, name), 'utf8'));
  const save = async (name, value) =>
    writeFile(join(evidenceRoot, name), JSON.stringify(value), { mode: 0o600 });
  const source = await load(`${sourcePrefix}-policy-input.json`);
  const first = await load('policy-set-result.json');
  const method = await load('rpc-method-resource.json');
  const discovery = await load('discovery-credential-input.json');
  assert.equal(method.state, 'ACTIVE');
  const semanticDocument = structuredClone(source.semanticDocument);
  if (family === 'rpc') {
    const original = await load('policy-set-input.json');
    // The method policy binds its own exact RPC policy digest. The new header
    // policy belongs to source acquisition and does not replace that binding.
    const methodRpc = original.semanticDocument.rpcPolicies.find(
      (policy) =>
        `sha256:${pcCbor1(policy).digest.toString('hex')}` === method.rpcMethodPolicyDigest,
    );
    assert.ok(methodRpc);
    semanticDocument.rpcPolicies.push(methodRpc);
    const fact = await load(`${rpcPrefix}-fact.json`);
    assert.equal(fact.outcome, 'PRESENT');
    assert.ok(fact.freshUntilMs > Date.now(), 'Fresh authoritative source Fact required');
    semanticDocument.contractPolicies = [
      {
        contractMethodPolicyId: method.contractMethodPolicyId.slice(-36),
        revision: method.revision,
      },
    ];
    semanticDocument.requiredFacts = [
      {
        candidateId: fact.candidateId,
        generationId: fact.generationId,
        factDigest: `sha256:${Buffer.from(fact.factDigest).toString('hex')}`,
      },
    ];
  }
  const semantic = validatePolicySemantics(semanticDocument);
  const input = {
    ...source,
    semanticVersion: family === 'source' ? source.semanticVersion : `1.2.${generation - 2}`,
    semanticDocument,
    semanticDigest: `sha256:${semantic.digest.toString('hex')}`,
    predecessorDigest: family === 'source' ? source.predecessorDigest : source.semanticDigest,
    policySetId: first.policySetId,
  };
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_policy_runtime',
    password: (await readFile(join(secretRoot, 'policy_runtime_db_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  let versionId;
  try {
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',true)",
        [input.participantId, input.privacyDomainId],
      );
      await assertPolicyModuleBindings(
        client,
        semanticDocument,
        pcCbor1(semanticDocument.moduleBindings).digest,
        true,
      );
      const admitted = await loadPolicyContractInputs(client, semanticDocument);
      assert.equal(admitted.length, semanticDocument.contractPolicies.length);
      const fixture = await load(`${sourcePrefix}-configuration.json`);
      compilePolicySemantics(
        semanticDocument,
        admitted,
        `urn:openpc:workload:${discovery.targetId}`,
        [],
        [
          {
            configurationCbor: [...Buffer.from(fixture.configurationCborHex, 'hex')],
            configurationDigest: fixture.configurationDigest.slice(7),
          },
        ],
      );
      const versions = await client.query(
        'select policy_version_id::text id from control.policy_version where participant_id=$1 and privacy_domain_id=$2 and policy_id=$3 and version=$4',
        [
          input.participantId,
          input.privacyDomainId,
          input.policySetId.slice(-36),
          input.semanticVersion,
        ],
      );
      assert.ok(versions.rowCount <= 1);
      versionId = versions.rows[0]?.id;
      await client.query('rollback');
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
  const prior = await load(`${prefix}-input.json`).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  if (prior) assert.deepEqual(input, prior, 'Successor policy inputs stay immutable');
  else await save(`${prefix}-input.json`, input);
  process.stdout.write(
    'OPENPC_RPC_POLICY|PASS|actual-module-contract-source-inputs|canonical-compile\n',
  );
  const withBrowser = browser ? async (_options, run) => run(browser) : withTransactionBrowser;
  await withBrowser(
    {
      secretRoot,
      evidenceRoot,
      privacyDomainId: input.privacyDomainId,
      reuseSessions: true,
      artifacts: join(
        evidenceRoot,
        `${prefix}-browser`,
        new Date().toISOString().replaceAll(':', '-'),
      ),
    },
    async ({ maker, actors }) => {
      const publicRead = async (path) => {
        const ids = responseIds();
        const response = await fetch(`http://127.0.0.1:8080${path}`, {
          headers: {
            'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
            'OpenPC-Participant-ID': `urn:openpc:participant:${input.participantId}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${input.privacyDomainId}`,
            'OpenPC-API-Version': '1',
            'X-Request-ID': ids.requestId,
            'X-Correlation-ID': ids.correlationId,
          },
        });
        assert.equal(response.status, 200);
        return response.json();
      };
      const parent = await publicRead(`/api/v1/policy-sets/${input.policySetId}`);
      assert.equal(parent.state, 'ACTIVE');
      assert.equal(
        parent.activeVersionDigest,
        input.predecessorDigest,
        'Authoring cannot change serving authority',
      );
      await maker.goto('http://localhost:8080/configure/policies');
      await maker
        .getByLabel('Policy set for this version', { exact: true })
        .selectOption(input.policySetId);
      if (!versionId) {
        await maker.getByLabel('Semantic version', { exact: true }).fill(input.semanticVersion);
        await maker.getByLabel('Policy source', { exact: true }).selectOption('DOCUMENT');
        await importPolicyDocument(maker, semanticDocument);
        const pending = maker.waitForResponse(
          (response) =>
            response.url().endsWith('/actions/create-version') &&
            response.request().method() === 'POST',
        );
        await maker.getByRole('button', { name: 'Create immutable version', exact: true }).click();
        const response = await pending;
        assert.equal(response.status(), 202, 'Public successor version creation');
        const operation = await response.json();
        await save(`${prefix}-version-operation.json`, operation);
        versionId = operation.resourceRef.slice(-36);
      }
      const version = await publicRead(
        `/api/v1/policy-versions/urn:openpc:policy-version:${versionId}`,
      );
      assert.equal(version.normalizedPolicyDigest, input.semanticDigest);
      assert.equal(version.policySetId, input.policySetId);
      await save(`${prefix}-result.json`, { policySetId: input.policySetId, versionId });
      await openPolicySimulation(maker);
      await selectPolicyVersion(maker, versionId, input.policySetId);
      if (family === 'source') await simulateSourcePolicy(maker, input.sourceRequest, versionId);
      else {
        await maker.getByLabel('Policy family', { exact: true }).selectOption('CONTRACT');
        await selectContractSimulationAuthority(maker, evidenceRoot);
        await maker
          .getByLabel('Contract method policy ID', { exact: true })
          .fill(method.contractMethodPolicyId.slice(-36));
        await maker.getByLabel('RPC method', { exact: true }).selectOption('eth_call');
        for (const [account, truth] of [
          ['1', 'SUCCESS'],
          ['2', 'DENIED'],
        ]) {
          await maker
            .getByLabel('Encoded call data', { exact: true })
            .fill(`0x70a08231${'0'.repeat(24)}${account.repeat(40)}`);
          const [response] = await Promise.all([
            maker.waitForResponse(
              (response) =>
                response.url().endsWith('/actions/simulate') &&
                response.request().method() === 'POST',
            ),
            maker.getByRole('button', { name: 'Run simulation', exact: true }).click(),
          ]);
          assert.equal(
            response.status(),
            201,
            'Contract simulation must return a completed result',
          );
          const result = await response.json();
          assert.equal(result.authorityLabel, 'SIMULATION_ONLY');
          assert.equal(result.evaluation.truthState, truth);
        }
      }
      assert.deepEqual(await publicRead(`/api/v1/policy-sets/${input.policySetId}`), parent);
      process.stdout.write(
        `OPENPC_RPC_POLICY|PASS|${family}|browser-authoring|typed-allow-deny|parent-unchanged|no-activation\n`,
      );
    },
  );
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [secretRoot, evidenceRoot, family = 'rpc'] = process.argv.slice(2);
  if (family === 'catalogue') await prepareContractSimulation(secretRoot, evidenceRoot);
  else await authorRpcPolicy({ secretRoot, evidenceRoot, family });
}
