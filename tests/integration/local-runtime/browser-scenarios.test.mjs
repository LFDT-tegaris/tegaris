import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import {
  browserScenarios,
  createScenarioSession,
  runScenarioBatch,
  selectScenarios,
  sourceIdentity,
  verifyOwnedContainers,
  ownsContainerId,
} from './browser-scenarios.mjs';
import { scenarioAccounts } from './oidc-emulator.mjs';

const registry = {
  a: { dependsOn: [] },
  dependent: { dependsOn: ['a'] },
  sibling: { dependsOn: [] },
};
test('a failure blocks its dependent, continues an independent sibling, and exits unsuccessfully', async () => {
  const calls = [];
  const result = await runScenarioBatch({
    names: ['a', 'dependent', 'sibling'],
    registry,
    verify: () => {},
    run: (name) => {
      calls.push(name);
      if (name === 'a') throw new Error('retained failure');
    },
  });
  assert.deepEqual(calls, ['a', 'sibling']);
  assert.deepEqual(
    result.results.map((r) => r.status),
    ['FAIL', 'BLOCKED', 'PASS'],
  );
  assert.equal(result.exitCode, 1);
  assert.equal(result.results[0].reason, 'scenario execution: retained failure');
});
test('environment drift blocks all remaining scenarios before dispatch', async () => {
  let checks = 0;
  const calls = [];
  const result = await runScenarioBatch({
    names: ['a', 'sibling'],
    registry,
    verify: () => {
      if (++checks === 2) throw new Error('image mismatch');
    },
    run: (name) => calls.push(name),
  });
  assert.deepEqual(calls, ['a']);
  assert.deepEqual(
    result.results.map((r) => r.status),
    ['PASS', 'BLOCKED'],
  );
  assert.equal(result.exitCode, 1);
  assert.equal(result.results[1].reason, 'environment verification: image mismatch');
});
test('added, removed and replaced project containers block before inspection or scenario dispatch', async () => {
  for (const currentIds of [['one', 'two', 'extra'], ['one'], ['one', 'replacement']]) {
    let inspected = false;
    let dispatched = false;
    const reports = [];
    const result = await runScenarioBatch({
      names: ['a', 'sibling'],
      registry,
      verify: () =>
        verifyOwnedContainers({
          expectedIds: ['one', 'two'],
          listIds: () => currentIds,
          inspect: () => {
            inspected = true;
            return [];
          },
          project: 'owned',
          images: new Map(),
        }),
      run: () => {
        dispatched = true;
      },
      report: (item) => reports.push(item),
    });
    assert.equal(inspected, false);
    assert.equal(dispatched, false);
    assert.equal(result.exitCode, 1);
    assert.equal(result.results.length, 2);
    assert.deepEqual(reports, result.results);
    for (const item of result.results) {
      assert.equal(item.status, 'BLOCKED');
      assert.equal(item.reason, 'environment verification: Owned container set changed');
    }
  }
});
test('container ordering is immaterial but image, health, ownership and resource bounds remain enforced', () => {
  const container = {
    Id: 'one',
    Image: 'image-one',
    Config: { Labels: { 'com.docker.compose.project': 'owned' } },
    State: { Running: true, Health: { Status: 'healthy' } },
    HostConfig: { Memory: 1024, NanoCpus: 1, CpuQuota: 0 },
  };
  const options = {
    expectedIds: ['two', 'one'],
    listIds: () => ['one', 'two'],
    inspect: (ids) => {
      assert.deepEqual(ids, ['one', 'two']);
      return [container, { ...container, Id: 'two', Image: 'image-two' }];
    },
    project: 'owned',
    images: new Map([
      ['one', 'image-one'],
      ['two', 'image-two'],
    ]),
  };
  assert.doesNotThrow(() => verifyOwnedContainers(options));
  assert.throws(
    () => verifyOwnedContainers({ ...options, inspect: () => [container] }),
    /Inspected container set changed/u,
  );
  for (const change of [
    { Image: 'other' },
    { Config: { Labels: {} } },
    { State: { Running: false } },
    { State: { Running: true, Health: { Status: 'unhealthy' } } },
    { HostConfig: { Memory: 0, NanoCpus: 1 } },
    { HostConfig: { Memory: 1024 } },
  ]) {
    assert.throws(() =>
      verifyOwnedContainers({
        ...options,
        inspect: () => [
          { ...container, ...change },
          { ...container, Id: 'two', Image: 'image-two' },
        ],
      }),
    );
  }
});
test('identity ownership accepts exact and unambiguous abbreviated IDs in either direction', () => {
  const id = 'a'.repeat(64);
  const short = id.slice(0, 12);
  assert.equal(ownsContainerId([id], id), true);
  assert.equal(ownsContainerId([id], short), true);
  assert.equal(ownsContainerId([short], id), true);
  assert.equal(ownsContainerId([id], 'b'.repeat(12)), false);
  assert.equal(ownsContainerId([id], ''), false);
  assert.equal(ownsContainerId([id, `${short}${'b'.repeat(52)}`], short), false);
});
test('failure reports retain only a bounded single-line causal message', async () => {
  const result = await runScenarioBatch({
    names: ['a'],
    registry,
    verify: () => {},
    run: () => {
      throw Object.assign(new Error('selector missing\nprivate output'), {
        env: { SECRET: 'private' },
      });
    },
  });
  assert.equal(result.results[0].reason, 'scenario execution: selector missing');
  assert.ok(!JSON.stringify(result).includes('private'));
});
test('a targeted batch runs only its selected scenario and cannot invent absent prerequisite success', async () => {
  const calls = [];
  assert.equal(
    (
      await runScenarioBatch({
        names: ['sibling'],
        registry,
        verify: () => {},
        run: (n) => calls.push(n),
      })
    ).exitCode,
    0,
  );
  const blocked = await runScenarioBatch({
    names: ['dependent'],
    registry,
    verify: () => {},
    run: (n) => calls.push(n),
  });
  assert.deepEqual(calls, ['sibling']);
  assert.equal(blocked.results[0].status, 'BLOCKED');
  assert.equal(blocked.exitCode, 1);
});
test('selection rejects unknown, duplicate and empty lists before setup', () => {
  for (const names of [[], ['groups', 'groups'], ['invented'], ['workloads']])
    assert.throws(() => selectScenarios(names));
  assert.deepEqual(selectScenarios(['credentials', 'groups']), ['credentials', 'groups']);
  assert.deepEqual(Object.keys(browserScenarios), ['recovery', 'credentials', 'groups']);
});
test('targeted retries allocate fresh namespaces and cannot erase the first failure', async () => {
  const attempts = [];
  const session = createScenarioSession({
    registry,
    verify: () => {},
    run: (name, attempt) => {
      attempts.push([name, attempt]);
      if (attempt === 1) throw new Error('first failure');
    },
  });
  assert.equal((await session.execute(['a'])).exitCode, 1);
  assert.equal((await session.execute(['a'])).exitCode, 0);
  assert.deepEqual(attempts, [
    ['a', 1],
    ['a', 2],
  ]);
  assert.equal(session.exitCode, 1);
});
test('source provenance permits browser-selector edits but refuses product and fixture drift', () => {
  const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
    encoding: 'utf8',
  }).trim();
  const parent = join(common, '..', '..', 'Agents', 'tmp');
  const root = mkdtempSync(join(parent, 'openpc-scenario-test.'));
  try {
    execFileSync('git', ['init', '-q', root]);
    mkdirSync(join(root, 'apps'), { recursive: true });
    mkdirSync(join(root, 'tests/integration/local-runtime'), { recursive: true });
    writeFileSync(join(root, 'apps/input.ts'), 'accepted');
    execFileSync('git', ['-C', root, 'add', '.']);
    execFileSync('git', [
      '-C',
      root,
      '-c',
      'user.name=Fixture',
      '-c',
      'user.email=fixture@example.invalid',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '-qm',
      'fixture',
    ]);
    const before = sourceIdentity(root);
    writeFileSync(
      join(root, 'tests/integration/local-runtime/group-browser.ts'),
      'corrected selector',
    );
    assert.equal(sourceIdentity(root), before);
    writeFileSync(join(root, 'apps/input.ts'), 'changed');
    assert.notEqual(sourceIdentity(root), before);
    writeFileSync(join(root, 'apps/input.ts'), 'accepted');
    writeFileSync(
      join(root, 'tests/integration/local-runtime/recovery-browser-fixture.ts'),
      'changed trust',
    );
    assert.notEqual(sourceIdentity(root), before);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
test('scenario account changes are explicit and previously read accounts remain bound', () => {
  const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
    encoding: 'utf8',
  }).trim();
  const root = mkdtempSync(join(common, '..', '..', 'Agents', 'tmp', 'openpc-accounts-test.'));
  try {
    const path = join(root, 'accounts');
    writeFileSync(path, JSON.stringify({ maker: '018f0000-0000-7000-8000-000000001131' }));
    const first = scenarioAccounts(path);
    writeFileSync(path, JSON.stringify({ maker: '018f0000-0000-7000-8000-000000002131' }));
    assert.notDeepEqual(first, scenarioAccounts(path));
    assert.equal(first.maker, '018f0000-0000-7000-8000-000000001131');
    writeFileSync(path, '{"maker":42}');
    assert.throws(() => scenarioAccounts(path));
    assert.throws(() => scenarioAccounts(join(root, 'missing')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
