import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, mkdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

// These journeys already allocate their business resources independently. Other
// journeys retain their existing clean runners until their isolation is proven.
export const browserScenarios = Object.freeze({
  recovery: { file: 'recovery-browser.ts', dependsOn: [] },
  credentials: { file: 'credential-browser.ts', dependsOn: [] },
  groups: { file: 'group-browser.ts', dependsOn: [] },
});

export function selectScenarios(names, registry = browserScenarios) {
  assert.ok(Array.isArray(names) && names.length > 0, 'Select at least one scenario');
  assert.equal(new Set(names).size, names.length, 'Duplicate scenario');
  for (const name of names) assert.ok(Object.hasOwn(registry, name), `Unknown scenario: ${name}`);
  return names;
}

function failureReason(stage, error) {
  // Preserve the causal message, never the error object, stack, environment or
  // multiline subprocess output. Assertions below use fixed messages.
  const message = error instanceof Error ? error.message : 'Non-Error failure';
  const firstLine = Array.from(message.split(/[\r\n]/u)[0])
    .map((character) =>
      character.codePointAt(0) < 32 || character.codePointAt(0) === 127 ? ' ' : character,
    )
    .join('');
  return `${stage}: ${firstLine.slice(0, 240)}`;
}

export function verifyOwnedContainers({ expectedIds, listIds, inspect, project, images }) {
  const currentIds = [...listIds()].sort();
  assert.ok(
    JSON.stringify(currentIds) === JSON.stringify([...expectedIds].sort()),
    'Owned container set changed',
  );
  const containers = inspect(currentIds);
  assert.ok(
    JSON.stringify(containers.map((container) => container.Id).sort()) ===
      JSON.stringify(currentIds),
    'Inspected container set changed',
  );
  for (const container of containers) {
    assert.ok(
      container.Config.Labels['com.docker.compose.project'] === project,
      'Container ownership changed',
    );
    assert.ok(container.Image === images.get(container.Id), 'Container image changed');
    assert.ok(container.State.Running === true, 'Container stopped');
    if (container.State.Health)
      assert.ok(container.State.Health.Status === 'healthy', 'Container is unhealthy');
    assert.ok(container.HostConfig.Memory > 0, 'Unbounded container');
    assert.ok(
      container.HostConfig.NanoCpus > 0 || container.HostConfig.CpuQuota > 0,
      'Unbounded container CPU',
    );
  }
}

export function ownsContainerId(ids, containerId) {
  return (
    Boolean(containerId) &&
    ids.filter(
      (id) => id === containerId || id.startsWith(containerId) || containerId.startsWith(id),
    ).length === 1
  );
}

export async function runScenarioBatch({
  names,
  registry = browserScenarios,
  verify,
  run,
  report = () => {},
}) {
  selectScenarios(names, registry);
  const results = [];
  for (const name of names) {
    const dependencies = registry[name].dependsOn;
    let result;
    if (dependencies.some((id) => !results.some((r) => r.name === id && r.status === 'PASS'))) {
      result = { name, status: 'BLOCKED', reason: 'prerequisite did not pass' };
    } else {
      try {
        await verify();
      } catch (error) {
        for (const blocked of names.slice(results.length)) {
          const item = {
            name: blocked,
            status: 'BLOCKED',
            reason: failureReason('environment verification', error),
          };
          results.push(item);
          report(item);
        }
        return { results, exitCode: 1 };
      }
      try {
        await run(name);
        result = { name, status: 'PASS' };
      } catch (error) {
        result = { name, status: 'FAIL', reason: failureReason('scenario execution', error) };
      }
    }
    results.push(result);
    report(result);
  }
  return { results, exitCode: results.every((r) => r.status === 'PASS') ? 0 : 1 };
}

export function createScenarioSession(options) {
  let attempt = 0;
  let failed = false;
  return {
    async execute(names) {
      const result = await runScenarioBatch({
        ...options,
        names,
        run: (name) => {
          assert.ok(++attempt <= 999, 'Scenario namespace exhausted');
          return options.run(name, attempt);
        },
      });
      failed ||= result.exitCode !== 0;
      return result;
    },
    get exitCode() {
      return failed ? 1 : 0;
    },
  };
}

// HEAD authenticates unchanged tracked inputs. Hash only dirty/untracked inputs
// that feed images, migrations or the running fixture; browser edits may rerun.
export function sourceIdentity(root) {
  const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
  const relevant = (path) =>
    /^(apps\/|packages\/|services\/|generated\/|schemas\/|migrations\/|deploy\/|scripts\/maintenance\/|package\.json$|pnpm-|\.npmrc$|\.dockerignore$|tsconfig)/u.test(
      path,
    ) ||
    /^tests\/integration\/local-runtime\/.*(?:fixture|emulator|bootstrap|run-compose-e2e|browser-scenarios)/u.test(
      path,
    );
  const changed = new Set(
    (
      git('diff', 'HEAD', '--name-only', '-z') +
      git('ls-files', '--others', '--exclude-standard', '-z')
    )
      .split('\0')
      .filter((p) => p && relevant(p)),
  );
  const hash = createHash('sha256').update(git('rev-parse', 'HEAD'));
  for (const path of [...changed].sort()) {
    hash.update(path).update('\0');
    try {
      hash.update(readFileSync(join(root, path)));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      hash.update('DELETED');
    }
  }
  return hash.digest('hex');
}

function treeIdentity(root) {
  const hash = createHash('sha256');
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      assert.ok(!entry.isSymbolicLink(), 'Unexpected fixture symlink');
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else hash.update(relative(root, path)).update(readFileSync(path));
    }
  }
  visit(root);
  return hash.digest('hex');
}

function command(program, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, { stdio: 'inherit', ...options });
    // Kill the entire owned scenario process group if a test never terminates.
    const timer = setTimeout(() => {
      try {
        process.kill(-child.pid, 'SIGTERM');
      } catch {
        /* The owned process group has already exited. */
      }
    }, 10 * 60_000);
    const hardTimer = setTimeout(
      () => {
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch {
          /* The owned process group has already exited. */
        }
      },
      10 * 60_000 + 5000,
    );
    child.once('error', (error) => {
      clearTimeout(timer);
      clearTimeout(hardTimer);
      reject(error);
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      clearTimeout(hardTimer);
      if (code === 0) resolve();
      else reject(new Error(`Scenario command exited ${code}`));
    });
  });
}

async function main() {
  const root = process.cwd();
  const names = selectScenarios(
    (process.env.OPENPC_BROWSER_SCENARIOS ?? 'recovery,credentials,groups').split(','),
  );
  for (const [key, value] of Object.entries(process.env)) {
    if (
      /^OPENPC_LOCAL_RUNTIME_.*_ONLY$/u.test(key) &&
      value === '1' &&
      key !== 'OPENPC_LOCAL_RUNTIME_RECOVERY_BROWSER_ONLY' &&
      key !== 'OPENPC_LOCAL_RUNTIME_BUILD_ONLY'
    ) {
      throw new Error(`Conflicting scenario selection: ${key}`);
    }
  }
  if (process.argv[2] === 'source') {
    process.stdout.write(`${sourceIdentity(root)}\n`);
    return;
  }
  const [secretRoot, evidenceRoot, identityContainer, project, dataRoot] = process.argv.slice(2);
  assert.ok(
    secretRoot && evidenceRoot && identityContainer && project && dataRoot,
    'Missing scenario runner arguments',
  );
  const expectedSource = process.env.OPENPC_BROWSER_SOURCE_IDENTITY;
  assert.match(expectedSource ?? '', /^[a-f0-9]{64}$/u, 'Missing pre-build source identity');
  assert.equal(
    sourceIdentity(root),
    expectedSource,
    'Source changed during environment construction',
  );
  const secrets = treeIdentity(secretRoot);
  const composeFiles = [
    join(root, 'deploy/compose/local/compose.yaml'),
    join(dataRoot, 'recovery-browser/compose.yaml'),
  ];
  const config = composeFiles.map((path) => readFileSync(path, 'utf8'));
  const listIds = () =>
    execFileSync(
      'docker',
      ['ps', '-q', '--no-trunc', '--filter', `label=com.docker.compose.project=${project}`],
      { encoding: 'utf8' },
    )
      .trim()
      .split(/\s+/u)
      .filter(Boolean);
  const ids = listIds();
  assert.ok(ownsContainerId(ids, identityContainer), 'Identity container is not owned');
  const inspect = (containerIds) =>
    JSON.parse(execFileSync('docker', ['inspect', ...containerIds], { encoding: 'utf8' }));
  const initial = inspect(ids);
  const images = new Map(initial.map((container) => [container.Id, container.Image]));
  const verify = () => {
    assert.ok(sourceIdentity(root) === expectedSource, 'Source provenance changed');
    assert.ok(treeIdentity(secretRoot) === secrets, 'Runtime credentials changed');
    assert.ok(
      composeFiles.every((path, index) => readFileSync(path, 'utf8') === config[index]),
      'Configuration changed',
    );
    verifyOwnedContainers({ expectedIds: ids, listIds, inspect, project, images });
  };
  let invalidRequest = false;
  const session = createScenarioSession({
    verify,
    report: (result) => process.stdout.write(`OPENPC_BROWSER_SCENARIO|${JSON.stringify(result)}\n`),
    run: async (name, attempt) => {
      const output = join(evidenceRoot, `${name}-${attempt}`);
      mkdirSync(output, { recursive: true, mode: 0o700 });
      const env = {
        ...process.env,
        OPENPC_RECOVERY_BROWSER_SCENARIO: String(attempt),
        OPENPC_BROWSER_ARTIFACT_ROOT: output,
      };
      const options = { env, detached: true };
      await command(
        process.execPath,
        [
          '--import',
          'tsx',
          'tests/integration/local-runtime/recovery-browser-fixture.ts',
          'seed',
          secretRoot,
          dataRoot,
        ],
        options,
      );
      await command(
        process.execPath,
        [
          '--import',
          'tsx',
          `tests/integration/local-runtime/${browserScenarios[name].file}`,
          secretRoot,
          output,
          identityContainer,
          project,
        ],
        options,
      );
    },
  });
  await session.execute(names);
  if (process.env.OPENPC_BROWSER_SESSION === '1') {
    process.stdout.write(
      'OPENPC_BROWSER_SESSION|READY|diagnostic-only|send JSON {"scenarios":["groups"]} or {"close":true}|expires=15m\n',
    );
    const input = createInterface({ input: process.stdin });
    const deadline = setTimeout(() => input.close(), 15 * 60_000);
    try {
      for await (const line of input) {
        try {
          const request = JSON.parse(line);
          if (request.close === true) break;
          await session.execute(selectScenarios(request.scenarios));
        } catch {
          invalidRequest = true;
          process.stderr.write(
            'OPENPC_BROWSER_SESSION|REJECTED|invalid request or unavailable environment\n',
          );
        }
      }
    } finally {
      clearTimeout(deadline);
      input.close();
    }
    process.stdout.write('OPENPC_BROWSER_SESSION|CLOSED|clean-final-acceptance=required\n');
  }
  process.exitCode = invalidRequest ? 1 : session.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
