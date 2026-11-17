import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

const execute = promisify(execFile);

export function faultProxyRule(network, project, host, port) {
  assert.match(project, /^openpc-local-e2e-[0-9a-f]{12}$/u);
  assert.equal(network.Name, `${project}_openpc-local`);
  assert.equal(network.Driver, 'bridge');
  assert.equal(network.Labels['com.docker.compose.project'], project);
  assert.match(network.Id, /^[0-9a-f]{64}$/u);
  assert.equal(network.Options?.['com.docker.network.bridge.name'], undefined);
  assert.equal(network.IPAM.Config.length, 1);
  const { Gateway, Subnet } = network.IPAM.Config[0];
  assert.equal(Gateway, host);
  assert.match(host, /^172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.1$/u);
  assert.equal(Subnet, host.replace(/\.1$/u, '.0/24'));
  assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535);
  return [
    'allow',
    'in',
    'on',
    `br-${network.Id.slice(0, 12)}`,
    'proto',
    'tcp',
    'from',
    Subnet,
    'to',
    host,
    'port',
    String(port),
  ];
}

// Explicit private-host opt-in. A timer removes the exact rule even if this
// process is killed; normal close removes it immediately. No public interface,
// forwarding rule, default policy, or unrelated project is changed.
export async function allowFaultProxy(host, port) {
  if (process.env.OPENPC_LOCAL_FAULT_PROXY_UFW !== '1' || host === '127.0.0.1' || host === '::1')
    return async () => {};
  const root = process.env.OPENPC_LOCAL_RUNTIME_NETWORK_ROOT;
  assert.ok(root && (await realpath(root)) === root);
  assert.equal((await stat(root)).mode & 0o777, 0o700);
  const owner = (await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8'))
    .trim()
    .split(':');
  assert.equal(owner[0], 'openpc-local-runtime');
  const project = owner[1];
  const { stdout } = await execute('docker', ['network', 'inspect', `${project}_openpc-local`]);
  const [network] = JSON.parse(stdout);
  assert.equal(network.Labels['io.openpc.network.root'], root);
  assert.equal(network.Labels['io.openpc.network.owner'], owner[2]);
  assert.equal(network.Labels['io.openpc.network.schema'], 'openpc-local-network-v1');
  const rule = faultProxyRule(network, project, host, port);
  const unit = `openpc-fault-${randomUUID()}`;
  rule.push('comment', unit);
  const remove = ['--force', 'delete', ...rule];
  const sudo = async (...args) => execute('sudo', ['-n', ...args], { timeout: 15000 });
  await sudo(
    '/usr/bin/systemd-run',
    '--quiet',
    `--unit=${unit}`,
    '--on-active=5min',
    '/usr/sbin/ufw',
    ...remove,
  );
  // The timer remains armed if adding the rule has an ambiguous outcome.
  await sudo('/usr/sbin/ufw', ...rule);
  process.stdout.write(
    `OPENPC_FAULT_PROXY_FIREWALL|opened|bridge=${rule[3]}|port=${port}|expires=5min\n`,
  );
  let closed = false;
  return async () => {
    if (closed) return;
    await sudo('/usr/sbin/ufw', ...remove);
    await sudo('/usr/bin/systemctl', 'stop', `${unit}.timer`);
    closed = true;
    process.stdout.write(`OPENPC_FAULT_PROXY_FIREWALL|closed|port=${port}\n`);
  };
}
