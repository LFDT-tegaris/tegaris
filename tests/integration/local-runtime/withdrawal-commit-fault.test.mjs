import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import {
  WithdrawalCommitCorrelation,
  startWithdrawalCommitFault,
} from './withdrawal-commit-fault.mjs';
import { createHash } from 'node:crypto';
import { faultProxyRule } from './fault-proxy-firewall.mjs';
import {
  SourceImportCommitCorrelation,
  sourceImportQuery,
} from './runtime-source-import-fault.mjs';

const target = '018f0000-0000-7000-8000-000000000101';
const work = '018f0000-0000-7000-8000-000000000102';

test('fault proxy firewall rules are limited to the owned private bridge and exact listener', () => {
  const project = 'openpc-local-e2e-123456abcdef';
  const network = {
    Name: `${project}_openpc-local`,
    Driver: 'bridge',
    Id: 'a'.repeat(64),
    Labels: { 'com.docker.compose.project': project },
    Options: {},
    IPAM: { Config: [{ Subnet: '172.16.4.0/24', Gateway: '172.16.4.1' }] },
  };
  assert.deepEqual(faultProxyRule(network, project, '172.16.4.1', 41715), [
    'allow',
    'in',
    'on',
    'br-aaaaaaaaaaaa',
    'proto',
    'tcp',
    'from',
    '172.16.4.0/24',
    'to',
    '172.16.4.1',
    'port',
    '41715',
  ]);
  for (const change of [
    { Name: 'unrelated' },
    { Driver: 'host' },
    { Labels: { 'com.docker.compose.project': 'other' } },
    { Options: { 'com.docker.network.bridge.name': 'eno1' } },
    { IPAM: { Config: [{ Subnet: '0.0.0.0/0', Gateway: '172.16.4.1' }] } },
  ])
    assert.throws(() => faultProxyRule({ ...network, ...change }, project, '172.16.4.1', 41715));
  for (const host of ['0.0.0.0', '203.0.113.10', '127.0.0.1', '172.16.5.1'])
    assert.throws(() => faultProxyRule(network, project, host, 41715));
  for (const port of [0, 22, 65536, '41715'])
    assert.throws(() => faultProxyRule(network, project, '172.16.4.1', port));
});
const other = '018f0000-0000-7000-8000-000000000103';
const text = (value) => Buffer.from(`${value}\0`);
const u16 = (value) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(value);
  return b;
};
const u32 = (value) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value);
  return b;
};
const source = await readFile('services/fleet-controller/src/target_disposition.rs', 'utf8');
const query = source.match(
  /let admission = if platform \{\s*"select binding,admission_digest from openpc\.begin_platform_scope_target_withdrawal[^"\n]+"\s*\} else \{\s*"(select binding,admission_digest from openpc\.begin_runtime_target_withdrawal[^"\n]+)"\s*\};\s*let row = sqlx::query\(admission\)/u,
)?.[1];
assert.ok(query, 'Actual worker query must be recognized before runtime allocation');

test('source import fault matches actual packaged SQL and preserves original COMMIT correlation', async () => {
  const native = await readFile(
    'services/fleet-controller/src/runtime_configuration_input.rs',
    'utf8',
  );
  assert.ok(
    native.includes(`sqlx::query(r#"${sourceImportQuery}"#)`),
    'Actual INSERT must match before images',
  );
  const bytes = Buffer.from('domain-valid bytes are validated by the real runtime'),
    digest = createHash('sha256').update(bytes).digest('hex');
  const scope = { participant: target, privacy: work, configurationDigest: digest };
  const bind = (c, overrides = {}) => {
    c.frontend(
      'P',
      Buffer.concat([text('source'), text(overrides.query ?? sourceImportQuery), u16(0)]),
    );
    const values = [
      Buffer.from(overrides.participant ?? target),
      Buffer.from(work),
      Buffer.from(other),
      Buffer.from(other),
      overrides.bytes ?? bytes,
      Buffer.from('[]'),
      Buffer.from(other),
    ];
    c.frontend(
      'B',
      Buffer.concat([
        text(''),
        text('source'),
        u16(1),
        u16(1),
        u16(7),
        ...values.flatMap((value) => [u32(value.length), value]),
        u16(0),
      ]),
    );
    c.frontend('E', Buffer.concat([text(''), u32(0)]));
  };
  for (const scenario of [
    'match',
    'other-tenant',
    'other-input',
    'other-statement',
    'rollback',
    'error',
    'idle',
  ]) {
    const c = new SourceImportCommitCorrelation(scope);
    assert.equal(simple(c, 'COMMIT'), null);
    simple(c, 'BEGIN');
    bind(
      c,
      scenario === 'other-tenant'
        ? { participant: other }
        : scenario === 'other-input'
          ? { bytes: Buffer.from('different') }
          : scenario === 'other-statement'
            ? { query: 'select 1' }
            : {},
    );
    assert.equal(c.backend('C', text('INSERT 0 1')), null);
    c.backend('Z', Buffer.from('T'));
    if (scenario === 'rollback') simple(c, 'ROLLBACK');
    if (scenario === 'error') c.backend('E', Buffer.from(''));
    if (scenario === 'idle') c.backend('Z', Buffer.from('I'));
    const result = simple(c, 'COMMIT');
    assert.deepEqual(
      result,
      scenario === 'match'
        ? {
            input_id: other,
            module_installation_id: other,
            module_configuration_generation_id: other,
            configuration_digest: digest,
          }
        : null,
    );
    assert.equal(simple(c, 'COMMIT'), null);
  }
  const invalid = new SourceImportCommitCorrelation(scope);
  invalid.frontend('P', Buffer.concat([text('source'), text(sourceImportQuery), u16(0)]));
  assert.throws(() =>
    invalid.frontend('B', Buffer.concat([text(''), text('source'), u16(0), u16(6)])),
  );
});
function simple(c, value, result = value) {
  c.frontend('Q', text(value));
  return c.backend('C', text(result));
}
function prepare(
  c,
  {
    sql = query,
    targetId = target,
    workId = work,
    name = 's1',
    portal = '',
    certificate = `sha256:${'1'.repeat(64)}`,
  } = {},
) {
  c.frontend('P', Buffer.concat([text(name), text(sql), u16(0)]));
  const values = [targetId, workId, 'worker', certificate, '3'].map((v) =>
    v === null ? null : Buffer.from(v),
  );
  c.frontend(
    'B',
    Buffer.concat([
      text(portal),
      text(name),
      u16(1),
      u16(1),
      u16(5),
      ...values.flatMap((v) => (v === null ? [u32(0xffffffff)] : [u32(v.length), v])),
      u16(0),
    ]),
  );
  c.frontend('E', Buffer.concat([text(portal), u32(0)]));
}

test('withdrawal recovery fault accepts only its exact original work', () => {
  const c = new WithdrawalCommitCorrelation(target, work);
  assert.equal(simple(c, 'BEGIN'), null);
  assert.throws(() => prepare(c, { workId: other }), /Original withdrawal work required/u);
  const exact = new WithdrawalCommitCorrelation(target, work);
  simple(exact, 'BEGIN');
  prepare(exact);
  assert.equal(exact.backend('C', text('SELECT 1')), null);
  assert.equal(simple(exact, 'COMMIT'), work);
});

test('withdrawal commit correlation isolates actual bound owner and successful transaction', () => {
  const c = new WithdrawalCommitCorrelation(target);
  assert.equal(simple(c, 'BEGIN'), null);
  assert.equal(simple(c, 'select 1', 'SELECT 1'), null);
  assert.equal(simple(c, 'COMMIT'), null, 'Prior read-only commit must pass');
  c.backend('Z', Buffer.from('I'));
  simple(c, 'BEGIN');
  prepare(c);
  assert.equal(c.backend('C', text('SELECT 1')), null);
  c.backend('Z', Buffer.from('T'));
  assert.equal(simple(c, 'COMMIT'), work);
  assert.equal(simple(c, 'COMMIT'), null, 'No stale transaction correlation');
});

test('withdrawal fault rejects wrong query, foreign target, parse-only, rollback and error', () => {
  for (const mode of [
    'wrong-query',
    'foreign-target',
    'parse-only',
    'rollback',
    'error',
    'idle',
    'zero-row',
  ]) {
    const c = new WithdrawalCommitCorrelation(target);
    simple(c, 'BEGIN');
    if (mode === 'parse-only') c.frontend('P', Buffer.concat([text('s1'), text(query), u16(0)]));
    else {
      prepare(c, {
        sql: mode === 'wrong-query' ? `select '${query}'` : query,
        targetId: mode === 'foreign-target' ? other : target,
      });
      c.backend('C', text(mode === 'zero-row' ? 'SELECT 0' : 'SELECT 1'));
    }
    if (mode === 'rollback') simple(c, 'ROLLBACK');
    if (mode === 'error') c.backend('E', Buffer.from('error'));
    if (mode === 'idle') c.backend('Z', Buffer.from('I'));
    assert.equal(simple(c, 'COMMIT'), null, mode);
  }
});

test('withdrawal wire correlation forwards SQL NULL selectors for real owner denial', () => {
  for (const options of [{ certificate: null }, { targetId: null }]) {
    const c = new WithdrawalCommitCorrelation(target);
    simple(c, 'BEGIN');
    prepare(c, options);
    c.backend('E', Buffer.from('actual database denial'));
    assert.equal(simple(c, 'ROLLBACK'), null);
    assert.equal(simple(c, 'COMMIT'), null);
  }
});

test('withdrawal correlation separates connections and follows cached prepared statements', () => {
  const c = new WithdrawalCommitCorrelation(target),
    unrelated = new WithdrawalCommitCorrelation(target);
  simple(c, 'BEGIN');
  prepare(c);
  c.backend('C', text('SELECT 1'));
  assert.equal(simple(unrelated, 'COMMIT'), null);
  assert.equal(simple(c, 'COMMIT'), work);
  c.backend('Z', Buffer.from('I'));
  simple(c, 'BEGIN');
  // A cached Bind/Execute may omit Parse; retain its statement identity.
  c.frontend('E', Buffer.concat([text(''), u32(0)]));
  c.backend('C', text('SELECT 1'));
  assert.equal(simple(c, 'COMMIT'), work);
  assert.throws(() => c.frontend('E', Buffer.concat([text(''), u32(1)])));
  assert.throws(() => c.frontend('P', Buffer.from('unterminated')));
});

// This is a fixture wire test, not simulated business acceptance. PostgreSQL
// authentication, admission and commit are independently exercised at runtime.
test('withdrawal wire fault handles fragments and drops COMMIT plus coalesced ReadyForQuery once', async (t) => {
  const noDelay = [];
  const setNoDelay = net.Socket.prototype.setNoDelay;
  t.mock.method(net.Socket.prototype, 'setNoDelay', function (enabled) {
    noDelay.push({ socket: this, enabled });
    return Reflect.apply(setNoDelay, this, [enabled]);
  });
  const frame = (tag, body) => Buffer.concat([Buffer.from(tag), u32(body.length + 4), body]);
  const backends = [];
  const backend = net.createServer((socket) => {
    backends.push(socket);
    socket.on('error', () => {});
  });
  backend.listen(0, '127.0.0.1');
  await once(backend, 'listening');
  let observe, releaseObservation;
  const observed = new Promise((resolve) => {
    observe = resolve;
  });
  const observationGate = new Promise((resolve) => {
    releaseObservation = resolve;
  });
  const proxy = await startWithdrawalCommitFault({
    host: '127.0.0.1',
    upstreamPort: backend.address().port,
    targetId: target,
    observeCommitted: async (fault) => {
      assert.deepEqual(fault, { targetId: target, workId: work, count: 1 });
      observe();
      await observationGate;
    },
  });
  const clients = [];
  const open = async () => {
    const client = net.createConnection(proxy.port, '127.0.0.1');
    clients.push(client);
    client.on('error', () => {});
    const received = [];
    client.on('data', (data) => received.push(data));
    await once(client, 'connect');
    const index = clients.length - 1;
    for (let i = 0; !backends[index] && i < 100; i++) await delay(2);
    assert.ok(backends[index]);
    const upstream = backends[index];
    assert.ok(
      noDelay.some(
        ({ socket, enabled }) =>
          enabled === true &&
          socket.localPort === proxy.port &&
          socket.remotePort === client.localPort,
      ),
      'Proxy downstream must disable Nagle buffering',
    );
    assert.ok(
      noDelay.some(
        ({ socket, enabled }) =>
          enabled === true &&
          socket.localPort === upstream.remotePort &&
          socket.remotePort === backend.address().port,
      ),
      'Proxy upstream must disable Nagle buffering',
    );
    const incoming = [];
    upstream.on('data', (data) => incoming.push(data));
    client.write(Buffer.concat([u32(8), u32(80877103)]));
    for (let i = 0; Buffer.concat(incoming).length < 8 && i < 100; i++) await delay(2);
    assert.deepEqual(Buffer.concat(incoming), Buffer.concat([u32(8), u32(80877103)]));
    upstream.write('N');
    for (let i = 0; Buffer.concat(received).length < 1 && i < 100; i++) await delay(2);
    assert.equal(Buffer.concat(received).toString(), 'N');
    client.write(Buffer.concat([u32(8), u32(196608)]));
    return { client, upstream, received, incoming };
  };
  try {
    const first = await open();
    proxy.arm();
    const begin = frame('Q', text('BEGIN'));
    first.client.write(begin);
    for (let i = 0; Buffer.concat(first.incoming).length < 16 + begin.length && i < 100; i++)
      await delay(2);
    first.upstream.write(Buffer.concat([frame('C', text('BEGIN')), frame('Z', Buffer.from('T'))]));
    await delay(10);
    const emit = [];
    prepare({ frontend: (tag, body) => emit.push(frame(tag, body)) });
    const payload = Buffer.concat(emit);
    // Deliberately split both header and body across socket writes.
    for (let offset = 0; offset < payload.length; offset += 3)
      first.client.write(payload.subarray(offset, offset + 3));
    for (
      let i = 0;
      Buffer.concat(first.incoming).length < payload.length + begin.length + 16 && i < 100;
      i++
    )
      await delay(2);
    assert.deepEqual(Buffer.concat(first.incoming).subarray(16 + begin.length), payload);
    const success = Buffer.concat([frame('C', text('SELECT 1')), frame('Z', Buffer.from('T'))]);
    first.upstream.write(success);
    await delay(10);
    first.client.write(frame('Q', text('COMMIT')));
    for (let i = 0; !Buffer.concat(first.incoming).includes(text('COMMIT')) && i < 100; i++)
      await delay(2);
    const before = Buffer.concat(first.received);
    const closed = once(first.client, 'close');
    first.upstream.write(Buffer.concat([frame('C', text('COMMIT')), frame('Z', Buffer.from('I'))]));
    await observed;
    assert.equal(
      first.client.destroyed,
      false,
      'Native COMMIT remains pending during independent observation',
    );
    assert.deepEqual(
      Buffer.concat(first.received),
      before,
      'Success is withheld before observation',
    );
    releaseObservation();
    await closed;
    assert.deepEqual(
      Buffer.concat(first.received),
      before,
      'No COMMIT or ReadyForQuery success forwarded',
    );
    assert.deepEqual(proxy.status(), { targetId: target, workId: work, count: 1 });
    const second = await open();
    second.client.write(frame('Q', text('COMMIT')));
    for (let i = 0; !Buffer.concat(second.incoming).includes(text('COMMIT')) && i < 100; i++)
      await delay(2);
    const ordinary = Buffer.concat([frame('C', text('COMMIT')), frame('Z', Buffer.from('I'))]);
    second.upstream.write(ordinary);
    for (let i = 0; Buffer.concat(second.received).length < 1 + ordinary.length && i < 100; i++)
      await delay(2);
    assert.deepEqual(Buffer.concat(second.received).subarray(1), ordinary);
    assert.equal(proxy.status().count, 1);
  } finally {
    releaseObservation();
    for (const socket of [...clients, ...backends]) socket.destroy();
    await proxy.close();
    await new Promise((resolve) => backend.close(resolve));
  }
});

test('withdrawal wire fixture rejects encrypted negotiation and oversized startup without downgrade', async () => {
  for (const mode of ['encrypted', 'oversized']) {
    const sockets = [];
    const backend = net.createServer((socket) => {
      sockets.push(socket);
      socket.on('error', () => {});
      socket.once('data', () => {
        if (mode === 'encrypted') socket.write('S');
      });
    });
    backend.listen(0, '127.0.0.1');
    await once(backend, 'listening');
    const proxy = await startWithdrawalCommitFault({
      host: '127.0.0.1',
      upstreamPort: backend.address().port,
      targetId: target,
    });
    const client = net.createConnection(proxy.port, '127.0.0.1');
    client.on('error', () => {});
    const received = [];
    client.on('data', (data) => received.push(data));
    try {
      await once(client, 'connect');
      const closed = once(client, 'close');
      client.write(mode === 'encrypted' ? Buffer.concat([u32(8), u32(80877103)]) : u32(65537));
      await closed;
      assert.equal(Buffer.concat(received).toString(), mode === 'encrypted' ? 'S' : '');
      assert.throws(() => proxy.status(), /PostgreSQL fault fixture protocol failure/u);
    } finally {
      client.destroy();
      await proxy.close();
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => backend.close(resolve));
    }
  }
  await assert.rejects(startWithdrawalCommitFault({ host: '0.0.0.0', targetId: target }));
});

test('withdrawal proxy admits the four-connection worker pool plus its independent healthcheck', async () => {
  const clients = [],
    backends = [];
  const backend = net.createServer((socket) => {
    backends.push(socket);
    socket.on('error', () => {});
    socket.once('data', () =>
      socket.write(Buffer.concat([Buffer.from('Z'), u32(5), Buffer.from('I')])),
    );
  });
  backend.listen(0, '127.0.0.1');
  await once(backend, 'listening');
  const proxy = await startWithdrawalCommitFault({
    host: '127.0.0.1',
    upstreamPort: backend.address().port,
    targetId: target,
  });
  try {
    for (let index = 0; index < 5; index++) {
      const client = net.createConnection(proxy.port, '127.0.0.1');
      clients.push(client);
      client.on('error', () => {});
      await once(client, 'connect');
      const data = [];
      client.on('data', (bytes) => data.push(bytes));
      client.write(Buffer.concat([u32(8), u32(196608)]));
      for (let attempt = 0; !data.length && !client.destroyed && attempt < 100; attempt++)
        await delay(2);
      assert.equal(
        client.destroyed,
        false,
        `Required connection ${index + 1} must remain admitted`,
      );
      assert.deepEqual(
        Buffer.concat(data),
        Buffer.concat([Buffer.from('Z'), u32(5), Buffer.from('I')]),
      );
    }
    assert.equal(backends.length, 5);
    assert.equal(proxy.status(), null);
    const excess = net.createConnection(proxy.port, '127.0.0.1');
    clients.push(excess);
    excess.on('error', () => {});
    await once(excess, 'close');
    assert.equal(backends.length, 5, 'Excess connection must never reach PostgreSQL');
    assert.throws(() => proxy.status(), /PostgreSQL fault fixture connection bound/u);
  } finally {
    for (const socket of [...clients, ...backends]) socket.destroy();
    await proxy.close();
    await new Promise((resolve) => backend.close(resolve));
  }
});

test('committed withdrawal remains known when observation rejects, times out or another socket fails', async () => {
  const frame = (tag, body) => Buffer.concat([Buffer.from(tag), u32(body.length + 4), body]);
  for (const mode of ['reject', 'timeout', 'other-socket']) {
    const sockets = [];
    const backend = net.createServer((socket) => {
      sockets.push(socket);
      socket.on('error', () => {});
    });
    backend.listen(0, '127.0.0.1');
    await once(backend, 'listening');
    let observed, release;
    const entered = new Promise((resolve) => {
      observed = resolve;
    });
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    let signal;
    const proxy = await startWithdrawalCommitFault({
      host: '127.0.0.1',
      upstreamPort: backend.address().port,
      targetId: target,
      workId: work,
      observationTimeoutMs: mode === 'timeout' ? 30 : 1000,
      observeCommitted: async (_fact, cancellation) => {
        signal = cancellation;
        observed();
        if (mode === 'reject') throw new Error('Private observer detail must not escape');
        await gate;
      },
    });
    const clients = [];
    try {
      const client = net.createConnection(proxy.port, '127.0.0.1');
      clients.push(client);
      client.on('error', () => {});
      const received = [];
      client.on('data', (data) => received.push(data));
      await once(client, 'connect');
      for (let i = 0; !sockets[0] && i < 100; i++) await delay(2);
      const incoming = [];
      sockets[0].on('data', (data) => incoming.push(data));
      proxy.arm();
      const queries = [u32(8), u32(196608), frame('Q', text('BEGIN'))];
      prepare({ frontend: (tag, body) => queries.push(frame(tag, body)) });
      queries.push(frame('Q', text('COMMIT')));
      client.write(Buffer.concat(queries));
      for (
        let i = 0;
        Buffer.concat(incoming).length < Buffer.concat(queries).length && i < 100;
        i++
      )
        await delay(2);
      assert.equal(Buffer.concat(incoming).length, Buffer.concat(queries).length);
      const closed = once(client, 'close');
      sockets[0].write(
        Buffer.concat([
          frame('C', text('BEGIN')),
          frame('C', text('SELECT 1')),
          frame('C', text('COMMIT')),
          frame('Z', Buffer.from('I')),
        ]),
      );
      await entered;
      assert.deepEqual(proxy.committed(), { targetId: target, workId: work, count: 1 });
      if (mode === 'other-socket') {
        const otherClient = net.createConnection(proxy.port, '127.0.0.1');
        clients.push(otherClient);
        otherClient.on('error', () => {});
        await once(otherClient, 'connect');
        const ended = once(otherClient, 'close');
        otherClient.write(u32(65537));
        await ended;
      } else await closed;
      assert.throws(
        () => proxy.status(),
        (error) => {
          assert.deepEqual(error.backendCommitted, { targetId: target, workId: work, count: 1 });
          assert.match(error.message, /backendCommitted=/u);
          assert.ok(!error.message.includes('Private observer'));
          return true;
        },
      );
      assert.throws(() => proxy.arm());
      const start = Date.now();
      await proxy.close();
      assert.ok(Date.now() - start < 1000);
      assert.equal(signal.aborted, true);
      await closed;
      assert.ok(!Buffer.concat(received).includes(text('COMMIT')));
      assert.ok(!Buffer.concat(received).includes(frame('Z', Buffer.from('I'))));
      assert.deepEqual(proxy.committed(), { targetId: target, workId: work, count: 1 });
    } finally {
      release();
      for (const socket of [...clients, ...sockets]) socket.destroy();
      await proxy.close();
      await new Promise((resolve) => backend.close(resolve));
    }
  }
});
