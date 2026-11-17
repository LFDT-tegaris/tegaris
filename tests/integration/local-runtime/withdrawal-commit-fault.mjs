import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { allowFaultProxy } from './fault-proxy-firewall.mjs';

const MAX_FRAME = 16 * 1024 * 1024;
// The native process owns a four-connection pool. Docker runs one independent
// healthcheck at a time; its database connection must not starve that pool.
const MAX_CONNECTIONS = 5;
const QUERY =
  'select binding,admission_digest from openpc.begin_runtime_target_withdrawal($1::text::uuid,$2::text::uuid,$3,$4,$5)';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function cstring(bytes, offset = 0) {
  const end = bytes.indexOf(0, offset);
  assert.ok(end >= offset, 'Invalid PostgreSQL string');
  return [bytes.toString('utf8', offset, end), end + 1];
}

// Observes protocol only. It neither executes SQL nor grants signing authority.
export class WithdrawalCommitCorrelation {
  constructor(targetId, workId) {
    assert.match(targetId, uuid);
    if (workId !== undefined) assert.match(workId, uuid);
    this.targetId = targetId;
    this.workId = workId;
    this.statements = new Map();
    this.portals = new Map();
    this.pending = [];
    this.admittedWork = null;
  }

  frontend(tag, body) {
    if (tag === 'P') {
      const [name, offset] = cstring(body);
      const [query] = cstring(body, offset);
      this.statements.set(name, query === QUERY);
      assert.ok(this.statements.size <= 512, 'Prepared statement bound');
    } else if (tag === 'B') {
      const [portal, offset] = cstring(body);
      const [statement, start] = cstring(body, offset);
      let work = null;
      if (this.statements.get(statement)) {
        let cursor = start;
        const formats = body.readUInt16BE(cursor);
        cursor += 2 + 2 * formats;
        const count = body.readUInt16BE(cursor);
        cursor += 2;
        assert.equal(count, 5, 'Actual withdrawal selector cardinality');
        const selectors = [];
        for (let i = 0; i < count; i++) {
          const length = body.readInt32BE(cursor);
          cursor += 4;
          if (length === -1) {
            if (i < 2) selectors.push(null);
            continue;
          }
          assert.ok(length >= 0 && length <= MAX_FRAME && cursor + length <= body.length);
          if (i < 2) selectors.push(body.toString('utf8', cursor, cursor + length));
          cursor += length;
        }
        if (selectors[0] === this.targetId && uuid.test(selectors[1] ?? '')) {
          if (this.workId !== undefined)
            assert.equal(selectors[1], this.workId, 'Original withdrawal work required');
          work = selectors[1];
        }
      }
      this.portals.set(portal, work);
      assert.ok(this.portals.size <= 512, 'Portal bound');
    } else if (tag === 'E') {
      const [portal, offset] = cstring(body);
      assert.equal(body.readUInt32BE(offset), 0, 'Suspended portals unsupported');
      this.pending.push({ work: this.portals.get(portal) ?? null, command: null });
    } else if (tag === 'Q') {
      const [query, end] = cstring(body);
      assert.equal(end, body.length);
      // SQLx uses simple protocol for transaction commands, extended protocol
      // for the bound owner query. Multi-statement simple queries cannot arm.
      this.pending.push({ work: null, command: query.trim().toUpperCase() });
    } else if (tag === 'C') {
      const [name] = cstring(body, 1);
      if (body[0] === 83) this.statements.delete(name);
      else if (body[0] === 80) this.portals.delete(name);
    }
    assert.ok(this.pending.length <= 64, 'Pending command bound');
  }

  backend(tag, body) {
    if (tag === 'E') {
      this.pending = [];
      this.admittedWork = null;
    } else if (tag === 'Z') {
      this.pending = [];
      if (body[0] !== 84) this.admittedWork = null;
    } else if (tag === 'C') {
      const command = cstring(body)[0];
      const executed = this.pending.shift();
      if (command === 'COMMIT') {
        const work = executed?.command === 'COMMIT' ? this.admittedWork : null;
        this.admittedWork = null;
        return work;
      }
      if (command === 'ROLLBACK' || command === 'BEGIN') this.admittedWork = null;
      if (command === 'SELECT 1' && executed?.work) this.admittedWork = executed.work;
    } else if (tag === 'I') this.pending.shift();
    return null;
  }
}

function reader(socket) {
  const iterator = socket[Symbol.asyncIterator]();
  let remaining = Buffer.alloc(0);
  return async (size) => {
    assert.ok(size > 0 && size <= MAX_FRAME);
    const chunks = [];
    let needed = size;
    while (needed) {
      if (!remaining.length) {
        const next = await iterator.next();
        if (next.done) throw new Error('PostgreSQL connection ended');
        remaining = next.value;
      }
      const take = Math.min(remaining.length, needed);
      chunks.push(remaining.subarray(0, take));
      remaining = remaining.subarray(take);
      needed -= take;
    }
    return Buffer.concat(chunks, size);
  };
}
async function write(socket, bytes) {
  if (!socket.write(bytes)) await once(socket, 'drain');
}
async function frame(read) {
  const header = await read(5);
  const length = header.readUInt32BE(1);
  assert.ok(length >= 4 && length <= MAX_FRAME, 'PostgreSQL frame bound');
  const body = length === 4 ? Buffer.alloc(0) : await read(length - 4);
  return { tag: String.fromCharCode(header[0]), body, bytes: Buffer.concat([header, body]) };
}

/** One owned local test listener. Authentication bytes are forwarded unchanged
 * and never retained in diagnostics. Encrypted transport is unsupported, never
 * downgraded. The real server must emit COMMIT before the connection is lost. */
export async function startWithdrawalCommitFault({ targetId, workId, ...options }) {
  return startPgCommitFault({
    ...options,
    correlationFactory: () => new WithdrawalCommitCorrelation(targetId, workId),
    describeCommit: (id) => ({ targetId, workId: id, count: 1 }),
  });
}

// Shared transport framing only. Each fixture supplies an exact native query
// and identity correlator; an arbitrary transaction can never arm a fault.
export async function startPgCommitFault({
  host,
  port = 0,
  upstreamHost = '127.0.0.1',
  upstreamPort = 55432,
  correlationFactory,
  describeCommit,
  observeCommitted,
  observationTimeoutMs = 10000,
}) {
  assert.ok(net.isIP(host) && host !== '0.0.0.0' && host !== '::');
  assert.ok(net.isIP(upstreamHost) && upstreamHost !== '0.0.0.0' && upstreamHost !== '::');
  assert.ok(observeCommitted === undefined || typeof observeCommitted === 'function');
  assert.equal(typeof correlationFactory, 'function');
  assert.equal(typeof describeCommit, 'function');
  assert.ok(
    Number.isInteger(observationTimeoutMs) &&
      observationTimeoutMs > 0 &&
      observationTimeoutMs <= 10000,
  );
  const observation = new AbortController();
  const sockets = new Set();
  const tasks = new Set();
  let armed = false;
  let fault = null;
  let backendCommitted = null;
  let faultInProgress = false;
  let failure = null;
  let closing = false;
  let deadline;
  const server = net.createServer((client) => {
    if (closing || sockets.size >= MAX_CONNECTIONS * 2) {
      if (!closing) failure ??= 'PostgreSQL fault fixture connection bound';
      client.destroy();
      return;
    }
    const upstream = net.createConnection({ host: upstreamHost, port: upstreamPort });
    for (const socket of [client, upstream]) {
      // Match the native client: small PostgreSQL frames must not acquire
      // Nagle/delayed-ACK latency while a real authority transaction holds locks.
      socket.setNoDelay(true);
      sockets.add(socket);
      socket.on('error', () => {});
      socket.once('close', () => sockets.delete(socket));
    }
    let dropped = false;
    let stage = 'connect';
    const startupDeadline = setTimeout(() => {
      failure ??= 'PostgreSQL fault fixture startup timeout';
      client.destroy();
      upstream.destroy();
    }, 10000);
    const task = (async () => {
      await once(upstream, 'connect');
      stage = 'startup';
      const fromClient = reader(client),
        fromServer = reader(upstream);
      let startup = false;
      for (let attempts = 0; attempts < 3 && !startup; attempts++) {
        const header = await fromClient(4);
        const length = header.readUInt32BE();
        assert.ok(length >= 8 && length <= 65536, 'Startup frame bound');
        const body = await fromClient(length - 4);
        const code = body.readUInt32BE();
        stage = `startup-${code}`;
        await write(upstream, Buffer.concat([header, body]));
        if (code === 80877103 || code === 80877104) {
          const response = await fromServer(1);
          await write(client, response);
          assert.equal(
            response.toString(),
            'N',
            'Encrypted PostgreSQL fault injection unsupported',
          );
        } else {
          assert.equal(code, 196608, 'Expected PostgreSQL startup');
          startup = true;
        }
      }
      assert.ok(startup);
      clearTimeout(startupDeadline);
      const correlation = correlationFactory();
      await Promise.all([
        (async () => {
          for (;;) {
            const f = await frame(fromClient);
            stage = `frontend-${f.tag.charCodeAt(0)}`;
            correlation.frontend(f.tag, f.body);
            await write(upstream, f.bytes);
          }
        })(),
        (async () => {
          for (;;) {
            const f = await frame(fromServer);
            stage = `backend-${f.tag.charCodeAt(0)}`;
            const workId = correlation.backend(f.tag, f.body);
            if (armed && !fault && !faultInProgress && workId) {
              faultInProgress = true;
              backendCommitted = describeCommit(workId);
              clearTimeout(deadline);
              // The backend has committed, but the native caller still awaits
              // COMMIT. Observe durable custody independently before EOF can
              // allow its next retry. Never forward success while observing.
              const observationDeadline = setTimeout(
                () => observation.abort(new Error('Committed observation timeout')),
                observationTimeoutMs,
              );
              let abortObservation;
              try {
                await Promise.race([
                  observeCommitted?.({ ...backendCommitted }, observation.signal),
                  new Promise((_, reject) => {
                    abortObservation = () => reject(observation.signal.reason);
                    observation.signal.addEventListener('abort', abortObservation, { once: true });
                    if (observation.signal.aborted) abortObservation();
                  }),
                ]);
              } catch (error) {
                failure ??= 'PostgreSQL backend committed; observation incomplete';
                observation.abort(error);
                throw error;
              } finally {
                clearTimeout(observationDeadline);
                observation.signal.removeEventListener('abort', abortObservation);
              }
              fault = { ...backendCommitted };
              dropped = true;
              // Drop this complete success frame AND every subsequent frame;
              // SQLx must receive EOF, never COMMIT or ReadyForQuery success.
              client.destroy();
              upstream.destroy();
              return;
            }
            await write(client, f.bytes);
          }
        })(),
      ]);
    })()
      .catch((error) => {
        if (!closing && !dropped && error.message !== 'PostgreSQL connection ended')
          failure ??= `PostgreSQL fault fixture protocol failure (${stage})`;
      })
      .finally(() => {
        clearTimeout(startupDeadline);
        client.destroy();
        upstream.destroy();
        tasks.delete(task);
      });
    tasks.add(task);
  });
  server.listen(port, host);
  await once(server, 'listening');
  let closeAccess;
  try {
    closeAccess = await allowFaultProxy(host, server.address().port);
  } catch (error) {
    server.close();
    throw error;
  }
  return {
    port: server.address().port,
    arm() {
      assert.equal(failure, null);
      assert.equal(armed, false);
      assert.equal(fault, null);
      armed = true;
      deadline = setTimeout(() => {
        failure ??= 'PostgreSQL correlated commit fault was not reached';
        for (const socket of sockets) socket.destroy();
      }, 45000);
    },
    committed() {
      return backendCommitted && { ...backendCommitted };
    },
    status() {
      if (failure) {
        const error = new Error(`${failure}; backendCommitted=${JSON.stringify(backendCommitted)}`);
        error.backendCommitted = backendCommitted && { ...backendCommitted };
        throw error;
      }
      return fault && { ...fault };
    },
    async close() {
      closing = true;
      observation.abort(new Error('Committed observation closed'));
      clearTimeout(deadline);
      server.close();
      for (const socket of sockets) socket.destroy();
      await Promise.allSettled([...tasks]);
      await closeAccess();
    },
  };
}
