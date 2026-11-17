import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir, readlink } from 'node:fs/promises';
import { connect } from 'node:net';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';

const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const entry = z.strictObject({
  credentialId: z.uuid(),
  participantId: z.uuid(),
  principalId: z.uuid(),
  workloadId: z.string().regex(/^urn:openpc:workload:[0-9a-f-]{36}$/u),
  publicKeySpkiDer: z.string().min(1).max(8192),
  certificateDer: z.string().min(1).max(32768),
});
const inputSchema = z.strictObject({
  pid: z.number().int().positive(),
  startTicks: z.string().regex(/^\d+$/u),
  scriptUrl: z.string().startsWith('file:'),
  scriptDigest: z.string().regex(/^[0-9a-f]{64}$/u),
  manifest: z.array(entry).min(1).max(7),
  inspectorPort: z.number().int().min(1).max(65535),
  issuerPort: z.number().int().min(1).max(65535),
});
export async function issuerProcessStartTicks(pid: number) {
  const stat = await readFile(`/proc/${pid}/stat`, 'utf8');
  const ticks = stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19];
  assert.match(ticks ?? '', /^\d+$/u);
  return ticks!;
}
async function refusesConnection(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.once('connect', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', (error: NodeJS.ErrnoException) => resolve(error.code === 'ECONNREFUSED'));
    socket.setTimeout(250, () => {
      socket.destroy();
      resolve(false);
    });
  });
}
const targetsSchema = z.array(z.object({ webSocketDebuggerUrl: z.string() })).max(1);
const locationSchema = z.object({
  scriptId: z.string().max(128),
  lineNumber: z.number().int().nonnegative(),
});
const payloadSchema = z.object({
  result: z.object({ value: z.unknown() }).optional(),
  exceptionDetails: z.unknown().optional(),
  scriptSource: z.string().max(1_048_576).optional(),
  scriptId: z.string().max(128).optional(),
  url: z.string().max(4096).optional(),
  actualLocation: locationSchema.optional(),
  breakpointId: z.string().max(128).optional(),
  callFrames: z
    .array(z.object({ callFrameId: z.string().max(128), location: locationSchema }))
    .max(128)
    .optional(),
});
type Payload = z.infer<typeof payloadSchema>;
const messageSchema = z.object({
  id: z.number().int().positive().optional(),
  error: z.unknown().optional(),
  result: payloadSchema.optional(),
  method: z.string().max(128).optional(),
  params: payloadSchema.optional(),
});
const capturedMapSchema = z.strictObject({
  valid: z.literal(true),
  size: z.number().int().min(0).max(7),
  claims: z.array(z.tuple([z.uuid(), z.string().max(16384)])).max(7),
  manifestEqual: z.literal(true),
});
const captureSchema = z.strictObject({
  schema: z.literal('pc.local.workload-issuer-claims-capture.v1'),
  sourceBundleDigest: z.string(),
  legacyManifestDigest: z.string(),
  processIdentity: z.string(),
  claims: z.array(z.strictObject({ credentialId: z.uuid(), requestJson: z.string() })).max(7),
});
async function awaitSocketClosed(socket: WebSocket, timeout: number) {
  if (socket.readyState === WebSocket.CLOSED) return;
  await new Promise<void>((resolve, reject) => {
    const closed = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      socket.removeEventListener('close', closed);
      reject(new Error('INSPECTOR_SOCKET_CLOSE_UNRESOLVED'));
    }, timeout);
    socket.addEventListener('close', closed, { once: true });
  });
}
class Protocol {
  private sequence = 0;
  private requests = new Map<
    number,
    {
      resolve: (value: Payload) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private notifications: { method: string; params: Payload }[] = [];
  private broken = false;
  private nativeShutdownArmed = false;
  get available() {
    return !this.broken && this.socket.readyState === WebSocket.OPEN;
  }
  cancelPending() {
    for (const pending of this.requests.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('INSPECTOR_PROTOCOL_UNAVAILABLE'));
    }
    this.requests.clear();
  }
  dispose() {
    this.cancelPending();
    if (!this.nativeShutdownArmed) this.socket.close();
  }
  armNativeShutdown() {
    this.nativeShutdownArmed = true;
  }
  async awaitNativeShutdown(timeout: number) {
    this.cancelPending();
    await awaitSocketClosed(this.socket, timeout);
  }
  async disposeAndWait(timeout: number) {
    this.dispose();
    await awaitSocketClosed(this.socket, timeout);
  }
  constructor(readonly socket: WebSocket) {
    const fail = () => {
      this.broken = true;
      this.cancelPending();
      if (!this.nativeShutdownArmed) socket.close();
    };
    socket.addEventListener('error', fail);
    socket.addEventListener('close', fail);
    socket.addEventListener('message', (event) => {
      try {
        if (typeof event.data !== 'string' || event.data.length > 1_048_576) {
          fail();
          return;
        }
        const response = messageSchema.parse(JSON.parse(event.data));
        if (response.id) {
          const pending = this.requests.get(response.id);
          if (!pending) return;
          this.requests.delete(response.id);
          clearTimeout(pending.timer);
          if (response.error) pending.reject(new Error('INSPECTOR_PROTOCOL_ERROR'));
          else pending.resolve(response.result ?? {});
        } else if (
          response.method === 'Debugger.scriptParsed' ||
          response.method === 'Debugger.paused'
        ) {
          if (this.notifications.length >= 256) {
            fail();
            return;
          }
          this.notifications.push({ method: response.method, params: response.params ?? {} });
        }
      } catch {
        fail();
      }
    });
  }
  send(method: string, params: unknown = {}, onDispatch?: () => void) {
    if (this.broken || this.socket.readyState !== WebSocket.OPEN)
      return Promise.reject(new Error('INSPECTOR_PROTOCOL_UNAVAILABLE'));
    assert.ok(
      [
        'Runtime.evaluate',
        'Debugger.enable',
        'Debugger.disable',
        'Debugger.getScriptSource',
        'Debugger.setBreakpoint',
        'Debugger.removeBreakpoint',
        'Debugger.evaluateOnCallFrame',
        'Debugger.resume',
      ].includes(method),
    );
    const id = ++this.sequence;
    return new Promise<Payload>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.requests.delete(id);
        reject(new Error('INSPECTOR_RESPONSE_TIMEOUT'));
      }, 3_000);
      this.requests.set(id, { resolve, reject, timer });
      try {
        const wire = JSON.stringify({ id, method, params });
        onDispatch?.();
        this.socket.send(wire);
      } catch (error) {
        clearTimeout(timer);
        this.requests.delete(id);
        reject(error);
      }
    });
  }
  async event(method: string, predicate: (params: Payload) => boolean) {
    const deadline = Date.now() + 3_000;
    while (Date.now() < deadline) {
      if (this.broken) throw new Error('INSPECTOR_PROTOCOL_UNAVAILABLE');
      const i = this.notifications.findIndex((v) => v.method === method && predicate(v.params));
      if (i >= 0) return this.notifications.splice(i, 1)[0]!.params;
      await delay(10);
    }
    throw new Error('INSPECTOR_EVENT_TIMEOUT');
  }
}
export type IssuerCapturePhase =
  | 'before-signal'
  | 'after-signal'
  | 'after-discovery'
  | 'after-connect'
  | 'after-identity'
  | 'after-breakpoint'
  | 'paused'
  | 'after-map'
  | 'cleanup-resume'
  | 'cleanup-remove'
  | 'cleanup-disable'
  | 'cleanup-close'
  | 'final-identity';
type CaptureOptions = {
  signal?: AbortSignal;
  onPhase?: (phase: IssuerCapturePhase) => void | Promise<void>;
};
type FailureOwner =
  | 'capture'
  | 'capture-result'
  | 'post-capture-process'
  | 'cleanup-start'
  | 'cleanup-listener'
  | 'cleanup-post-state'
  | 'health-settlement'
  | 'final-identity';
type FailureReason =
  'ASSERTION' | 'SCHEMA' | 'FETCH' | 'PROCESS_UNAVAILABLE' | 'PROTOCOL' | 'REJECTED';
export class LocalIssuerCaptureFailure extends Error {
  constructor(
    readonly diagnostic: {
      capturePhase: IssuerCapturePhase | 'preflight';
      listener: 'not-opened' | 'closed' | 'unresolved';
      originalProcess: 'verified' | 'unverified';
    },
    readonly failures: readonly { owner: FailureOwner; reason: FailureReason }[] = [],
  ) {
    super('ORIGINAL_ISSUER_CAPTURE_FAILED');
  }
}
/** Exact lexical-map reconciliation. The caller owns the process and quiesces all issuers first. */
export async function captureOwnedLocalIssuerClaims(value: unknown, options: CaptureOptions = {}) {
  try {
    return await captureOwnedLocalIssuerClaimsInternal(value, options);
  } catch (error) {
    if (error instanceof LocalIssuerCaptureFailure) throw error;
    throw new LocalIssuerCaptureFailure({
      capturePhase: 'preflight',
      listener: 'not-opened',
      originalProcess: 'unverified',
    });
  }
}
type IssuerCaptureInput = z.infer<typeof inputSchema>;
async function assertOwnedIssuerListener(
  input: IssuerCaptureInput,
  port: number,
  loopbackOnly: boolean,
) {
  const descriptors = await readdir(`/proc/${input.pid}/fd`);
  assert.ok(descriptors.length <= 1024);
  const links = await Promise.all(
    descriptors.map((fd) => readlink(`/proc/${input.pid}/fd/${fd}`).catch(() => '')),
  );
  const sockets = new Set(
    links.map((link) => link.match(/^socket:\[(\d+)\]$/u)?.[1]).filter(Boolean),
  );
  const tcp = await readFile(`/proc/${input.pid}/net/tcp`, 'utf8');
  assert.ok(tcp.length <= 131072);
  const listeners = tcp
    .split('\n')
    .map((line) => line.trim().split(/\s+/u))
    .filter(
      (fields) =>
        fields[3] === '0A' &&
        fields[1]?.split(':')[1] === port.toString(16).toUpperCase().padStart(4, '0'),
    );
  assert.equal(listeners.length, 1);
  const address = listeners[0]![1]!.split(':')[0];
  assert.ok(address === '0100007F' || (!loopbackOnly && address === '00000000'));
  assert.equal(sockets.has(listeners[0]![9]!), true);
}
/** Shared read-only admission; never opens the inspector or reads a lexical scope. */
export async function preflightOwnedLocalIssuerClaims(value: unknown) {
  try {
    const { input, healthLine } = await prepareOwnedLocalIssuerClaims(value);
    return {
      pid: input.pid,
      startTicks: input.startTicks,
      scriptDigest: input.scriptDigest,
      manifestDigest: hash(JSON.stringify(input.manifest)),
      issuerPort: input.issuerPort,
      inspectorPort: input.inspectorPort,
      healthLine,
    };
  } catch {
    throw new LocalIssuerCaptureFailure({
      capturePhase: 'preflight',
      listener: 'not-opened',
      originalProcess: 'unverified',
    });
  }
}
async function prepareOwnedLocalIssuerClaims(value: unknown) {
  const input = inputSchema.parse(value);
  const captureUid = process.getuid?.();
  assert.notEqual(captureUid, undefined);
  assert.notEqual(input.pid, process.pid);
  assert.equal(process.version, 'v24.19.0');
  assert.equal(await issuerProcessStartTicks(input.pid), input.startTicks);
  const sourcePath = fileURLToPath(input.scriptUrl),
    source = await readFile(sourcePath, 'utf8');
  assert.equal(hash(source), input.scriptDigest);
  async function originalProcess() {
    assert.equal(await issuerProcessStartTicks(input.pid), input.startTicks);
    const status = await readFile(`/proc/${input.pid}/status`, 'utf8');
    const uid = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu.exec(status);
    assert.ok(uid);
    assert.equal(
      uid.slice(1).every((value) => Number(value) === captureUid),
      true,
    );
    assert.equal(hash(await readFile(sourcePath)), input.scriptDigest);
    const argsBytes = await readFile(`/proc/${input.pid}/cmdline`);
    assert.ok(argsBytes.length <= 8192);
    const args = argsBytes.toString().split('\0').filter(Boolean);
    assert.equal(args.at(-1), sourcePath);
    const portArgs = args.filter((arg) => arg.startsWith('--inspect-port='));
    assert.ok(portArgs.length <= 1);
    assert.equal(args.length, 2 + portArgs.length);
    assert.equal(args[0]?.split('/').at(-1), 'node');
    assert.equal(
      args.slice(1, -1).every((arg) => portArgs.includes(arg)),
      true,
    );
    assert.equal(
      args.some((arg) => /^--inspect(?:=|-brk|$)/u.test(arg)),
      false,
    );
    // Only inspect NODE_OPTIONS for an unsupported inspector override. Other
    // environment values are never parsed, retained, returned or logged.
    const environment = await readFile(`/proc/${input.pid}/environ`);
    assert.ok(environment.length <= 131072);
    const nodeOptions = environment
      .toString()
      .split('\0')
      .find((arg) => arg.startsWith('NODE_OPTIONS='));
    assert.equal(nodeOptions?.includes('inspect') ?? false, false);
    assert.match(
      nodeOptions?.slice('NODE_OPTIONS='.length) ?? '',
      /^(?:\s*--max-old-space-size=\d+\s*)?$/u,
    );
    const configured = portArgs[0]?.match(/^--inspect-port=127\.0\.0\.1:(\d+)$/u);
    if (portArgs.length) assert.ok(configured);
    assert.equal(input.inspectorPort, configured ? Number(configured[1]) : 9229);
  }
  await originalProcess();
  assert.equal(new Set(input.manifest.map((v) => v.credentialId)).size, input.manifest.length);
  assert.equal(await refusesConnection(input.inspectorPort), true, 'Inspector already open');
  await assertOwnedIssuerListener(input, input.issuerPort, false);
  const health = await fetch(`http://127.0.0.1:${input.issuerPort}/healthz`, {
    signal: AbortSignal.timeout(2000),
  });
  assert.equal(health.status, 200);
  const reader = health.body?.getReader();
  assert.ok(reader);
  let healthBytes = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      healthBytes += part.value.length;
      assert.ok(healthBytes <= 4096);
    }
  } finally {
    await reader.cancel();
  }
  await originalProcess();
  const candidates = source
    .split('\n')
    .map((line, index) => ({ line, index }))
    .filter(
      (v) =>
        v.line.includes('request.method === "GET"') &&
        v.line.includes('request.url === "/healthz"'),
    );
  assert.equal(candidates.length, 1, 'Expected exact original health callback');
  return { input, originalProcess, healthLine: candidates[0]!.index };
}
async function captureOwnedLocalIssuerClaimsInternal(value: unknown, options: CaptureOptions) {
  const { input, originalProcess, healthLine } = await prepareOwnedLocalIssuerClaims(value);
  let listenerObserved = false;
  async function ownedInspectorListener() {
    await originalProcess();
    await assertOwnedIssuerListener(input, input.inspectorPort, true);
    listenerObserved = true;
  }
  const expected = Object.fromEntries(
    input.manifest.map(({ certificateDer, ...request }) => {
      void certificateDer;
      return [request.credentialId, JSON.stringify(request)];
    }),
  );
  const manifestJson = JSON.stringify(input.manifest);
  const expression = `(()=>{const size=claims.size;if(!Number.isInteger(size)||size<0||size>7)return JSON.stringify({valid:false});const rows=[...claims.entries()];const expected=${JSON.stringify(expected)};const valid=rows.length===size&&rows.every(([id,request])=>typeof id==='string'&&id.length<=36&&typeof request==='string'&&request.length<=16384&&expected[id]===request);return JSON.stringify({valid,size,claims:valid?rows:[],manifestEqual:JSON.stringify(manifest)===${JSON.stringify(manifestJson)}});})()`;
  const pendingHealth: Promise<number>[] = [];
  let protocol: Protocol | undefined,
    breakpoint: string | undefined,
    opened = false,
    identified = false;
  let failure: unknown,
    result: z.infer<typeof captureSchema> | undefined,
    cleanupReplyLost = false;
  const failures: { owner: FailureOwner; reason: FailureReason }[] = [];
  let activeOwner: FailureOwner = 'capture';
  const keepFailure = (owner: FailureOwner, error: unknown) => {
    const code = error instanceof Error && 'code' in error ? error.code : undefined;
    const reason =
      code === 'ERR_ASSERTION'
        ? 'ASSERTION'
        : error instanceof z.ZodError
          ? 'SCHEMA'
          : error instanceof TypeError && error.message === 'fetch failed'
            ? 'FETCH'
            : ['ENOENT', 'ESRCH', 'EACCES'].includes(String(code))
              ? 'PROCESS_UNAVAILABLE'
              : error instanceof Error && error.message.startsWith('INSPECTOR_')
                ? 'PROTOCOL'
                : 'REJECTED';
    failures.push({ owner, reason });
    failure = failure ? new AggregateError([failure, error], 'CAPTURE_LIFECYCLE_FAILED') : error;
  };
  let lastPhase: IssuerCapturePhase | 'preflight' = 'preflight',
    listenerClosed = false,
    originalProcessVerified = false;
  async function invokePhase(value: IssuerCapturePhase, timeout: number) {
    if (!options.onPhase) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        timer = setTimeout(() => reject(new Error('CAPTURE_PHASE_TIMEOUT')), timeout);
        Promise.resolve()
          .then(() => options.onPhase!(value))
          .then(() => resolve(), reject);
      });
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  const phase = async (value: IssuerCapturePhase) => {
    lastPhase = value;
    options.signal?.throwIfAborted();
    await invokePhase(value, 3000);
    options.signal?.throwIfAborted();
  };
  const abort = () => protocol?.cancelPending();
  options.signal?.addEventListener('abort', abort);
  async function attach(forCleanup = false) {
    await ownedInspectorListener();
    const response = await fetch(`http://127.0.0.1:${input.inspectorPort}/json/list`, {
      signal: AbortSignal.timeout(500),
    });
    assert.equal(response.status, 200);
    const bytes = await response.text();
    assert.ok(bytes.length <= 16384);
    const targets = targetsSchema.parse(JSON.parse(bytes));
    assert.equal(targets.length, 1);
    if (!forCleanup) await phase('after-discovery');
    const url = new URL(targets[0]!.webSocketDebuggerUrl);
    assert.equal(url.protocol, 'ws:');
    assert.equal(url.hostname, '127.0.0.1');
    assert.equal(Number(url.port), input.inspectorPort);
    assert.equal(url.username + url.password + url.search + url.hash, '');
    await ownedInspectorListener();
    const socket = new WebSocket(url);
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('INSPECTOR_CONNECT_TIMEOUT')), 3000);
        socket.addEventListener(
          'open',
          () => {
            clearTimeout(timer);
            resolve();
          },
          { once: true },
        );
        socket.addEventListener(
          'error',
          () => {
            clearTimeout(timer);
            reject(new Error('INSPECTOR_CONNECT_FAILED'));
          },
          { once: true },
        );
        socket.addEventListener(
          'close',
          () => {
            clearTimeout(timer);
            reject(new Error('INSPECTOR_CONNECT_FAILED'));
          },
          { once: true },
        );
      });
      protocol = new Protocol(socket);
      if (!forCleanup) await phase('after-connect');
      const identity = await protocol.send('Runtime.evaluate', {
        expression: 'process.pid+"|"+process.version',
        returnByValue: true,
        throwOnSideEffect: true,
      });
      assert.equal(identity.result?.value, `${input.pid}|v24.19.0`);
      await ownedInspectorListener();
      identified = true;
      if (!forCleanup) await phase('after-identity');
      else await protocol.send('Debugger.enable');
    } catch (error) {
      socket.close();
      identified = false;
      try {
        await awaitSocketClosed(socket, 3000);
      } catch (closeError) {
        throw new AggregateError([error, closeError], 'INSPECTOR_ATTACH_CLOSE_UNRESOLVED');
      }
      throw error;
    }
  }
  try {
    await phase('before-signal');
    process.kill(input.pid, 'SIGUSR1');
    opened = true;
    await phase('after-signal');
    const deadline = Date.now() + 3_000;
    let targets: z.infer<typeof targetsSchema> | undefined;
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`http://127.0.0.1:${input.inspectorPort}/json/list`, {
          signal: AbortSignal.timeout(500),
        });
        const bytes = await response.text();
        assert.ok(bytes.length <= 16_384);
        targets = targetsSchema.parse(JSON.parse(bytes));
        break;
      } catch {
        await delay(20);
      }
    }
    assert.equal(targets?.length, 1);
    await attach();
    assert.ok(protocol);
    await protocol.send('Debugger.enable');
    const script = await protocol.event('Debugger.scriptParsed', (p) => p.url === input.scriptUrl);
    const loaded = await protocol.send('Debugger.getScriptSource', { scriptId: script.scriptId });
    assert.equal(hash(z.string().parse(loaded.scriptSource)), input.scriptDigest);
    const selected = await protocol.send('Debugger.setBreakpoint', {
      location: { scriptId: script.scriptId, lineNumber: healthLine },
    });
    assert.equal(selected.actualLocation?.scriptId, script.scriptId);
    assert.equal(selected.actualLocation?.lineNumber, healthLine);
    breakpoint = selected.breakpointId;
    await phase('after-breakpoint');
    const capture = async () => {
      const health = fetch(`http://127.0.0.1:${input.issuerPort}/healthz`, {
        signal: AbortSignal.timeout(5_000),
      }).then(async (response) => {
        await response.arrayBuffer();
        return response.status;
      });
      pendingHealth.push(health);
      // Observe rejection even while the issuer is paused.
      void health.catch(() => undefined);
      const event = await protocol!.event(
        'Debugger.paused',
        (p) => p.callFrames?.[0]?.location?.scriptId === script.scriptId,
      );
      await phase('paused');
      const read = await protocol!.send('Debugger.evaluateOnCallFrame', {
        callFrameId: event.callFrames![0]!.callFrameId,
        expression,
        returnByValue: true,
        throwOnSideEffect: true,
      });
      if (read.exceptionDetails) throw new Error('ORIGINAL_LEXICAL_CLAIMS_UNAVAILABLE');
      assert.equal(typeof read.result?.value, 'string');
      assert.ok(z.string().parse(read.result?.value).length <= 131_072);
      const captured = capturedMapSchema.parse(JSON.parse(z.string().parse(read.result?.value)));
      await phase('after-map');
      assert.equal(captured.valid, true);
      assert.equal(captured.manifestEqual, true);
      assert.equal(captured.size, captured.claims.length);
      await protocol!.send('Debugger.resume');
      assert.equal(await health, 200);
      return captured;
    };
    const before = await capture(),
      after = await capture();
    activeOwner = 'capture-result';
    if (JSON.stringify(after) !== JSON.stringify(before)) throw new Error('ISSUER_CLAIMS_CHANGED');
    activeOwner = 'post-capture-process';
    await originalProcess();
    activeOwner = 'capture-result';
    result = captureSchema.parse({
      schema: 'pc.local.workload-issuer-claims-capture.v1',
      sourceBundleDigest: input.scriptDigest,
      legacyManifestDigest: hash(manifestJson),
      processIdentity: `${input.pid}:${input.startTicks}`,
      claims: before.claims.map(([credentialId, requestJson]: [string, string]) => ({
        credentialId,
        requestJson,
      })),
    });
  } catch (error) {
    keepFailure(activeOwner, error);
  } finally {
    options.signal?.removeEventListener('abort', abort);
    const cleanupDeadline = Date.now() + 15000;
    if (opened && !listenerObserved) {
      const startDeadline = Math.min(cleanupDeadline, Date.now() + 3000);
      while (Date.now() < startDeadline && !listenerObserved) {
        try {
          await ownedInspectorListener();
        } catch {
          await delay(20);
        }
      }
      if (!listenerObserved)
        keepFailure('cleanup-start', new Error('SIGNALED_INSPECTOR_START_UNRESOLVED'));
    }
    if (opened)
      for (let attempt = 0; attempt < 2 && Date.now() < cleanupDeadline; attempt++) {
        if (listenerObserved && (await refusesConnection(input.inspectorPort))) break;
        if (!identified || !protocol?.available) {
          try {
            await protocol?.disposeAndWait(
              Math.max(1, Math.min(3000, cleanupDeadline - Date.now())),
            );
          } catch (error) {
            keepFailure('cleanup-listener', error);
            break;
          }
          protocol = undefined;
          try {
            await attach(true);
          } catch {
            cleanupReplyLost = true;
            continue;
          }
        }
        let nativeCloseSent = false;
        const step = async (value: IssuerCapturePhase, method: string, params: unknown = {}) => {
          if (Date.now() >= cleanupDeadline) return;
          try {
            await invokePhase(value, Math.max(1, Math.min(3000, cleanupDeadline - Date.now())));
            await ownedInspectorListener();
            if (value === 'cleanup-close') {
              if (!protocol!.available) throw new Error('INSPECTOR_PROTOCOL_UNAVAILABLE');
            }
            await protocol!.send(
              method,
              params,
              value === 'cleanup-close'
                ? () => {
                    // The public send call can throw after bytes escaped. Arm only
                    // at that call boundary, then never infer safe repetition.
                    nativeCloseSent = true;
                    protocol!.armNativeShutdown();
                  }
                : undefined,
            );
          } catch {
            cleanupReplyLost = true;
          }
        };
        await step('cleanup-resume', 'Debugger.resume');
        await Promise.race([
          Promise.allSettled(pendingHealth),
          delay(Math.max(1, Math.min(1000, cleanupDeadline - Date.now() - 3000))),
        ]);
        if (breakpoint)
          await step('cleanup-remove', 'Debugger.removeBreakpoint', { breakpointId: breakpoint });
        await step('cleanup-disable', 'Debugger.disable');
        await step('cleanup-close', 'Runtime.evaluate', {
          expression: 'void setImmediate(()=>process.getBuiltinModule("node:inspector").close())',
          returnByValue: true,
        });
        if (nativeCloseSent) {
          try {
            await protocol!.awaitNativeShutdown(
              Math.max(1, Math.min(3000, cleanupDeadline - Date.now())),
            );
          } catch (error) {
            keepFailure('cleanup-listener', error);
          }
        }
        protocol?.dispose();
        protocol = undefined;
        identified = false;
        if (nativeCloseSent) break;
        await delay(20);
      }
    protocol?.dispose();
    if (opened) {
      const deadline = Date.now() + 3_000;
      let closed = false;
      while (Date.now() < deadline) {
        if (await refusesConnection(input.inspectorPort)) {
          closed = true;
          break;
        }
        await delay(20);
      }
      if (!closed || !listenerObserved)
        keepFailure('cleanup-listener', new Error('INSPECTOR_LISTENER_REMAINS_OPEN'));
      else {
        listenerClosed = true;
        try {
          await originalProcess();
          const health = await fetch(`http://127.0.0.1:${input.issuerPort}/healthz`, {
            signal: AbortSignal.timeout(2000),
          });
          assert.equal(health.status, 200);
          await health.arrayBuffer();
          originalProcessVerified = true;
        } catch (error) {
          keepFailure('cleanup-post-state', error);
        }
      }
    }
    let settleTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      const settled = await new Promise<boolean>((resolve) => {
        settleTimer = setTimeout(() => resolve(false), 5000);
        void Promise.allSettled(pendingHealth).then(() => resolve(true));
      });
      if (!settled)
        keepFailure('health-settlement', new Error('ORIGINAL_HEALTH_RESPONSE_UNSETTLED'));
    } finally {
      if (settleTimer) clearTimeout(settleTimer);
    }
    if (opened && listenerClosed) {
      try {
        if (!failure) lastPhase = 'final-identity';
        await invokePhase('final-identity', 3000);
        await originalProcess();
        if (!failure) assert.ok(result);
      } catch (error) {
        originalProcessVerified = false;
        keepFailure('final-identity', error);
      }
    }
  }
  if (failure)
    throw new LocalIssuerCaptureFailure(
      {
        capturePhase: lastPhase,
        listener: !opened ? 'not-opened' : listenerClosed ? 'closed' : 'unresolved',
        originalProcess: originalProcessVerified ? 'verified' : 'unverified',
      },
      failures,
    );
  return {
    capture: result!,
    diagnostic: {
      listenerClosed: true,
      originalProcessUnchanged: true,
      originalHealthSettled: true,
      cleanupReplyLost,
    },
  };
}
