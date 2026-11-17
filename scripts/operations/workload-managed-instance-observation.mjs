import { isIP } from 'node:net';
import { TLSSocket } from 'node:tls';
import { createHash, X509Certificate } from 'node:crypto';
import { z } from 'zod';
import {
  managedWorkloadCopy,
  managedWorkloadDigest,
  managedWorkloadInstanceDescriptorSchema,
  managedWorkloadDescriptorFromHistoricalPins,
} from '../../services/identity-service/src/contracts/workload-managed-instance.ts';
import {
  withInstallationProcessObservationBudget,
  readInstallationProcessIsolation,
  readInstallationProcessTcp4Table,
  readInstallationProcessFileDescriptors,
} from './installation-process-observation.mjs';
import {
  parseQualificationDeploymentPins,
  collectQualificationDeployment,
  readCollectedQualificationDeployment,
  qualificationDeploymentDigest,
} from './qualification-deployment-observation.mjs';

const ipv4 = z.string().refine((value) => isIP(value) === 4);
export const managedWorkloadConnectionSchema = z.strictObject({
  profile: z.literal('LINUX_DOCKER_BRIDGE_DIRECT_TCP4_V1'),
  family: z.literal('IPv4'),
  remoteAddress: ipv4,
  remotePort: z.number().int().min(1).max(65535),
  localAddress: ipv4,
  localPort: z.number().int().min(1).max(65535),
});
function fail() {
  throw new Error('MANAGED_WORKLOAD_OBSERVATION_UNAVAILABLE');
}
const decimal = /^(0|[1-9][0-9]*)$/u;
const hex = /^[0-9A-F]{8}$/u;
function address(value) {
  const parts = /^([0-9A-F]{8}):([0-9A-F]{4})$/u.exec(value);
  if (!parts) fail();
  const raw = parts[1];
  return {
    address: [6, 4, 2, 0]
      .map((offset) => Number.parseInt(raw.slice(offset, offset + 2), 16))
      .join('.'),
    port: Number.parseInt(parts[2], 16),
  };
}

/** Pure Linux TCP4 decoder only, never a native observation or authority.
 * Caller-supplied tables/JSON cannot mint the opaque collector handle.
 * IPv6/mapped/NAT/proxy profiles are deliberately outside this exact profile. */
export function parseManagedWorkloadTcp4Table(text) {
  if (typeof text !== 'string' || text.length > 262144 || !text.endsWith('\n')) fail();
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code !== 9 && code !== 10 && (code < 32 || code > 126)) fail();
  }
  const lines = text.split('\n');
  lines.pop();
  if (
    lines.length > 4097 ||
    !/^\s*sl\s+local_address\s+rem_address\s+st\s+tx_queue\s+rx_queue\s+tr\s+tm->when\s+retrnsmt\s+uid\s+timeout\s+inode\s*$/u.test(
      lines.shift() ?? '',
    )
  )
    fail();
  const slots = new Set();
  const rows = lines.map((line) => {
    if (line.length > 1024) fail();
    const fields = line.trim().split(/\s+/u);
    // Linux emits full sockets as17 fields and request/timewait sockets as12;
    // a prefix ending at inode is a truncated observation, never a complete row.
    // https://docs.kernel.org/networking/proc_net_tcp.html
    // net/ipv4/tcp_ipv4.c: get_tcp4_sock/get_openreq4/get_timewait4_sock.
    const short =
      fields.length === 12 && ['03', '05', '06'].includes(fields[3]) && fields[9] === '0';
    if (
      (!short && fields.length !== 17) ||
      !/^(0|[1-9][0-9]*):$/u.test(fields[0]) ||
      slots.has(fields[0]) ||
      !/^0[1-9AB]$/u.test(fields[3]) ||
      !/^[0-9A-F]{8}:[0-9A-F]{8}$/u.test(fields[4]) ||
      !/^[0-9A-F]{2}:[0-9A-F]{8}$/u.test(fields[5]) ||
      !hex.test(fields[6]) ||
      !decimal.test(fields[7]) ||
      !decimal.test(fields[8]) ||
      !decimal.test(fields[9]) ||
      !decimal.test(fields[10]) ||
      !/^[0-9a-f]{16}$/u.test(fields[11]) ||
      (!short &&
        (fields.slice(12, 16).some((field) => !decimal.test(field)) ||
          !(decimal.test(fields[16]) || fields[16] === '-1'))) ||
      BigInt(fields[9]) > 18446744073709551615n
    )
      fail();
    slots.add(fields[0]);
    const local = address(fields[1]),
      remote = address(fields[2]);
    return {
      localAddress: local.address,
      localPort: local.port,
      remoteAddress: remote.address,
      remotePort: remote.port,
      state: fields[3],
      inode: fields[9],
      uid: fields[7],
    };
  });
  return managedWorkloadCopy(rows);
}

/** Pure tuple/FD correlation, not installed process ownership. Native collection
 * must additionally authenticate namespace/PID/start/boot/cgroup/isolation and
 * the SAME actual socket before+after. Duplicate rows/FDs remain unavailable. */
export function correlateManagedWorkloadSocket(text, fdLinks, connection) {
  const tuple = managedWorkloadConnectionSchema.parse(managedWorkloadCopy(connection));
  const links = z
    .array(
      z.strictObject({
        fd: z
          .string()
          .regex(/^(0|[1-9][0-9]*)$/u)
          .max(10),
        target: z.string().max(4096),
      }),
    )
    .max(1024)
    .parse(managedWorkloadCopy(fdLinks));
  if (new Set(links.map((link) => link.fd)).size !== links.length) fail();
  // Reverse the server socket's genuine tuple to the client's process view.
  const matches = parseManagedWorkloadTcp4Table(text).filter(
    (row) =>
      row.localAddress === tuple.remoteAddress &&
      row.localPort === tuple.remotePort &&
      row.remoteAddress === tuple.localAddress &&
      row.remotePort === tuple.localPort,
  );
  if (matches.length !== 1 || matches[0].state !== '01' || matches[0].inode === '0') fail();
  const row = matches[0];
  const owners = links.filter((link) => link.target === 'socket:[' + row.inode + ']');
  if (owners.length !== 1) fail();
  return managedWorkloadCopy({
    fd: owners[0].fd,
    inode: row.inode,
    uid: row.uid,
    connection: tuple,
  });
}

const issued = new WeakMap();
function same(a, b) {
  if (managedWorkloadDigest(a) !== managedWorkloadDigest(b)) fail();
}
export function readManagedWorkloadTransport(socket) {
  if (
    !(socket instanceof TLSSocket) ||
    !socket.authorized ||
    socket.destroyed ||
    socket.connecting ||
    socket.getProtocol() !== 'TLSv1.3'
  )
    fail();
  const connection = managedWorkloadConnectionSchema.parse({
    profile: 'LINUX_DOCKER_BRIDGE_DIRECT_TCP4_V1',
    family: socket.remoteFamily,
    remoteAddress: socket.remoteAddress,
    remotePort: socket.remotePort,
    localAddress: socket.localAddress,
    localPort: socket.localPort,
  });
  const raw = socket.getPeerCertificate(true).raw;
  if (!Buffer.isBuffer(raw) || raw.length < 1 || raw.length > 65536) fail();
  const certificate = new X509Certificate(Buffer.from(raw));
  const sans = (certificate.subjectAltName ?? '')
    .split(', ')
    .filter((value) => value.startsWith('URI:'));
  if (sans.length !== 1) fail();
  const uriSan = sans[0].slice(4);
  const identity =
    /^urn:openpc:participant:([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}):workload:([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/u.exec(
      uriSan,
    );
  if (!identity) fail();
  return managedWorkloadCopy({
    connection,
    participantId: identity[1],
    workloadId: `urn:openpc:workload:${identity[2]}`,
    uriSan,
    certificateDigest: 'sha256:' + createHash('sha256').update(certificate.raw).digest('hex'),
    keyDigest:
      'sha256:' +
      createHash('sha256')
        .update(certificate.publicKey.export({ format: 'der', type: 'spki' }))
        .digest('hex'),
    notBefore: new Date(certificate.validFrom).toISOString(),
    notAfter: new Date(certificate.validTo).toISOString(),
  });
}
async function processSocket(pid, connection) {
  const table = await readInstallationProcessTcp4Table(pid);
  const fds = await readInstallationProcessFileDescriptors(pid);
  return correlateManagedWorkloadSocket(table, fds, connection);
}
/** Historical native evidence only. This performs no registry lookup, admits
 * no workload and grants no effect. Original pins/measurement bytes stay intact;
 * the current leaf is a SEPARATE genuine TLS observation. No reader injection.
 * Two brackets cannot establish continuous/exclusive FD or private-key custody. */
export async function collectManagedWorkloadInstance(pins, otherPins, descriptor, socket, attempt) {
  const p = parseQualificationDeploymentPins(managedWorkloadCopy(pins));
  const peers = managedWorkloadCopy(otherPins).map(parseQualificationDeploymentPins);
  const d = managedWorkloadInstanceDescriptorSchema.parse(managedWorkloadCopy(descriptor));
  same(
    d,
    managedWorkloadDescriptorFromHistoricalPins(p, {
      registrationId: d.registrationId,
      instanceId: d.instanceId,
      instanceGeneration: d.instanceGeneration,
    }),
  );
  const occurrence = z
    .strictObject({
      observationId: z.uuidv7(),
      requestDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    })
    .parse(managedWorkloadCopy(attempt));
  const measurement = await withInstallationProcessObservationBudget(async () => {
    const startedAtMs = Date.now(),
      firstTransport = readManagedWorkloadTransport(socket);
    if (
      firstTransport.participantId !== d.participantId ||
      firstTransport.workloadId !== d.workloadId ||
      firstTransport.connection.remoteAddress !== p.address
    )
      fail();
    const before = await readInstallationProcessIsolation(p.installedProcess.process.pid);
    same(before, p.installedProcess);
    const firstSocket = await processSocket(before.process.pid, firstTransport.connection);
    if (firstSocket.uid !== String(before.process.uid)) fail();
    const oldHandle = await collectQualificationDeployment(
      p,
      peers,
      firstTransport.connection,
      occurrence,
    );
    const oldMeasurement = readCollectedQualificationDeployment(oldHandle);
    const lastSocket = await processSocket(before.process.pid, firstTransport.connection);
    const after = await readInstallationProcessIsolation(before.process.pid);
    const lastTransport = readManagedWorkloadTransport(socket);
    same(firstTransport, lastTransport);
    same(firstSocket, lastSocket);
    same(before, after);
    same(oldMeasurement.instance.process, before);
    if (
      before.namespaces.net !== d.networkNamespace ||
      managedWorkloadDigest(before) !== d.processIdentityDigest ||
      oldMeasurement.installationDigest !== qualificationDeploymentDigest(p)
    )
      fail();
    return managedWorkloadCopy({
      domain: 'pc.identity.workload-managed-instance.native-observation.v1',
      version: 1,
      ...occurrence,
      descriptor: d,
      descriptorDigest: managedWorkloadDigest(d),
      startedAtMs,
      completedAtMs: Date.now(),
      transport: firstTransport,
      process: before,
      socket: firstSocket,
      historicalQualification: oldMeasurement,
      registration: 'UNESTABLISHED',
      continuousOwnership: 'UNESTABLISHED',
      privateKeyCustody: 'UNESTABLISHED',
    });
  });
  // Issue only AFTER all owned IO/cleanup and the shared budget have settled.
  const handle = Object.freeze({});
  issued.set(handle, measurement);
  return handle;
}
export function readCollectedManagedWorkloadInstance(handle) {
  const value = issued.get(handle);
  if (!value) fail();
  return managedWorkloadCopy(value);
}
