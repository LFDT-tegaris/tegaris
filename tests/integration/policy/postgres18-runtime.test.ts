import { inScope } from '../../../services/module-registry/src/db/public-approval-store.js';
import { requireModuleDisablePredicates } from '../../../services/module-registry/src/db/module-disable-fence.js';
import { moduleDisableReplacementDigest } from '../../../services/module-registry/src/module-command-contract.js';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assertModuleLifecycleObservationUnchanged,
  lockModuleLifecycleReferences,
  withModuleLifecyclePreflight,
} from '../../../services/module-registry/src/db/module-lifecycle-preflight.js';
import {
  createModuleReleaseVerifier,
  moduleReleaseCoseContext,
  moduleReleasePayload,
  type ModuleReleaseBundle,
} from '../../../services/module-registry/src/domain/module-release.js';
import { resolveDependencies } from '../../../services/module-registry/src/domain/dependency-resolver.js';
import { readVerifiedModuleLifecycleSnapshot } from '../../../services/module-registry/src/db/module-lifecycle-store.js';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import { Pool, type PoolClient } from 'pg';
import { z } from 'zod';

import { encodeIdentityCredentialPayload } from '../../../packages/security-kernel/src/index.js';
import {
  buildIdentityService,
  type IdentityAuthorizationAdapter,
} from '../../../services/identity-service/src/app.js';
import {
  IdentityKernel,
  IdentityKernelError,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { authorizeLocalPolicyAction } from '../../../services/identity-service/src/domain/policy-authorization.js';
import { localPolicyAuthorizationResponse } from '../../../services/identity-service/src/local-runtime.js';
import { authorizeLocalConfigurationMutation } from '../../../services/identity-service/src/domain/local-configuration-authorization.js';
import { registerConfigurationRoutes } from '../../../services/control-api/src/configuration/http.js';
import { canonicalJson, pcCbor1 } from '../../../services/module-registry/src/domain/digest.js';
import {
  encodePolicyArtifactPayload,
  policyArtifactCoseContext,
} from '../../../services/module-registry/src/domain/policy-artifact.js';
import {
  activatePolicyGeneration,
  type PolicyActivationMutation,
} from '../../../services/module-registry/src/db/policy-store.js';
import {
  buildPolicyService,
  HttpPolicyIdentityGateway,
} from '../../../services/module-registry/src/policy-http.js';
import type { TraceSemanticRecord } from '../../../services/module-registry/src/domain/trace-authority.js';
import {
  encodePolicyActivationAuthorizationPayload,
  policyActivationAuthorizationCoseContext,
} from '../../../services/module-registry/src/domain/policy-activation-authorization.js';
import {
  createVerifiedWebAuthnAssertion,
  type IdentityTrustAdapter,
  verifiedWebAuthnAssertionDigest,
} from '../../../services/identity-service/src/domain/trust-adapter.js';

const runtimeUrl = process.env.I03_POSTGRES_RUNTIME_URL;
const adminUrl = process.env.I03_POSTGRES_ADMIN_URL;
const live = runtimeUrl !== undefined && adminUrl !== undefined;
const suite = live ? describe : describe.skip;

// These descriptors locate evidence; they never authorize DDL by themselves.
// The live verifier below binds them to the runner, kernel lock and fresh storage.
const i03FaultDescriptorSchema = z
  .object({
    root: z.string(),
    parent: z.string(),
    ownerPid: z.string().regex(/^[1-9][0-9]{0,9}$/u),
    containerId: z.string().regex(/^[0-9a-f]{64}$/u),
    adminUrl: z.string(),
    runtimeUrl: z.string(),
  })
  .strict();
type I03FaultDescriptor = z.infer<typeof i03FaultDescriptorSchema>;
function faultPrerequisite(condition: unknown, boundary: string): asserts condition {
  if (!condition) throw new Error(`BLOCKED: M1a disposable fixture ${boundary}`);
}
function parseI03FaultDescriptor(input: unknown): I03FaultDescriptor {
  const parsed = i03FaultDescriptorSchema.safeParse(input);
  faultPrerequisite(parsed.success, 'descriptor missing or malformed');
  const descriptor = parsed.data;
  faultPrerequisite(
    path.isAbsolute(descriptor.parent) &&
      path.normalize(descriptor.parent) === descriptor.parent &&
      path.dirname(descriptor.root) === descriptor.parent &&
      /^i03-owned\.[A-Za-z0-9]{8}$/u.test(path.basename(descriptor.root)) &&
      path.resolve(descriptor.root) === descriptor.root,
    'root is not the exact external runner path',
  );
  const urls = [descriptor.adminUrl, descriptor.runtimeUrl].map((text) => {
    try {
      return new URL(text);
    } catch {
      throw new Error('BLOCKED: M1a disposable fixture URL malformed');
    }
  });
  for (const [index, url] of urls.entries()) {
    faultPrerequisite(
      url.protocol === 'postgresql:' &&
        url.hostname === '127.0.0.1' &&
        /^[1-9][0-9]{0,4}$/u.test(url.port) &&
        Number(url.port) <= 65535 &&
        url.pathname === '/openpc_control' &&
        !url.search &&
        !url.hash &&
        url.password.length > 0 &&
        url.username === (index === 0 ? 'postgres' : 'openpc_i03_r8_runtime'),
      'URL is not the owned loopback database',
    );
  }
  faultPrerequisite(urls[0]!.port === urls[1]!.port, 'URL ports differ');
  return descriptor;
}
function i03FaultDescriptor() {
  return parseI03FaultDescriptor({
    root: process.env.OPENPC_I03_FIXTURE_ROOT,
    parent: process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT,
    ownerPid: process.env.OPENPC_I03_FIXTURE_OWNER_PID,
    containerId: process.env.OPENPC_I03_FIXTURE_CONTAINER_ID,
    adminUrl,
    runtimeUrl,
  });
}
function assertI03RunnerOwner(descriptor: I03FaultDescriptor) {
  const owner = Number(descriptor.ownerPid);
  let current = process.pid;
  let found = false;
  let ownerStart = '';
  for (let depth = 0; current > 1 && depth < 128; depth++) {
    const stat = readFileSync(`/proc/${current}/stat`, 'utf8');
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    faultPrerequisite(fields[0] !== 'Z', 'ancestor is no longer live');
    if (current === owner && current !== process.pid) {
      found = true;
      ownerStart = fields[19]!;
      break;
    }
    current = Number(fields[1]);
  }
  faultPrerequisite(found && /^[0-9]+$/u.test(ownerStart), 'owner is not a live runner ancestor');
  const command = readFileSync(`/proc/${owner}/cmdline`, 'utf8').split('\0');
  const cwd = readlinkSync(`/proc/${owner}/cwd`);
  faultPrerequisite(
    path.basename(readlinkSync(`/proc/${owner}/exe`)) === 'bash' &&
      command.some(
        (part) =>
          part.length > 0 &&
          path.resolve(cwd, part) ===
            path.join(
              repositoryRoot,
              'tests/integration/policy/run-postgres18-trace-owner-proof.sh',
            ),
      ),
    'ancestor is not the committed runner entrypoint',
  );
  for (const directory of [descriptor.parent, descriptor.root]) {
    const stat = lstatSync(directory);
    faultPrerequisite(
      stat.isDirectory() &&
        !stat.isSymbolicLink() &&
        realpathSync(directory) === directory &&
        stat.uid === process.getuid?.(),
      'root ownership or symlink mismatch',
    );
  }
  const relative = path.relative(repositoryRoot, descriptor.root);
  faultPrerequisite(
    relative.startsWith(`..${path.sep}`) && (lstatSync(descriptor.root).mode & 0o077) === 0,
    'root is not private external scratch',
  );
  const lockPath = path.join(descriptor.root, '.owner');
  const lock = lstatSync(lockPath);
  const fdPath = `/proc/${owner}/fd/8`;
  const fd = statSync(fdPath);
  const fdInfo = readFileSync(`/proc/${owner}/fdinfo/8`, 'utf8');
  faultPrerequisite(
    lock.isFile() &&
      !lock.isSymbolicLink() &&
      lock.nlink === 1 &&
      lock.uid === process.getuid?.() &&
      readlinkSync(fdPath) === lockPath &&
      lock.dev === fd.dev &&
      lock.ino === fd.ino &&
      /^lock:\s+\d+: FLOCK\s+ADVISORY\s+WRITE\s+.*\s0 EOF$/mu.test(fdInfo),
    'runner FD8 does not hold the exact owner lock',
  );
  // An independent open must contend: an inherited descriptor alone is not proof.
  let contended = false;
  try {
    execFileSync('flock', ['--nonblock', lockPath, 'true'], { stdio: 'ignore', timeout: 2000 });
  } catch (error) {
    contended = (error as { status?: unknown }).status === 1;
  }
  faultPrerequisite(contended, 'owner lock is not exclusively held');
  return ownerStart;
}
function fixtureDocker(args: string[]) {
  try {
    return execFileSync('docker', args, {
      encoding: 'utf8',
      timeout: 5000,
      maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    // Never report inspect output, environment, URLs or subprocess diagnostics.
    throw new Error('BLOCKED: M1a disposable fixture Docker identity unavailable');
  }
}
function fixtureDockerJson(args: string[]): unknown {
  const output = fixtureDocker(args);
  try {
    return JSON.parse(output) as unknown;
  } catch {
    throw new Error('BLOCKED: M1a disposable fixture Docker descriptor malformed');
  }
}
const i03ContainerSchema = z.object({
  Id: z.string(),
  Name: z.string(),
  Created: z.string(),
  State: z.object({
    Running: z.boolean(),
    Paused: z.boolean(),
    Restarting: z.boolean(),
    Dead: z.boolean(),
  }),
  Config: z.object({
    Image: z.string(),
    Env: z.array(z.string()),
    Labels: z.record(z.string(), z.string()),
    Volumes: z.record(z.string(), z.unknown()),
  }),
  HostConfig: z.object({
    Memory: z.number(),
    MemorySwap: z.number(),
    NanoCpus: z.number(),
    PidsLimit: z.number(),
    Binds: z.array(z.string()),
    VolumesFrom: z.array(z.string()).nullable(),
    Tmpfs: z.record(z.string(), z.string()).nullish(),
  }),
  NetworkSettings: z.object({
    Ports: z.record(
      z.string(),
      z.array(z.object({ HostIp: z.string(), HostPort: z.string() })).nullable(),
    ),
  }),
  Mounts: z.array(
    z.object({
      Type: z.string(),
      Source: z.string(),
      Destination: z.string(),
      RW: z.boolean(),
      Name: z.string().optional(),
      Driver: z.string().optional(),
    }),
  ),
});
async function assertI03FaultOwnership(descriptor: I03FaultDescriptor, admin: Pool, runtime: Pool) {
  const started = assertI03RunnerOwner(descriptor);
  const parsed = i03ContainerSchema.safeParse(
    fixtureDockerJson(['container', 'inspect', '--format', '{{json .}}', descriptor.containerId]),
  );
  faultPrerequisite(parsed.success, 'container descriptor malformed');
  const container = parsed.data;
  faultPrerequisite(
    container.Id === descriptor.containerId &&
      container.Name ===
        `/openpc-i03-r8-trace-owner-proof-${descriptor.ownerPid}-${path.basename(descriptor.root).split('.')[1]}` &&
      container.Config.Labels['io.openpc.test-owner'] === descriptor.root &&
      container.Config.Labels['io.openpc.test-owner-pid'] === descriptor.ownerPid &&
      container.Config.Labels['io.openpc.test-runner'] === 'postgres18-trace-owner-proof' &&
      container.State.Running &&
      !container.State.Paused &&
      !container.State.Restarting &&
      !container.State.Dead &&
      container.Config.Image ===
        'docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7',
    'container identity or live state mismatch',
  );
  const host = container.HostConfig;
  faultPrerequisite(
    host.Memory === 1073741824 &&
      host.MemorySwap === 1073741824 &&
      host.NanoCpus === 1000000000 &&
      host.PidsLimit === 256 &&
      !host.VolumesFrom?.length &&
      Object.keys(host.Tmpfs ?? {}).length === 0,
    'finite resource scope mismatch',
  );
  faultPrerequisite(
    JSON.stringify(container.NetworkSettings.Ports) ===
      JSON.stringify({
        '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: new URL(descriptor.adminUrl).port }],
      }),
    'database URLs do not match the only published port',
  );
  const binds = [
    [path.join(repositoryRoot, 'migrations'), '/migrations'],
    [path.join(repositoryRoot, 'deploy/compose/local/migrate.sh'), '/openpc-migrate.sh'],
  ];
  faultPrerequisite(
    host.Binds.length === 2 &&
      binds.every(
        ([source, target]) =>
          host.Binds.includes(`${source}:${target}:ro`) &&
          container.Mounts.some(
            (mount) =>
              mount.Type === 'bind' &&
              mount.Source === source &&
              mount.Destination === target &&
              !mount.RW,
          ),
      ),
    'unexpected bind storage',
  );
  const volume = container.Mounts.find((mount) => mount.Type === 'volume');
  faultPrerequisite(
    container.Mounts.length === 3 &&
      volume &&
      volume.Driver === 'local' &&
      volume.RW &&
      volume.Destination === '/var/lib/postgresql' &&
      /^[a-f0-9]{64}$/u.test(volume.Name ?? '') &&
      Object.keys(container.Config.Volumes).join() === '/var/lib/postgresql' &&
      container.Config.Env.filter((value) => value.startsWith('PGDATA=')).join() ===
        'PGDATA=/var/lib/postgresql/18/docker' &&
      container.Config.Env.filter((value) => value.startsWith('POSTGRES_DB=')).join() ===
        'POSTGRES_DB=openpc_control',
    'unknown database storage',
  );
  const volumeParsed = z
    .object({
      Name: z.string(),
      Driver: z.string(),
      Scope: z.string(),
      Mountpoint: z.string(),
      CreatedAt: z.string(),
      Options: z.record(z.string(), z.unknown()).nullable(),
      Labels: z.record(z.string(), z.unknown()).nullable(),
    })
    .safeParse(fixtureDockerJson(['volume', 'inspect', '--format', '{{json .}}', volume.Name!]));
  faultPrerequisite(volumeParsed.success, 'volume metadata unavailable');
  const storage = volumeParsed.data;
  const age = Date.parse(container.Created) - Date.parse(storage.CreatedAt);
  faultPrerequisite(
    storage.Name === volume.Name &&
      storage.Driver === 'local' &&
      storage.Scope === 'local' &&
      storage.Mountpoint === volume.Source &&
      Object.keys(storage.Options ?? {}).length === 0 &&
      Object.entries(storage.Labels ?? {}).every(
        ([key, value]) => key === 'com.docker.volume.anonymous' && value === '',
      ) &&
      Number.isFinite(age) &&
      Math.abs(age) < 5000 &&
      fixtureDocker([
        'ps',
        '--all',
        '--quiet',
        '--no-trunc',
        '--filter',
        `volume=${volume.Name}`,
      ]).trim() === descriptor.containerId,
    'storage is retained, shared or not created for this container',
  );
  // Tie both actual pool connections to the container, not merely to URL text.
  const system = fixtureDocker([
    'exec',
    descriptor.containerId,
    'psql',
    '-XAt',
    '-U',
    'postgres',
    '-d',
    'openpc_control',
    '-c',
    'select system_identifier::text from pg_control_system()',
  ]).trim();
  const database =
    await admin.query(`select current_database() database,current_user role,inet_server_port() port,
    current_setting('data_directory') directory,
    (select system_identifier::text from pg_control_system()) system`);
  faultPrerequisite(
    database.rows.length === 1 &&
      database.rows[0].database === 'openpc_control' &&
      database.rows[0].role === 'postgres' &&
      database.rows[0].port === 5432 &&
      database.rows[0].directory === '/var/lib/postgresql/18/docker' &&
      /^[0-9]+$/u.test(system) &&
      database.rows[0].system === system,
    'admin connection is not the owned server',
  );
  const runtimeIdentity =
    await runtime.query(`select current_database() database,current_user role,inet_server_port() port,
    rolsuper,rolbypassrls,pg_has_role(current_user,'openpc_control_runtime','member') runtime,
    pg_has_role(current_user,'openpc_control_owner','member') owner from pg_roles where rolname=current_user`);
  faultPrerequisite(
    runtimeIdentity.rows.length === 1 &&
      runtimeIdentity.rows[0].database === 'openpc_control' &&
      runtimeIdentity.rows[0].role === 'openpc_i03_r8_runtime' &&
      runtimeIdentity.rows[0].port === 5432 &&
      runtimeIdentity.rows[0].rolsuper === false &&
      runtimeIdentity.rows[0].rolbypassrls === false &&
      runtimeIdentity.rows[0].runtime === true &&
      runtimeIdentity.rows[0].owner === false,
    'runtime connection is not the non-bypass fixture role',
  );
  faultPrerequisite(
    assertI03RunnerOwner(descriptor) === started,
    'runner changed during verification',
  );
}

describe('M1a disposable fault descriptor denials before DDL', () => {
  const descriptor = {
    root: '/tmp/i03-owned.Abc12345',
    parent: '/tmp',
    ownerPid: '2147483647',
    containerId: 'a'.repeat(64),
    adminUrl: 'postgresql://postgres:fixture@127.0.0.1:23456/openpc_control',
    runtimeUrl: 'postgresql://openpc_i03_r8_runtime:fixture@127.0.0.1:23456/openpc_control',
  };
  it.each([
    ['missing descriptor', undefined],
    ['missing root', { ...descriptor, root: undefined }],
    ['malformed owner PID', { ...descriptor, ownerPid: '0' }],
    ['partial container identity', { ...descriptor, containerId: 'a'.repeat(12) }],
    ['normalized-away root traversal', { ...descriptor, root: '/tmp/../tmp/i03-owned.Abc12345' }],
    ['wrong fixture root family', { ...descriptor, root: '/tmp/retained.Abc12345' }],
    ['wrong external parent', { ...descriptor, parent: '/var/tmp' }],
    ['malformed URL', { ...descriptor, adminUrl: 'not-a-url' }],
    [
      'remote database',
      { ...descriptor, adminUrl: descriptor.adminUrl.replace('127.0.0.1', 'example.invalid') },
    ],
    [
      'different database',
      { ...descriptor, runtimeUrl: descriptor.runtimeUrl.replace('openpc_control', 'other') },
    ],
    [
      'mismatched port',
      { ...descriptor, runtimeUrl: descriptor.runtimeUrl.replace('23456', '23457') },
    ],
    [
      'URL options',
      { ...descriptor, runtimeUrl: `${descriptor.runtimeUrl}?options=-csearch_path=other` },
    ],
    ['wrong runtime role', { ...descriptor, runtimeUrl: descriptor.adminUrl }],
  ])('rejects %s', (_name, input) => {
    expect(() => parseI03FaultDescriptor(input)).toThrow('BLOCKED: M1a disposable fixture');
  });
  it('rejects stale and self-asserted owners before filesystem, container or SQL mutation', () => {
    for (const ownerPid of [descriptor.ownerPid, String(process.pid)]) {
      expect(() =>
        assertI03RunnerOwner(parseI03FaultDescriptor({ ...descriptor, ownerPid })),
      ).toThrow('BLOCKED: M1a disposable fixture owner is not a live runner ancestor');
    }
  });
});

const participantA = '018f0000-0000-7000-8000-000000000901';
const privacyA = '018f0000-0000-7000-8000-000000000902';
const makerA = '018f0000-0000-7000-8000-000000000903';
const checkerA = '018f0000-0000-7000-8000-000000000904';
const participantB = '018f0000-0000-7000-8000-000000000a01';
const privacyB = '018f0000-0000-7000-8000-000000000a02';
const makerB = '018f0000-0000-7000-8000-000000000a03';
const activationId = '018f0000-0000-7000-8000-000000000918';
let challengeId = '018f0000-0000-7000-8000-000000000922';
let scopeTwoChallengeId = '018f0000-0000-7000-8000-000000000936';
let scopeThreeChallengeId = '018f0000-0000-7000-8000-000000000946';
const hex = (value: string) => Buffer.from(value.repeat(64).slice(0, 64), 'hex');
const sha256 = (value: string | Buffer) => createHash('sha256').update(value).digest();
const idFromUrnForTest = (value: string) => value.slice(value.lastIndexOf(':') + 1);
const sessionId = '018f0000-0000-7000-8000-000000000920';
const makerSessionId = '018f0000-0000-7000-8000-0000000009a0';
const delegateA = '018f0000-0000-7000-8000-0000000009d1';
const delegateSessionId = '018f0000-0000-7000-8000-0000000009d2';
const webauthnOrigin = 'https://control.openpc.example';
const webauthnRpIdHash = sha256('openpc.example');
const webauthnVerifiedAtBySignature = new Map<string, string>();
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const traceCorpusLines = readFileSync(
  path.join(repositoryRoot, 'policies/modules/generated/module-trace-semantic-corpus.jsonl'),
  'utf8',
)
  .trim()
  .split('\n');
const traceCorpusRawById = new Map(
  traceCorpusLines.map((line) => {
    const record = JSON.parse(line) as TraceSemanticRecord;
    return [record.traceId, line] as const;
  }),
);
const policyStoreTraceRecords = traceCorpusLines
  .map((line) => JSON.parse(line) as TraceSemanticRecord)
  .filter(
    (record) =>
      record.targetSectionId === 'MOD-OPERATIONS' || record.targetSectionId === 'MOD-PARTICIPANT',
  );
const traceCorpusManifest = JSON.parse(
  readFileSync(
    path.join(repositoryRoot, 'policies/modules/generated/module-trace-corpus-manifest.json'),
    'utf8',
  ),
) as {
  rootCommitmentSha256: string;
  recordCommitments: Array<{
    traceId: string;
    recordDigest: string;
    rawRecordSha256: string;
  }>;
  policyStoreLiveOwner: {
    owner: string;
    operation: string;
    rowCount: number;
    accepted: number;
    rejectedFailClosed: number;
    orderedRecordDigestAggregateSha256: string;
  };
};
const signerSpki = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  'hex',
);
const signerPrivateKey = createPrivateKey({
  format: 'jwk',
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(
      '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
      'hex',
    ).toString('base64url'),
    y: Buffer.from(
      '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
      'hex',
    ).toString('base64url'),
    d: Buffer.from(
      '0000000000000000000000000000000000000000000000000000000000000001',
      'hex',
    ).toString('base64url'),
  },
});
const webauthnProofs = new Map<string, ReturnType<typeof createWebAuthnProof>>();
const activationArtifacts = new Map<
  string,
  Readonly<{
    evidenceCbor: Buffer;
    evidenceDigest: Buffer;
    coseSign1: Buffer;
    payloadCbor: Buffer;
    payloadDigest: Buffer;
    receiptDigest: Buffer;
  }>
>();
function activationArtifact(
  candidateDigest: Buffer,
  aggregateId: string,
  approvalRequestId: string,
  aggregateVersion: bigint,
) {
  const cacheKey = `${candidateDigest.toString('hex')}:${aggregateId}:${approvalRequestId}:${aggregateVersion}`;
  const cached = activationArtifacts.get(cacheKey);
  if (cached !== undefined) return cached;
  const evidenceCbor = encodePolicyActivationAuthorizationPayload({
    participantId: `urn:openpc:participant:${participantA}`,
    checkerPrincipalId: `urn:openpc:principal:${checkerA}`,
    checkerPrincipalEpoch: '6',
    operationId: 'POL-OP-ACTIVATE',
    actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
    candidateDigest,
    approvalRequestId,
    aggregateType: 'policy-activation',
    aggregateId,
    aggregateVersion: aggregateVersion.toString(),
    decision: 'APPROVE',
    issuedAt: '2026-01-01T00:00:00.000000Z',
    expiresAt: '2030-01-01T00:00:00.000000Z',
  });
  const purpose = Buffer.from(policyActivationAuthorizationCoseContext.purpose);
  const protectedHeader = Buffer.concat([
    Buffer.from(
      'a5012603776170706c69636174696f6e2f6f70656e70632b63626f720458205cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd31903e91957e6',
      'hex',
    ),
    Buffer.from([0x19, 0x03, 0xea, 0x78, purpose.length]),
    purpose,
  ]);
  const signature = sign(
    'sha256',
    Buffer.concat([
      Buffer.from([0x84, 0x6a]),
      Buffer.from('Signature1'),
      cborByteString(protectedHeader),
      Buffer.from([0x40]),
      cborByteString(evidenceCbor),
    ]),
    { key: signerPrivateKey, dsaEncoding: 'ieee-p1363' },
  );
  const coseSign1 = Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    cborByteString(protectedHeader),
    Buffer.from([0xa0]),
    cborByteString(evidenceCbor),
    cborByteString(signature),
  ]);
  const evidenceDigest = sha256(evidenceCbor);
  const artifact = Object.freeze({
    evidenceCbor,
    evidenceDigest,
    coseSign1,
    payloadCbor: evidenceCbor,
    payloadDigest: evidenceDigest,
    receiptDigest: sha256(coseSign1),
  });
  activationArtifacts.set(cacheKey, artifact);
  return artifact;
}

function cborByteString(value: Buffer): Buffer {
  if (value.length < 24) return Buffer.concat([Buffer.from([0x40 | value.length]), value]);
  if (value.length <= 0xff) return Buffer.concat([Buffer.from([0x58, value.length]), value]);
  const length = Buffer.alloc(3);
  length[0] = 0x59;
  length.writeUInt16BE(value.length, 1);
  return Buffer.concat([length, value]);
}

function policyArtifactCose(payload: Buffer): Buffer {
  const contentType = Buffer.from('application/openpc+cbor');
  const purpose = Buffer.from(policyArtifactCoseContext.purpose);
  const keyId = sha256(signerSpki);
  const protectedHeader = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x26, 0x03, 0x60 | contentType.length]),
    contentType,
    Buffer.from([0x04]),
    cborByteString(keyId),
    Buffer.from([0x19, 0x03, 0xe9, 0x19]),
    Buffer.from([
      (policyArtifactCoseContext.schemaId >> 8) & 0xff,
      policyArtifactCoseContext.schemaId & 0xff,
    ]),
    Buffer.from([0x19, 0x03, 0xea, 0x78, purpose.length]),
    purpose,
  ]);
  const signature = sign(
    'sha256',
    Buffer.concat([
      Buffer.from([0x84, 0x6a]),
      Buffer.from('Signature1'),
      cborByteString(protectedHeader),
      Buffer.from([0x40]),
      cborByteString(payload),
    ]),
    { key: signerPrivateKey, dsaEncoding: 'ieee-p1363' },
  );
  return Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    cborByteString(protectedHeader),
    Buffer.from([0xa0]),
    cborByteString(payload),
    cborByteString(signature),
  ]);
}

function identityOperationArtifact(seed: number, principalId = checkerA, authorityEpoch = '6') {
  const micros = seed.toString().padStart(6, '0');
  const evidenceCbor = encodeIdentityCredentialPayload({
    participantId: `urn:openpc:participant:${participantA}`,
    principalId: `urn:openpc:principal:${principalId}`,
    authorityEpoch,
    issuedAt: `2026-01-01T00:00:00.${micros}Z`,
    expiresAt: `2030-01-01T00:00:00.${micros}Z`,
  });
  const protectedHeader = Buffer.from(
    'a5012603776170706c69636174696f6e2f6f70656e70632b63626f720458205cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd31903e91957e51903ea781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631',
    'hex',
  );
  const signature = sign(
    'sha256',
    Buffer.concat([
      Buffer.from([0x84, 0x6a]),
      Buffer.from('Signature1'),
      cborByteString(protectedHeader),
      Buffer.from([0x40]),
      cborByteString(evidenceCbor),
    ]),
    { key: signerPrivateKey, dsaEncoding: 'ieee-p1363' },
  );
  const coseSign1 = Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    cborByteString(protectedHeader),
    Buffer.from([0xa0]),
    cborByteString(evidenceCbor),
    cborByteString(signature),
  ]);
  return { evidenceCbor, evidenceDigest: sha256(evidenceCbor), coseSign1 };
}

function createWebAuthnProof(candidateDigest: Buffer, seed: number, issuedChallenge?: string) {
  const challengeBytes = Buffer.alloc(32);
  challengeBytes.writeUInt32BE(seed, 28);
  const challenge = issuedChallenge ?? challengeBytes.toString('base64url');
  const clientDataJson = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin: webauthnOrigin }),
    'utf8',
  );
  const authenticatorData = Buffer.alloc(37);
  webauthnRpIdHash.copy(authenticatorData);
  authenticatorData[32] = 0x05;
  authenticatorData.writeUInt32BE(seed, 33);
  const signature = sign(
    'sha256',
    Buffer.concat([authenticatorData, sha256(clientDataJson)]),
    signerPrivateKey,
  );
  const webauthnVerifiedAt = new Date().toISOString();
  webauthnVerifiedAtBySignature.set(signature.toString('base64url'), webauthnVerifiedAt);
  const assertion = createVerifiedWebAuthnAssertion({
    credentialId: '018f0000-0000-7000-8000-000000000916',
    credentialPublicKeyDigest: `sha256:${sha256(signerSpki).toString('hex')}`,
    principalId: checkerA,
    sessionId,
    actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
    resourceDigest: `sha256:${candidateDigest.toString('hex')}`,
    challengeDigest: `sha256:${sha256(challenge).toString('hex')}`,
    rpIdHash: `sha256:${webauthnRpIdHash.toString('hex')}`,
    origin: webauthnOrigin,
    authenticatorDataDigest: `sha256:${sha256(authenticatorData).toString('hex')}`,
    clientDataJsonDigest: `sha256:${sha256(clientDataJson).toString('hex')}`,
    signatureDigest: `sha256:${sha256(signature).toString('hex')}`,
    signCount: String(seed),
    verifiedAt: webauthnVerifiedAt,
  });
  return {
    webauthnAssertionBindingDigest: verifiedWebAuthnAssertionDigest(assertion),
    webauthnCredentialPublicKeySpkiDer: signerSpki,
    webauthnChallenge: challenge,
    webauthnOrigin,
    webauthnAuthenticatorData: authenticatorData,
    webauthnClientDataJson: clientDataJson,
    webauthnSignature: signature,
    webauthnVerifiedAt,
  };
}

function webauthnProof(candidateDigest: Buffer, seed: number) {
  const key = `${candidateDigest.toString('hex')}:${seed}`;
  const existing = webauthnProofs.get(key);
  if (existing !== undefined) return existing;
  const proof = createWebAuthnProof(candidateDigest, seed);
  webauthnProofs.set(key, proof);
  return proof;
}

function encodedWebAuthnAssertion(proof: ReturnType<typeof createWebAuthnProof>): string {
  return JSON.stringify({
    credentialId: '018f0000-0000-7000-8000-000000000916',
    authenticatorData: proof.webauthnAuthenticatorData.toString('base64url'),
    clientDataJson: proof.webauthnClientDataJson.toString('base64url'),
    signature: proof.webauthnSignature.toString('base64url'),
  });
}

function identityTrustAdapter(): IdentityTrustAdapter {
  return {
    async exchangeAuthorizationCode() {
      return undefined;
    },
    async verifyWebAuthnAssertion(input) {
      try {
        const encoded = JSON.parse(input.assertion) as Record<string, unknown>;
        if (
          encoded.credentialId !== '018f0000-0000-7000-8000-000000000916' ||
          typeof encoded.authenticatorData !== 'string' ||
          typeof encoded.clientDataJson !== 'string' ||
          typeof encoded.signature !== 'string'
        )
          return undefined;
        const authenticatorData = Buffer.from(encoded.authenticatorData, 'base64url');
        const clientDataJson = Buffer.from(encoded.clientDataJson, 'base64url');
        const signature = Buffer.from(encoded.signature, 'base64url');
        const clientData = JSON.parse(clientDataJson.toString('utf8')) as Record<string, unknown>;
        if (
          authenticatorData.length !== 37 ||
          !authenticatorData.subarray(0, 32).equals(Buffer.from(input.rpIdHash.slice(7), 'hex')) ||
          (authenticatorData[32]! & 0x05) !== 0x05 ||
          clientData.type !== 'webauthn.get' ||
          clientData.challenge !== input.challenge ||
          clientData.origin !== input.allowedOrigin ||
          !verify(
            'sha256',
            Buffer.concat([authenticatorData, sha256(clientDataJson)]),
            createPublicKey({ key: signerSpki, format: 'der', type: 'spki' }),
            signature,
          )
        )
          return undefined;
        return createVerifiedWebAuthnAssertion({
          credentialId: String(encoded.credentialId),
          credentialPublicKeyDigest: `sha256:${sha256(signerSpki).toString('hex')}`,
          principalId: input.principalId,
          sessionId: input.sessionId,
          actionIntentId: input.actionIntentId,
          resourceDigest: input.resourceDigest,
          challengeDigest: `sha256:${sha256(input.challenge).toString('hex')}`,
          rpIdHash: input.rpIdHash,
          origin: input.allowedOrigin,
          authenticatorDataDigest: `sha256:${sha256(authenticatorData).toString('hex')}`,
          clientDataJsonDigest: `sha256:${sha256(clientDataJson).toString('hex')}`,
          signatureDigest: `sha256:${sha256(signature).toString('hex')}`,
          signCount: String(authenticatorData.readUInt32BE(33)),
          verifiedAt:
            webauthnVerifiedAtBySignature.get(signature.toString('base64url')) ??
            'INVALID_UNBOUND_VERIFICATION_TIME',
        });
      } catch {
        return undefined;
      }
    },
  };
}

let operationSequence = 0;
const mutation = (overrides: Partial<PolicyActivationMutation> = {}): PolicyActivationMutation => {
  operationSequence += 1;
  const suffix = operationSequence.toString(16).padStart(12, '0');
  const candidateDigest = overrides.candidateDigest ?? hex('11');
  const aggregateId = overrides.aggregateId ?? activationId;
  const approvalRequestId = overrides.approvalRequestId ?? '018f0000-0000-7000-8000-000000000913';
  const expectedAggregateVersion = overrides.expectedAggregateVersion ?? 1n;
  return {
    participantId: participantA,
    privacyDomainId: privacyA,
    principalId: makerA,
    checkerPrincipalId: checkerA,
    operationId: `018f1000-0000-7000-8000-${suffix}`,
    actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
    catalogOperationId: 'POL-OP-ACTIVATE',
    idempotencyKey: `i03-activation-${operationSequence}`,
    aggregateType: 'policy-activation',
    aggregateId,
    expectedAggregateVersion,
    candidateDigest,
    approvalRequestId,
    mfaChallengeId: challengeId,
    ...webauthnProof(hex('11'), 0x24),
    ...activationArtifact(
      candidateDigest,
      aggregateId,
      approvalRequestId,
      expectedAggregateVersion,
    ),
    eventId: `018f2000-0000-7000-8000-${suffix}`,
    eventType: 'openpc.policy.generation.activated.v1',
    participantEpoch: 4n,
    principalEpoch: 5n,
    checkerPrincipalEpoch: 6n,
    authorityEnvelopeId: '018f0000-0000-7000-8000-000000000914',
    authorityEpoch: 6n,
    delegationEpoch: 1n,
    envelopeRowVersion: 1n,
    assignmentId: '018f0000-0000-7000-8000-000000000915',
    assignmentRowVersion: 1n,
    checkerCredentialId: '018f0000-0000-7000-8000-000000000916',
    checkerCredentialEpoch: 3n,
    policySimulationId: '018f0000-0000-7000-8000-000000000912',
    scopeDigest: hex('31'),
    dependencyClosureDigest: hex('22'),
    exactCohortDigest: hex('23'),
    ...overrides,
  };
};

function activationHttpBody(input: PolicyActivationMutation) {
  const asDigest = (value: Buffer) => `sha256:${value.toString('hex')}`;
  const asBase64 = (value: Buffer) => value.toString('base64');
  return {
    sessionToken: `${participantA}.${makerSessionId}`,
    activationId: input.aggregateId,
    principalId: input.principalId,
    checkerPrincipalId: input.checkerPrincipalId,
    catalogOperationId: input.catalogOperationId,
    actionIntentId: input.actionIntentId,
    idempotencyKey: input.idempotencyKey,
    aggregateType: input.aggregateType,
    aggregateId: input.aggregateId,
    expectedAggregateVersion: input.expectedAggregateVersion.toString(),
    candidateDigest: asDigest(input.candidateDigest),
    approvalRequestId: input.approvalRequestId,
    mfaChallengeId: input.mfaChallengeId,
    webauthnAssertionBindingDigest: asDigest(input.webauthnAssertionBindingDigest),
    evidenceCbor: asBase64(input.evidenceCbor),
    evidenceDigest: asDigest(input.evidenceDigest),
    coseSign1: asBase64(input.coseSign1),
    payloadCbor: asBase64(input.payloadCbor),
    payloadDigest: asDigest(input.payloadDigest),
    eventId: input.eventId,
    eventType: input.eventType,
    participantEpoch: input.participantEpoch.toString(),
    principalEpoch: input.principalEpoch.toString(),
    checkerPrincipalEpoch: input.checkerPrincipalEpoch.toString(),
    authorityEnvelopeId: input.authorityEnvelopeId,
    authorityEpoch: input.authorityEpoch.toString(),
    delegationEpoch: input.delegationEpoch.toString(),
    envelopeRowVersion: input.envelopeRowVersion.toString(),
    assignmentId: input.assignmentId,
    assignmentRowVersion: input.assignmentRowVersion.toString(),
    checkerCredentialId: input.checkerCredentialId,
    checkerCredentialEpoch: input.checkerCredentialEpoch.toString(),
    webauthnCredentialPublicKeySpkiDer: asBase64(input.webauthnCredentialPublicKeySpkiDer),
    webauthnChallenge: input.webauthnChallenge,
    webauthnOrigin: input.webauthnOrigin,
    webauthnAuthenticatorData: asBase64(input.webauthnAuthenticatorData),
    webauthnClientDataJson: asBase64(input.webauthnClientDataJson),
    webauthnSignature: asBase64(input.webauthnSignature),
    webauthnVerifiedAt: input.webauthnVerifiedAt,
    policySimulationId: input.policySimulationId,
    scopeDigest: asDigest(input.scopeDigest),
    dependencyClosureDigest: asDigest(input.dependencyClosureDigest),
    exactCohortDigest: asDigest(input.exactCohortDigest),
    receiptDigest: asDigest(input.receiptDigest),
  };
}

let baselineActivationHttpBody: ReturnType<typeof activationHttpBody> | undefined;

type PolicyStoreTraceFixture = {
  policyId: string;
  policyVersionId: string;
  simulationId: string;
  approvalRequestId: string;
  generationId: string;
  activationId: string;
  challengeId: string;
  envelopeId: string;
  assignmentId: string;
  operationId: string;
  eventId: string;
  candidateDigest: Buffer;
  scopeDigest: Buffer;
  dependencyClosureDigest: Buffer;
  cohortDigest: Buffer;
  generationDigest: Buffer;
};

function traceUuid(record: TraceSemanticRecord, slot: string): string {
  const suffix = sha256(`${record.recordDigest}:${slot}`).toString('hex').slice(0, 12);
  return `018f8000-0000-7000-8000-${suffix}`;
}

function policyStoreTraceFixture(record: TraceSemanticRecord): PolicyStoreTraceFixture {
  const ownerInput = record.productInput.ownerInput;
  if (ownerInput.kind !== 'POLICY_STORE_ACTIVATION_INPUT')
    throw new Error(`policy-store owner input missing: ${record.traceId}`);
  return {
    policyId: traceUuid(record, 'policy'),
    policyVersionId: traceUuid(record, 'version'),
    simulationId: traceUuid(record, 'simulation'),
    approvalRequestId: ownerInput.approvalRequestId,
    generationId: traceUuid(record, 'generation'),
    activationId: ownerInput.aggregateId,
    challengeId: traceUuid(record, 'challenge'),
    envelopeId: traceUuid(record, 'envelope'),
    assignmentId: traceUuid(record, 'assignment'),
    operationId: traceUuid(record, 'operation'),
    eventId: traceUuid(record, 'event'),
    candidateDigest: Buffer.from(ownerInput.candidateDigest, 'hex'),
    scopeDigest: sha256(`scope:${record.recordDigest}`),
    dependencyClosureDigest: sha256(`dependency:${record.recordDigest}`),
    cohortDigest: sha256(`cohort:${record.recordDigest}`),
    generationDigest: sha256(`generation:${record.recordDigest}`),
  };
}

async function insertPolicyStoreTraceFixture(
  admin: Pool,
  record: TraceSemanticRecord,
  fixture: PolicyStoreTraceFixture,
  proof: ReturnType<typeof createWebAuthnProof>,
  artifacts: ReturnType<typeof activationArtifact>,
): Promise<void> {
  const decision = record.productInput.mutation === 'DECISION_SUBSTITUTION' ? 'REJECT' : 'APPROVE';
  const client = await admin.connect();
  try {
    await client.query('begin');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-POLICY_ACTIVATE_RELEASE-V1',true)",
      [participantA, privacyA],
    );
    await client.query(
      `insert into control.mfa_challenge(
         mfa_challenge_id,participant_id,session_id,principal_id,action_intent_id,
         resource_digest,challenge_digest,rp_id_hash,expires_at)
       values($1,$2,$3,$4,'ACT-POLICY_ACTIVATE_RELEASE-V1',$5,$6,$7,
         clock_timestamp()+interval '30 minutes')`,
      [
        fixture.challengeId,
        participantA,
        sessionId,
        checkerA,
        fixture.candidateDigest,
        sha256(proof.webauthnChallenge),
        webauthnRpIdHash,
      ],
    );
    await client.query(
      `insert into control.policy(policy_id,participant_id,privacy_domain_id,policy_name)
       values($1,$2,$3,$4)`,
      [fixture.policyId, participantA, privacyA, `I03 trace ${record.traceId}`],
    );
    await client.query(
      `insert into control.policy_version(
         policy_version_id,policy_id,participant_id,privacy_domain_id,version,schema_digest,
         semantic_cbor,semantic_digest,cose_sign1,created_by_principal_id)
       values($1,$2,$3,$4,'1.0.0',$5,decode('a0','hex'),$6,
         decode('d28440a04040','hex'),$7)`,
      [
        fixture.policyVersionId,
        fixture.policyId,
        participantA,
        privacyA,
        sha256(`schema:${record.recordDigest}`),
        fixture.candidateDigest,
        makerA,
      ],
    );
    await client.query(
      `insert into control.authority_envelope(
         authority_envelope_id,participant_id,principal_id,maker_principal_id,
         checker_principal_id,authority_epoch,delegation_epoch,state,valid_from,valid_until,
         semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,
         resource_ids,risk_classes,maker_checker_required,step_up_required,
         onward_delegation_depth)
       values($1,$2,$3,$4,$3,6,1,'ACTIVE',clock_timestamp()-interval '1 hour',
         clock_timestamp()+interval '1 hour',decode('a0','hex'),$5,
         decode('d28440a04040','hex'),array[$6]::uuid[],
         array['ACT-POLICY_ACTIVATE_RELEASE-V1'],array[$7]::uuid[],array['HIGH'],true,true,0)`,
      [
        fixture.envelopeId,
        participantA,
        checkerA,
        makerA,
        sha256(`envelope:${record.recordDigest}`),
        privacyA,
        fixture.policyVersionId,
      ],
    );
    await client.query(
      `insert into control.assignment(
         assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
         scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
         action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
         onward_delegation_depth)
       values($1,$2,$3,$4,1,$5,
         tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),
         'ACTIVE',$6,array[$7]::uuid[],array['ACT-POLICY_ACTIVATE_RELEASE-V1'],
         array[$8]::uuid[],array['HIGH'],true,true,0)`,
      [
        fixture.assignmentId,
        participantA,
        checkerA,
        fixture.envelopeId,
        fixture.scopeDigest,
        makerA,
        privacyA,
        fixture.policyVersionId,
      ],
    );
    const factDigest = sha256(`fact:${record.recordDigest}`);
    await client.query(
      `insert into control.policy_simulation(
         simulation_id,participant_id,privacy_domain_id,policy_version_id,input_digest,
         result_digest,fact_generation_digest,dependency_closure_digest,truth_state,
         result_document,completed_at)
       values($1,$2,$3,$4,$5,$6,$7,$8,'SUCCESS',
         '{"authority":"SIMULATION_ONLY","truthState":"SUCCESS"}'::jsonb,clock_timestamp())`,
      [
        fixture.simulationId,
        participantA,
        privacyA,
        fixture.policyVersionId,
        fixture.candidateDigest,
        sha256(`result:${record.recordDigest}`),
        factDigest,
        fixture.dependencyClosureDigest,
      ],
    );
    await client.query(
      `insert into control.approval_request(
         approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
         subject_id,subject_digest,subject_version,maker_principal_id,required_approvals,
         state,expires_at)
       values($1,$2,$3,'ACT-POLICY_APPROVE_REQUEST-V1','policy-version',$4,$5,1,$6,1,
         'APPROVED',clock_timestamp()+interval '30 minutes')`,
      [
        fixture.approvalRequestId,
        participantA,
        privacyA,
        fixture.policyVersionId,
        fixture.candidateDigest,
        makerA,
      ],
    );
    await client.query(
      `insert into control.approval_decision_record(
         participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
         approver_principal_epoch,approver_authority_envelope_id,approver_envelope_epoch,
         approver_assignment_id,signer_credential_id,aggregate_version,candidate_digest,
         decision,decision_digest,evidence_cbor,cose_sign1)
       values($1,$2,$3,$4,6,$5,6,$6,$7,1,$8,$9,$10,$11,$12)`,
      [
        participantA,
        privacyA,
        fixture.approvalRequestId,
        checkerA,
        fixture.envelopeId,
        fixture.assignmentId,
        '018f0000-0000-7000-8000-000000000916',
        fixture.candidateDigest,
        decision,
        sha256(`${decision}:${record.recordDigest}`),
        artifacts.evidenceCbor,
        artifacts.coseSign1,
      ],
    );
    await client.query(
      `insert into control.policy_generation(
         policy_generation_id,participant_id,privacy_domain_id,policy_version_id,simulation_id,
         approval_request_id,generation,scope_digest,generation_digest,fact_generation_digest,
         artifact_digest,compiler_manifest_digest,dependency_closure_digest,state)
       values($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,$11,$12,'PREPARED')`,
      [
        fixture.generationId,
        participantA,
        privacyA,
        fixture.policyVersionId,
        fixture.simulationId,
        fixture.approvalRequestId,
        fixture.scopeDigest,
        fixture.generationDigest,
        factDigest,
        sha256(`artifact:${record.recordDigest}`),
        sha256(`compiler:${record.recordDigest}`),
        fixture.dependencyClosureDigest,
      ],
    );
    await client.query(
      `insert into control.policy_activation(
         policy_activation_id,participant_id,privacy_domain_id,policy_generation_id,
         approval_request_id,mfa_challenge_id,exact_cohort_digest,
         webauthn_assertion_binding_digest,state)
       values($1,$2,$3,$4,$5,$6,$7,$8,'PREPARED')`,
      [
        fixture.activationId,
        participantA,
        privacyA,
        fixture.generationId,
        fixture.approvalRequestId,
        fixture.challengeId,
        fixture.cohortDigest,
        proof.webauthnAssertionBindingDigest,
      ],
    );
    await client.query(
      `insert into control.policy_activation_prerequisite(
         policy_activation_id,participant_id,privacy_domain_id,prerequisite_type,
         prerequisite_subject_digest,receipt_digest,ready,observed_at)
       select $1::uuid,$2::uuid,$3::uuid,prerequisite,
         case prerequisite when 'SIMULATION' then $4::bytea when 'APPROVAL' then $4::bytea
           when 'FACT_READINESS' then $5::bytea when 'FLEET_READY' then $6::bytea
           when 'DEPENDENCY_CLOSURE' then $7::bytea else $8::bytea end,
         decode(md5($1::text || prerequisite::text) || md5(prerequisite::text || $1::text),'hex'),
         true,clock_timestamp()
       from unnest(enum_range(null::control.policy_prerequisite_type)) prerequisite`,
      [
        fixture.activationId,
        participantA,
        privacyA,
        fixture.candidateDigest,
        factDigest,
        fixture.cohortDigest,
        fixture.dependencyClosureDigest,
        fixture.generationDigest,
      ],
    );
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
}

function tracePolicyMutation(
  record: TraceSemanticRecord,
  fixture: PolicyStoreTraceFixture,
  proof: ReturnType<typeof createWebAuthnProof>,
  artifacts: ReturnType<typeof activationArtifact>,
): PolicyActivationMutation {
  const input: PolicyActivationMutation = {
    participantId: participantA,
    privacyDomainId: privacyA,
    principalId: makerA,
    checkerPrincipalId: checkerA,
    operationId: fixture.operationId,
    actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
    catalogOperationId: 'POL-OP-ACTIVATE',
    idempotencyKey: `i03-trace-${record.traceId}`,
    aggregateType: 'policy-activation',
    aggregateId: fixture.activationId,
    expectedAggregateVersion: 1n,
    candidateDigest: fixture.candidateDigest,
    approvalRequestId: fixture.approvalRequestId,
    mfaChallengeId: fixture.challengeId,
    ...proof,
    ...artifacts,
    eventId: fixture.eventId,
    eventType: 'openpc.policy.generation.activated.v1',
    participantEpoch: 4n,
    principalEpoch: 5n,
    checkerPrincipalEpoch: 6n,
    authorityEnvelopeId: fixture.envelopeId,
    authorityEpoch: 6n,
    delegationEpoch: 1n,
    envelopeRowVersion: 1n,
    assignmentId: fixture.assignmentId,
    assignmentRowVersion: 1n,
    checkerCredentialId: '018f0000-0000-7000-8000-000000000916',
    checkerCredentialEpoch: 3n,
    policySimulationId: fixture.simulationId,
    scopeDigest: fixture.scopeDigest,
    dependencyClosureDigest: fixture.dependencyClosureDigest,
    exactCohortDigest: fixture.cohortDigest,
  };
  const replacement = traceUuid(record, 'substitution');
  switch (record.productInput.mutation) {
    case 'NONE':
    case 'DECISION_SUBSTITUTION':
      break;
    case 'RECEIPT_DIGEST_MISMATCH':
      input.receiptDigest = Buffer.alloc(32);
      break;
    case 'CANDIDATE_SUBSTITUTION':
      input.candidateDigest = sha256(`candidate-substitution:${record.recordDigest}`);
      break;
    case 'ACTION_SUBSTITUTION':
      input.actionIntentId = 'ACT-POLICY_APPROVE_REQUEST-V1';
      break;
    case 'APPROVAL_SUBSTITUTION':
      input.approvalRequestId = replacement;
      break;
    case 'AGGREGATE_SUBSTITUTION':
      input.aggregateId = replacement;
      break;
    case 'COSE_SIGNATURE_INVALID':
      input.coseSign1 = Buffer.from(input.coseSign1);
      input.coseSign1[input.coseSign1.length - 1] ^= 1;
      break;
    case 'EVIDENCE_DIGEST_MISMATCH':
      input.evidenceDigest = Buffer.alloc(32);
      break;
    case 'PARTICIPANT_SUBSTITUTION':
      input.participantId = participantB;
      break;
    case 'CHECKER_SUBSTITUTION':
      input.checkerPrincipalId = makerA;
      break;
    case 'PRINCIPAL_EPOCH_STALE':
      input.checkerPrincipalEpoch = 5n;
      break;
    case 'CREDENTIAL_SUBSTITUTION':
      input.checkerCredentialId = replacement;
      break;
    case 'CHALLENGE_SUBSTITUTION':
      input.mfaChallengeId = replacement;
      break;
    case 'PRIVACY_DOMAIN_SUBSTITUTION':
      input.privacyDomainId = privacyB;
      break;
    case 'ASSIGNMENT_SUBSTITUTION':
      input.assignmentId = replacement;
      break;
    case 'WEBAUTHN_PROOF_REPLAY':
      input.webauthnAssertionBindingDigest = sha256(`replayed-proof:${record.recordDigest}`);
      break;
    default:
      throw new Error(`unsupported policy-store trace mutation: ${record.productInput.mutation}`);
  }
  return input;
}

suite.sequential('I03 PostgreSQL 18.6 non-bypass policy activation', () => {
  const runtime = new Pool({ connectionString: runtimeUrl });
  const admin = new Pool({ connectionString: adminUrl });
  let catalogRestorationFailure: unknown;
  beforeEach(() => {
    if (catalogRestorationFailure !== undefined) {
      throw new Error(
        'BLOCKED: M1a catalog restoration is unverified; disposable fixture cannot be reused',
        {
          cause: catalogRestorationFailure,
        },
      );
    }
  });

  async function verifyCheckerStepUp(
    kernel: IdentityKernel,
    actionIntentId: string,
    resourceId: string,
    resourceDigest: string,
    seed: number,
  ) {
    const sessionToken = `${participantA}.${sessionId}`;
    const host = new URL(webauthnOrigin).host;
    const artifact = identityOperationArtifact(seed);
    const app = buildIdentityService(kernel, identityTrustAdapter(), undefined, {
      async authorize(input) {
        await authorizeLocalPolicyAction(runtime, kernel, {
          sessionToken: input.actor.sessionToken,
          privacyDomainId: privacyA,
          actionIntentId: input.actionIntentId,
          resourceId: input.resourceId,
          stepUpRequired: false,
        });
        if (input.candidateDigest === undefined) return { allowed: true };
        return {
          allowed: true,
          signerCredentialId: '018f0000-0000-7000-8000-000000000916',
          privacyDomainId: privacyA,
          evidenceCbor: artifact.evidenceCbor,
          evidenceDigest: artifact.evidenceDigest,
          coseSign1: artifact.coseSign1,
        };
      },
    });
    try {
      const headers = {
        'cookie': `__Host-openpc_session=${sessionToken}`,
        'origin': webauthnOrigin,
        host,
        'x-csrf-token': await kernel.csrfToken(sessionToken, actionIntentId, webauthnOrigin, host),
      };
      const payload = {
        actionIntentId,
        resourceId,
        resourceDigest,
        rpIdHash: `sha256:${webauthnRpIdHash.toString('hex')}`,
      };
      const challengeResponse = await app.inject({
        method: 'POST',
        url: '/v1/identity/webauthn/assertion/challenge',
        headers,
        payload,
      });
      expect(challengeResponse.statusCode, challengeResponse.body).toBe(200);
      const challenge = (challengeResponse.json() as { challenge: string }).challenge;
      const proof = createWebAuthnProof(
        Buffer.from(resourceDigest.slice(7), 'hex'),
        seed,
        challenge,
      );
      const revision = (
        await admin.query<{ row_version: string }>(
          'select row_version::text from control.session where participant_id=$1 and session_id=$2',
          [participantA, sessionId],
        )
      ).rows[0]?.row_version;
      if (revision === undefined) throw new Error('missing checker session');
      const verified = await app.inject({
        method: 'POST',
        url: '/v1/identity/webauthn/assertion/verify',
        headers: {
          ...headers,
          'idempotency-key': `policy-http-step-up-${seed}`,
          'x-openpc-aggregate-version': revision,
          'openpc-action-intent-digest': await kernel.actionIntentSemanticDigest(
            sessionToken,
            'ACT-IDENTITY_UPDATE_STEP_UP-V1',
          ),
        },
        payload: { ...payload, challenge, assertion: encodedWebAuthnAssertion(proof) },
      });
      expect(verified.statusCode, verified.body).toBe(200);
    } finally {
      await app.close();
    }
  }

  beforeAll(async () => {
    expect(
      (await admin.query(`select current_setting('server_version_num')::int version`)).rows[0],
    ).toMatchObject({ version: 180006 });
    await admin.query(
      `update control.credential set public_key_digest=$1,public_key_spki_der=$2
       where credential_id='018f0000-0000-7000-8000-000000000916'`,
      [sha256(signerSpki), signerSpki],
    );
    await admin.query(
      `update control.session set opaque_token_digest=$1
        where participant_id=$2 and session_id=$3`,
      [sha256(`${participantA}.${sessionId}`), participantA, sessionId],
    );
    await admin.query(
      `insert into control.action_intent
         (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
          step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
       values
         ('ACT-MODULES_READ_RESOURCE-V1','modules','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','READ_MODULES'),
         ('ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1','policy-version','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','POLICY_MUTATION'),
         ('ACT-POLICY_VERSIONS_READ_RESOURCE-V1','policy-version','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','POLICY_READ'),
         ('ACT-POLICY_CREATE_SIMULATION-V1','policy','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','POLICY_SIMULATION'),
         ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','approval-requests','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','CREATE_APPROVAL_REQUESTS'),
         ('ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1','approval-requests','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_APPROVAL_REQUESTS'),
         ('ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','approval-requests','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_APPROVAL_REQUESTS'),
         ('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','approval-requests','UPDATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_APPROVAL_REQUESTS'),
         ('ACT-POLICY_APPROVE_REQUEST-V1','approval-request','APPROVE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','APPROVE_APPROVAL_REQUEST'),
         ('ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1','release-bundles','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CREATE_RELEASE_BUNDLE'),
         ('ACT-RELEASE_BUNDLES_READ_COLLECTION-V1','release-bundles','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_RELEASE_BUNDLE'),
         ('ACT-RELEASE_BUNDLES_READ_RESOURCE-V1','release-bundles','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','READ_RELEASE_BUNDLE'),
         ('ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1','release-bundles','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','UPDATE_RELEASE_BUNDLE'),
         ('ACT-POLICY_ACTIVATE_PUBLISH-V1','release-bundle','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','PUBLISH_RELEASE_BUNDLE'),
         ('ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1','activation-occurrences','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CREATE_ACTIVATION_OCCURRENCE'),
         ('ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1','activation-occurrences','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_ACTIVATION_OCCURRENCE'),
         ('ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1','activation-occurrences','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','READ_ACTIVATION_OCCURRENCE'),
         ('ACT-ACTIVATION_OCCURRENCES_UPDATE_RESOURCE-V1','activation-occurrences','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','UPDATE_ACTIVATION_OCCURRENCE'),
         ('ACT-POLICY_ACTIVATE_RELEASE-V1','release','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','ACTIVATE_RELEASE'),
         ('ACT-FLEET_RECOVER_OCCURRENCE-V1','activation-occurrence','RECOVER','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RECOVER_ACTIVATION_OCCURRENCE'),
         ('ACT-POLICY_ROLLBACK_RELEASE-V1','release','ROLLBACK','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','ROLLBACK_RELEASE'),
         ('ACT-POLICY_READ_EFFECTIVE_ACCESS-V1','policy','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','POLICY_EVALUATION'),
         ('ACT-WORK_ITEMS_CREATE_RESOURCE-V1','work-items','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','CREATE_WORK_ITEMS'),
         ('ACT-WORK_ITEMS_READ_COLLECTION-V1','work-items','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_WORK_ITEMS'),
         ('ACT-WORK_ITEMS_READ_RESOURCE-V1','work-items','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_WORK_ITEMS'),
         ('ACT-WORK_ITEMS_UPDATE_RESOURCE-V1','work-items','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_WORK_ITEMS'),
         ('ACT-OPERATIONS_UPDATE_CLAIM-V1','work-item','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_WORK_ITEM'),
         ('ACT-OPERATIONS_UPDATE_COMPLETE-V1','work-item','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_WORK_ITEM'),
         ('ACT-OPERATIONS_READ_OPERATION-V1','operations','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','READ_OPERATIONS')
       on conflict (action_intent_id) do update set
         resource_type=excluded.resource_type,operation_class=excluded.operation_class,
         risk_class=excluded.risk_class,maker_checker_required=excluded.maker_checker_required,
         step_up_required=excluded.step_up_required,idempotency_required=excluded.idempotency_required,
         existence_disclosure=excluded.existence_disclosure,
         payload_disclosure=excluded.payload_disclosure,evidence_class=excluded.evidence_class`,
    );
    await admin.query(
      `insert into control.authority_envelope(
         authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
         authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
         semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
         risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
       values('018f0000-0000-7000-8000-0000000009a1',$1,$2,$2,$3,5,1,'ACTIVE',
              clock_timestamp()-interval '1 hour',clock_timestamp()+interval '4 hours',
              decode('a0','hex'),decode(repeat('a1',32),'hex'),decode('d28440a04040','hex'),
              array[$4]::text[],array[
                'ACT-MODULES_READ_RESOURCE-V1',
                'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1','ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
                'ACT-POLICY_CREATE_SIMULATION-V1','ACT-POLICY_APPROVE_REQUEST-V1',
                'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
                'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
                'ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1','ACT-RELEASE_BUNDLES_READ_COLLECTION-V1',
                'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1','ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1',
                'ACT-POLICY_ACTIVATE_PUBLISH-V1',
                'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
                'ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1',
                'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1',
                'ACT-ACTIVATION_OCCURRENCES_UPDATE_RESOURCE-V1',
                'ACT-WORK_ITEMS_CREATE_RESOURCE-V1','ACT-WORK_ITEMS_READ_COLLECTION-V1',
                'ACT-WORK_ITEMS_READ_RESOURCE-V1','ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
                'ACT-OPERATIONS_UPDATE_CLAIM-V1','ACT-OPERATIONS_UPDATE_COMPLETE-V1',
                'ACT-OPERATIONS_READ_OPERATION-V1',
                'ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
                'ACT-IDENTITY_UPDATE_STEP_UP-V1'
              ]::text[],array['*']::text[],array['LOW','STANDARD','HIGH']::text[],true,false,1)
       on conflict (authority_envelope_id) do nothing`,
      [participantA, makerA, checkerA, privacyA],
    );
    await admin.query(
      `insert into control.assignment(
         assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
         scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
         action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
         onward_delegation_depth)
       values('018f0000-0000-7000-8000-0000000009a2',$1,$2,
              '018f0000-0000-7000-8000-0000000009a1',1,decode(repeat('a2',32),'hex'),
              tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '4 hours','[)'),
              'ACTIVE',$2,array[$3]::text[],array[
                'ACT-MODULES_READ_RESOURCE-V1',
                'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1','ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
                'ACT-POLICY_CREATE_SIMULATION-V1','ACT-POLICY_APPROVE_REQUEST-V1',
                'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
                'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
                'ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1','ACT-RELEASE_BUNDLES_READ_COLLECTION-V1',
                'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1','ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1',
                'ACT-POLICY_ACTIVATE_PUBLISH-V1',
                'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
                'ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1',
                'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1',
                'ACT-ACTIVATION_OCCURRENCES_UPDATE_RESOURCE-V1',
                'ACT-WORK_ITEMS_CREATE_RESOURCE-V1','ACT-WORK_ITEMS_READ_COLLECTION-V1',
                'ACT-WORK_ITEMS_READ_RESOURCE-V1','ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
                'ACT-OPERATIONS_UPDATE_CLAIM-V1','ACT-OPERATIONS_UPDATE_COMPLETE-V1',
                'ACT-OPERATIONS_READ_OPERATION-V1',
                'ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
                'ACT-IDENTITY_UPDATE_STEP_UP-V1'
              ]::text[],array['*']::text[],array['LOW','STANDARD','HIGH']::text[],true,false,1)
       on conflict (assignment_id) do nothing`,
      [participantA, makerA, privacyA],
    );
    await admin.query(
      `insert into control.session(
         session_id,participant_id,principal_id,opaque_token_digest,state,authority_epoch,
         delegation_epoch,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,
         step_up_verified_at,client_fingerprint_digest,participant_epoch,session_epoch,
         refresh_family_id,refresh_token_digest,csrf_secret)
       values($1,$2,$3,decode(repeat('a3',32),'hex'),'ACTIVE',5,1,
              statement_timestamp()-interval '5 minutes',statement_timestamp()-interval '1 minute',
              statement_timestamp()+interval '29 minutes',statement_timestamp()+interval '11 hours 55 minutes',
              statement_timestamp()-interval '1 minute',decode(repeat('a4',32),'hex'),4,1,
              '018f0000-0000-7000-8000-0000000009a3',decode(repeat('a5',32),'hex'),
              decode(repeat('a6',32),'hex'))
       on conflict (session_id) do nothing`,
      [makerSessionId, participantA, makerA],
    );
    await admin.query(
      `insert into control.credential(
         credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,
         state,valid_from,credential_epoch)
       values('018f0000-0000-7000-8000-0000000009e3',$1,$2,'WEBAUTHN',$3,$4,
              'ACTIVE',clock_timestamp()-interval '1 hour',1)
       on conflict (credential_id) do nothing`,
      [participantA, makerA, sha256(signerSpki), signerSpki],
    );
    await admin.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
       values($1,$2,'USER','Delegated policy reader','ACTIVE',7)
       on conflict (principal_id) do nothing`,
      [delegateA, participantA],
    );
    await admin.query(
      `insert into control.delegation(
         delegation_id,participant_id,parent_assignment_id,grantor_principal_id,
         delegate_principal_id,delegation_epoch,scope_digest,privacy_domain_ids,
         action_intent_ids,resource_ids,risk_classes,maker_checker_required,
         step_up_required,onward_delegation_depth,valid_during,state)
       values('018f0000-0000-7000-8000-0000000009d3',$1,
              '018f0000-0000-7000-8000-0000000009a2',$2,$3,2,
              decode(repeat('d3',32),'hex'),array[$4]::text[],
              array['ACT-POLICY_VERSIONS_READ_RESOURCE-V1']::text[],array['*']::text[],
              array['LOW']::text[],false,false,0,
              tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '4 hours','[)'),
              'ACTIVE') on conflict (delegation_id) do nothing`,
      [participantA, makerA, delegateA, privacyA],
    );
    await admin.query(
      `insert into control.session(
         session_id,participant_id,principal_id,opaque_token_digest,state,authority_epoch,
         delegation_epoch,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,
         client_fingerprint_digest,participant_epoch,session_epoch,refresh_family_id,
         refresh_token_digest,csrf_secret)
       values($1,$2,$3,decode(repeat('d4',32),'hex'),'ACTIVE',7,2,
              statement_timestamp()-interval '5 minutes',statement_timestamp()-interval '1 minute',
              statement_timestamp()+interval '29 minutes',statement_timestamp()+interval '11 hours 55 minutes',
              decode(repeat('d5',32),'hex'),4,1,
              '018f0000-0000-7000-8000-0000000009d4',decode(repeat('d6',32),'hex'),
              decode(repeat('d7',32),'hex')) on conflict (session_id) do nothing`,
      [delegateSessionId, participantA, delegateA],
    );
    for (const fixtureSessionId of [sessionId, makerSessionId, delegateSessionId]) {
      await admin.query(
        `update control.session set opaque_token_digest=$1,
           context_mode='PARTICIPANT',privacy_domain_id=$4
          where participant_id=$2 and session_id=$3`,
        [sha256(`${participantA}.${fixtureSessionId}`), participantA, fixtureSessionId, privacyA],
      );
    }
    await admin.query(
      `insert into control.authority_envelope(
         authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
         authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
         semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
         risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
       values('018f0000-0000-7000-8000-0000000009e1',$1,$2,$3,$2,6,1,'ACTIVE',
              clock_timestamp()-interval '1 hour',clock_timestamp()+interval '4 hours',
              decode('a0','hex'),decode(repeat('e1',32),'hex'),decode('d28440a04040','hex'),
              array[$4]::text[],array['ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_ACTIVATE_PUBLISH-V1',
                'ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-FLEET_RECOVER_OCCURRENCE-V1',
                'ACT-POLICY_ROLLBACK_RELEASE-V1']::text[],
              array['*']::text[],array['HIGH']::text[],true,true,0)
       on conflict (authority_envelope_id) do nothing`,
      [participantA, checkerA, makerA, privacyA],
    );
    await admin.query(
      `insert into control.assignment(
         assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
         scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
         action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
         onward_delegation_depth)
       values('018f0000-0000-7000-8000-0000000009e2',$1,$2,
              '018f0000-0000-7000-8000-0000000009e1',1,decode(repeat('e2',32),'hex'),
              tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '4 hours','[)'),
              'ACTIVE',$3,array[$4]::text[],array['ACT-POLICY_APPROVE_REQUEST-V1','ACT-POLICY_ACTIVATE_PUBLISH-V1',
                'ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-FLEET_RECOVER_OCCURRENCE-V1',
                'ACT-POLICY_ROLLBACK_RELEASE-V1']::text[],
              array['*']::text[],array['HIGH']::text[],true,true,0)
       on conflict (assignment_id) do nothing`,
      [participantA, checkerA, makerA, privacyA],
    );
    let authorizedArtifact = identityOperationArtifact(0x24);
    const fixtureIdentityKernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    let observedAuthorizationDigest: string | undefined;
    const authorization: IdentityAuthorizationAdapter = {
      async authorize(input) {
        if (input.candidateDigest === undefined) {
          await authorizeLocalPolicyAction(runtime, fixtureIdentityKernel, {
            sessionToken: input.actor.sessionToken,
            privacyDomainId: privacyA,
            actionIntentId: input.actionIntentId,
            resourceId: input.resourceId,
            stepUpRequired: false,
          });
          return { allowed: true };
        }
        expect(input.actionIntentId).toBe('ACT-IDENTITY_UPDATE_STEP_UP-V1');
        expect(input.resourceId).toBe(sessionId);
        observedAuthorizationDigest = input.candidateDigest;
        expect(input.makerCheckerRequired).toBe(false);
        expect(input.stepUpRequired).toBe(false);
        return {
          allowed: true,
          signerCredentialId: '018f0000-0000-7000-8000-000000000916',
          privacyDomainId: privacyA,
          evidenceCbor: authorizedArtifact.evidenceCbor,
          evidenceDigest: authorizedArtifact.evidenceDigest,
          coseSign1: authorizedArtifact.coseSign1,
        };
      },
    };
    const identityApp = buildIdentityService(
      fixtureIdentityKernel,
      identityTrustAdapter(),
      undefined,
      authorization,
    );
    const proofs = [
      {
        activationId,
        candidateDigest: hex('11'),
        seed: 0x24,
        approvalRequestId: '018f0000-0000-7000-8000-000000000913',
        assignmentId: '018f0000-0000-7000-8000-000000000915',
      },
      {
        activationId: '018f0000-0000-7000-8000-000000000938',
        candidateDigest: hex('33'),
        seed: 0x37,
        approvalRequestId: '018f0000-0000-7000-8000-000000000933',
        assignmentId: '018f0000-0000-7000-8000-000000000935',
      },
      {
        activationId: '018f0000-0000-7000-8000-000000000948',
        candidateDigest: hex('43'),
        seed: 0x47,
        approvalRequestId: '018f0000-0000-7000-8000-000000000943',
        assignmentId: '018f0000-0000-7000-8000-000000000945',
      },
    ];
    try {
      for (const proof of proofs) {
        const signedAuthorization = activationArtifact(
          proof.candidateDigest,
          proof.activationId,
          proof.approvalRequestId,
          1n,
        );
        await admin.query(
          `insert into control.approval_decision_record(
             participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
             approver_principal_epoch,approver_authority_envelope_id,approver_envelope_epoch,
             approver_assignment_id,signer_credential_id,aggregate_version,candidate_digest,
             decision,decision_digest,evidence_cbor,cose_sign1
           ) values($1,$2,$3,$4,6,$5,6,$6,$7,1,$8,'APPROVE',$9,$10,$11)`,
          [
            participantA,
            privacyA,
            proof.approvalRequestId,
            checkerA,
            '018f0000-0000-7000-8000-000000000914',
            proof.assignmentId,
            '018f0000-0000-7000-8000-000000000916',
            proof.candidateDigest,
            signedAuthorization.evidenceDigest,
            signedAuthorization.evidenceCbor,
            signedAuthorization.coseSign1,
          ],
        );
        const registration = {
          actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
          resourceDigest: `sha256:${proof.candidateDigest.toString('hex')}`,
          rpIdHash: `sha256:${webauthnRpIdHash.toString('hex')}`,
        };
        const fixtureSession = `${participantA}.${sessionId}`;
        const fixtureHost = new URL(webauthnOrigin).host;
        const challengeCsrf = await fixtureIdentityKernel.csrfToken(
          fixtureSession,
          registration.actionIntentId,
          webauthnOrigin,
          fixtureHost,
        );
        const mutationActionDigest = await fixtureIdentityKernel.actionIntentSemanticDigest(
          fixtureSession,
          'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        );
        const registered = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/assertion/challenge',
          headers: {
            'cookie': `__Host-openpc_session=${fixtureSession}`,
            'origin': webauthnOrigin,
            'host': fixtureHost,
            'x-csrf-token': challengeCsrf,
          },
          payload: { ...registration, resourceId: proof.activationId },
        });
        expect(registered.statusCode, registered.body).toBe(200);
        const issuedChallenge = (registered.json() as { challenge: string }).challenge;
        const webauthn = createWebAuthnProof(proof.candidateDigest, proof.seed, issuedChallenge);
        webauthnProofs.set(`${proof.candidateDigest.toString('hex')}:${proof.seed}`, webauthn);
        const binding = webauthn.webauthnAssertionBindingDigest;
        const issuedChallengeId = (
          await admin.query<{ mfa_challenge_id: string }>(
            `select mfa_challenge_id from control.mfa_challenge
              where participant_id=$1 and challenge_digest=$2`,
            [participantA, sha256(issuedChallenge)],
          )
        ).rows[0]?.mfa_challenge_id;
        if (issuedChallengeId === undefined)
          throw new Error('missing registered WebAuthn challenge');
        if (proof.activationId === activationId) challengeId = issuedChallengeId;
        else if (proof.activationId.endsWith('938')) scopeTwoChallengeId = issuedChallengeId;
        else scopeThreeChallengeId = issuedChallengeId;
        await admin.query(
          `update control.policy_activation
              set mfa_challenge_id=$1,webauthn_assertion_binding_digest=$2
            where policy_activation_id=$3`,
          [issuedChallengeId, binding, proof.activationId],
        );
        const version = (
          await admin.query<{ row_version: string }>(
            `select row_version::text from control.session where participant_id=$1 and session_id=$2`,
            [participantA, sessionId],
          )
        ).rows[0]?.row_version;
        if (version === undefined) throw new Error('missing I03 identity session');
        authorizedArtifact = identityOperationArtifact(proof.seed);
        observedAuthorizationDigest = undefined;
        const verifyIdempotencyKey = `i03-linked-webauthn-${proof.seed}`;
        const response = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/verify',
          headers: {
            'cookie': `__Host-openpc_session=${participantA}.${sessionId}`,
            'origin': webauthnOrigin,
            'host': fixtureHost,
            'x-csrf-token': challengeCsrf,
            'openpc-action-intent-digest': mutationActionDigest,
            'idempotency-key': verifyIdempotencyKey,
            'x-openpc-aggregate-version': version,
          },
          payload: {
            actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
            resourceDigest: `sha256:${proof.candidateDigest.toString('hex')}`,
            rpIdHash: `sha256:${webauthnRpIdHash.toString('hex')}`,
            challenge: webauthn.webauthnChallenge,
            assertion: encodedWebAuthnAssertion(webauthn),
          },
        });
        expect(response.statusCode, response.body).toBe(200);
        expect(response.json()).toEqual({ status: 'verified' });
        const persistedDigest = (
          await admin.query<{ input_digest: Buffer }>(
            `select input_digest from control.idempotency_record
              where participant_id=$1 and principal_id=$2 and idempotency_key=$3`,
            [participantA, checkerA, verifyIdempotencyKey],
          )
        ).rows[0]?.input_digest;
        expect(persistedDigest?.toString('hex')).toBe(observedAuthorizationDigest?.slice(7));
        if (proof.seed === 0x24) {
          const replayVersion = (
            await admin.query<{ row_version: string }>(
              `select row_version::text from control.session where participant_id=$1 and session_id=$2`,
              [participantA, sessionId],
            )
          ).rows[0]?.row_version;
          if (replayVersion === undefined) throw new Error('missing replay identity session');
          const replay = await identityApp.inject({
            method: 'POST',
            url: '/v1/identity/webauthn/verify',
            headers: {
              'cookie': `__Host-openpc_session=${participantA}.${sessionId}`,
              'origin': webauthnOrigin,
              'host': fixtureHost,
              'x-csrf-token': challengeCsrf,
              'openpc-action-intent-digest': mutationActionDigest,
              'idempotency-key': `i03-replayed-webauthn-${proof.seed}`,
              'x-openpc-aggregate-version': replayVersion,
            },
            payload: {
              ...registration,
              challenge: webauthn.webauthnChallenge,
              assertion: encodedWebAuthnAssertion(webauthn),
            },
          });
          expect(replay.statusCode, replay.body).toBe(401);
          expect(replay.json()).toMatchObject({ error: { code: 'PC-AUTH-0006' } });
        }
      }
    } finally {
      await identityApp.close();
    }
  });
  afterAll(async () => {
    await Promise.all([runtime.end(), admin.end()]);
  });

  const authoritySnapshot = async () => {
    const result = await admin.query(`select
      (select count(*)::int from control.policy_activation where state='ACTIVE') activations,
      (select count(*)::int from control.policy_generation where active) generations,
      (select count(*)::int from control.mutation_evidence) evidence,
      (select count(*)::int from control.outbox_event) outbox,
      (select count(*)::int from control.idempotency_record) idempotency,
      (select count(*)::int from control.mfa_challenge where used_at is not null) used_proofs`);
    return result.rows[0] as Record<string, number>;
  };

  it('recovers policy session-touch conflicts over HTTP and preserves real authority denials', async () => {
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const sessionToken = `${participantA}.${makerSessionId}`;
    const internalToken = 'policy-conflict-local-internal-token-0000000000000000';
    const identity = Fastify({ logger: false });
    identity.post('/internal/v1/local/policy/authorize', async (request, reply) => {
      if (request.headers.authorization !== `Bearer ${internalToken}`) {
        return reply.code(403).send({ code: 'PC-AUTH-0005' });
      }
      try {
        return localPolicyAuthorizationResponse(
          await authorizeLocalPolicyAction(
            runtime,
            kernel,
            request.body as Parameters<typeof authorizeLocalPolicyAction>[2],
          ),
        );
      } catch {
        return reply.code(403).send({ code: 'PC-AUTH-0005' });
      }
    });
    const identityAddress = await identity.listen({ host: '127.0.0.1', port: 0 });
    const scheduled = new Pool({ connectionString: runtimeUrl, max: 1 });
    const connect = scheduled.connect.bind(scheduled);
    let remainingTouches = 0;
    let sessionLocks = 0;
    let conflicts = 0;
    let invalidate = false;
    // Schedule real Identity writes between the real SERIALIZABLE snapshot and
    // session lock. No SQL result, PostgreSQL error or authority is fabricated.
    scheduled.connect = (async () => {
      const client = await connect();
      const query = client.query.bind(client);
      const release = client.release.bind(client);
      client.query = (async (...args: unknown[]) => {
        const sql = typeof args[0] === 'string' ? args[0] : '';
        if (
          /select session_id from control\.session .* for share/u.test(sql.replace(/\s+/gu, ' '))
        ) {
          sessionLocks += 1;
          if (remainingTouches > 0) {
            remainingTouches -= 1;
            await kernel.sessionSnapshot(sessionToken);
            if (invalidate) {
              // Adversarial fixture mutation only: prove the retry rechecks the
              // original binding instead of substituting fresh authority.
              await admin.query(
                'update control.session set session_epoch=session_epoch+1 where session_id=$1',
                [makerSessionId],
              );
            }
          }
        }
        try {
          return await Reflect.apply(query, client, args);
        } catch (error) {
          if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === '40001'
          )
            conflicts += 1;
          throw error;
        }
      }) as PoolClient['query'];
      client.release = (error?: Error | boolean) => {
        client.query = query;
        client.release = release;
        release(error);
      };
      return client;
    }) as Pool['connect'];
    const policy = buildPolicyService({
      pool: scheduled,
      identityGateway: new HttpPolicyIdentityGateway(identityAddress, internalToken),
      trustedArtifactSigners: [{ publicKeySpkiDer: signerSpki }],
      internalToken,
    });
    const address = await policy.listen({ host: '127.0.0.1', port: 0 });
    const requestId = '018f0000-0000-7000-8000-00000000b090';
    const originalEpoch = (
      await admin.query('select session_epoch::text from control.session where session_id=$1', [
        makerSessionId,
      ])
    ).rows[0].session_epoch as string;
    const before = await authoritySnapshot();
    try {
      for (const testCase of [
        { touches: 1, status: 200, locks: 2, revoked: false },
        { touches: 2, status: 200, locks: 3, revoked: false },
        { touches: 3, status: 503, locks: 3, revoked: false },
        { touches: 1, status: 403, locks: 1, revoked: true },
      ]) {
        remainingTouches = testCase.touches;
        sessionLocks = 0;
        conflicts = 0;
        invalidate = testCase.revoked;
        const response = await fetch(new URL('/api/v1/activation-occurrences', address), {
          headers: {
            'cookie': `__Host-openpc_session=${sessionToken}`,
            'openpc-api-version': '1',
            'openpc-participant-id': `urn:openpc:participant:${participantA}`,
            'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyA}`,
            'x-request-id': requestId,
            'x-correlation-id': requestId,
          },
        });
        const body = await response.json();
        expect(response.status, JSON.stringify(body)).toBe(testCase.status);
        expect(sessionLocks).toBe(testCase.locks);
        expect(conflicts).toBe(testCase.touches);
        if (testCase.status === 503)
          expect(body).toEqual({
            type: 'https://errors.openpc.local/unavailable',
            title: 'The service is unavailable',
            status: 503,
            code: 'PC-INTEGRATION-5001',
            retryable: true,
            truthState: 'UNAVAILABLE',
            traceId: requestId,
          });
        if (testCase.status === 403)
          expect(body).toMatchObject({ code: 'PC-POLICY-2004', retryable: false });
        expect(await authoritySnapshot()).toEqual(before);
      }
      await admin.query('update control.session set session_epoch=$2 where session_id=$1', [
        makerSessionId,
        originalEpoch,
      ]);
      await assertI03FaultOwnership(i03FaultDescriptor(), admin, runtime);
      // Disposable transaction probe, not a substitute for business acceptance.
      await admin.query('create schema policy_conflict_fixture');
      await admin.query('grant usage on schema policy_conflict_fixture to openpc_i03_r8_runtime');
      await admin.query(
        'create table policy_conflict_fixture.probe(id integer primary key, value integer not null)',
      );
      try {
        await admin.query(
          'grant select,insert,update on policy_conflict_fixture.probe to openpc_i03_r8_runtime',
        );
        await admin.query('insert into policy_conflict_fixture.probe values(0,0)');
        const actionIntentId = 'ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1';
        const actor = await authorizeLocalPolicyAction(runtime, kernel, {
          sessionToken,
          privacyDomainId: privacyA,
          actionIntentId,
          resourceId: '*',
          stepUpRequired: false,
        });
        let attempts = 0;
        await inScope(
          runtime,
          {
            participantId: participantA,
            privacyDomainId: privacyA,
            principalId: actor.principalId,
            operationId: requestId,
            actionIntentId,
            authority: { ...actor, privacyDomainId: privacyA, actionIntentId, resourceId: '*' },
          },
          async (client) => {
            attempts += 1;
            await client.query('insert into policy_conflict_fixture.probe values(1,1)');
            if (attempts < 3)
              await admin.query(
                'update policy_conflict_fixture.probe set value=value+1 where id=0',
              );
            await client.query(
              'select value from policy_conflict_fixture.probe where id=0 for update',
            );
          },
        );
        expect(attempts).toBe(3);
        expect(
          (await admin.query('select * from policy_conflict_fixture.probe order by id')).rows,
        ).toEqual([
          { id: 0, value: 2 },
          { id: 1, value: 1 },
        ]);
        expect(await authoritySnapshot()).toEqual(before);
      } finally {
        await admin.query('drop table policy_conflict_fixture.probe');
        await admin.query('drop schema policy_conflict_fixture');
      }
    } finally {
      await admin.query('update control.session set session_epoch=$2 where session_id=$1', [
        makerSessionId,
        originalEpoch,
      ]);
      await policy.close();
      await identity.close();
      await scheduled.end();
    }
  });

  const rejectsWithoutEffect = async (
    input: PolicyActivationMutation,
    expected: 'PC-POLICY-2004' | 'PC-POLICY-2005' = 'PC-POLICY-2005',
    targetActivationId = activationId,
  ) => {
    const before = await authoritySnapshot();
    await expect(activatePolicyGeneration(runtime, input, targetActivationId)).rejects.toThrow(
      expected,
    );
    expect(await authoritySnapshot()).toEqual(before);
  };

  it('reads signed module references with real scoped authority and preserves original state (M1a component only)', async () => {
    // Seeded lifecycle rows prove this reader only. Public register/install/enable
    // and later DISABLE acceptance stay in module-admission-journey.sh.
    const loadManifest = (name: string) =>
      JSON.parse(
        readFileSync(
          path.join(repositoryRoot, `policies/modules/generated/manifests/${name}.json`),
          'utf8',
        ),
      );
    const manifests = [loadManifest('pc.foundation.kernel'), loadManifest('pc.policy.rpc-surface')];
    const schema = JSON.parse(
      readFileSync(
        path.join(repositoryRoot, 'policies/modules/generated/module-manifest.compat.schema.json'),
        'utf8',
      ),
    );
    const tagged = (value: Buffer) => `sha256:${sha256(value).toString('hex')}`;
    const encode = (value: unknown) => Buffer.from(canonicalJson(value));
    const text = (value: string) => {
      const bytes = Buffer.from(value);
      return Buffer.concat([
        Buffer.from(bytes.length < 24 ? [0x60 | bytes.length] : [0x78, bytes.length]),
        bytes,
      ]);
    };
    const bundles: ModuleReleaseBundle[] = [];
    for (const [index, source] of manifests.entries()) {
      const manifest = structuredClone(source);
      // A deliberately small, signed component graph. Never a release candidate
      // for installation or acceptance of the full dependency graph.
      manifest.dependencies =
        index === 0
          ? []
          : [
              {
                edgeId: 'INSTALL-pc.foundation.kernel-BEFORE-pc.policy.rpc-surface',
                providerModuleId: 'pc.foundation.kernel',
                moduleId: 'pc.foundation.kernel',
                capabilityId: manifests[0].capabilities.provided[0].capabilityId,
                version: manifests[0].metadata.version,
                manifestDigest: tagged(bundles[0]!.manifestBytes),
                traceSetId: 'TS-MOD-DEPENDENCY',
              },
            ];
      manifest.capabilities.required =
        index === 0
          ? []
          : [
              {
                providerModuleId: 'pc.foundation.kernel',
                capabilityId: manifests[0].capabilities.provided[0].capabilityId,
                version: manifests[0].metadata.version,
                traceSetId: 'TS-MOD-DEPENDENCY',
              },
            ];
      const artifactBytes = Buffer.from('M1a component release artifact');
      const sbomBytes = encode({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [] });
      const provenanceBytes = encode({
        subject: tagged(artifactBytes),
        builder: 'M1a component fixture',
      });
      manifest.supplyChain = {
        ...manifest.supplyChain,
        releaseEvidenceState: 'RELEASE_CANDIDATE',
        artifactDigest: tagged(artifactBytes),
        sbomDigest: tagged(sbomBytes),
        provenanceDigest: tagged(provenanceBytes),
        buildReceiptId: `urn:openpc:build-receipt:018f0000-0000-7000-8000-00000000b00${index}`,
        signature: tagged(signerSpki),
      };
      const bundle = {
        manifestBytes: encode(manifest),
        artifactBytes,
        sbomBytes,
        provenanceBytes,
        configurationBytes: encode({}),
        buildReceiptBytes: encode({
          receiptId: manifest.supplyChain.buildReceiptId,
          moduleId: manifest.metadata.id,
          moduleVersion: manifest.metadata.version,
          artifactDigest: manifest.supplyChain.artifactDigest,
          sbomDigest: manifest.supplyChain.sbomDigest,
          provenanceDigest: manifest.supplyChain.provenanceDigest,
          stackLockDigest: manifest.compatibility.stackLockDigest,
          result: 'SUCCEEDED',
        }),
      };
      const payloadCbor = moduleReleasePayload(bundle);
      const protectedHeader = Buffer.concat([
        Buffer.from([0xa5, 0x01, 0x26, 0x03]),
        text('application/openpc+cbor'),
        Buffer.from([0x04]),
        cborByteString(sha256(signerSpki)),
        Buffer.from([
          0x19,
          0x03,
          0xe9,
          0x19,
          moduleReleaseCoseContext.schemaId >> 8,
          moduleReleaseCoseContext.schemaId & 255,
          0x19,
          0x03,
          0xea,
        ]),
        text(moduleReleaseCoseContext.purpose),
      ]);
      const signature = sign(
        'sha256',
        Buffer.concat([
          Buffer.from([0x84]),
          text('Signature1'),
          cborByteString(protectedHeader),
          Buffer.from([0x40]),
          cborByteString(payloadCbor),
        ]),
        { key: signerPrivateKey, dsaEncoding: 'ieee-p1363' },
      );
      bundles.push({
        ...bundle,
        payloadCbor,
        coseSign1: Buffer.concat([
          Buffer.from([0xd2, 0x84]),
          cborByteString(protectedHeader),
          Buffer.from([0xa0]),
          cborByteString(payloadCbor),
          cborByteString(signature),
        ]),
      });
    }
    const verify = createModuleReleaseVerifier({
      manifestSchema: schema,
      manifestSchemaDigest: manifests[0].compatibility.manifestSchemaDigest,
      stackLockDigest: manifests[0].compatibility.stackLockDigest,
      targetProfile: 'local',
      moduleIds: manifests.map((manifest) => manifest.metadata.id),
      capabilityIds: manifests.flatMap((manifest) =>
        manifest.capabilities.provided.map((item: { capabilityId: string }) => item.capabilityId),
      ),
      executionHostIds: [
        ...new Set<string>(
          manifests.flatMap((manifest) => manifest.deployment.r1AdmittedExecutionHostIds),
        ),
      ],
      signers: [
        {
          publicKeySpkiDer: signerSpki,
          state: 'ACTIVE',
          validFromMs: Date.now() - 60_000,
          validUntilMs: Date.now() + 60_000,
        },
      ],
    });
    const releases = bundles.map((bundle) => verify(bundle, Date.now()));
    const installationIds = [
      '018f0000-0000-7000-8000-00000000b010',
      '018f0000-0000-7000-8000-00000000b011',
    ];
    const seed = await admin.connect();
    try {
      await seed.query('begin');
      await seed.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-MODULES_READ_RESOURCE-V1',true)",
        [participantA, privacyA],
      );
      for (const [index, release] of releases.entries()) {
        const bundle = bundles[index]!;
        const versionId = `018f0000-0000-7000-8000-00000000b02${index}`;
        const closure = releases.slice(0, index + 1);
        const resolved = resolveDependencies(
          closure.map((item) => ({
            moduleId: item.manifest.metadata.id,
            semanticVersion: item.manifest.metadata.version,
            manifestDigest: `sha256:${item.manifestDigest.toString('hex')}`,
            capabilities: item.manifest.capabilities.provided.map(
              (capability) => capability.capabilityId,
            ),
          })),
          closure.flatMap((item) =>
            item.manifest.dependencies.map((edge) => ({
              edgeId: edge.edgeId,
              consumerModuleId: item.manifest.metadata.id,
              providerModuleId: edge.providerModuleId,
              capabilityId: edge.capabilityId,
              semanticVersion: edge.version,
              providerManifestDigest: edge.manifestDigest,
            })),
          ),
        );
        await seed.query(
          `insert into control.module_registration(module_id,display_name,owner,state)
        values($1::text,$1::text,'LS-MODULE-REGISTRY','ADMITTED') on conflict do nothing`,
          [release.manifest.metadata.id],
        );
        await seed.query(
          `insert into control.module_version(module_version_id,module_id,semantic_version,manifest_cbor,manifest_digest,
        cose_sign1,sbom_digest,provenance_digest,build_receipt_digest,release_manifest_json,release_artifact,release_sbom,
        release_provenance,release_build_receipt,release_configuration_json,release_payload_cbor,release_signer_key_digest)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
          [
            versionId,
            release.manifest.metadata.id,
            release.manifest.metadata.version,
            release.manifestCbor,
            release.manifestDigest,
            release.coseSign1,
            release.sbomDigest,
            release.provenanceDigest,
            release.buildReceiptDigest,
            bundle.manifestBytes,
            bundle.artifactBytes,
            bundle.sbomBytes,
            bundle.provenanceBytes,
            bundle.buildReceiptBytes,
            bundle.configurationBytes,
            bundle.payloadCbor,
            release.signerKeyDigest,
          ],
        );
        for (const capability of release.manifest.capabilities.provided) {
          await seed.query(
            'insert into control.module_capability(module_version_id,capability_id,contract_digest) values($1,$2,$3)',
            [versionId, capability.capabilityId, sha256(canonicalJson(capability))],
          );
        }
        for (const edge of release.manifest.dependencies) {
          await seed.query(
            `insert into control.module_dependency(consumer_module_version_id,edge_id,provider_module_id,capability_id,
          semantic_version,provider_manifest_digest) values($1,$2,$3,$4,$5,$6)`,
            [
              versionId,
              edge.edgeId,
              edge.providerModuleId,
              edge.capabilityId,
              edge.version,
              Buffer.from(edge.manifestDigest.slice(7), 'hex'),
            ],
          );
        }
        await seed.query(
          `insert into control.module_installation(module_installation_id,participant_id,privacy_domain_id,module_version_id,
        state,authority_epoch,delegation_epoch,aggregate_version,admission_dependency_digest,desired_manifest_digest,active_manifest_digest,
        lifecycle_evaluation_digest,lifecycle_operation_id,idempotency_key) values($1,$2,$3,$4,'ENABLED',5,1,3,$5,$6,$6,$7,$1,$8)`,
          [
            installationIds[index],
            participantA,
            privacyA,
            versionId,
            Buffer.from(resolved.closureDigest, 'hex'),
            release.manifestDigest,
            sha256(`m1a-component-evaluation-${index}`),
            `m1a-component-${index}`,
          ],
        );
        await seed.query(
          `insert into control.module_configuration_generation(generation_id,participant_id,privacy_domain_id,module_installation_id,
        generation,configuration_cbor,configuration_digest,active) values($1,$2,$3,$4,1,$5,$6,true)`,
          [
            `018f0000-0000-7000-8000-00000000b03${index}`,
            participantA,
            privacyA,
            installationIds[index],
            release.configurationCbor,
            release.configurationDigest,
          ],
        );
      }
      await seed.query('commit');
    } catch (error) {
      await seed.query('rollback');
      throw error;
    } finally {
      seed.release(true);
    }
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const actionIntentId = 'ACT-MODULES_READ_RESOURCE-V1';
    const actor = await authorizeLocalPolicyAction(runtime, kernel, {
      sessionToken: `${participantA}.${makerSessionId}`,
      privacyDomainId: privacyA,
      actionIntentId,
      resourceId: installationIds[0]!,
      stepUpRequired: false,
    });
    const scope = {
      participantId: participantA,
      privacyDomainId: privacyA,
      principalId: actor.principalId,
      operationId: '018f0000-0000-7000-8000-00000000b040',
      actionIntentId,
      authority: {
        ...actor,
        privacyDomainId: privacyA,
        actionIntentId,
        resourceId: installationIds[0]!,
      },
    };
    const request = {
      operation: 'MOD-OP-DISABLE' as const,
      moduleInstallationId: installationIds[0]!,
      expectedRevision: '3',
      generation: '1',
      manifestDigest: `sha256:${releases[0]!.manifestDigest.toString('hex')}`,
      configurationDigest: `sha256:${releases[0]!.configurationDigest.toString('hex')}`,
    };
    const original = await authoritySnapshot();
    const referenceWriter = await admin.connect();
    const assertMigratedReferenceFences = async (
      observation: Awaited<ReturnType<typeof withModuleLifecyclePreflight>>,
      hasSettingsBinding = false,
    ) => {
      const expected = [
        ['runtime_configuration_generation', 'TRY_CIGL_INSERT', 'RUNTIME_GENERATION_WRITE_FENCE'],
        ['policy_activation_occurrence', 'TRY', 'ACTIVATION_OCCURRENCE_WRITE_FENCE'],
        ['policy_activation_occurrence_target', 'TRY', 'ACTIVATION_OCCURRENCE_WRITE_FENCE'],
        ['cigl_settings', 'TRY', 'CIGL_SETTINGS_WRITE_FENCE'],
      ] as const;
      // Actual catalog read through the ordinary runtime connection. This is
      // an independent presence/profile oracle; the preflight additionally
      // checks the complete owned bodies and execution metadata on every read.
      const catalog = await runtime.query<{
        table: string;
        owner: string;
        type: number;
        enabled: string;
        arguments: string;
        schema: string;
        function: string;
        function_owner: string;
      }>(
        `select c.relname "table",o.rolname owner,t.tgtype::int type,t.tgenabled enabled,
        encode(t.tgargs,'hex') arguments,n.nspname schema,p.proname function,fo.rolname function_owner
        from pg_catalog.pg_trigger t join pg_catalog.pg_class c on c.oid=t.tgrelid
        join pg_catalog.pg_roles o on o.oid=c.relowner
        join pg_catalog.pg_proc p on p.oid=t.tgfoid
        join pg_catalog.pg_namespace n on n.oid=p.pronamespace
        join pg_catalog.pg_roles fo on fo.oid=p.proowner
        where c.relnamespace='control'::regnamespace and c.relname=any($1::text[])
          and t.tgname=c.relname||'_reference_fence'`,
        [expected.map(([table]) => table)],
      );
      const missing = expected.filter(([table, mode]) => {
        const rows = catalog.rows.filter((row) => row.table === table);
        const row = rows[0];
        return (
          rows.length !== 1 ||
          !row ||
          row.owner !== 'openpc_control_owner' ||
          row.type !== 30 ||
          !['O', 'A'].includes(row.enabled) ||
          row.arguments !== Buffer.from(`${mode}\0`).toString('hex') ||
          row.schema !== 'openpc' ||
          row.function !== 'guard_policy_generation_fence' ||
          row.function_owner !== 'openpc_control_owner'
        );
      });
      for (const marker of new Set(expected.map(([, , marker]) => marker))) {
        if (marker === 'CIGL_SETTINGS_WRITE_FENCE' && !hasSettingsBinding) continue;
        const issues =
          marker === 'CIGL_SETTINGS_WRITE_FENCE'
            ? observation.predicates.configurationReferences.unresolved
            : observation.predicates.runtimeReferences.unresolved;
        if (missing.some(([, , unavailable]) => unavailable === marker))
          expect(issues, `absent/invalid migrated coverage must retain ${marker}`).toContain(
            marker,
          );
        else
          expect(issues, `complete owned coverage must resolve only ${marker}`).not.toContain(
            marker,
          );
      }
      // Missing migrations are a failed prerequisite, never a passing negative
      // scenario that silently substitutes for the required valid-catalog case.
      expect(
        missing.map(([table]) => table),
        'BLOCKED: M1a requires current owner-applied fence migrations',
      ).toEqual([]);
      expect(observation.predicates.factProjectionDrain).toEqual({
        status: 'UNRESOLVED',
        references: [],
        unresolved: ['FACT_CANDIDATE_DRAIN_OWNER_REQUIRED'],
      });
      expect(observation.predicates.uiInvalidation).toEqual({
        status: 'UNRESOLVED',
        references: [],
        unresolved: ['MODULE_UI_GENERATION_OWNER_REQUIRED'],
      });
      expect(observation.predicates.grantAndOwnedDataSafety).toEqual({
        status: 'UNRESOLVED',
        references: [],
        unresolved: ['MODULE_GRANT_DATA_REFERENCE_OWNER_REQUIRED'],
      });
      expect(observation.predicates.custodyDisposition.status).toBe('NOT_APPLICABLE');
    };
    const insertReference = async () => {
      await referenceWriter.query('begin');
      await referenceWriter.query('set local role openpc_control_worker');
      await referenceWriter.query("set local statement_timeout='2s'");
      await referenceWriter.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),$3,true)`,
        [participantA, privacyA, actionIntentId],
      );
      return referenceWriter.query(
        `insert into control.runtime_configuration_input
        (runtime_configuration_input_id,participant_id,privacy_domain_id,module_installation_id,module_configuration_generation_id,
          configuration_cbor,configuration_digest,resource_bindings,selected)
        values('018f0000-0000-7000-8000-00000000b050',$1,$2,$3,'018f0000-0000-7000-8000-00000000b030',
          decode('a0','hex'),sha256(decode('a0','hex')),$4::jsonb,false)`,
        [
          participantA,
          privacyA,
          installationIds[0],
          JSON.stringify([
            {
              kind: 'ProviderProfile',
              id: '018f0000-0000-7000-8000-00000000b051',
              digest: `sha256:${'51'.repeat(32)}`,
              chainId: '31337',
            },
            {
              kind: 'CiglSettings',
              id: '018f0000-0000-7000-8000-00000000b052',
            },
          ]),
        ],
      );
    };
    let escaped: (() => Promise<void>) | undefined;
    let componentFailed = false;
    let componentFailure: unknown;
    try {
      const observed = await withModuleLifecyclePreflight(
        runtime,
        scope,
        request,
        verify,
        async (observation, revalidate) => {
          escaped = revalidate;
          await assertMigratedReferenceFences(observation);
          expect(() => requireModuleDisablePredicates(observation)).toThrow('PC-MODULE-7009');
          expect(
            observation.predicates.runtimeReferences.unresolved.filter((issue) =>
              issue.startsWith('MODULE_REFERENCE_WRITE_FENCE:'),
            ),
          ).toEqual([]);
          expect(observation.predicates.reverseDependencies).toEqual({
            status: 'BLOCKED',
            references: [`MODULE:${installationIds[1]}:3`],
            unresolved: [],
          });
          expect(observation.predicates.custodyDisposition.status).toBe('NOT_APPLICABLE');
          expect(observation.predicates.runtimeReferences.status).toBe('UNRESOLVED');
          expect(Object.isFrozen(observation.predicates.reverseDependencies.references)).toBe(true);
          await expect(insertReference()).rejects.toMatchObject({
            code: 'P0001',
            message: 'PC-DATA-6007',
          });
          await referenceWriter.query('rollback');
          await revalidate();
        },
      );
      expect(observed.observationDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      await expect(escaped!()).rejects.toThrow('PC-MODULE-7009');
      await insertReference();
      await referenceWriter.query('commit');
      await withModuleLifecyclePreflight(runtime, scope, request, verify, async (next) => {
        await assertMigratedReferenceFences(next, true);
        expect(() =>
          assertModuleLifecycleObservationUnchanged(observed.observationDigest, next),
        ).toThrow('PC-MODULE-7009');
        expect(next.predicates.configurationReferences.unresolved).toContain(
          'RESOURCE_BINDINGS:018f0000-0000-7000-8000-00000000b050',
        );
        expect(next.predicates.reverseDependencies).toEqual(
          observed.predicates.reverseDependencies,
        );
      });
      await expect(
        withModuleLifecyclePreflight(
          runtime,
          scope,
          { ...request, expectedRevision: '2' },
          verify,
          async () => {
            throw new Error('stale read reached callback');
          },
        ),
      ).rejects.toThrow('PC-MODULE-7009');
      await expect(
        withModuleLifecyclePreflight(
          runtime,
          { ...scope, privacyDomainId: privacyB },
          request,
          verify,
          async () => {
            throw new Error('foreign scope reached callback');
          },
        ),
      ).rejects.toThrow('PC-POLICY-2004');
      const foreignReader = await runtime.connect();
      try {
        await foreignReader.query('begin isolation level read committed');
        await foreignReader.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),$3,true)`,
          [participantB, privacyB, actionIntentId],
        );
        expect(
          (
            await foreignReader.query(
              'select module_installation_id from control.module_installation where module_installation_id=any($1::uuid[])',
              [installationIds],
            )
          ).rows,
        ).toEqual([]);
        expect(
          await readVerifiedModuleLifecycleSnapshot(foreignReader, participantB, privacyB, verify),
        ).toEqual([]);
      } finally {
        await foreignReader.query('rollback');
        foreignReader.release(true);
      }
      // Faults use the same real scoped/signed reader, after its clean-catalog
      // prerequisite passed. No descriptor, fake catalog or seeded approval can
      // replace the live runner/storage proof at the mutation boundary.
      const descriptor = i03FaultDescriptor();
      const tables = [
        ['runtime_configuration_generation', 'RUNTIME_GENERATION_WRITE_FENCE'],
        ['policy_activation_occurrence', 'ACTIVATION_OCCURRENCE_WRITE_FENCE'],
        ['policy_activation_occurrence_target', 'ACTIVATION_OCCURRENCE_WRITE_FENCE'],
        ['cigl_settings', 'CIGL_SETTINGS_WRITE_FENCE'],
      ] as const;
      type FenceCatalogRow = {
        table: string;
        definition: string;
        enabled: string;
        comment: string | null;
        functionDefinition: string;
        metadata: unknown;
      };
      const catalog = async () =>
        (
          await runtime.query<FenceCatalogRow>(
            `select c.relname "table",pg_get_triggerdef(t.oid,false) definition,t.tgenabled enabled,
          obj_description(t.oid,'pg_trigger') comment,pg_get_functiondef(p.oid) "functionDefinition",
          jsonb_build_object('trigger',to_jsonb(t)-'oid','function',to_jsonb(p),
            'tableOwner',c.relowner,'functionComment',obj_description(p.oid,'pg_proc')) metadata
         from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_proc p on p.oid=t.tgfoid
         where c.relnamespace='control'::regnamespace and c.relname=any($1::text[])
           and t.tgname=c.relname||'_reference_fence' order by c.relname`,
            [tables.map(([table]) => table)],
          )
        ).rows;
      const executeDdl = async (statements: readonly string[]) => {
        const client = await admin.connect();
        try {
          await client.query('begin');
          await client.query('set local role openpc_control_owner');
          await client.query("set local lock_timeout='2s'");
          await client.query("set local statement_timeout='5s'");
          for (const statement of statements) await client.query(statement);
          await client.query('commit');
        } catch (error) {
          await client.query('rollback').catch(() => undefined);
          throw error;
        } finally {
          client.release(true);
        }
      };
      type CatalogFault = {
        name: string;
        statements: (before: readonly FenceCatalogRow[]) => readonly string[];
        restoration: (before: readonly FenceCatalogRow[]) => readonly string[];
      };
      const withCatalogFault = async (fault: CatalogFault, inspect: () => Promise<void>) => {
        faultPrerequisite(
          catalogRestorationFailure === undefined,
          'previous catalog restoration is unverified',
        );
        await assertI03FaultOwnership(descriptor, admin, runtime);
        const before = await catalog();
        expect(
          before.map((row) => row.table),
          `${fault.name}: original coverage`,
        ).toEqual(tables.map(([table]) => table).sort());
        const statements = fault.statements(before);
        const restoration = fault.restoration(before);
        let failed = false;
        let firstFailure: unknown;
        try {
          await executeDdl(statements);
          expect(
            await catalog(),
            `${fault.name}: committed cross-connection visibility`,
          ).not.toEqual(before);
          await inspect();
        } catch (error) {
          failed = true;
          firstFailure = error;
        }
        // This also handles ambiguous COMMIT: attempt exact restoration even
        // when the mutation failed. Never treat a later pass as the first result.
        let restoreFailure: unknown;
        try {
          await assertI03FaultOwnership(descriptor, admin, runtime);
          await executeDdl(restoration);
          expect(
            await catalog(),
            `${fault.name}: separate reader verifies exact restoration`,
          ).toEqual(before);
        } catch (error) {
          restoreFailure = new Error(`BLOCKED: ${fault.name} catalog restoration unverified`, {
            cause: error,
          });
          catalogRestorationFailure = restoreFailure;
        }
        if (restoreFailure !== undefined) {
          throw new AggregateError(
            failed ? [firstFailure, restoreFailure] : [restoreFailure],
            'M1a fault result retained; dependent disposable-database reuse BLOCKED',
          );
        }
        if (failed) throw firstFailure;
      };
      const baseline = await withModuleLifecyclePreflight(
        runtime,
        scope,
        request,
        verify,
        async (value) => {
          await assertMigratedReferenceFences(value, true);
        },
      );
      const assertOnlyFaultMarkers = (value: typeof baseline, markers: readonly string[]) => {
        const expected = { ...structuredClone(baseline.predicates) };
        for (const owner of ['runtimeReferences', 'configurationReferences'] as const) {
          const added = markers.filter(
            (marker) =>
              (marker === 'CIGL_SETTINGS_WRITE_FENCE') === (owner === 'configurationReferences'),
          );
          if (added.length)
            expected[owner] = {
              ...expected[owner],
              status: 'UNRESOLVED',
              unresolved: [...new Set([...expected[owner].unresolved, ...added])].sort(),
            };
        }
        expect(value.predicates).toEqual(expected);
        expect(value.target).toEqual(baseline.target);
        expect(value.operation).toBe(baseline.operation);
        expect(value.observationDigest).not.toBe(baseline.observationDigest);
      };
      const assertHealthyAgain = async () => {
        const restored = await withModuleLifecyclePreflight(
          runtime,
          scope,
          request,
          verify,
          async (value) => {
            await assertMigratedReferenceFences(value, true);
          },
        );
        expect(restored).toEqual(baseline);
      };
      const enableOriginal = (row: FenceCatalogRow) => {
        faultPrerequisite(['O', 'A'].includes(row.enabled), 'original trigger was not enabled');
        return `alter table control.${row.table} enable ${row.enabled === 'A' ? 'always ' : ''}trigger ${row.table}_reference_fence`;
      };
      // Disabled coverage must affect only the corresponding predicate. Both
      // occurrence tables are required; CIGL is exercised with a real binding.
      for (const [table, marker] of tables) {
        await withCatalogFault(
          {
            name: `disabled ${table} coverage`,
            statements: () => [
              `alter table control.${table} disable trigger ${table}_reference_fence`,
            ],
            restoration: (before) => [enableOriginal(before.find((row) => row.table === table)!)],
          },
          async () => {
            await withModuleLifecyclePreflight(runtime, scope, request, verify, async (value) => {
              assertOnlyFaultMarkers(value, [marker]);
            });
          },
        );
        await assertHealthyAgain();
      }
      const generationTable = 'runtime_configuration_generation';
      await withCatalogFault(
        {
          name: 'substituted runtime generation trigger mode',
          statements: (before) => {
            const row = before.find((item) => item.table === generationTable)!;
            faultPrerequisite(
              row.definition.split("('TRY_CIGL_INSERT')").length === 2,
              'original generation trigger mode unavailable',
            );
            return [
              `drop trigger ${generationTable}_reference_fence on control.${generationTable}`,
              row.definition.replace("('TRY_CIGL_INSERT')", "('TRY')"),
            ];
          },
          restoration: (before) => {
            const row = before.find((item) => item.table === generationTable)!;
            return [
              `drop trigger ${generationTable}_reference_fence on control.${generationTable}`,
              row.definition,
              enableOriginal(row),
              ...(row.comment === null
                ? []
                : [
                    `comment on trigger ${generationTable}_reference_fence on control.${generationTable} is '${row.comment.replaceAll("'", "''")}'`,
                  ]),
            ];
          },
        },
        async () => {
          await withModuleLifecyclePreflight(runtime, scope, request, verify, async (value) => {
            assertOnlyFaultMarkers(value, ['RUNTIME_GENERATION_WRITE_FENCE']);
          });
        },
      );
      await assertHealthyAgain();
      const substitutedFunction: CatalogFault = {
        name: 'same-name reference fence function substitution',
        statements: (before) => {
          const definition = before[0]!.functionDefinition;
          const start = definition.indexOf('AS $function$');
          faultPrerequisite(
            start > 0 && definition.trimEnd().endsWith('$function$'),
            'original function body delimiter unavailable',
          );
          // Keep the name/signature/properties; only the owned body is replaced.
          return [
            `${definition.slice(0, start)}AS $function$\nBEGIN RETURN NULL; END;\n$function$`,
          ];
        },
        restoration: (before) => [before[0]!.functionDefinition],
      };
      await withCatalogFault(substitutedFunction, async () => {
        await withModuleLifecyclePreflight(runtime, scope, request, verify, async (value) => {
          assertOnlyFaultMarkers(value, [...new Set(tables.map(([, marker]) => marker))]);
        });
      });
      await assertHealthyAgain();
      // Function replacement is visible without waiting for the original
      // reader's table locks. READ COMMITTED revalidation must see that loss;
      // catching it or restoring the catalog cannot resurrect the observation.
      await expect(
        withModuleLifecyclePreflight(runtime, scope, request, verify, async (value, revalidate) => {
          expect(value).toEqual(baseline);
          await withCatalogFault(substitutedFunction, async () => {
            await expect(revalidate()).rejects.toThrow('PC-MODULE-7009');
          });
          await expect(revalidate()).rejects.toThrow('PC-MODULE-7009');
        }),
      ).rejects.toThrow('PC-MODULE-7009');
      await assertHealthyAgain();
      expect(await authoritySnapshot()).toEqual(original);
      expect(
        (
          await admin.query(
            `select state,aggregate_version::text revision from control.module_installation
      where module_installation_id=any($1::uuid[]) order by module_installation_id`,
            [installationIds],
          )
        ).rows,
      ).toEqual([
        { state: 'ENABLED', revision: '3' },
        { state: 'ENABLED', revision: '3' },
      ]);
    } catch (error) {
      componentFailed = true;
      componentFailure = error;
    }
    const cleanupFailures: unknown[] = [];
    try {
      await referenceWriter.query('rollback');
    } catch (error) {
      cleanupFailures.push(error);
    }
    try {
      referenceWriter.release(true);
    } catch (error) {
      cleanupFailures.push(error);
    }
    if (cleanupFailures.length)
      throw new AggregateError(
        componentFailed ? [componentFailure, ...cleanupFailures] : cleanupFailures,
        'M1a component result retained with connection cleanup failure',
      );
    if (componentFailed) throw componentFailure;
  }, 120_000);

  it('fences actual module reference producers, global catalogue, empty writes and truncate without effects (M2)', async () => {
    const tables = [
      'module_installation',
      'module_configuration_generation',
      'module_version',
      'module_dependency',
      'module_capability',
      'policy_generation',
      'policy_version',
      'policy_artifact',
      'runtime_configuration_input',
      'configuration_work',
      'runtime_configuration_generation',
      'runtime_target',
      'policy_activation_occurrence',
      'policy_activation_occurrence_target',
      'provider_profile',
      'indexer_profile',
      'projection_plan',
    ];
    const holder = await runtime.connect();
    const writer = await admin.connect();
    const begin = async (
      client: typeof holder,
      participant = participantA,
      privacy = privacyA,
      role?: string,
    ) => {
      await client.query('begin');
      if (role) await client.query(`set local role ${role}`);
      await client.query("set local lock_timeout='250ms'");
      await client.query("set local statement_timeout='2s'");
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-MODULES_UPDATE_RESOURCE-V1',true)",
        [participant, privacy],
      );
    };
    const snapshot = await authoritySnapshot();
    try {
      const catalog = await runtime.query<{
        table: string;
        type: number;
        enabled: string;
        function: string;
        args: number;
      }>(
        `
        select c.relname "table",t.tgtype::int type,t.tgenabled enabled,p.proname function,t.tgnargs::int args
        from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_proc p on p.oid=t.tgfoid
        where c.relnamespace='control'::regnamespace and c.relname=any($1::text[])
          and t.tgname='a_module_reference_fence_'||c.relname order by c.relname`,
        [tables],
      );
      expect(catalog.rows, 'BLOCKED: M2 requires the complete owner-applied migration').toEqual(
        [...tables].sort().map((table) => ({
          table,
          type: 62,
          enabled: 'O',
          function: 'guard_module_reference_write_fence',
          args: 0,
        })),
      );
      await begin(holder);
      await lockModuleLifecycleReferences(holder, {
        participantId: participantA,
        privacyDomainId: privacyA,
      });
      for (const table of tables) {
        // Owner role exercises the trigger even on tables where runtime only has
        // column grants. This is an empty statement, never lifecycle acceptance.
        await begin(writer, participantA, privacyA, 'openpc_control_owner');
        await expect(
          writer.query(`insert into control.${table} select * from control.${table} where false`),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
        await writer.query('rollback');
      }
      // A foreign scope cannot change the shared catalogue under this observer.
      for (const table of ['module_version', 'module_capability', 'module_dependency']) {
        await begin(writer, participantB, privacyB, 'openpc_control_runtime');
        await expect(
          writer.query(`insert into control.${table} select * from control.${table} where false`),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
        await writer.query('rollback');
      }
      // Independent scope remains usable for a scoped producer.
      await begin(writer, participantB, privacyB, 'openpc_control_worker');
      expect(
        (
          await writer.query(
            'update control.runtime_configuration_input set selected=selected where false',
          )
        ).rowCount,
      ).toBe(0);
      await writer.query('rollback');
      await holder.query('rollback');
      await begin(writer, participantA, privacyA, 'openpc_control_runtime');
      await writer.query(
        'insert into control.module_capability select * from control.module_capability where false',
      );
      await begin(holder);
      await expect(
        lockModuleLifecycleReferences(holder, {
          participantId: participantB,
          privacyDomainId: privacyB,
        }),
      ).rejects.toThrow('PC-MODULE-7009');
      await holder.query('rollback');
      await writer.query('rollback');
      // TRUNCATE bypasses RLS; it is rejected even without a live observer. Use a
      // leaf with no inbound FK so rejection is from this guard, then roll back.
      await begin(writer, participantA, privacyA, 'openpc_control_owner');
      await expect(writer.query('truncate control.module_capability')).rejects.toMatchObject({
        code: 'P0001',
        message: 'DATA-6020-MODULE-REFERENCE-HISTORY',
      });
      await writer.query('rollback');
      expect(await authoritySnapshot()).toEqual(snapshot);
    } finally {
      await holder.query('rollback');
      await writer.query('rollback');
      holder.release(true);
      writer.release(true);
    }
  });

  it('matches the independent fixed DISABLE transport vectors in PostgreSQL framing (M2 contract only)', async () => {
    for (const revision of ['3', '9007199254740993', '18446744073709551615']) {
      const descriptor = {
        operation: 'MOD-OP-DISABLE',
        targetRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000301',
        expectedRevision: revision,
        manifestDigest: `sha256:${'11'.repeat(32)}`,
      };
      const result = await runtime.query<{ digest: string }>(
        `
        select 'sha256:'||encode(sha256(convert_to('pc.control.module-disable.v1','UTF8')||decode('00','hex')||
          int4send(octet_length($1::text))||convert_to($1,'UTF8')||int4send(octet_length($2::text))||convert_to($2,'UTF8')||
          int4send(octet_length($3::text))||convert_to($3,'UTF8')||int4send(octet_length($4::text))||convert_to($4,'UTF8')),'hex') digest`,
        [
          descriptor.operation,
          descriptor.targetRef,
          descriptor.expectedRevision,
          descriptor.manifestDigest,
        ],
      );
      expect(result.rows[0]!.digest).toBe(moduleDisableReplacementDigest(descriptor));
    }
  });

  it('enforces runtime-input scope fences before row locks, including empty writes and reversed callers (M1a)', async () => {
    const holder = await runtime.connect();
    const writer = await admin.connect();
    const context = async (
      client: typeof holder,
      participant = participantA,
      privacy = privacyA,
    ) => {
      await client.query('begin');
      if (client === writer) await client.query('set local role openpc_control_worker');
      await client.query("set local statement_timeout='2s'");
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-MODULES_READ_RESOURCE-V1',true)`,
        [participant, privacy],
      );
    };
    try {
      expect(
        (
          await admin.query(`select t.tgtype::int type,t.tgenabled enabled from pg_trigger t
        where t.tgrelid='control.runtime_configuration_input'::regclass and t.tgname='runtime_input_reference_fence'`)
        ).rows,
      ).toEqual([{ type: 30, enabled: 'O' }]);
      await context(holder);
      await holder.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
        `module-admission:${participantA}:${privacyA}`,
      ]);
      await context(writer);
      await expect(
        writer.query(
          'update control.runtime_configuration_input set selected=selected where false',
        ),
      ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
      await writer.query('rollback');
      await context(writer, participantB, privacyB);
      expect(
        (
          await writer.query(
            'update control.runtime_configuration_input set selected=selected where false',
          )
        ).rowCount,
      ).toBe(0);
      await writer.query('rollback');
      await holder.query('rollback');
      // A caller already holding the policy fence must fail rather than wait
      // for another transaction's module fence in the opposite order.
      await context(holder);
      await holder.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
        `openpc-policy-generations:${participantA}:${privacyA}`,
      ]);
      await context(writer);
      await writer.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
        `module-admission:${participantA}:${privacyA}`,
      ]);
      await expect(
        writer.query(
          'update control.runtime_configuration_input set selected=selected where false',
        ),
      ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
      await writer.query('rollback');
      await holder.query('rollback');
      await context(writer);
      await writer.query(
        'update control.runtime_configuration_input set selected=selected where false',
      );
      await context(holder);
      expect(
        (
          await holder.query('select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired', [
            `module-admission:${participantA}:${privacyA}`,
          ])
        ).rows[0].acquired,
      ).toBe(false);
    } finally {
      await holder.query('rollback');
      await writer.query('rollback');
      holder.release(true);
      writer.release(true);
    }
  });

  it('fences activation and settings statements in scoped runtime and worker roles, including empty writes (M1a)', async () => {
    const holder = await runtime.connect();
    const writer = await admin.connect();
    const tables = [
      ['runtime_configuration_generation', 'TRY_CIGL_INSERT'],
      ['policy_activation_occurrence', 'TRY'],
      ['policy_activation_occurrence_target', 'TRY'],
      ['cigl_settings', 'TRY'],
    ] as const;
    const cases = tables.flatMap(([table]) => {
      const action =
        table === 'cigl_settings'
          ? 'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1'
          : table === 'runtime_configuration_generation'
            ? 'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1'
            : 'ACT-POLICY_ACTIVATE_RELEASE-V1';
      const writes = [
        {
          role: 'openpc_control_runtime',
          action,
          sql: `insert into control.${table} select * from control.${table} where false`,
        },
      ];
      if (table !== 'cigl_settings')
        writes.push({
          role: 'openpc_control_worker',
          action: 'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',
          sql: `update control.${table} set state=state where false`,
        });
      if (table === 'policy_activation_occurrence_target')
        writes.push({
          role: 'openpc_control_runtime',
          action,
          sql: `delete from control.${table} where false`,
        });
      return writes;
    });
    const begin = async (
      client: typeof holder,
      action: string,
      participant = participantA,
      privacy = privacyA,
      role?: string,
    ) => {
      await client.query('begin');
      if (role) await client.query(`set local role ${role}`);
      await client.query("set local lock_timeout='250ms'");
      await client.query("set local statement_timeout='2s'");
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),$3,true)`,
        [participant, privacy, action],
      );
    };
    const policyKey = `openpc-policy-generations:${participantA}:${privacyA}`;
    const original = await authoritySnapshot();
    try {
      for (const [table, mode] of tables) {
        expect(
          (
            await admin.query(
              `select t.tgtype::int type,t.tgenabled enabled,p.proname function,
                 encode(t.tgargs,'hex') arguments
               from pg_trigger t join pg_proc p on p.oid=t.tgfoid
               where t.tgrelid=$1::regclass and t.tgname=$2`,
              [`control.${table}`, `${table}_reference_fence`],
            )
          ).rows,
        ).toEqual([
          {
            type: 30,
            enabled: 'O',
            function: 'guard_policy_generation_fence',
            arguments: Buffer.from(`${mode}\0`).toString('hex'),
          },
        ]);
      }
      for (const test of cases) {
        await begin(holder, 'ACT-MODULES_READ_RESOURCE-V1');
        await holder.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
          policyKey,
        ]);
        await begin(writer, test.action, participantA, privacyA, test.role);
        await expect(writer.query(test.sql)).rejects.toMatchObject({
          code: 'P0001',
          message: 'PC-DATA-6007',
        });
        await writer.query('rollback');
        await begin(writer, test.action, participantB, privacyB, test.role);
        expect((await writer.query(test.sql)).rowCount).toBe(0);
        await writer.query('rollback');
        await holder.query('rollback');

        // Even a zero-row statement holds the exclusive writer fence until end
        // of transaction. A new preflight cannot observe through that writer.
        await begin(writer, test.action, participantA, privacyA, test.role);
        expect((await writer.query(test.sql)).rowCount).toBe(0);
        await begin(holder, 'ACT-MODULES_READ_RESOURCE-V1');
        expect(
          (
            await holder.query(
              'select pg_try_advisory_xact_lock_shared(hashtextextended($1,0)) acquired',
              [policyKey],
            )
          ).rows[0].acquired,
        ).toBe(false);
        await writer.query('rollback');
        expect(
          (
            await holder.query(
              'select pg_try_advisory_xact_lock_shared(hashtextextended($1,0)) acquired',
              [policyKey],
            )
          ).rows[0].acquired,
        ).toBe(true);
        await holder.query('rollback');
      }
      // A fence grants no new write or lock-owner privilege.
      await begin(
        writer,
        'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1',
        participantA,
        privacyA,
        'openpc_control_worker',
      );
      await expect(
        writer.query(
          'insert into control.cigl_settings select * from control.cigl_settings where false',
        ),
      ).rejects.toMatchObject({ code: '42501' });
      await writer.query('rollback');
      await begin(
        writer,
        'ACT-MODULES_READ_RESOURCE-V1',
        participantA,
        privacyA,
        'openpc_control_reader',
      );
      await expect(
        writer.query('select openpc.lock_cigl_grant_sources(true)'),
      ).rejects.toMatchObject({ code: '42501' });
      await writer.query('rollback');
      // Fail closed on a misinstalled mode, extra arguments, or assigning the
      // generation-only grant ordering mode to another table.
      for (const argumentsSql of ["'UNKNOWN'", "'TRY','EXTRA'", "'TRY_CIGL_INSERT'"]) {
        await begin(writer, 'ACT-MODULES_READ_RESOURCE-V1');
        await writer.query(
          'create temporary table m1a_invalid_fence_mode(value integer) on commit drop',
        );
        await writer.query(`create trigger invalid_fence before insert on m1a_invalid_fence_mode
          for each statement execute function openpc.guard_policy_generation_fence(${argumentsSql})`);
        await expect(
          writer.query('insert into m1a_invalid_fence_mode default values'),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6004' });
        await writer.query('rollback');
      }
      await begin(
        writer,
        'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',
        participantA,
        privacyA,
        'openpc_control_runtime',
      );
      await writer.query(
        "select openpc.set_request_context('PARTICIPANT',$1,null,uuidv7(),'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',false)",
        [participantA],
      );
      await expect(writer.query(cases[0]!.sql)).rejects.toMatchObject({
        code: 'P0001',
        message: 'DATA-6000-CONTEXT-MISSING',
      });
      await writer.query('rollback');
      expect(await authoritySnapshot()).toEqual(original);
    } finally {
      await holder.query('rollback');
      await writer.query('rollback');
      holder.release(true);
      writer.release(true);
    }
  });

  it('rejects generation grant/policy inversion and releases both fences on rollback (M1a)', async () => {
    const policy = await runtime.connect();
    const grants = await runtime.connect();
    const begin = async (client: typeof policy) => {
      await client.query('begin');
      await client.query("set local lock_timeout='250ms'");
      await client.query("set local statement_timeout='2s'");
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',true)`,
        [participantA, privacyA],
      );
    };
    const insert =
      'insert into control.runtime_configuration_generation select * from control.runtime_configuration_generation where false';
    const policyKey = `openpc-policy-generations:${participantA}:${privacyA}`;
    try {
      await begin(policy);
      await policy.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [policyKey]);
      await begin(grants);
      await grants.query('select openpc.lock_cigl_grant_sources()');
      // One caller already owns policy; the other owns grants. Neither new
      // statement may wait for the opposite fence or reach a row-trigger wait.
      await expect(policy.query(insert)).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-DATA-6007',
      });
      await policy.query('rollback');
      expect((await grants.query(insert)).rowCount).toBe(0);
      await grants.query('rollback');
      await begin(policy);
      await policy.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
        policyKey,
      ]);
      await begin(grants);
      await expect(grants.query(insert)).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-DATA-6007',
      });
      await grants.query('rollback');
      // The failed policy acquisition must not leave its earlier grant lock.
      await policy.query('select openpc.lock_cigl_grant_sources(true)');
      await begin(grants);
      // Old callers still block, with their ordinary bounded SQL timeout.
      await expect(grants.query('select openpc.lock_cigl_grant_sources()')).rejects.toMatchObject({
        code: '55P03',
      });
      await grants.query('rollback');
      await policy.query('rollback');
      await begin(grants);
      await grants.query('select openpc.lock_cigl_grant_sources()');
      await expect(
        grants.query('select openpc.lock_cigl_grant_sources(null::boolean)'),
      ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6004' });
    } finally {
      await policy.query('rollback');
      await grants.query('rollback');
      policy.release(true);
      grants.release(true);
    }
  });

  it('derives owner, forced RLS, revoked defaults and least privilege from generated migrations', async () => {
    const policyTables = [
      'module_capability',
      'module_configuration_generation',
      'module_conflict',
      'module_dependency',
      'module_installation',
      'module_registration',
      'module_version',
      'policy',
      'policy_activation',
      'policy_activation_occurrence',
      'policy_activation_occurrence_target',
      'policy_activation_prerequisite',
      'policy_artifact',
      'policy_generation',
      'policy_release_bundle',
      'policy_simulation',
      'policy_version',
    ];
    const rlsTables = policyTables.filter((table) =>
      [
        'module_configuration_generation',
        'module_installation',
        'policy',
        'policy_activation',
        'policy_activation_occurrence',
        'policy_activation_occurrence_target',
        'policy_activation_prerequisite',
        'policy_artifact',
        'policy_generation',
        'policy_release_bundle',
        'policy_simulation',
        'policy_version',
      ].includes(table),
    );
    const tables = await admin.query(
      `select c.relname,
              pg_get_userbyid(c.relowner) owner,
              c.relrowsecurity,c.relforcerowsecurity,
              has_table_privilege('openpc_control_runtime',c.oid,'SELECT') runtime_select,
              has_table_privilege('openpc_control_runtime',c.oid,'INSERT') runtime_insert,
              has_table_privilege('openpc_control_runtime',c.oid,'UPDATE') runtime_update,
              has_table_privilege('openpc_control_runtime',c.oid,'DELETE') runtime_delete,
              exists(select 1 from aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl
                     where acl.grantee=0 and acl.privilege_type in
                       ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER')) public_access
         from pg_class c join pg_namespace n on n.oid=c.relnamespace
        where n.nspname='control' and c.relname=any($1::text[])
        order by c.relname`,
      [policyTables],
    );
    expect(tables.rows).toHaveLength(17);
    for (const row of tables.rows) {
      expect(row.owner, row.relname).toBe('openpc_control_owner');
      expect(row.runtime_select, row.relname).toBe(true);
      expect(row.runtime_delete, row.relname).toBe(
        row.relname === 'policy_activation_occurrence_target',
      );
      expect(row.public_access, row.relname).toBe(false);
      expect(row.relrowsecurity, row.relname).toBe(rlsTables.includes(row.relname));
      expect(row.relforcerowsecurity, row.relname).toBe(rlsTables.includes(row.relname));
      const insertable = [
        'policy',
        'policy_activation',
        'policy_activation_occurrence',
        'policy_activation_occurrence_target',
        'policy_activation_prerequisite',
        'policy_artifact',
        'policy_generation',
        'policy_release_bundle',
        'policy_simulation',
        'policy_version',
      ].includes(row.relname);
      const updateable = [
        'policy',
        'policy_activation',
        'policy_activation_occurrence',
        'policy_activation_occurrence_target',
        'policy_activation_prerequisite',
        'policy_generation',
        'policy_release_bundle',
      ].includes(row.relname);
      expect(row.runtime_insert, row.relname).toBe(insertable);
      expect(row.runtime_update, row.relname).toBe(updateable);
    }
    const roles = await admin.query(
      `select rolname,rolsuper,rolbypassrls from pg_roles
        where rolname in ('openpc_control_owner','openpc_control_runtime','openpc_control_worker',
                          'openpc_control_platform_runtime','openpc_control_reader')`,
    );
    expect(roles.rows).toHaveLength(5);
    expect(roles.rows.every((row) => !row.rolsuper && !row.rolbypassrls)).toBe(true);
    expect(
      (
        await admin.query(
          `select count(*)::int count
             from pg_default_acl defaults
             join pg_roles owner on owner.oid=defaults.defaclrole
             join pg_namespace namespace on namespace.oid=defaults.defaclnamespace,
                  lateral aclexplode(defaults.defaclacl) acl
            where owner.rolname='openpc_control_owner' and namespace.nspname='control'
              and acl.grantee=0`,
        )
      ).rows[0].count,
    ).toBe(0);
  });

  it('enforces participant and privacy-domain RLS on read/insert/update and substitution', async () => {
    const client = await runtime.connect();
    try {
      await client.query('begin');
      await client.query('select openpc.set_request_context($1,$2,$3,$4,$5,true)', [
        'PARTICIPANT',
        participantB,
        privacyB,
        '018f3000-0000-7000-8000-000000000001',
        'ACT-POLICY_ACTIVATE_RELEASE-V1',
      ]);
      expect(
        (
          await client.query(
            'select count(*)::int count from control.policy_activation_prerequisite where policy_activation_id=$1',
            [activationId],
          )
        ).rows[0].count,
      ).toBe(0);
      await expect(
        client.query(
          `insert into control.policy_activation_prerequisite
           (policy_activation_id,participant_id,privacy_domain_id,prerequisite_type,
            prerequisite_subject_digest,receipt_digest,ready)
           values($1,$2,$3,'SIMULATION',$4,$5,true)`,
          [activationId, participantA, privacyA, hex('11'), hex('55')],
        ),
      ).rejects.toMatchObject({ code: '42501' });
      await client.query('rollback');
      await client.query('begin');
      await client.query('select openpc.set_request_context($1,$2,$3,$4,$5,true)', [
        'PARTICIPANT',
        participantB,
        privacyB,
        '018f3000-0000-7000-8000-000000000002',
        'ACT-POLICY_ACTIVATE_RELEASE-V1',
      ]);
      expect(
        (
          await client.query(
            'update control.policy_activation_prerequisite set ready=false where policy_activation_id=$1',
            [activationId],
          )
        ).rowCount,
      ).toBe(0);
      await client.query('rollback');
    } finally {
      client.release();
    }
    await rejectsWithoutEffect(
      mutation({
        participantId: participantB,
        privacyDomainId: privacyB,
        principalId: makerB,
        checkerPrincipalId: '018f0000-0000-7000-8000-000000000a04',
        participantEpoch: 7n,
        principalEpoch: 8n,
        checkerPrincipalEpoch: 9n,
      }),
    );
  });

  it('rejects wrong operation, self-checking, every stale epoch and every causal mismatch', async () => {
    const cases: Array<
      [string, Partial<PolicyActivationMutation>, 'PC-POLICY-2004' | 'PC-POLICY-2005']
    > = [
      [
        'wrong operation',
        { catalogOperationId: 'POL-OP-ENABLE' as 'POL-OP-ACTIVATE' },
        'PC-POLICY-2004',
      ],
      ['wrong action', { actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1' }, 'PC-POLICY-2004'],
      ['self checker', { checkerPrincipalId: makerA }, 'PC-POLICY-2004'],
      ['participant epoch', { participantEpoch: 3n }, 'PC-POLICY-2005'],
      ['maker epoch', { principalEpoch: 4n }, 'PC-POLICY-2005'],
      ['checker epoch', { checkerPrincipalEpoch: 5n }, 'PC-POLICY-2005'],
      ['authority epoch', { authorityEpoch: 5n }, 'PC-POLICY-2005'],
      ['delegation epoch', { delegationEpoch: 2n }, 'PC-POLICY-2005'],
      ['envelope version', { envelopeRowVersion: 2n }, 'PC-POLICY-2005'],
      ['assignment version', { assignmentRowVersion: 2n }, 'PC-POLICY-2005'],
      ['credential epoch', { checkerCredentialEpoch: 2n }, 'PC-POLICY-2005'],
      ['candidate', { candidateDigest: hex('12') }, 'PC-POLICY-2005'],
      [
        'simulation',
        { policySimulationId: '018f0000-0000-7000-8000-000000000999' },
        'PC-POLICY-2005',
      ],
      ['approval', { approvalRequestId: '018f0000-0000-7000-8000-000000000999' }, 'PC-POLICY-2005'],
      ['mfa', { mfaChallengeId: '018f0000-0000-7000-8000-000000000999' }, 'PC-POLICY-2005'],
      ['webauthn binding', { webauthnAssertionBindingDigest: hex('26') }, 'PC-POLICY-2005'],
      ['dependency', { dependencyClosureDigest: hex('26') }, 'PC-POLICY-2005'],
      ['cohort', { exactCohortDigest: hex('26') }, 'PC-POLICY-2005'],
      ['scope', { scopeDigest: hex('26') }, 'PC-POLICY-2005'],
      [
        'envelope',
        { authorityEnvelopeId: '018f0000-0000-7000-8000-000000000999' },
        'PC-POLICY-2005',
      ],
      ['assignment', { assignmentId: '018f0000-0000-7000-8000-000000000999' }, 'PC-POLICY-2005'],
      [
        'credential',
        { checkerCredentialId: '018f0000-0000-7000-8000-000000000999' },
        'PC-POLICY-2005',
      ],
    ];
    for (const [name, overrides, expected] of cases) {
      await rejectsWithoutEffect(mutation(overrides), expected).catch((error: unknown) => {
        throw new Error(`${name}: ${String(error)}`);
      });
    }
  });

  it('authorizes only a live bounded delegation and binds its terminal epoch', async () => {
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const request = {
      sessionToken: `${participantA}.${delegateSessionId}`,
      privacyDomainId: privacyA,
      actionIntentId: 'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
      resourceId: '018f0000-0000-7000-8000-000000000911',
      stepUpRequired: false,
    };
    await expect(authorizeLocalPolicyAction(runtime, kernel, request)).resolves.toMatchObject({
      participantId: participantA,
      principalId: delegateA,
      assignmentId: '018f0000-0000-7000-8000-0000000009a2',
      delegationEpoch: '2',
    });
    await admin.query(
      `update control.delegation set state='SUSPENDED'
        where delegation_id='018f0000-0000-7000-8000-0000000009d3'`,
    );
    try {
      await expect(authorizeLocalPolicyAction(runtime, kernel, request)).rejects.toThrow(
        'PC-IDENTITY-1002',
      );
    } finally {
      await admin.query(
        `update control.delegation set state='ACTIVE'
          where delegation_id='018f0000-0000-7000-8000-0000000009d3'`,
      );
    }
  });

  it('rejects expired approval, expired and replayed WebAuthn proof, and prerequisite substitution', async () => {
    await admin.query(
      `update control.approval_request set expires_at=clock_timestamp()-interval '1 second'
       where approval_request_id='018f0000-0000-7000-8000-000000000913'`,
    );
    await rejectsWithoutEffect(mutation());
    await admin.query(
      `update control.approval_request set expires_at=clock_timestamp()+interval '30 minutes'
       where approval_request_id='018f0000-0000-7000-8000-000000000913'`,
    );
    await admin.query(
      `update control.mfa_challenge set expires_at=clock_timestamp()-interval '1 second'
       where mfa_challenge_id=$1`,
      [challengeId],
    );
    await rejectsWithoutEffect(mutation());
    await admin.query(
      `update control.mfa_challenge set expires_at=clock_timestamp()+interval '30 minutes',
       used_at=clock_timestamp(),used_operation_id='018f3000-0000-7000-8000-000000000003'
       where mfa_challenge_id=$1`,
      [challengeId],
    );
    await rejectsWithoutEffect(mutation());
    await admin.query(
      `update control.mfa_challenge set used_at=null,used_operation_id=null
       where mfa_challenge_id=$1`,
      [challengeId],
    );
    await admin.query(
      `update control.policy_activation_prerequisite set prerequisite_subject_digest=$1
       where policy_activation_id=$2 and prerequisite_type='DEPENDENCY_CLOSURE'`,
      [hex('26'), activationId],
    );
    await rejectsWithoutEffect(mutation());
    await admin.query(
      `update control.policy_activation_prerequisite set prerequisite_subject_digest=$1
       where policy_activation_id=$2 and prerequisite_type='DEPENDENCY_CLOSURE'`,
      [hex('22'), activationId],
    );
  });

  it('requires linked cryptographic WebAuthn verification and rejects forged proof fields', async () => {
    const valid = mutation();
    const alteredSignature = Buffer.from(valid.webauthnSignature);
    alteredSignature[alteredSignature.length - 1] ^= 1;
    const alteredSpki = Buffer.from(valid.webauthnCredentialPublicKeySpkiDer);
    alteredSpki[alteredSpki.length - 1] ^= 1;
    const wrongClientData = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: `${valid.webauthnChallenge}changed`,
        origin: valid.webauthnOrigin,
      }),
      'utf8',
    );
    const cases: Array<[string, Partial<PolicyActivationMutation>]> = [
      ['forged signature', { webauthnSignature: alteredSignature }],
      ['mismatched SPKI', { webauthnCredentialPublicKeySpkiDer: alteredSpki }],
      ['mismatched challenge', { webauthnChallenge: `${valid.webauthnChallenge}changed` }],
      ['mismatched client challenge', { webauthnClientDataJson: wrongClientData }],
    ];
    for (const [name, override] of cases) {
      await rejectsWithoutEffect(mutation(override)).catch((error: unknown) => {
        throw new Error(`${name}: ${String(error)}`);
      });
    }
    await admin.query(
      'alter table control.mutation_evidence disable trigger mutation_evidence_immutable',
    );
    await admin.query(
      `update control.mutation_evidence
          set mfa_challenge_id='018f0000-0000-7000-8000-0000000009f2'
        where mfa_challenge_id=$1 and catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'`,
      [challengeId],
    );
    await admin.query(
      'alter table control.mutation_evidence enable trigger mutation_evidence_immutable',
    );
    try {
      await rejectsWithoutEffect(mutation());
    } finally {
      await admin.query(
        'alter table control.mutation_evidence disable trigger mutation_evidence_immutable',
      );
      await admin.query(
        `update control.mutation_evidence set mfa_challenge_id=$1
          where mfa_challenge_id='018f0000-0000-7000-8000-0000000009f2'
            and catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'`,
        [challengeId],
      );
      await admin.query(
        'alter table control.mutation_evidence enable trigger mutation_evidence_immutable',
      );
    }
    await rejectsWithoutEffect(
      mutation({
        aggregateId: '018f0000-0000-7000-8000-000000000938',
        candidateDigest: hex('33'),
        approvalRequestId: '018f0000-0000-7000-8000-000000000933',
        policySimulationId: '018f0000-0000-7000-8000-000000000932',
        assignmentId: '018f0000-0000-7000-8000-000000000935',
        scopeDigest: hex('32'),
        exactCohortDigest: hex('36'),
      }),
      'PC-POLICY-2005',
      '018f0000-0000-7000-8000-000000000938',
    );
  });

  it('rejects forged or semantically unrelated signed activation artifacts with zero effect', async () => {
    const placeholderCose = Buffer.from('d28440a04040', 'hex');
    const unrelatedEvidence = Buffer.from('a0', 'hex');
    const unrelatedDigest = sha256(unrelatedEvidence);
    const valid = mutation();
    const alteredCose = Buffer.from(valid.coseSign1);
    alteredCose[alteredCose.length - 1] ^= 1;
    const cases: Array<[string, Partial<PolicyActivationMutation>]> = [
      [
        'unrelated complete blob set',
        {
          evidenceCbor: unrelatedEvidence,
          evidenceDigest: unrelatedDigest,
          payloadCbor: unrelatedEvidence,
          payloadDigest: unrelatedDigest,
          coseSign1: placeholderCose,
          receiptDigest: sha256(placeholderCose),
        },
      ],
      ['forged COSE signature', { coseSign1: alteredCose, receiptDigest: sha256(alteredCose) }],
      ['mismatched payload', { payloadCbor: unrelatedEvidence, payloadDigest: unrelatedDigest }],
      ['unbound receipt', { receiptDigest: hex('93') }],
    ];
    for (const [name, overrides] of cases) {
      await rejectsWithoutEffect(mutation(overrides)).catch((error: unknown) => {
        throw new Error(`${name}: ${String(error)}`);
      });
    }
  });

  it('binds signed authorization to candidate, action, approval, aggregate, version and decision', async () => {
    const baselineCandidate = hex('11');
    const baselineApproval = '018f0000-0000-7000-8000-000000000913';
    const substitutions: Array<
      [string, Partial<PolicyActivationMutation>, 'PC-POLICY-2004' | 'PC-POLICY-2005'?]
    > = [
      ['candidate', activationArtifact(hex('33'), activationId, baselineApproval, 1n)],
      [
        'action',
        {
          actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
          ...activationArtifact(baselineCandidate, activationId, baselineApproval, 1n),
        },
        'PC-POLICY-2004',
      ],
      [
        'approval',
        activationArtifact(
          baselineCandidate,
          activationId,
          '018f0000-0000-7000-8000-000000000933',
          1n,
        ),
      ],
      [
        'aggregate',
        activationArtifact(
          baselineCandidate,
          '018f0000-0000-7000-8000-000000000938',
          baselineApproval,
          1n,
        ),
      ],
      [
        'aggregate version',
        activationArtifact(baselineCandidate, activationId, baselineApproval, 2n),
      ],
    ];
    for (const [name, overrides, expected] of substitutions) {
      await rejectsWithoutEffect(mutation(overrides), expected).catch((error: unknown) => {
        throw new Error(`${name}: ${String(error)}`);
      });
    }

    await admin.query(
      'alter table control.approval_decision_record disable trigger approval_decision_immutable',
    );
    try {
      await admin.query(
        `update control.approval_decision_record set decision='REJECT'
         where approval_request_id=$1`,
        [baselineApproval],
      );
      await rejectsWithoutEffect(mutation()).catch((error: unknown) => {
        throw new Error(`decision: ${String(error)}`);
      });
    } finally {
      await admin.query(
        `update control.approval_decision_record set decision='APPROVE'
         where approval_request_id=$1`,
        [baselineApproval],
      );
      await admin.query(
        'alter table control.approval_decision_record enable trigger approval_decision_immutable',
      );
    }
  });

  it('rejects stored checker envelope, assignment and challenge identity substitution', async () => {
    const substitutions = [
      {
        breakSql:
          "update control.authority_envelope set principal_id='018f0000-0000-7000-8000-000000000903' where authority_envelope_id='018f0000-0000-7000-8000-000000000914'",
        restoreSql:
          "update control.authority_envelope set principal_id='018f0000-0000-7000-8000-000000000904' where authority_envelope_id='018f0000-0000-7000-8000-000000000914'",
      },
      {
        breakSql:
          "update control.assignment set principal_id='018f0000-0000-7000-8000-000000000903' where assignment_id='018f0000-0000-7000-8000-000000000915'",
        restoreSql:
          "update control.assignment set principal_id='018f0000-0000-7000-8000-000000000904' where assignment_id='018f0000-0000-7000-8000-000000000915'",
      },
      {
        breakSql: `update control.mfa_challenge set principal_id='018f0000-0000-7000-8000-000000000903' where mfa_challenge_id='${challengeId}'`,
        restoreSql: `update control.mfa_challenge set principal_id='018f0000-0000-7000-8000-000000000904' where mfa_challenge_id='${challengeId}'`,
      },
    ];
    for (const substitution of substitutions) {
      await admin.query(substitution.breakSql);
      try {
        await rejectsWithoutEffect(mutation());
      } finally {
        await admin.query(substitution.restoreSql);
      }
    }
  });

  it('activates two exact scopes concurrently and retires only each own predecessor', async () => {
    const scopeTwoActivation = '018f0000-0000-7000-8000-000000000938';
    const scopeThreeActivation = '018f0000-0000-7000-8000-000000000948';
    const scopeTwo = mutation({
      aggregateId: scopeTwoActivation,
      candidateDigest: hex('33'),
      approvalRequestId: '018f0000-0000-7000-8000-000000000933',
      mfaChallengeId: scopeTwoChallengeId,
      ...webauthnProof(hex('33'), 0x37),
      assignmentId: '018f0000-0000-7000-8000-000000000935',
      policySimulationId: '018f0000-0000-7000-8000-000000000932',
      scopeDigest: hex('32'),
      exactCohortDigest: hex('36'),
    });
    const scopeThree = mutation({
      aggregateId: scopeThreeActivation,
      candidateDigest: hex('43'),
      approvalRequestId: '018f0000-0000-7000-8000-000000000943',
      mfaChallengeId: scopeThreeChallengeId,
      ...webauthnProof(hex('43'), 0x47),
      assignmentId: '018f0000-0000-7000-8000-000000000945',
      policySimulationId: '018f0000-0000-7000-8000-000000000942',
      scopeDigest: hex('42'),
      exactCohortDigest: hex('46'),
    });
    await Promise.all([
      activatePolicyGeneration(runtime, scopeTwo, scopeTwoActivation),
      activatePolicyGeneration(runtime, scopeThree, scopeThreeActivation),
    ]);
    const result = await admin.query(
      `select
      scope_digest, count(*) filter (where active)::int active_count,
      array_agg(encode(generation_digest,'hex') order by generation) digests,
      array_agg(state order by generation) states
      from control.policy_generation
      where scope_digest in ($1,$2)
      group by scope_digest order by scope_digest`,
      [hex('32'), hex('42')],
    );
    expect(result.rows).toHaveLength(2);
    for (const row of result.rows) {
      expect(row.active_count).toBe(1);
      expect(row.states).toBe('{RETIRED,ACTIVE}');
    }
    const activations = await admin.query(
      `select policy_activation_id,state from control.policy_activation
       where policy_activation_id in
       ('018f0000-0000-7000-8000-000000000937','018f0000-0000-7000-8000-000000000938',
        '018f0000-0000-7000-8000-000000000947','018f0000-0000-7000-8000-000000000948')
       order by policy_activation_id`,
    );
    expect(activations.rows.map((row) => row.state)).toEqual([
      'RETIRED',
      'ACTIVE',
      'RETIRED',
      'ACTIVE',
    ]);
  });

  it('commits activation, generation, evidence, outbox, proof use and idempotency atomically', async () => {
    const input = mutation();
    baselineActivationHttpBody = activationHttpBody(input);
    const before = await authoritySnapshot();
    const internalToken = 'local-policy-internal-token-000000000000000000000000';
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const identity = Fastify({ logger: false });
    identity.post('/internal/v1/local/policy/authorize', async (request, reply) => {
      if (request.headers.authorization !== `Bearer ${internalToken}`) {
        return reply.code(403).send({ code: 'PC-AUTH-0005' });
      }
      try {
        return localPolicyAuthorizationResponse(
          await authorizeLocalPolicyAction(
            runtime,
            kernel,
            request.body as Parameters<typeof authorizeLocalPolicyAction>[2],
          ),
        );
      } catch (error) {
        return reply.code(403).send({
          code: error instanceof IdentityKernelError ? error.code : 'PC-IDENTITY-1004',
        });
      }
    });
    const identityAddress = await identity.listen({ host: '127.0.0.1', port: 0 });
    const policy = buildPolicyService({
      pool: runtime,
      identityGateway: new HttpPolicyIdentityGateway(identityAddress, internalToken),
      trustedArtifactSigners: [{ publicKeySpkiDer: signerSpki }],
      internalToken,
    });
    const policyAddress = await policy.listen({ host: '127.0.0.1', port: 0 });
    const headers = {
      'authorization': `Bearer ${internalToken}`,
      'content-type': 'application/json',
      'openpc-participant-id': `urn:openpc:participant:${participantA}`,
      'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyA}`,
      'x-request-id': input.operationId,
    };
    try {
      const activated = await fetch(new URL('/internal/v1/policy-activations', policyAddress), {
        method: 'POST',
        headers,
        body: JSON.stringify(baselineActivationHttpBody),
      });
      const activatedBody = await activated.text();
      expect(activated.status, activatedBody).toBe(200);
      const replay = await fetch(new URL('/internal/v1/policy-activations', policyAddress), {
        method: 'POST',
        headers,
        body: JSON.stringify(baselineActivationHttpBody),
      });
      const replayBody = await replay.text();
      expect(replay.status, replayBody).toBe(200);
      const evidence = await fetch(
        new URL(`/internal/v1/policy-activations/${activationId}/evidence`, policyAddress),
        {
          headers: {
            ...headers,
            'x-openpc-session-token': `${participantA}.${makerSessionId}`,
          },
        },
      );
      const evidenceBody = await evidence.text();
      expect(evidence.status, evidenceBody).toBe(200);
      expect(JSON.parse(evidenceBody) as Record<string, unknown>).toMatchObject({
        policyActivationId: activationId,
        state: 'ACTIVE',
        approvalRequestId: input.approvalRequestId,
        outboxEventId: input.eventId,
      });
    } finally {
      await Promise.all([policy.close(), identity.close()]);
    }
    const after = await authoritySnapshot();
    expect(after).toEqual({
      activations: before.activations + 1,
      generations: before.generations + 1,
      evidence: before.evidence + 1,
      outbox: before.outbox + 1,
      idempotency: before.idempotency + 1,
      used_proofs: before.used_proofs + 1,
    });
    await activatePolicyGeneration(runtime, input, activationId);
    expect(await authoritySnapshot()).toEqual(after);

    const boundRows = await admin.query(
      `select activation.state, evidence.bound_envelope_epoch,
              envelope.row_version envelope_row_version,
              assignment.row_version assignment_row_version,
              evidence.catalog_operation_id,
              octet_length(evidence.webauthn_assertion_binding_digest) evidence_binding_length,
              octet_length(outbox.webauthn_assertion_binding_digest) outbox_binding_length
         from control.policy_activation activation
         join control.mutation_evidence evidence
           on (evidence.participant_id,evidence.aggregate_type,evidence.aggregate_id)=
              (activation.participant_id,'policy-activation',activation.policy_activation_id)
         join control.outbox_event outbox
           on (outbox.participant_id,outbox.aggregate_type,outbox.aggregate_id,outbox.aggregate_sequence)=
              (evidence.participant_id,evidence.aggregate_type,evidence.aggregate_id,evidence.aggregate_version)
         join control.authority_envelope envelope
           on (envelope.participant_id,envelope.authority_envelope_id)=
              (evidence.participant_id,evidence.bound_authority_envelope_id)
         join control.assignment assignment
           on (assignment.participant_id,assignment.assignment_id)=
              (evidence.participant_id,evidence.bound_assignment_id)
        where activation.policy_activation_id=$1 and evidence.operation_id=$2`,
      [activationId, input.operationId],
    );
    expect(boundRows.rows).toEqual([
      {
        state: 'ACTIVE',
        bound_envelope_epoch: '6',
        envelope_row_version: '1',
        assignment_row_version: '1',
        catalog_operation_id: 'POL-OP-ACTIVATE',
        evidence_binding_length: 32,
        outbox_binding_length: 32,
      },
    ]);

    const replayMismatches: Array<[string, Partial<PolicyActivationMutation>]> = [
      ['operation', { operationId: '018f1000-0000-7000-8000-ffffffffff01' }],
      ['aggregate type', { aggregateType: 'policy-release' }],
      ['aggregate id', { aggregateId: '018f0000-0000-7000-8000-000000000999' }],
      ['aggregate version', { expectedAggregateVersion: 2n }],
      ['event id', { eventId: '018f2000-0000-7000-8000-ffffffffff02' }],
      ['event type', { eventType: 'openpc.policy.release.activated.v1' }],
      ['candidate', { candidateDigest: hex('12') }],
      ['scope', { scopeDigest: hex('32') }],
      ['dependency', { dependencyClosureDigest: hex('26') }],
      ['cohort', { exactCohortDigest: hex('27') }],
      ['approval', { approvalRequestId: '018f0000-0000-7000-8000-000000000999' }],
      ['simulation', { policySimulationId: '018f0000-0000-7000-8000-000000000999' }],
      ['participant epoch', { participantEpoch: 3n }],
      ['maker epoch', { principalEpoch: 4n }],
      ['checker epoch', { checkerPrincipalEpoch: 5n }],
      ['authority epoch', { authorityEpoch: 5n }],
      ['delegation epoch', { delegationEpoch: 2n }],
      ['envelope row version', { envelopeRowVersion: 2n }],
      ['assignment row version', { assignmentRowVersion: 2n }],
      ['credential epoch', { checkerCredentialEpoch: 2n }],
      ['WebAuthn proof', { webauthnAssertionBindingDigest: hex('26') }],
      ['WebAuthn SPKI', { webauthnCredentialPublicKeySpkiDer: Buffer.from('00', 'hex') }],
      ['WebAuthn challenge', { webauthnChallenge: `${input.webauthnChallenge}changed` }],
      ['WebAuthn authenticator data', { webauthnAuthenticatorData: Buffer.alloc(37) }],
      ['WebAuthn client data', { webauthnClientDataJson: Buffer.from('{}') }],
      ['WebAuthn signature', { webauthnSignature: Buffer.from('00', 'hex') }],
      ['WebAuthn verified time', { webauthnVerifiedAt: '2020-01-01T00:00:00.000Z' }],
      ['evidence CBOR', { evidenceCbor: Buffer.from('a1', 'hex') }],
      ['evidence digest', { evidenceDigest: hex('91') }],
      ['COSE', { coseSign1: Buffer.from('d28440a04041', 'hex') }],
      ['payload CBOR', { payloadCbor: Buffer.from('a1', 'hex') }],
      ['payload digest', { payloadDigest: hex('92') }],
      ['receipt digest', { receiptDigest: hex('93') }],
    ];
    for (const [name, mismatch] of replayMismatches) {
      const beforeReplay = await authoritySnapshot();
      await expect(
        activatePolicyGeneration(runtime, { ...input, ...mismatch }, activationId),
        name,
      ).rejects.toThrow('IDEMPOTENCY_CONFLICT');
      expect(await authoritySnapshot()).toEqual(beforeReplay);
    }
  });

  it('prevents the runtime role from mutating immutable policy inputs', async () => {
    await expect(
      runtime.query(
        `update control.policy_version set semantic_digest=$1
         where policy_version_id='018f0000-0000-7000-8000-000000000911'`,
        [hex('99')],
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      runtime.query(
        `delete from control.policy_simulation
         where simulation_id='018f0000-0000-7000-8000-000000000912'`,
      ),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('denies an active authenticated principal without version authority over real HTTP', async () => {
    const internalToken = 'local-policy-internal-token-000000000000000000000000';
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const identity = Fastify({ logger: false });
    identity.post('/internal/v1/local/policy/authorize', async (request, reply) => {
      if (request.headers.authorization !== `Bearer ${internalToken}`) {
        return reply.code(403).send({ code: 'PC-AUTH-0005' });
      }
      try {
        return localPolicyAuthorizationResponse(
          await authorizeLocalPolicyAction(
            runtime,
            kernel,
            request.body as Parameters<typeof authorizeLocalPolicyAction>[2],
          ),
        );
      } catch {
        return reply.code(403).send({ code: 'PC-IDENTITY-1002' });
      }
    });
    const identityAddress = await identity.listen({ host: '127.0.0.1', port: 0 });
    const policy = buildPolicyService({
      pool: runtime,
      identityGateway: new HttpPolicyIdentityGateway(identityAddress, internalToken),
      trustedArtifactSigners: [{ publicKeySpkiDer: signerSpki }],
      internalToken,
    });
    const policyAddress = await policy.listen({ host: '127.0.0.1', port: 0 });
    const headers = {
      'content-type': 'application/json',
      'cookie': `__Host-openpc_session=${participantA}.${sessionId}`,
      'idempotency-key': 'unauthorized-version-create',
      'openpc-participant-id': `urn:openpc:participant:${participantA}`,
      'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyA}`,
      'x-openpc-action-intent-digest': `sha256:${'33'.repeat(32)}`,
      'x-request-id': '018f0000-0000-7000-8000-0000000009f1',
    };
    try {
      const create = await fetch(new URL('/api/v1/policy-versions', policyAddress), {
        method: 'POST',
        headers,
        body: JSON.stringify({
          policySetId: 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000910',
          semanticVersion: '2.0.0',
          normalizedPolicyDigest: `sha256:${'11'.repeat(32)}`,
          dependencyClosureDigest: `sha256:${'22'.repeat(32)}`,
          actionIntentId: 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
          actionIntentDigest: `sha256:${'33'.repeat(32)}`,
          reason: 'authorization negative',
        }),
      });
      expect(create.status).toBe(403);
      const artifact = await fetch(new URL('/internal/v1/policy-artifacts', policyAddress), {
        method: 'POST',
        headers: { ...headers, authorization: `Bearer ${internalToken}` },
        body: JSON.stringify({
          sessionToken: `${participantA}.${sessionId}`,
          policyId: '018f0000-0000-7000-8000-000000000910',
          semanticVersion: '2.0.0',
          semanticDocument: {},
          semanticCbor: 'oA==',
          policySchemaDigest: `sha256:${'44'.repeat(32)}`,
          dependencyClosureDigest: `sha256:${'22'.repeat(32)}`,
          payloadCbor: 'oA==',
          coseSign1: '0oRAoEA=',
        }),
      });
      expect(artifact.status).toBe(403);
    } finally {
      await Promise.all([policy.close(), identity.close()]);
    }
  });

  it('rejects signed untyped semantics and caller-authored authority or currentness over HTTP', async () => {
    const internalToken = 'local-policy-internal-token-000000000000000000000000';
    const policyId = '018f0000-0000-7000-8000-0000000009b0';
    await admin.query(
      `insert into control.policy(policy_id,participant_id,privacy_domain_id,policy_name)
       values($1,$2,$3,'HTTP lifecycle policy') on conflict (policy_id) do nothing`,
      [policyId, participantA, privacyA],
    );
    const semanticDocument = {
      policy: 'HTTP lifecycle policy',
      rules: [{ action: 'read', effect: 'ALLOW' }],
      version: 1,
    };
    const semantic = pcCbor1(semanticDocument);
    const schemaDigest = sha256('http-policy-schema-v1');
    const dependencyDigest = sha256('http-policy-dependency-closure-v1');
    const payload = encodePolicyArtifactPayload({
      participantId: `urn:openpc:participant:${participantA}`,
      privacyDomainId: `urn:openpc:privacy-domain:${privacyA}`,
      policySetId: `urn:openpc:policy-set:${policyId}`,
      semanticVersion: '1.0.0',
      policySchemaDigest: schemaDigest,
      semanticDigest: semantic.digest,
      dependencyClosureDigest: dependencyDigest,
      semanticBytesDigest: semantic.digest,
    });
    const coseSign1 = policyArtifactCose(payload);
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const identity = Fastify({ logger: false });
    identity.post('/internal/v1/local/policy/authorize', async (request, reply) => {
      if (request.headers.authorization !== `Bearer ${internalToken}`) {
        return reply.code(403).send({ code: 'PC-AUTH-0005' });
      }
      try {
        return localPolicyAuthorizationResponse(
          await authorizeLocalPolicyAction(
            runtime,
            kernel,
            request.body as Parameters<typeof authorizeLocalPolicyAction>[2],
          ),
        );
      } catch {
        return reply.code(403).send({ code: 'PC-IDENTITY-1002' });
      }
    });
    const identityAddress = await identity.listen({ host: '127.0.0.1', port: 0 });
    const makePolicy = () =>
      buildPolicyService({
        pool: runtime,
        identityGateway: new HttpPolicyIdentityGateway(identityAddress, internalToken),
        trustedArtifactSigners: [{ publicKeySpkiDer: signerSpki }],
        internalToken,
      });
    const policy = makePolicy();
    const policyAddress = await policy.listen({ host: '127.0.0.1', port: 0 });
    const sessionToken = `${participantA}.${makerSessionId}`;
    const baseHeaders = {
      'authorization': `Bearer ${internalToken}`,
      'content-type': 'application/json',
      'openpc-participant-id': `urn:openpc:participant:${participantA}`,
      'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyA}`,
    };
    try {
      const authorizationProbe = await fetch(
        new URL('/internal/v1/local/policy/authorize', identityAddress),
        {
          method: 'POST',
          headers: {
            'authorization': `Bearer ${internalToken}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            sessionToken,
            privacyDomainId: privacyA,
            actionIntentId: 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
            resourceId: policyId,
            stepUpRequired: false,
          }),
        },
      );
      const authorizationProbeBody = await authorizationProbe.text();
      expect(authorizationProbe.status, authorizationProbeBody).toBe(200);
      const artifactRequest = {
        sessionToken,
        policyId,
        semanticVersion: '1.0.0',
        semanticDocument,
        semanticCbor: semantic.bytes.toString('base64'),
        policySchemaDigest: `sha256:${schemaDigest.toString('hex')}`,
        dependencyClosureDigest: `sha256:${dependencyDigest.toString('hex')}`,
        payloadCbor: payload.toString('base64'),
        coseSign1: coseSign1.toString('base64'),
      };
      const before = await admin.query(`select
        (select count(*)::text from control.policy_artifact) artifacts,
        (select count(*)::text from control.policy_simulation) simulations,
        (select count(*)::text from control.policy_generation) generations`);
      // A valid signer cannot make an untyped desired outcome authoritative.
      const admitted = await fetch(new URL('/internal/v1/policy-artifacts', policyAddress), {
        method: 'POST',
        headers: { ...baseHeaders, 'x-request-id': '018f0000-0000-7000-8000-0000000009b1' },
        body: JSON.stringify(artifactRequest),
      });
      expect(admitted.status, await admitted.text()).toBe(422);
      for (const [endpoint, selection] of [
        [
          '/internal/v1/policy-simulations',
          { policyVersionId: '018f0000-0000-7000-8000-000000000911' },
        ],
        [
          '/internal/v1/policy-evaluations/active',
          { scopeDigest: `sha256:${hex('31').toString('hex')}` },
        ],
      ] as const) {
        for (const forged of [
          {
            context: {
              platformTerminalDeny: false,
              assignmentAllows: true,
              contributions: [{ effect: 'ALLOW' }],
            },
          },
          { roles: ['urn:openpc:role:018f0000-0000-7000-8000-000000000801'] },
          { currentFactDigest: `sha256:${hex('21').toString('hex')}` },
        ]) {
          const response = await fetch(new URL(endpoint, policyAddress), {
            method: 'POST',
            headers: { ...baseHeaders, 'x-request-id': '018f0000-0000-7000-8000-0000000009b3' },
            body: JSON.stringify({
              sessionToken,
              ...selection,
              request: {
                contractMethodPolicyId: '018f0000-0000-7000-8000-0000000009b4',
                method: 'eth_call',
                calldata: '0x70a08231' + '00'.repeat(32),
              },
              ...forged,
            }),
          });
          expect(response.status, await response.text()).toBe(422);
        }
      }
      const after = await admin.query(`select
        (select count(*)::text from control.policy_artifact) artifacts,
        (select count(*)::text from control.policy_simulation) simulations,
        (select count(*)::text from control.policy_generation) generations`);
      expect(after.rows).toEqual(before.rows);
    } finally {
      await Promise.all([policy.close(), identity.close()]);
    }
  });

  it('creates, reads and approves an immutable public request with a distinct checker and one-use step-up', async () => {
    const fixtureMutation = async (sql: string, values: unknown[]) => {
      const client = await admin.connect();
      try {
        await client.query('begin');
        await client.query('select openpc.set_request_context($1,$2,$3,uuidv7(),$4,true)', [
          'PARTICIPANT',
          participantA,
          privacyA,
          'ACT-POLICY_ACTIVATE_RELEASE-V1',
        ]);
        const result = await client.query(sql, values);
        await client.query('commit');
        return result;
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
    };
    const internalToken = 'local-policy-internal-token-000000000000000000000000';
    const policyId = '018f0000-0000-7000-8000-0000000009c0';
    const policyVersionId = '018f0000-0000-7000-8000-0000000009c1';
    const replacementPolicyVersionId = '018f0000-0000-7000-8000-0000000009d8';
    const candidateDigest = sha256('public-approval-candidate');
    const replacementCandidateDigest = sha256('public-approval-replacement-candidate');
    await admin.query(
      `insert into control.policy(policy_id,participant_id,privacy_domain_id,policy_name)
       values($1,$2,$3,'Public approval policy') on conflict (policy_id) do nothing`,
      [policyId, participantA, privacyA],
    );
    await fixtureMutation(
      `insert into control.policy_version(
         policy_version_id,policy_id,participant_id,privacy_domain_id,version,schema_digest,
         semantic_cbor,semantic_digest,cose_sign1,created_by_principal_id)
       values($1,$2,$3,$4,'1.0.0',$5,decode('a0','hex'),$6,decode('d28440a04040','hex'),$7)
       on conflict (policy_version_id) do nothing`,
      [
        policyVersionId,
        policyId,
        participantA,
        privacyA,
        sha256('public-approval-schema'),
        candidateDigest,
        makerA,
      ],
    );
    await fixtureMutation(
      `insert into control.policy_version(
         policy_version_id,policy_id,participant_id,privacy_domain_id,version,schema_digest,
         semantic_cbor,semantic_digest,cose_sign1,created_by_principal_id)
       values($1,$2,$3,$4,'1.1.0',$5,decode('a0','hex'),$6,decode('d28440a04040','hex'),$7)
       on conflict (policy_version_id) do nothing`,
      [
        replacementPolicyVersionId,
        policyId,
        participantA,
        privacyA,
        sha256('public-approval-replacement-schema'),
        replacementCandidateDigest,
        makerA,
      ],
    );
    const releaseDependencyDigest = sha256('public-release-dependency');
    await fixtureMutation(
      `insert into control.policy_artifact(
         policy_artifact_id,participant_id,privacy_domain_id,policy_id,semantic_version,
         policy_schema_digest,semantic_cbor,semantic_digest,semantic_bytes_digest,
         dependency_closure_digest,payload_cbor,payload_digest,cose_sign1,signer_key_digest,
         admitted_by_principal_id)
       values
         ('018f0000-0000-7000-8000-0000000009d9',$1,$2,$3,'1.0.0',$4,decode('a0','hex'),$5,$5,
          $6,decode('a0','hex'),$7,decode('d28440a04040','hex'),$8,$9),
         ('018f0000-0000-7000-8000-0000000009e0',$1,$2,$3,'1.1.0',$10,decode('a0','hex'),$11,$11,
          $6,decode('a0','hex'),$12,decode('d28440a04040','hex'),$8,$9)
       on conflict (policy_artifact_id) do nothing`,
      [
        participantA,
        privacyA,
        policyId,
        sha256('public-approval-schema'),
        candidateDigest,
        releaseDependencyDigest,
        sha256('public-release-original-payload'),
        sha256(signerSpki),
        makerA,
        sha256('public-approval-replacement-schema'),
        replacementCandidateDigest,
        sha256('public-release-replacement-payload'),
      ],
    );
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const identity = Fastify({ logger: false });
    identity.post('/internal/v1/local/policy/authorize', async (request, reply) => {
      if (request.headers.authorization !== `Bearer ${internalToken}`) {
        return reply.code(403).send({ code: 'PC-AUTH-0005' });
      }
      const input = request.body as Parameters<typeof authorizeLocalPolicyAction>[2] & {
        csrfToken?: string;
        origin?: string;
        host?: string;
      };
      try {
        if (
          input.csrfToken !== undefined ||
          input.origin !== undefined ||
          input.host !== undefined
        ) {
          if (
            input.csrfToken === undefined ||
            input.origin === undefined ||
            input.host === undefined
          ) {
            return reply.code(422).send({ code: 'PC-IDENTITY-1004' });
          }
          await kernel.verifyCsrf(
            input.sessionToken,
            input.actionIntentId,
            input.origin,
            input.host,
            input.csrfToken,
          );
        }
        return localPolicyAuthorizationResponse(
          await authorizeLocalPolicyAction(runtime, kernel, input),
        );
      } catch {
        return reply.code(403).send({ code: 'PC-IDENTITY-1002' });
      }
    });
    const identityAddress = await identity.listen({ host: '127.0.0.1', port: 0 });
    const makePolicy = () =>
      buildPolicyService({
        pool: runtime,
        identityGateway: new HttpPolicyIdentityGateway(identityAddress, internalToken),
        trustedArtifactSigners: [{ publicKeySpkiDer: signerSpki }],
        internalToken,
      });
    let policy = makePolicy();
    let policyAddress = await policy.listen({ host: '127.0.0.1', port: 0 });
    const makerToken = `${participantA}.${makerSessionId}`;
    const checkerToken = `${participantA}.${sessionId}`;
    const webauthnHost = new URL(webauthnOrigin).host;
    const policyHost = new URL(policyAddress).host;
    const actionDigest = async (actionIntentId: string) => {
      const value = (
        await admin.query<{ semantic_digest: Buffer }>(
          `select semantic_digest from control.action_intent where action_intent_id=$1`,
          [actionIntentId],
        )
      ).rows[0]?.semantic_digest;
      if (value === undefined) throw new Error(`missing action intent ${actionIntentId}`);
      return `sha256:${value.toString('hex')}`;
    };
    const baseHeaders = {
      'content-type': 'application/json',
      'openpc-api-version': '1',
      'openpc-participant-id': `urn:openpc:participant:${participantA}`,
      'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyA}`,
      'origin': webauthnOrigin,
    };
    try {
      const createAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
      const createIntentDigest = await actionDigest(createAction);
      const createCsrf = await kernel.csrfToken(
        makerToken,
        createAction,
        webauthnOrigin,
        policyHost,
      );
      const createBody = {
        actionIntentId: createAction,
        candidateDigest: `sha256:${candidateDigest.toString('hex')}`,
        makerSubjectRef: `urn:openpc:resource:${makerA}`,
        checkerSubjectRef: `urn:openpc:resource:${checkerA}`,
        actionIntentDigest: createIntentDigest,
        reason: 'public maker-checker acceptance',
      };
      const createHeaders = {
        ...baseHeaders,
        'cookie': `__Host-openpc_session=${makerToken}`,
        'x-request-id': '018f0000-0000-7000-8000-0000000009c2',
        'x-correlation-id': '018f0000-0000-7000-8000-0000000009c3',
        'x-openpc-action-intent-digest': createIntentDigest,
        'idempotency-key': 'public-approval-create-0001',
        'x-csrf-token': createCsrf,
      };
      const created = await fetch(new URL('/api/v1/approval-requests', policyAddress), {
        method: 'POST',
        headers: createHeaders,
        body: JSON.stringify(createBody),
      });
      const createdText = await created.text();
      expect(created.status, createdText).toBe(202);
      const createdOperation = JSON.parse(createdText) as { resourceRef: string; revision: string };
      const approvalRequestId = idFromUrnForTest(createdOperation.resourceRef);
      expect(createdOperation.revision).toBe('1');

      const replay = await fetch(new URL('/api/v1/approval-requests', policyAddress), {
        method: 'POST',
        headers: createHeaders,
        body: JSON.stringify(createBody),
      });
      expect(await replay.json()).toEqual(createdOperation);

      const readHeaders = {
        'cookie': `__Host-openpc_session=${makerToken}`,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantA}`,
        'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyA}`,
        'x-request-id': '018f0000-0000-7000-8000-0000000009c4',
        'x-correlation-id': '018f0000-0000-7000-8000-0000000009c5',
      };
      const requested = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}`, policyAddress),
        { headers: readHeaders },
      );
      const requestedText = await requested.text();
      expect(requested.status, requestedText).toBe(200);
      expect(JSON.parse(requestedText)).toMatchObject({
        approvalRequestId: createdOperation.resourceRef,
        candidateDigest: createBody.candidateDigest,
        state: 'REQUESTED',
        makerSubjectRef: createBody.makerSubjectRef,
        checkerSubjectRef: createBody.checkerSubjectRef,
        revision: '1',
      });

      const createReleaseAction = 'ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1';
      const createReleaseIntentDigest = await actionDigest(createReleaseAction);
      const createReleaseBody = {
        participantId: `urn:openpc:participant:${participantA}`,
        manifestDigest: createBody.candidateDigest,
        dependencyClosureDigest: `sha256:${releaseDependencyDigest.toString('hex')}`,
        actionIntentId: createReleaseAction,
        actionIntentDigest: createReleaseIntentDigest,
        reason: 'create an editable exact-version release draft',
      };
      const createReleaseResponse = await fetch(new URL('/api/v1/release-bundles', policyAddress), {
        method: 'POST',
        headers: {
          ...baseHeaders,
          'cookie': `__Host-openpc_session=${makerToken}`,
          'x-request-id': '018f0000-0000-7000-8000-0000000009f0',
          'x-correlation-id': '018f0000-0000-7000-8000-0000000009f1',
          'x-openpc-action-intent-digest': createReleaseIntentDigest,
          'idempotency-key': 'public-release-create-0001',
          'x-csrf-token': await kernel.csrfToken(
            makerToken,
            createReleaseAction,
            webauthnOrigin,
            policyHost,
          ),
        },
        body: JSON.stringify(createReleaseBody),
      });
      const createReleaseText = await createReleaseResponse.text();
      expect(createReleaseResponse.status, createReleaseText).toBe(202);
      const releaseOperation = JSON.parse(createReleaseText) as {
        resourceRef: string;
        revision: string;
      };
      const releaseBundleId = idFromUrnForTest(releaseOperation.resourceRef);
      expect(releaseOperation.revision).toBe('1');
      const duplicateRelease = await fetch(new URL('/api/v1/release-bundles', policyAddress), {
        method: 'POST',
        headers: {
          ...baseHeaders,
          'cookie': `__Host-openpc_session=${makerToken}`,
          'x-request-id': '018f0000-0000-7000-8000-0000000009ee',
          'x-correlation-id': '018f0000-0000-7000-8000-0000000009ef',
          'x-openpc-action-intent-digest': createReleaseIntentDigest,
          'idempotency-key': 'public-release-create-duplicate',
          'x-csrf-token': await kernel.csrfToken(
            makerToken,
            createReleaseAction,
            webauthnOrigin,
            policyHost,
          ),
        },
        body: JSON.stringify(createReleaseBody),
      });
      expect(duplicateRelease.status).toBe(409);

      const updateAction = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
      const updateIntentDigest = await actionDigest(updateAction);
      const updateCsrf = await kernel.csrfToken(
        makerToken,
        updateAction,
        webauthnOrigin,
        policyHost,
      );
      const updateBody = {
        actionIntentId: updateAction,
        actionIntentDigest: updateIntentDigest,
        expectedRevision: '1',
        replacementDigest: `sha256:${replacementCandidateDigest.toString('hex')}`,
        reason: 'replace the undecided candidate',
      };
      const updated = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}`, policyAddress),
        {
          method: 'PATCH',
          headers: {
            ...baseHeaders,
            'cookie': `__Host-openpc_session=${makerToken}`,
            'x-request-id': '018f0000-0000-7000-8000-0000000009da',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009db',
            'x-openpc-action-intent-digest': updateIntentDigest,
            'idempotency-key': 'public-approval-update-0001',
            'x-csrf-token': updateCsrf,
            'if-match': `"sha256:${sha256(
              canonicalJson({ resourceId: approvalRequestId, revision: '1' }),
            ).toString('hex')}"`,
          },
          body: JSON.stringify(updateBody),
        },
      );
      const updatedText = await updated.text();
      expect(updated.status, updatedText).toBe(202);
      expect(JSON.parse(updatedText)).toMatchObject({
        resourceRef: createdOperation.resourceRef,
        revision: '2',
      });
      const readUpdated = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}`, policyAddress),
        {
          headers: {
            ...readHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009dc',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009dd',
          },
        },
      );
      expect(await readUpdated.json()).toMatchObject({
        candidateDigest: updateBody.replacementDigest,
        revision: '2',
      });

      const updateReleaseAction = 'ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1';
      const updateReleaseIntentDigest = await actionDigest(updateReleaseAction);
      const updateReleaseBody = {
        actionIntentId: updateReleaseAction,
        actionIntentDigest: updateReleaseIntentDigest,
        expectedRevision: '1',
        replacementDigest: updateBody.replacementDigest,
        reason: 'replace the draft with the exact candidate awaiting approval',
      };
      const updateReleaseResponse = await fetch(
        new URL(`/api/v1/release-bundles/${releaseOperation.resourceRef}`, policyAddress),
        {
          method: 'PATCH',
          headers: {
            ...baseHeaders,
            'cookie': `__Host-openpc_session=${makerToken}`,
            'x-request-id': '018f0000-0000-7000-8000-0000000009f2',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009f3',
            'x-openpc-action-intent-digest': updateReleaseIntentDigest,
            'idempotency-key': 'public-release-update-0001',
            'x-csrf-token': await kernel.csrfToken(
              makerToken,
              updateReleaseAction,
              webauthnOrigin,
              policyHost,
            ),
            'if-match': `"sha256:${sha256(canonicalJson({ resourceId: releaseBundleId, revision: '1' })).toString('hex')}"`,
          },
          body: JSON.stringify(updateReleaseBody),
        },
      );
      const updateReleaseText = await updateReleaseResponse.text();
      expect(updateReleaseResponse.status, updateReleaseText).toBe(202);
      expect(JSON.parse(updateReleaseText)).toMatchObject({
        resourceRef: releaseOperation.resourceRef,
        revision: '2',
      });

      const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
      const approveIntentDigest = await actionDigest(approveAction);
      const decisionInput = {
        actionIntentId: approveAction,
        approvalRequestId: createdOperation.resourceRef,
        candidateDigest: updateBody.replacementDigest,
        expectedRevision: '2',
        decision: 'APPROVE',
      };
      const decisionInputDigest = `sha256:${sha256(canonicalJson(decisionInput)).toString('hex')}`;
      const stepUpRequest = {
        actionIntentId: approveAction,
        resourceId: approvalRequestId,
        resourceDigest: decisionInputDigest,
        rpIdHash: `sha256:${webauthnRpIdHash.toString('hex')}`,
      };
      const firstPageResponse = await fetch(
        new URL('/api/v1/approval-requests?limit=1&sort=-updatedAt', policyAddress),
        {
          headers: {
            ...readHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009d2',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009d3',
          },
        },
      );
      expect(firstPageResponse.status).toBe(200);
      const firstPage = (await firstPageResponse.json()) as {
        items: Array<{ approvalRequestId: string }>;
        nextCursor: string | null;
        snapshotRevision: string;
        total: string;
      };
      expect(firstPage.items).toHaveLength(1);
      expect(firstPage.nextCursor).toMatch(/^pc1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u);
      expect(BigInt(firstPage.total)).toBeGreaterThanOrEqual(2n);
      const secondPageResponse = await fetch(
        new URL(
          `/api/v1/approval-requests?limit=1&sort=-updatedAt&cursor=${encodeURIComponent(
            firstPage.nextCursor as string,
          )}`,
          policyAddress,
        ),
        {
          headers: {
            ...readHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009d4',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009d5',
          },
        },
      );
      expect(secondPageResponse.status).toBe(200);
      const secondPage = (await secondPageResponse.json()) as {
        items: Array<{ approvalRequestId: string }>;
        snapshotRevision: string;
        total: string;
      };
      expect(secondPage.items).toHaveLength(1);
      expect(secondPage.items[0]?.approvalRequestId).not.toBe(
        firstPage.items[0]?.approvalRequestId,
      );
      expect(secondPage.snapshotRevision).toBe(firstPage.snapshotRevision);
      expect(secondPage.total).toBe(firstPage.total);
      const cursorParts = (firstPage.nextCursor as string).split('.');
      const signature = cursorParts[2] as string;
      cursorParts[2] = `${signature.startsWith('A') ? 'B' : 'A'}${signature.slice(1)}`;
      const tamperedCursor = cursorParts.join('.');
      const tamperedPage = await fetch(
        new URL(
          `/api/v1/approval-requests?limit=1&sort=-updatedAt&cursor=${encodeURIComponent(
            tamperedCursor,
          )}`,
          policyAddress,
        ),
        {
          headers: {
            ...readHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009d6',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009d7',
          },
        },
      );
      expect(tamperedPage.status).toBe(400);
      const verificationArtifact = identityOperationArtifact(0x6c);
      const identityApp = buildIdentityService(kernel, identityTrustAdapter(), undefined, {
        async authorize(input) {
          if (input.candidateDigest === undefined) return { allowed: true };
          return {
            allowed: true,
            signerCredentialId: '018f0000-0000-7000-8000-000000000916',
            privacyDomainId: privacyA,
            evidenceCbor: verificationArtifact.evidenceCbor,
            evidenceDigest: verificationArtifact.evidenceDigest,
            coseSign1: verificationArtifact.coseSign1,
          };
        },
      });
      try {
        const stepUpCsrf = await kernel.csrfToken(
          checkerToken,
          approveAction,
          webauthnOrigin,
          webauthnHost,
        );
        const challenged = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/assertion/challenge',
          headers: {
            'cookie': `__Host-openpc_session=${checkerToken}`,
            'origin': webauthnOrigin,
            'host': webauthnHost,
            'x-csrf-token': stepUpCsrf,
          },
          payload: stepUpRequest,
        });
        expect(challenged.statusCode, challenged.body).toBe(200);
        expect(challenged.json()).toMatchObject({
          credentialIds: ['018f0000-0000-7000-8000-000000000916'],
        });
        const supersededChallenge = (challenged.json() as { challenge: string }).challenge;
        const replacementChallenge = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/assertion/challenge',
          headers: {
            'cookie': `__Host-openpc_session=${checkerToken}`,
            'origin': webauthnOrigin,
            'host': webauthnHost,
            'x-csrf-token': stepUpCsrf,
          },
          payload: stepUpRequest,
        });
        expect(replacementChallenge.statusCode, replacementChallenge.body).toBe(200);
        const challenge = (replacementChallenge.json() as { challenge: string }).challenge;
        expect(challenge).not.toBe(supersededChallenge);
        const proof = createWebAuthnProof(
          Buffer.from(decisionInputDigest.slice('sha256:'.length), 'hex'),
          0x6c,
          challenge,
        );
        const sessionVersion = (
          await admin.query<{ row_version: string }>(
            `select row_version::text from control.session where participant_id=$1 and session_id=$2`,
            [participantA, sessionId],
          )
        ).rows[0]?.row_version;
        if (sessionVersion === undefined) throw new Error('missing checker session');
        const supersededProof = createWebAuthnProof(
          Buffer.from(decisionInputDigest.slice('sha256:'.length), 'hex'),
          0x6b,
          supersededChallenge,
        );
        const supersededVerification = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/assertion/verify',
          headers: {
            'cookie': `__Host-openpc_session=${checkerToken}`,
            'origin': webauthnOrigin,
            'host': webauthnHost,
            'x-csrf-token': stepUpCsrf,
            'openpc-action-intent-digest': await kernel.actionIntentSemanticDigest(
              checkerToken,
              'ACT-IDENTITY_UPDATE_STEP_UP-V1',
            ),
            'idempotency-key': 'public-approval-superseded-webauthn-verify',
            'x-openpc-aggregate-version': sessionVersion,
          },
          payload: {
            ...stepUpRequest,
            challenge: supersededChallenge,
            assertion: encodedWebAuthnAssertion(supersededProof),
          },
        });
        expect(supersededVerification.statusCode).toBe(401);
        const verifyPayload = {
          ...stepUpRequest,
          challenge,
          assertion: encodedWebAuthnAssertion(proof),
        };
        const verifyHeaders = {
          'cookie': `__Host-openpc_session=${checkerToken}`,
          'origin': webauthnOrigin,
          'host': webauthnHost,
          'x-csrf-token': stepUpCsrf,
          'openpc-action-intent-digest': await kernel.actionIntentSemanticDigest(
            checkerToken,
            'ACT-IDENTITY_UPDATE_STEP_UP-V1',
          ),
          'idempotency-key': 'public-approval-webauthn-verify',
          'x-openpc-aggregate-version': sessionVersion,
        };
        const verified = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/assertion/verify',
          headers: verifyHeaders,
          payload: verifyPayload,
        });
        expect(verified.statusCode, verified.body).toBe(200);
        const idempotentReplay = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/assertion/verify',
          headers: verifyHeaders,
          payload: verifyPayload,
        });
        expect(idempotentReplay.statusCode, idempotentReplay.body).toBe(200);
        const replaySessionVersion = (
          await admin.query<{ row_version: string }>(
            `select row_version::text from control.session where participant_id=$1 and session_id=$2`,
            [participantA, sessionId],
          )
        ).rows[0]?.row_version;
        if (replaySessionVersion === undefined) throw new Error('missing replay session');
        const oneUseReplay = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/assertion/verify',
          headers: {
            ...verifyHeaders,
            'idempotency-key': 'public-approval-webauthn-one-use-replay',
            'x-openpc-aggregate-version': replaySessionVersion,
          },
          payload: verifyPayload,
        });
        expect(oneUseReplay.statusCode).toBe(401);
      } finally {
        await identityApp.close();
      }

      const approveCsrf = await kernel.csrfToken(
        checkerToken,
        approveAction,
        webauthnOrigin,
        policyHost,
      );
      const approveBody = {
        targetRef: createdOperation.resourceRef,
        actionIntentId: approveAction,
        actionIntentDigest: approveIntentDigest,
        inputDigest: decisionInputDigest,
        expectedRevision: '2',
        reason: 'distinct checker approved exact candidate',
      };
      const approvalEtag = `"sha256:${sha256(
        canonicalJson({ resourceId: approvalRequestId, revision: '2' }),
      ).toString('hex')}"`;
      const approveHeaders = {
        ...baseHeaders,
        'cookie': `__Host-openpc_session=${checkerToken}`,
        'x-request-id': '018f0000-0000-7000-8000-0000000009c6',
        'x-correlation-id': '018f0000-0000-7000-8000-0000000009c7',
        'x-openpc-action-intent-digest': approveIntentDigest,
        'idempotency-key': 'public-approval-decide-0001',
        'x-csrf-token': approveCsrf,
        'if-match': approvalEtag,
      };
      const approveHeadersWithoutMatch = Object.fromEntries(
        Object.entries(approveHeaders).filter(([name]) => name !== 'if-match'),
      );
      const missingPrecondition = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}/approve`, policyAddress),
        {
          method: 'POST',
          headers: {
            ...approveHeadersWithoutMatch,
            'x-request-id': '018f0000-0000-7000-8000-0000000009cc',
            'idempotency-key': 'public-approval-missing-etag',
          },
          body: JSON.stringify(approveBody),
        },
      );
      expect(missingPrecondition.status).toBe(428);
      const tamperedDecision = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}/approve`, policyAddress),
        {
          method: 'POST',
          headers: {
            ...approveHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009cd',
            'idempotency-key': 'public-approval-tampered-input',
          },
          body: JSON.stringify({ ...approveBody, inputDigest: `sha256:${'dd'.repeat(32)}` }),
        },
      );
      expect(tamperedDecision.status).toBe(403);
      const makerApproveCsrf = await kernel.csrfToken(
        makerToken,
        approveAction,
        webauthnOrigin,
        policyHost,
      );
      const selfDecision = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}/approve`, policyAddress),
        {
          method: 'POST',
          headers: {
            ...approveHeaders,
            'cookie': `__Host-openpc_session=${makerToken}`,
            'x-request-id': '018f0000-0000-7000-8000-0000000009ce',
            'idempotency-key': 'public-approval-self-decision',
            'x-csrf-token': makerApproveCsrf,
          },
          body: JSON.stringify(approveBody),
        },
      );
      expect(selfDecision.status).toBe(403);
      expect(
        (
          await admin.query<{ count: string }>(
            `select count(*)::text from control.approval_decision_record
              where participant_id=$1 and approval_request_id=$2`,
            [participantA, approvalRequestId],
          )
        ).rows[0]?.count,
      ).toBe('0');
      const approved = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}/approve`, policyAddress),
        { method: 'POST', headers: approveHeaders, body: JSON.stringify(approveBody) },
      );
      const approvedText = await approved.text();
      expect(approved.status, approvedText).toBe(202);
      const approvedOperation = JSON.parse(approvedText) as { revision: string };
      expect(approvedOperation.revision).toBe('3');

      const publishAction = 'ACT-POLICY_ACTIVATE_PUBLISH-V1';
      const publishIntentDigest = await actionDigest(publishAction);
      const publishCandidate = {
        actionIntentId: publishAction,
        targetRef: releaseOperation.resourceRef,
        manifestDigest: updateBody.replacementDigest,
        dependencyClosureDigest: createReleaseBody.dependencyClosureDigest,
        expectedRevision: '2',
      };
      const publishInputDigest = `sha256:${sha256(canonicalJson(publishCandidate)).toString('hex')}`;
      await verifyCheckerStepUp(
        kernel,
        publishAction,
        idFromUrnForTest(releaseOperation.resourceRef),
        publishInputDigest,
        0x6e,
      );

      const publishBody = {
        targetRef: releaseOperation.resourceRef,
        actionIntentId: publishAction,
        actionIntentDigest: publishIntentDigest,
        inputDigest: publishInputDigest,
        expectedRevision: '2',
        reason: 'publish the approved immutable release',
      };
      const publishHeaders = {
        ...baseHeaders,
        'cookie': `__Host-openpc_session=${checkerToken}`,
        'x-request-id': '018f0000-0000-7000-8000-0000000009f4',
        'x-correlation-id': '018f0000-0000-7000-8000-0000000009f5',
        'x-openpc-action-intent-digest': publishIntentDigest,
        'idempotency-key': 'public-release-publish-0001',
        'x-csrf-token': await kernel.csrfToken(
          checkerToken,
          publishAction,
          webauthnOrigin,
          policyHost,
        ),
        'if-match': `"sha256:${sha256(canonicalJson({ resourceId: releaseBundleId, revision: '2' })).toString('hex')}"`,
      };
      const published = await fetch(
        new URL(`/api/v1/release-bundles/${releaseOperation.resourceRef}/publish`, policyAddress),
        { method: 'POST', headers: publishHeaders, body: JSON.stringify(publishBody) },
      );
      const publishedText = await published.text();
      expect(published.status, publishedText).toBe(202);
      expect(JSON.parse(publishedText)).toMatchObject({
        resourceRef: releaseOperation.resourceRef,
        revision: '3',
      });
      expect(
        (
          await admin.query<{ count: string }>(
            `select count(*)::text from control.outbox_event
              where participant_id=$1 and aggregate_type='policy-release-bundle'
                and aggregate_id=$2 and event_type='openpc.policy.release.created.v1'
                and webauthn_assertion_binding_digest is not null`,
            [participantA, releaseBundleId],
          )
        ).rows[0]?.count,
      ).toBe('1');
      expect(
        (
          await admin.query<{ count: string }>(
            `select count(*)::text from control.mfa_challenge
              where participant_id=$1 and action_intent_id=$2 and resource_digest=$3
                and used_operation_id=$4 and used_at is not null`,
            [
              participantA,
              publishAction,
              Buffer.from(publishInputDigest.slice('sha256:'.length), 'hex'),
              String(JSON.parse(publishedText).operationId),
            ],
          )
        ).rows[0]?.count,
      ).toBe('1');
      const publishReplay = await fetch(
        new URL(`/api/v1/release-bundles/${releaseOperation.resourceRef}/publish`, policyAddress),
        { method: 'POST', headers: publishHeaders, body: JSON.stringify(publishBody) },
      );
      expect(await publishReplay.json()).toEqual(JSON.parse(publishedText));

      const runtimeTargetId = '018f0000-0000-7000-8000-000000000a40';
      const moduleVersionId = '018f0000-0000-7000-8000-000000000a41';
      const moduleInstallationId = '018f0000-0000-7000-8000-000000000a42';
      const moduleConfigurationId = '018f0000-0000-7000-8000-000000000a43';
      const providerProfileId = '018f0000-0000-7000-8000-000000000a44';
      const indexerProfileId = '018f0000-0000-7000-8000-000000000a45';
      const projectionPlanId = '018f0000-0000-7000-8000-000000000a46';
      const priorPolicyDigest = `sha256:${sha256('public-activation-prior-policy').toString('hex')}`;
      await admin.query(
        `insert into control.policy_simulation(
           simulation_id,participant_id,privacy_domain_id,policy_version_id,input_digest,
           result_digest,fact_generation_digest,dependency_closure_digest,truth_state,
           result_document,completed_at)
         values('018f0000-0000-7000-8000-000000000a47',$1,$2,$3,$4,$5,$6,$7,
                'SUCCESS','{"authority":"SIMULATION_ONLY","truthState":"SUCCESS"}'::jsonb,
                clock_timestamp())`,
        [
          participantA,
          privacyA,
          replacementPolicyVersionId,
          sha256('public-activation-scope'),
          sha256('public-activation-simulation-result'),
          sha256('public-activation-fact-generation'),
          releaseDependencyDigest,
        ],
      );
      await admin.query(
        `insert into control.module_registration(module_id,display_name,owner,state)
         values('pc.config.assets','Configuration assets','OpenPC','ADMITTED')
         on conflict (module_id) do nothing`,
      );
      const moduleManifestDigest = sha256('public-activation-module-manifest');
      await fixtureMutation(
        `insert into control.module_version(
           module_version_id,module_id,semantic_version,manifest_cbor,manifest_digest,cose_sign1,
           sbom_digest,provenance_digest,build_receipt_digest)
         values($1,'pc.config.assets','1.0.0-test',decode('a0','hex'),$2,
                decode('d28440a04040','hex'),$3,$4,$5)`,
        [
          moduleVersionId,
          moduleManifestDigest,
          sha256('public-activation-module-sbom'),
          sha256('public-activation-module-provenance'),
          sha256('public-activation-module-build'),
        ],
      );
      await fixtureMutation(
        `insert into control.module_installation(
           module_installation_id,participant_id,privacy_domain_id,module_version_id,state,
           authority_epoch,delegation_epoch,desired_manifest_digest,active_manifest_digest,
           idempotency_key,lifecycle_operation_id)
         values($1,$2,$3,$4,'ENABLED',5,1,$5,$5,'public-activation-config-assets',$1)`,
        [moduleInstallationId, participantA, privacyA, moduleVersionId, moduleManifestDigest],
      );
      await fixtureMutation(
        `insert into control.module_configuration_generation(
           generation_id,participant_id,privacy_domain_id,module_installation_id,generation,
           configuration_cbor,configuration_digest,active)
         values($1,$2,$3,$4,1,decode('a0','hex'),$5,true)`,
        [
          moduleConfigurationId,
          participantA,
          privacyA,
          moduleInstallationId,
          sha256(Buffer.from('a0', 'hex')),
        ],
      );
      await fixtureMutation(
        `insert into control.provider_profile(
           provider_profile_id,participant_id,privacy_domain_id,chain_id,endpoint_secret_ref,
           behavior_fingerprint,state,policy_generation_digest)
         values($1,$2,$3,'1',$4,$5,'ACTIVE',$6)`,
        [
          providerProfileId,
          participantA,
          privacyA,
          `urn:openpc:secret:${providerProfileId}`,
          `sha256:${sha256('public-activation-provider').toString('hex')}`,
          priorPolicyDigest,
        ],
      );
      await fixtureMutation(
        `insert into control.indexer_profile(
           indexer_profile_id,participant_id,privacy_domain_id,engine,engine_version,
           method_profile_digest,state,policy_generation_digest)
         values($1,$2,$3,'CLIENT_INDEXER','1.0.0',$4,'ACTIVE',$5)`,
        [
          indexerProfileId,
          participantA,
          privacyA,
          `sha256:${sha256('public-activation-indexer').toString('hex')}`,
          priorPolicyDigest,
        ],
      );
      await fixtureMutation(
        `insert into control.projection_plan(
           projection_plan_id,participant_id,privacy_domain_id,indexer_profile_id,plan_digest,
           readiness,state,policy_generation_digest)
         values($1,$2,$3,$4,$5,'READY','RUNNING',$6)`,
        [
          projectionPlanId,
          participantA,
          privacyA,
          indexerProfileId,
          `sha256:${sha256('public-activation-projection').toString('hex')}`,
          priorPolicyDigest,
        ],
      );
      await fixtureMutation(
        `insert into control.runtime_target(
           runtime_target_id,participant_id,privacy_domain_id,state,observed_at,
           policy_generation_digest)
         values($1,$2,$3,'DISCOVERED',clock_timestamp(),$4)`,
        [runtimeTargetId, participantA, privacyA, priorPolicyDigest],
      );

      const configurationFixture = await admin.connect();
      try {
        await configurationFixture.query('begin');
        await configurationFixture.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',true)`,
          [participantA, privacyA],
        );
        await configurationFixture.query(
          `insert into control.runtime_configuration_input
             (participant_id,privacy_domain_id,module_installation_id,module_configuration_generation_id,
              configuration_cbor,configuration_digest,resource_bindings,selected)
           values($1,$2,$3,$4,decode('a0','hex'),sha256(decode('a0','hex')),$5,true)`,
          [
            participantA,
            privacyA,
            moduleInstallationId,
            moduleConfigurationId,
            JSON.stringify([
              {
                kind: 'ProviderProfile',
                id: providerProfileId,
                chainId: '1',
                digest: `sha256:${sha256('public-activation-provider').toString('hex')}`,
              },
            ]),
          ],
        );
        expect(
          (
            await configurationFixture.query(
              `select count(*)::int count
          from control.runtime_configuration_input_current where participant_id=$1 and privacy_domain_id=$2`,
              [participantA, privacyA],
            )
          ).rows[0].count,
        ).toBe(1);
        await configurationFixture.query('commit');
      } finally {
        configurationFixture.release();
      }

      const createActivationAction = 'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1';
      const createActivationIntentDigest = await actionDigest(createActivationAction);
      const createActivationBody = {
        releaseBundleId: releaseOperation.resourceRef,
        targetGenerationDigest: updateBody.replacementDigest,
        matchedTargetCount: '0',
        totalTargetCount: '1',
        actionIntentId: createActivationAction,
        actionIntentDigest: createActivationIntentDigest,
        reason: 'stage the exact published release against the eligible fleet cohort',
      };
      const createActivationHeaders = {
        ...baseHeaders,
        'cookie': `__Host-openpc_session=${makerToken}`,
        'x-request-id': '018f0000-0000-7000-8000-000000000a48',
        'x-correlation-id': '018f0000-0000-7000-8000-000000000a49',
        'x-openpc-action-intent-digest': createActivationIntentDigest,
        'idempotency-key': 'public-activation-create-0001',
        'x-csrf-token': await kernel.csrfToken(
          makerToken,
          createActivationAction,
          webauthnOrigin,
          policyHost,
        ),
      };
      const createdActivation = await fetch(
        new URL('/api/v1/activation-occurrences', policyAddress),
        {
          method: 'POST',
          headers: createActivationHeaders,
          body: JSON.stringify(createActivationBody),
        },
      );
      const createdActivationText = await createdActivation.text();
      expect(createdActivation.status, createdActivationText).toBe(202);
      const activationOperation = JSON.parse(createdActivationText) as {
        resourceRef: string;
        revision: string;
      };
      expect(activationOperation.revision).toBe('1');
      const publicActivationId = idFromUrnForTest(activationOperation.resourceRef);
      const readActivation = await fetch(
        new URL(`/api/v1/activation-occurrences/${activationOperation.resourceRef}`, policyAddress),
        {
          headers: {
            ...readHeaders,
            'x-request-id': '018f0000-0000-7000-8000-000000000a4a',
            'x-correlation-id': '018f0000-0000-7000-8000-000000000a4b',
          },
        },
      );
      expect(await readActivation.json()).toMatchObject({
        activationOccurrenceId: activationOperation.resourceRef,
        releaseBundleId: releaseOperation.resourceRef,
        targetGenerationDigest: updateBody.replacementDigest,
        matchedTargetCount: '0',
        totalTargetCount: '1',
        state: 'REQUESTED',
        revision: '1',
      });

      // Use the occurrence/cohort created by their real public owner. Exercise
      // both a caller that already owns these rows and a competing row owner;
      // fence contention must win before an UPDATE can wait or change state.
      const referenceReader = await runtime.connect();
      const referenceWriter = await admin.connect();
      try {
        for (const table of [
          'policy_activation_occurrence',
          'policy_activation_occurrence_target',
        ]) {
          const snapshot = () =>
            admin.query(
              `select to_jsonb(retained) value from control.${table} retained where activation_occurrence_id=$1`,
              [publicActivationId],
            );
          const original = (await snapshot()).rows;
          expect(original).toHaveLength(1);
          for (const callerOwnsRows of [true, false]) {
            for (const client of [referenceReader, referenceWriter]) {
              await client.query('begin');
              if (client === referenceWriter)
                await client.query('set local role openpc_control_worker');
              await client.query("set local lock_timeout='250ms'");
              await client.query("set local statement_timeout='2s'");
              await client.query(
                `select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),$3,true)`,
                [
                  participantA,
                  privacyA,
                  client === referenceWriter
                    ? 'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1'
                    : 'ACT-MODULES_READ_RESOURCE-V1',
                ],
              );
            }
            const rowOwner = callerOwnsRows ? referenceWriter : referenceReader;
            expect(
              (
                await rowOwner.query(
                  `select activation_occurrence_id from control.${table} where activation_occurrence_id=$1 for update`,
                  [publicActivationId],
                )
              ).rowCount,
            ).toBe(1);
            await referenceReader.query(
              'select pg_advisory_xact_lock_shared(hashtextextended($1,0))',
              [`openpc-policy-generations:${participantA}:${privacyA}`],
            );
            await expect(
              referenceWriter.query(
                `update control.${table} set state=state where activation_occurrence_id=$1`,
                [publicActivationId],
              ),
            ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
            await referenceWriter.query('rollback');
            await referenceReader.query('rollback');
            expect((await snapshot()).rows).toEqual(original);
          }
        }
      } finally {
        await referenceWriter.query('rollback');
        await referenceReader.query('rollback');
        referenceWriter.release(true);
        referenceReader.release(true);
      }

      const exactCohortDigest = (
        await admin.query<{ exact_cohort_digest: Buffer }>(
          `select exact_cohort_digest from control.policy_activation_occurrence
            where activation_occurrence_id=$1`,
          [publicActivationId],
        )
      ).rows[0]?.exact_cohort_digest;
      if (exactCohortDigest === undefined) throw new Error('missing exact activation cohort');
      const activateAction = 'ACT-POLICY_ACTIVATE_RELEASE-V1';
      const activateIntentDigest = await actionDigest(activateAction);
      const activateInputDigest = `sha256:${sha256(
        canonicalJson({
          actionIntentId: activateAction,
          targetRef: activationOperation.resourceRef,
          targetGenerationDigest: updateBody.replacementDigest,
          exactCohortDigest: `sha256:${exactCohortDigest.toString('hex')}`,
          expectedRevision: '1',
        }),
      ).toString('hex')}`;
      await verifyCheckerStepUp(
        kernel,
        activateAction,
        publicActivationId,
        activateInputDigest,
        0x73,
      );

      const activateBody = {
        targetRef: activationOperation.resourceRef,
        actionIntentId: activateAction,
        actionIntentDigest: activateIntentDigest,
        inputDigest: activateInputDigest,
        expectedRevision: '1',
        reason: 'activate the approved release across the frozen cohort',
      };
      const activateHeaders = {
        ...baseHeaders,
        'cookie': `__Host-openpc_session=${checkerToken}`,
        'x-request-id': '018f0000-0000-7000-8000-000000000a4e',
        'x-correlation-id': '018f0000-0000-7000-8000-000000000a4f',
        'x-openpc-action-intent-digest': activateIntentDigest,
        'idempotency-key': 'public-activation-activate-0001',
        'x-csrf-token': await kernel.csrfToken(
          checkerToken,
          activateAction,
          webauthnOrigin,
          policyHost,
        ),
        'if-match': `"sha256:${sha256(
          canonicalJson({ resourceId: publicActivationId, revision: '1' }),
        ).toString('hex')}"`,
      };
      const activated = await fetch(
        new URL(
          `/api/v1/activation-occurrences/${activationOperation.resourceRef}/activate`,
          policyAddress,
        ),
        { method: 'POST', headers: activateHeaders, body: JSON.stringify(activateBody) },
      );
      const activatedText = await activated.text();
      expect(activated.status, activatedText).toBe(202);
      expect(JSON.parse(activatedText)).toMatchObject({
        resourceRef: activationOperation.resourceRef,
        revision: '2',
      });
      const activationState = (
        await admin.query<{
          occurrence_state: string;
          release_state: string;
          target_state: string;
          work_state: string;
          prerequisites: string;
        }>(
          `select occurrence.state occurrence_state,release.state release_state,
                  target.state target_state,work.state work_state,
                  (select count(*)::text from control.policy_activation_prerequisite prerequisite
                    where prerequisite.policy_activation_id=occurrence.activation_occurrence_id
                      and prerequisite.ready) prerequisites
             from control.policy_activation_occurrence occurrence
             join control.policy_release_bundle release
               on release.release_bundle_id=occurrence.release_bundle_id
             join control.policy_activation_occurrence_target occurrence_target
               on occurrence_target.activation_occurrence_id=occurrence.activation_occurrence_id
              and occurrence_target.phase='FORWARD'
             join control.runtime_target target
               on target.runtime_target_id=occurrence_target.runtime_target_id
             join control.configuration_work work
               on work.configuration_work_id=occurrence_target.configuration_work_id
            where occurrence.activation_occurrence_id=$1`,
          [publicActivationId],
        )
      ).rows[0];
      expect(activationState).toEqual({
        occurrence_state: 'STAGING',
        release_state: 'PUBLISHED',
        target_state: 'STAGING',
        work_state: 'PENDING',
        prerequisites: '6',
      });

      const decisionReplay = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}/approve`, policyAddress),
        { method: 'POST', headers: approveHeaders, body: JSON.stringify(approveBody) },
      );
      expect(await decisionReplay.json()).toEqual(JSON.parse(approvedText));
      const secondDecision = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}/approve`, policyAddress),
        {
          method: 'POST',
          headers: {
            ...approveHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009cf',
            'idempotency-key': 'public-approval-second-decision',
          },
          body: JSON.stringify(approveBody),
        },
      );
      expect(secondDecision.status).toBe(403);
      expect(
        (
          await admin.query<{ count: string }>(
            `select count(*)::text from control.approval_decision_record
              where participant_id=$1 and approval_request_id=$2 and mfa_challenge_id is not null`,
            [participantA, approvalRequestId],
          )
        ).rows[0]?.count,
      ).toBe('1');

      await policy.close();
      policy = makePolicy();
      policyAddress = await policy.listen({ host: '127.0.0.1', port: 0 });
      const readApproved = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}`, policyAddress),
        {
          headers: {
            ...readHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009c8',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009c9',
          },
        },
      );
      expect(await readApproved.json()).toMatchObject({ state: 'APPROVED', revision: '3' });
      const readRelease = await fetch(
        new URL(`/api/v1/release-bundles/${releaseOperation.resourceRef}`, policyAddress),
        {
          headers: {
            ...readHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009f6',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009f7',
          },
        },
      );
      expect(await readRelease.json()).toMatchObject({
        releaseBundleId: releaseOperation.resourceRef,
        manifestDigest: updateBody.replacementDigest,
        dependencyClosureDigest: createReleaseBody.dependencyClosureDigest,
        state: 'PUBLISHED',
        revision: '3',
      });
      const releasePage = await fetch(
        new URL(
          '/api/v1/release-bundles?filter=state:eq:PUBLISHED&limit=1&sort=-updatedAt',
          policyAddress,
        ),
        {
          headers: {
            ...readHeaders,
            'x-request-id': '018f0000-0000-7000-8000-0000000009fa',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009fb',
          },
        },
      );
      const releasePageBody = (await releasePage.json()) as {
        items: Array<{ releaseBundleId: string }>;
        completeness: string;
      };
      expect(releasePage.status).toBe(200);
      expect(releasePageBody).toMatchObject({ completeness: 'COMPLETE' });
      expect(releasePageBody.items.map((item) => item.releaseBundleId)).toContain(
        releaseOperation.resourceRef,
      );
      const staleReleaseUpdate = await fetch(
        new URL(`/api/v1/release-bundles/${releaseOperation.resourceRef}`, policyAddress),
        {
          method: 'PATCH',
          headers: {
            ...baseHeaders,
            'cookie': `__Host-openpc_session=${makerToken}`,
            'x-request-id': '018f0000-0000-7000-8000-0000000009fc',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009fd',
            'x-openpc-action-intent-digest': updateReleaseIntentDigest,
            'idempotency-key': 'public-release-stale-update',
            'x-csrf-token': await kernel.csrfToken(
              makerToken,
              updateReleaseAction,
              webauthnOrigin,
              policyHost,
            ),
            'if-match': `"sha256:${sha256(canonicalJson({ resourceId: releaseBundleId, revision: '2' })).toString('hex')}"`,
          },
          body: JSON.stringify(updateReleaseBody),
        },
      );
      expect(staleReleaseUpdate.status).toBe(412);
      const crossTenant = await fetch(
        new URL(`/api/v1/approval-requests/${createdOperation.resourceRef}`, policyAddress),
        {
          headers: {
            ...readHeaders,
            'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyB}`,
            'x-request-id': '018f0000-0000-7000-8000-0000000009d0',
            'x-correlation-id': '018f0000-0000-7000-8000-0000000009d1',
          },
        },
      );
      expect(crossTenant.status).toBe(403);
      // Focused renewal-store fixture: prior runtime completion is installed
      // here, not claimed as a real target journey. The new occurrence and
      // dispatch below still cross the authenticated public owners.
      const priorDispatch = (
        await admin.query<{
          policy_generation_id: string;
          runtime_configuration_generation_id: string;
        }>(
          `select occurrence.policy_generation_id,target.runtime_configuration_generation_id
            from control.policy_activation_occurrence occurrence
            join control.policy_activation_occurrence_target target
              using(activation_occurrence_id,participant_id,privacy_domain_id)
           where occurrence.activation_occurrence_id=$1`,
          [publicActivationId],
        )
      ).rows[0]!;
      const predecessor = `sha256:${sha256('completed-renewal-predecessor').toString('hex')}`;
      await fixtureMutation(
        `update control.policy_generation set state='ACTIVE',active=true
                          where policy_generation_id=$1`,
        [priorDispatch.policy_generation_id],
      );
      await admin.query(
        `update control.policy_release_bundle set state='ACTIVE'
                          where release_bundle_id=$1`,
        [releaseBundleId],
      );
      await fixtureMutation(
        `update control.runtime_target set state='ACTIVE_MATCHED',
                            active_generation_digest=$2,desired_generation_digest=$2,revision=revision+1
                          where runtime_target_id=$1`,
        [runtimeTargetId, predecessor],
      );
      const renewalBody = { ...createActivationBody, matchedTargetCount: '1' };
      const renew = async (key: string) =>
        fetch(new URL('/api/v1/activation-occurrences', policyAddress), {
          method: 'POST',
          headers: {
            ...createActivationHeaders,
            'idempotency-key': key,
            'x-csrf-token': await kernel.csrfToken(
              makerToken,
              createActivationAction,
              webauthnOrigin,
              new URL(policyAddress).host,
            ),
          },
          body: JSON.stringify(renewalBody),
        });
      // ACTIVE content cannot bypass an in-flight occurrence.
      for (const state of ['REQUESTED', 'STAGING', 'PARTIAL', 'ROLLING_BACK']) {
        await fixtureMutation(
          `update control.policy_activation_occurrence set state=$2
                            where activation_occurrence_id=$1`,
          [publicActivationId, state],
        );
        const denied = await renew('public-renew-deny-' + state);
        expect(denied.status, await denied.text()).toBe(412);
      }
      await fixtureMutation(
        `update control.policy_activation_occurrence set state='ACTIVE_MATCHED',
                            matched_target_count=total_target_count
                          where activation_occurrence_id=$1`,
        [publicActivationId],
      );
      await admin.query(
        `update control.policy_activation set state='ACTIVE' where policy_activation_id=$1`,
        [publicActivationId],
      );
      const policySetRevision = async () => {
        const result = await admin.query<{ revision: string }>(
          `select p.row_version::text revision from control.policy p
            join control.policy_version v using(participant_id,privacy_domain_id,policy_id)
            join control.policy_generation g using(participant_id,privacy_domain_id,policy_version_id)
            where g.policy_generation_id=$1`,
          [priorDispatch.policy_generation_id],
        );
        expect(result.rowCount).toBe(1);
        return BigInt(result.rows[0]!.revision);
      };
      const activeRevision = await policySetRevision();
      for (const state of ['FAILED_FENCED', 'RETIRED']) {
        await fixtureMutation(
          `update control.policy_generation set state=$2,active=false
                            where policy_generation_id=$1`,
          [priorDispatch.policy_generation_id, state],
        );
        expect((await renew('public-renew-deny-generation-' + state)).status).toBe(412);
        expect(await policySetRevision()).toBe(activeRevision + 1n);
      }
      await fixtureMutation(
        `update control.policy_generation set state='ACTIVE',active=true
                          where policy_generation_id=$1`,
        [priorDispatch.policy_generation_id],
      );
      expect(await policySetRevision()).toBe(activeRevision + 2n);
      await fixtureMutation(
        `update control.policy_generation set state='ACTIVE',active=true where policy_generation_id=$1`,
        [priorDispatch.policy_generation_id],
      );
      expect(await policySetRevision()).toBe(activeRevision + 2n);
      expect(
        (
          await admin.query(`select
        has_column_privilege('openpc_control_worker','control.policy','row_version','UPDATE') revision,
        has_column_privilege('openpc_control_worker','control.policy','updated_at','UPDATE') updated,
        has_column_privilege('openpc_control_worker','control.policy','state','UPDATE') state`)
        ).rows[0],
      ).toEqual({ revision: true, updated: true, state: false });
      const renewed = await renew('public-renew-terminal-0001');
      const renewedText = await renewed.text();
      expect(renewed.status, renewedText).toBe(202);
      const renewedOperation = JSON.parse(renewedText) as { resourceRef: string };
      const renewedId = idFromUrnForTest(renewedOperation.resourceRef);
      expect((await renew('public-renew-concurrent-0001')).status).toBe(412);
      const renewedRow = (
        await admin.query<{ policy_generation_id: string; exact_cohort_digest: Buffer }>(
          `select policy_generation_id,exact_cohort_digest from control.policy_activation_occurrence
          where activation_occurrence_id=$1`,
          [renewedId],
        )
      ).rows[0]!;
      expect(renewedRow.policy_generation_id).toBe(priorDispatch.policy_generation_id);
      const renewedInput = `sha256:${sha256(
        canonicalJson({
          actionIntentId: activateAction,
          targetRef: renewedOperation.resourceRef,
          targetGenerationDigest: updateBody.replacementDigest,
          exactCohortDigest: `sha256:${renewedRow.exact_cohort_digest.toString('hex')}`,
          expectedRevision: '1',
        }),
      ).toString('hex')}`;
      await verifyCheckerStepUp(kernel, activateAction, renewedId, renewedInput, 0x74);
      const renewedActivation = await fetch(
        new URL(
          `/api/v1/activation-occurrences/${renewedOperation.resourceRef}/activate`,
          policyAddress,
        ),
        {
          method: 'POST',
          headers: {
            ...activateHeaders,
            'idempotency-key': 'public-renew-activate-0001',
            'x-csrf-token': await kernel.csrfToken(
              checkerToken,
              activateAction,
              webauthnOrigin,
              new URL(policyAddress).host,
            ),
            'if-match': `"sha256:${sha256(canonicalJson({ resourceId: renewedId, revision: '1' })).toString('hex')}"`,
          },
          body: JSON.stringify({
            ...activateBody,
            targetRef: renewedOperation.resourceRef,
            inputDigest: renewedInput,
          }),
        },
      );
      const renewedActivationText = await renewedActivation.text();
      expect(renewedActivation.status, renewedActivationText).toBe(202);
      const dispatch = (
        await admin.query<{
          runtime_configuration_generation_id: string;
          predecessor_digest: string;
        }>(
          `select target.runtime_configuration_generation_id,generation.predecessor_digest
           from control.policy_activation_occurrence_target target
           join control.runtime_configuration_generation generation using(runtime_configuration_generation_id)
          where target.activation_occurrence_id=$1`,
          [renewedId],
        )
      ).rows[0]!;
      expect(dispatch.runtime_configuration_generation_id).not.toBe(
        priorDispatch.runtime_configuration_generation_id,
      );
      expect(dispatch.predecessor_digest).toBe(predecessor);
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.policy_generation
        where policy_generation_id=$1`,
            [priorDispatch.policy_generation_id],
          )
        ).rows[0].count,
      ).toBe(1);
    } finally {
      await Promise.all([policy.close(), identity.close()]);
    }
  });

  it('persists the public work-item lifecycle with exact identity proof, replay, concurrency and restart readback', async () => {
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const makerToken = `${participantA}.${makerSessionId}`;
    const actionDigest = async (actionIntentId: string) => {
      const value = (
        await admin.query<{ semantic_digest: Buffer }>(
          `select semantic_digest from control.action_intent where action_intent_id=$1`,
          [actionIntentId],
        )
      ).rows[0]?.semantic_digest;
      if (value === undefined) throw new Error(`missing action intent ${actionIntentId}`);
      return `sha256:${value.toString('hex')}`;
    };
    const candidateDigest = (body: unknown) => sha256(canonicalJson(body));
    const transitionDigest = (
      actionIntentId: string,
      targetRef: string,
      expectedRevision: string,
      transition: 'CLAIM' | 'COMPLETE',
    ) =>
      `sha256:${sha256(
        canonicalJson({ actionIntentId, targetRef, expectedRevision, transition }),
      ).toString('hex')}`;
    const configurationProof = async (input: {
      readonly actionIntentId: string;
      readonly body: unknown;
      readonly expectedRevision: string;
      readonly approvalRequestId: string;
      readonly subjectId: string;
      readonly seed: number;
    }) => {
      const exactDigest = candidateDigest(input.body);
      const artifact = identityOperationArtifact(input.seed, makerA, '5');
      await admin.query(
        `insert into control.approval_request(
           approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
           subject_id,subject_digest,subject_version,maker_principal_id,required_approvals,
           state,expires_at)
         values($1,$2,$3,$4,'CONFIGURATION_CANDIDATE',$5,$6,$7,$8,1,'APPROVED',
                clock_timestamp()+interval '30 minutes')`,
        [
          input.approvalRequestId,
          participantA,
          privacyA,
          input.actionIntentId,
          input.subjectId,
          exactDigest,
          input.expectedRevision,
          makerA,
        ],
      );
      await admin.query(
        `insert into control.approval_decision_record(
           participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
           approver_principal_epoch,approver_authority_envelope_id,approver_envelope_epoch,
           approver_assignment_id,signer_credential_id,aggregate_version,candidate_digest,
           decision,decision_digest,evidence_cbor,cose_sign1)
         values($1,$2,$3,$4,5,$5,5,$6,$7,$8,$9,'APPROVE',$10,$11,$12)`,
        [
          participantA,
          privacyA,
          input.approvalRequestId,
          makerA,
          '018f0000-0000-7000-8000-0000000009a1',
          '018f0000-0000-7000-8000-0000000009a2',
          '018f0000-0000-7000-8000-0000000009e3',
          input.expectedRevision,
          exactDigest,
          sha256(`work-item-decision:${input.approvalRequestId}`),
          artifact.evidenceCbor,
          artifact.coseSign1,
        ],
      );
    };
    const readArtifact = identityOperationArtifact(0xb0, makerA, '5');
    const makeApp = () => {
      const app = Fastify({ logger: false });
      registerConfigurationRoutes(app, {
        pool: runtime,
        authorizer: {
          async authorize(input) {
            if (input.actionIntentDigest !== undefined && input.expectedRevision !== undefined) {
              if (
                input.csrfToken === undefined ||
                input.origin === undefined ||
                input.host === undefined
              ) {
                throw new IdentityKernelError('PC-IDENTITY-1004');
              }
              await kernel.verifyCsrf(
                input.sessionToken,
                input.actionIntentId,
                input.origin,
                input.host,
                input.csrfToken,
              );
              return authorizeLocalConfigurationMutation(runtime, kernel, {
                sessionToken: input.sessionToken,
                privacyDomainId: privacyA,
                actionIntentId: input.actionIntentId,
                actionIntentDigest: input.actionIntentDigest,
                resourceId: input.resourceId,
                candidateDigest: input.candidateDigest,
                expectedRevision: input.expectedRevision,
              });
            }
            const authority = await authorizeLocalPolicyAction(runtime, kernel, {
              sessionToken: input.sessionToken,
              privacyDomainId: privacyA,
              actionIntentId: input.actionIntentId,
              resourceId: input.resourceId,
              stepUpRequired: false,
            });
            return {
              sessionId: authority.sessionId,
              participantId: authority.participantId,
              privacyDomainId: privacyA,
              principalId: authority.principalId,
              principalEpoch: authority.principalEpoch,
              signerCredentialId: '018f0000-0000-7000-8000-0000000009e3',
              participantEpoch: authority.participantEpoch,
              authorityEnvelopeId: authority.authorityEnvelopeId,
              authorityEpoch: authority.authorityEpoch,
              delegationEpoch: authority.delegationEpoch,
              assignmentId: authority.assignmentId,
              assignmentEpoch: authority.assignmentRowVersion,
              evidenceCbor: readArtifact.evidenceCbor,
              evidenceDigest: readArtifact.evidenceDigest,
              coseSign1: readArtifact.coseSign1,
            };
          },
        },
      });
      return app;
    };
    let app = makeApp();
    let address = await app.listen({ host: '127.0.0.1', port: 0 });
    const origin = webauthnOrigin;
    const baseHeaders = {
      'content-type': 'application/json',
      'cookie': `__Host-openpc_session=${makerToken}`,
      'openpc-api-version': '1',
      'openpc-participant-id': `urn:openpc:participant:${participantA}`,
      origin,
    };
    const mutationHeaders = async (
      actionIntentId: string,
      actionIntentDigest: string,
      requestId: string,
      idempotencyKey: string,
    ) => ({
      ...baseHeaders,
      'x-request-id': requestId,
      'x-correlation-id': requestId,
      'openpc-action-intent-digest': actionIntentDigest,
      'idempotency-key': idempotencyKey,
      'x-csrf-token': await kernel.csrfToken(
        makerToken,
        actionIntentId,
        origin,
        new URL(address).host,
      ),
    });
    const readHeaders = (requestId: string) => ({
      ...baseHeaders,
      'x-request-id': requestId,
      'x-correlation-id': requestId,
    });
    try {
      const createAction = 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1';
      const createActionDigest = await actionDigest(createAction);
      const createBody = {
        participantId: `urn:openpc:participant:${participantA}`,
        kind: 'REMEDIATION',
        assigneeRef: `urn:openpc:resource:${makerA}`,
        resourceRef: `urn:openpc:resource:${activationId}`,
        actionIntentId: createAction,
        actionIntentDigest: createActionDigest,
        reason: 'repair a durable projection mismatch',
      };
      await configurationProof({
        actionIntentId: createAction,
        body: createBody,
        expectedRevision: '0',
        approvalRequestId: '018f1000-0000-7000-8000-000000000b01',
        subjectId: '018f1000-0000-7000-8000-000000000b11',
        seed: 0xb1,
      });
      const createHeaders = await mutationHeaders(
        createAction,
        createActionDigest,
        '018f1000-0000-7000-8000-000000000b21',
        'work-item-create-0001',
      );
      const created = await fetch(new URL('/api/v1/work-items', address), {
        method: 'POST',
        headers: createHeaders,
        body: JSON.stringify(createBody),
      });
      const createdText = await created.text();
      expect(created.status, createdText).toBe(202);
      const createdOperation = JSON.parse(createdText) as {
        operationId: string;
        resourceRef: string;
        revision: string;
      };
      expect(createdOperation).toMatchObject({ revision: '1', state: 'SUCCEEDED' });
      const workItemId = idFromUrnForTest(createdOperation.resourceRef);

      const createReplay = await fetch(new URL('/api/v1/work-items', address), {
        method: 'POST',
        headers: createHeaders,
        body: JSON.stringify(createBody),
      });
      expect(await createReplay.json()).toEqual(createdOperation);

      const readOpen = await fetch(
        new URL(`/api/v1/work-items/${createdOperation.resourceRef}`, address),
        { headers: readHeaders('018f1000-0000-7000-8000-000000000b22') },
      );
      expect(await readOpen.json()).toMatchObject({
        workItemId: createdOperation.resourceRef,
        state: 'OPEN',
        kind: 'REMEDIATION',
        assigneeRef: createBody.assigneeRef,
        revision: '1',
      });
      await expect(
        admin.query(
          `update control.work_item
              set assignee_principal_id=$1,row_version=row_version+1,updated_at=clock_timestamp()
            where work_item_id=$2`,
          [checkerA, workItemId],
        ),
      ).rejects.toThrow('DATA-6020-IMMUTABLE-ROW');
      const listed = await fetch(new URL('/api/v1/work-items?filter=state:eq:OPEN', address), {
        headers: readHeaders('018f1000-0000-7000-8000-000000000b23'),
      });
      const listedBody = (await listed.json()) as { items: Array<{ workItemId: string }> };
      expect(listed.status).toBe(200);
      expect(
        listedBody.items.some((item) => item.workItemId === createdOperation.resourceRef),
      ).toBe(true);

      const updateAction = 'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1';
      const updateActionDigest = await actionDigest(updateAction);
      const updateBody = {
        actionIntentId: updateAction,
        actionIntentDigest: updateActionDigest,
        expectedRevision: '1',
        replacementDigest: `sha256:${sha256('work-item-replacement').toString('hex')}`,
        reason: 'bind the corrected remediation payload',
      };
      await configurationProof({
        actionIntentId: updateAction,
        body: updateBody,
        expectedRevision: '1',
        approvalRequestId: '018f1000-0000-7000-8000-000000000b02',
        subjectId: workItemId,
        seed: 0xb2,
      });
      const updateHeaders = {
        ...(await mutationHeaders(
          updateAction,
          updateActionDigest,
          '018f1000-0000-7000-8000-000000000b24',
          'work-item-update-0001',
        )),
        'if-match': `"sha256:${sha256(
          canonicalJson({ resourceId: workItemId, revision: '1' }),
        ).toString('hex')}"`,
      };
      const updated = await fetch(
        new URL(`/api/v1/work-items/${createdOperation.resourceRef}`, address),
        { method: 'PATCH', headers: updateHeaders, body: JSON.stringify(updateBody) },
      );
      const updatedText = await updated.text();
      expect(updated.status, updatedText).toBe(202);
      expect(JSON.parse(updatedText)).toMatchObject({ revision: '2' });

      const claimAction = 'ACT-OPERATIONS_UPDATE_CLAIM-V1';
      const claimActionDigest = await actionDigest(claimAction);
      const claimBody = {
        targetRef: createdOperation.resourceRef,
        expectedRevision: '2',
        inputDigest: transitionDigest(claimAction, createdOperation.resourceRef, '2', 'CLAIM'),
        actionIntentId: claimAction,
        actionIntentDigest: claimActionDigest,
        reason: 'claim exact remediation work',
      };
      const tamperedClaimBody = { ...claimBody, inputDigest: `sha256:${'de'.repeat(32)}` };
      await configurationProof({
        actionIntentId: claimAction,
        body: tamperedClaimBody,
        expectedRevision: '2',
        approvalRequestId: '018f1000-0000-7000-8000-000000000b03',
        subjectId: '018f1000-0000-7000-8000-000000000b13',
        seed: 0xb3,
      });
      const claimEtag = `"sha256:${sha256(
        canonicalJson({ resourceId: workItemId, revision: '2' }),
      ).toString('hex')}"`;
      const tamperedClaim = await fetch(
        new URL(`/api/v1/work-items/${createdOperation.resourceRef}/claim`, address),
        {
          method: 'POST',
          headers: {
            ...(await mutationHeaders(
              claimAction,
              claimActionDigest,
              '018f1000-0000-7000-8000-000000000b25',
              'work-item-claim-tampered',
            )),
            'if-match': claimEtag,
          },
          body: JSON.stringify(tamperedClaimBody),
        },
      );
      expect(tamperedClaim.status).toBe(412);
      await configurationProof({
        actionIntentId: claimAction,
        body: claimBody,
        expectedRevision: '2',
        approvalRequestId: '018f1000-0000-7000-8000-000000000b04',
        subjectId: workItemId,
        seed: 0xb4,
      });
      const claimedHeaders = {
        ...(await mutationHeaders(
          claimAction,
          claimActionDigest,
          '018f1000-0000-7000-8000-000000000b26',
          'work-item-claim-0001',
        )),
        'if-match': claimEtag,
      };
      const claimed = await fetch(
        new URL(`/api/v1/work-items/${createdOperation.resourceRef}/claim`, address),
        { method: 'POST', headers: claimedHeaders, body: JSON.stringify(claimBody) },
      );
      const claimedText = await claimed.text();
      expect(claimed.status, claimedText).toBe(202);
      expect(JSON.parse(claimedText)).toMatchObject({ revision: '3' });
      const staleClaim = await fetch(
        new URL(`/api/v1/work-items/${createdOperation.resourceRef}/claim`, address),
        {
          method: 'POST',
          headers: {
            ...claimedHeaders,
            'x-request-id': '018f1000-0000-7000-8000-000000000b27',
            'x-correlation-id': '018f1000-0000-7000-8000-000000000b27',
            'idempotency-key': 'work-item-claim-stale',
          },
          body: JSON.stringify(claimBody),
        },
      );
      expect(staleClaim.status).toBe(412);

      const completeAction = 'ACT-OPERATIONS_UPDATE_COMPLETE-V1';
      const completeActionDigest = await actionDigest(completeAction);
      const completeBody = {
        targetRef: createdOperation.resourceRef,
        expectedRevision: '3',
        inputDigest: transitionDigest(
          completeAction,
          createdOperation.resourceRef,
          '3',
          'COMPLETE',
        ),
        actionIntentId: completeAction,
        actionIntentDigest: completeActionDigest,
        reason: 'complete exact remediation work',
      };
      await configurationProof({
        actionIntentId: completeAction,
        body: completeBody,
        expectedRevision: '3',
        approvalRequestId: '018f1000-0000-7000-8000-000000000b05',
        subjectId: workItemId,
        seed: 0xb5,
      });
      const completed = await fetch(
        new URL(`/api/v1/work-items/${createdOperation.resourceRef}/complete`, address),
        {
          method: 'POST',
          headers: {
            ...(await mutationHeaders(
              completeAction,
              completeActionDigest,
              '018f1000-0000-7000-8000-000000000b28',
              'work-item-complete-0001',
            )),
            'if-match': `"sha256:${sha256(
              canonicalJson({ resourceId: workItemId, revision: '3' }),
            ).toString('hex')}"`,
          },
          body: JSON.stringify(completeBody),
        },
      );
      const completedText = await completed.text();
      expect(completed.status, completedText).toBe(202);
      const completedOperation = JSON.parse(completedText) as {
        operationId: string;
        resourceRef: string;
        revision: string;
      };
      expect(completedOperation).toMatchObject({
        resourceRef: createdOperation.resourceRef,
        revision: '4',
      });

      const operationRead = await fetch(
        new URL(`/api/v1/operations/${completedOperation.operationId}`, address),
        { headers: readHeaders('018f1000-0000-7000-8000-000000000b29') },
      );
      const operationText = await operationRead.text();
      expect(operationRead.status, operationText).toBe(200);
      expect(JSON.parse(operationText)).toMatchObject({
        operationId: completedOperation.operationId,
        resourceRef: createdOperation.resourceRef,
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        revision: '4',
      });
      const durableCounts = (
        await admin.query<{
          evidence: string;
          outbox: string;
          idempotency: string;
          aggregateTypes: string;
          firstSequence: string;
          lastSequence: string;
        }>(
          `select
             (select count(*)::text from control.mutation_evidence
               where participant_id=$1 and aggregate_id=$2) evidence,
             (select count(*)::text from control.outbox_event
               where participant_id=$1 and aggregate_id=$2) outbox,
             (select count(distinct aggregate_type)::text from control.outbox_event
               where participant_id=$1 and aggregate_id=$2) "aggregateTypes",
             (select min(aggregate_sequence)::text from control.outbox_event
               where participant_id=$1 and aggregate_id=$2) "firstSequence",
             (select max(aggregate_sequence)::text from control.outbox_event
               where participant_id=$1 and aggregate_id=$2) "lastSequence",
             (select count(*)::text from control.idempotency_record record
               join control.mutation_evidence evidence
                 on evidence.participant_id=record.participant_id
                and evidence.operation_id=record.operation_id
              where record.participant_id=$1 and evidence.aggregate_id=$2
                and record.terminal_state='COMMITTED') idempotency`,
          [participantA, workItemId],
        )
      ).rows[0];
      expect(durableCounts).toEqual({
        evidence: '4',
        outbox: '4',
        idempotency: '4',
        aggregateTypes: '1',
        firstSequence: '1',
        lastSequence: '4',
      });

      await app.close();
      app = makeApp();
      address = await app.listen({ host: '127.0.0.1', port: 0 });
      const readCompleted = await fetch(
        new URL(`/api/v1/work-items/${createdOperation.resourceRef}`, address),
        { headers: readHeaders('018f1000-0000-7000-8000-000000000b30') },
      );
      const readCompletedText = await readCompleted.text();
      expect(readCompleted.status, readCompletedText).toBe(200);
      expect(JSON.parse(readCompletedText)).toMatchObject({
        workItemId: createdOperation.resourceRef,
        state: 'COMPLETED',
        assigneeRef: createBody.assigneeRef,
        revision: '4',
      });
    } finally {
      await app.close();
    }
  });

  it('executes all 422 operations and participant traces through activatePolicyGeneration', async () => {
    expect(traceCorpusManifest.rootCommitmentSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(traceCorpusManifest.policyStoreLiveOwner).toEqual({
      owner: 'services/module-registry/src/db/policy-store.ts',
      operation: 'activatePolicyGeneration',
      rowCount: 422,
      accepted: 64,
      rejectedFailClosed: 358,
      orderedRecordDigestAggregateSha256: sha256(
        policyStoreTraceRecords.map((record) => record.recordDigest).join('\n'),
      ).toString('hex'),
    });
    const commitments = new Map(
      traceCorpusManifest.recordCommitments.map((commitment) => [commitment.traceId, commitment]),
    );
    const fixtureIds = new Set<string>();
    const behavioralEvidence = new Set<string>();
    let accepted = 0;
    let rejected = 0;
    let authorizedArtifact = identityOperationArtifact(1_000);
    const authorization: IdentityAuthorizationAdapter = {
      async authorize(input) {
        expect(input.actionIntentId).toBe('ACT-IDENTITY_UPDATE_STEP_UP-V1');
        expect(input.resourceId).toBe(sessionId);
        return {
          allowed: true,
          signerCredentialId: '018f0000-0000-7000-8000-000000000916',
          privacyDomainId: privacyA,
          evidenceCbor: authorizedArtifact.evidenceCbor,
          evidenceDigest: authorizedArtifact.evidenceDigest,
          coseSign1: authorizedArtifact.coseSign1,
        };
      },
    };
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
    const identityApp = buildIdentityService(
      kernel,
      identityTrustAdapter(),
      undefined,
      authorization,
    );
    try {
      for (const [index, record] of policyStoreTraceRecords.entries()) {
        const rawRecord = traceCorpusRawById.get(record.traceId);
        const commitment = commitments.get(record.traceId);
        expect(rawRecord, record.traceId).toBeDefined();
        expect(commitment, record.traceId).toBeDefined();
        expect(commitment!.recordDigest, record.traceId).toBe(record.recordDigest);
        expect(commitment!.rawRecordSha256, record.traceId).toBe(
          sha256(rawRecord!).toString('hex'),
        );
        expect(record.declaredOwner, record.traceId).toBe(
          'services/module-registry/src/db/policy-store.ts',
        );
        const ownerInput = record.productInput.ownerInput;
        expect(ownerInput.kind, record.traceId).toBe('POLICY_STORE_ACTIVATION_INPUT');
        if (ownerInput.kind !== 'POLICY_STORE_ACTIVATION_INPUT')
          throw new Error(`invalid policy-store owner input: ${record.traceId}`);
        expect(ownerInput.participantId, record.traceId).toBe(participantA);
        expect(ownerInput.privacyDomainId, record.traceId).toBe(privacyA);
        expect(ownerInput.checkerPrincipalId, record.traceId).toBe(checkerA);
        expect(ownerInput.checkerPrincipalEpoch, record.traceId).toBe('6');

        const fixture = policyStoreTraceFixture(record);
        for (const id of [
          fixture.policyId,
          fixture.policyVersionId,
          fixture.simulationId,
          fixture.approvalRequestId,
          fixture.generationId,
          fixture.activationId,
          fixture.challengeId,
          fixture.envelopeId,
          fixture.assignmentId,
          fixture.operationId,
          fixture.eventId,
        ]) {
          expect(fixtureIds.has(id), `${record.traceId}:${id}`).toBe(false);
          fixtureIds.add(id);
        }
        const proof = createWebAuthnProof(fixture.candidateDigest, 1_000 + index);
        const artifacts = activationArtifact(
          fixture.candidateDigest,
          fixture.activationId,
          fixture.approvalRequestId,
          1n,
        );
        await insertPolicyStoreTraceFixture(admin, record, fixture, proof, artifacts);
        authorizedArtifact = identityOperationArtifact(1_000 + index);
        const sessionVersion = (
          await admin.query<{ row_version: string }>(
            `select row_version::text from control.session where participant_id=$1 and session_id=$2`,
            [participantA, sessionId],
          )
        ).rows[0]?.row_version;
        if (sessionVersion === undefined) throw new Error('missing trace identity session');
        const verification = await identityApp.inject({
          method: 'POST',
          url: '/v1/identity/webauthn/verify',
          headers: {
            'cookie': `__Host-openpc_session=${participantA}.${sessionId}`,
            'origin': webauthnOrigin,
            'host': new URL(webauthnOrigin).host,
            'x-csrf-token': await kernel.csrfToken(
              `${participantA}.${sessionId}`,
              'ACT-POLICY_ACTIVATE_RELEASE-V1',
              webauthnOrigin,
              new URL(webauthnOrigin).host,
            ),
            'openpc-action-intent-digest': await kernel.actionIntentSemanticDigest(
              `${participantA}.${sessionId}`,
              'ACT-IDENTITY_UPDATE_STEP_UP-V1',
            ),
            'idempotency-key': `i03-trace-webauthn-${record.traceId}`,
            'x-openpc-aggregate-version': sessionVersion,
          },
          payload: {
            actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
            resourceDigest: `sha256:${fixture.candidateDigest.toString('hex')}`,
            rpIdHash: `sha256:${webauthnRpIdHash.toString('hex')}`,
            challenge: proof.webauthnChallenge,
            assertion: encodedWebAuthnAssertion(proof),
          },
        });
        expect(verification.statusCode, `${record.traceId}:${verification.body}`).toBe(200);
        const input = tracePolicyMutation(record, fixture, proof, artifacts);
        const before = await authoritySnapshot();
        if (record.productAssertion.outcome === 'ACCEPTED') {
          try {
            await activatePolicyGeneration(runtime, input, fixture.activationId);
          } catch (error) {
            throw new Error(`${record.traceId}: ${String(error)}`, { cause: error });
          }
          const after = await authoritySnapshot();
          expect(after, record.traceId).toEqual({
            activations: before.activations + 1,
            generations: before.generations + 1,
            evidence: before.evidence + 1,
            outbox: before.outbox + 1,
            idempotency: before.idempotency + 1,
            used_proofs: before.used_proofs + 1,
          });
          accepted += 1;
          behavioralEvidence.add(
            sha256(
              JSON.stringify({ traceId: record.traceId, recordDigest: record.recordDigest, after }),
            ).toString('hex'),
          );
        } else {
          await expect(
            activatePolicyGeneration(runtime, input, fixture.activationId),
            record.traceId,
          ).rejects.toThrow(
            ['ACTION_SUBSTITUTION', 'AGGREGATE_SUBSTITUTION', 'CHECKER_SUBSTITUTION'].includes(
              record.productInput.mutation,
            )
              ? 'PC-POLICY-2004'
              : 'PC-POLICY-2005',
          );
          const after = await authoritySnapshot();
          expect(after, record.traceId).toEqual(before);
          rejected += 1;
          behavioralEvidence.add(
            sha256(
              JSON.stringify({
                traceId: record.traceId,
                recordDigest: record.recordDigest,
                before,
                after,
                mutation: record.productInput.mutation,
              }),
            ).toString('hex'),
          );
        }
      }
    } finally {
      await identityApp.close();
    }
    expect(policyStoreTraceRecords).toHaveLength(422);
    expect(accepted).toBe(64);
    expect(rejected).toBe(358);
    expect(behavioralEvidence.size).toBe(422);
  }, 900_000);
});

// Run with the existing CIGL/participant-readback PostgreSQL owner. Its real
// Identity/configuration services and signing roles differ from the I03 fixture.
// Keeping this gate explicit prevents a seeded settings row from claiming
// governed binding-change acceptance. The canonical runner owns invocation.
const settingsAdminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const settingsRuntimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const settingsIntegration = settingsAdminUrl && settingsRuntimeUrl ? it : it.skip;
settingsIntegration(
  'changes a CIGL binding through governed publication after the preflight fence releases (M1a)',
  async () => {
    const { contractAdministrationFixture } =
      await import('../identity/contract-administration-fixture.js');
    const { localOperationId: id } =
      await import('../../../services/identity-service/src/domain/local-operation-id.js');
    const { sha256: definitionDigest } =
      await import('../../../services/control-api/src/configuration/digest.js');
    const admin = new Pool({ connectionString: settingsAdminUrl, max: 2 });
    const runtime = new Pool({ connectionString: settingsRuntimeUrl, max: 2 });
    const participantId = id(),
      privacyDomainId = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const reader = await runtime.connect();
    const writer = await admin.connect();
    const action = 'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1';
    try {
      fixture = await contractAdministrationFixture(
        admin,
        settingsRuntimeUrl!,
        participantId,
        privacyDomainId,
      );
      const definition = {
        schemaVersion: '1.0',
        scope: { kind: 'ALL_CHAINS' },
        mode: 'HYBRID_STRICT',
        enforcement: {
          ethCall: true,
          ethEstimateGas: true,
          prepareWrite: true,
          rawSubmission: true,
          deploymentConstructors: true,
          runtimeTraceForWrites: true,
          reviewedSchemaSubset: true,
          failClosed: true,
          rejectExternalStateOverrides: true,
        },
        traceLimits: { maxDepth: 16, maxFrames: 32, maxResponseBytes: 100_000, timeoutMs: 5000 },
        traceProvider: 'DEBUG_TRACE_CALL',
        readinessScope: 'METHOD',
        schemaFallbackEnabled: false,
        precompileAllowlist: ['0x0000000000000000000000000000000000000001'],
        systemContractAllowlist: [],
        postMine: { enabled: true, freezeOnDivergence: true },
      };
      const prepared = await fixture.prepareCreation('cigl-settings', action, { definition });
      await prepared.stepUp();
      const begin = async (client: typeof reader, privacy = privacyDomainId) => {
        await client.query('begin isolation level read committed');
        if (client === writer) await client.query('set local role openpc_control_runtime');
        await client.query("set local lock_timeout='250ms'");
        await client.query("set local statement_timeout='2s'");
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),$3,true)`,
          [participantId, privacy, action],
        );
      };
      const binding = [{ kind: 'CiglSettings', id: prepared.resourceId }];
      const current = async () =>
        (
          await reader.query(
            'select openpc.runtime_configuration_bindings_current($1,$2,$3::jsonb) current',
            [participantId, privacyDomainId, JSON.stringify(binding)],
          )
        ).rows[0].current;
      const insert = (settingsId: string) =>
        writer.query(
          `insert into control.cigl_settings(cigl_settings_id,participant_id,privacy_domain_id,
        definition,definition_digest,publication_operation_id,publication_authority_digest)
       values($1,$2,$3,$4::jsonb,$5,openpc.current_operation_id(),$6)`,
          [
            settingsId,
            participantId,
            privacyDomainId,
            JSON.stringify(definition),
            definitionDigest(definition),
            definitionDigest('unpublished-test-input'),
          ],
        );
      await begin(reader);
      await reader.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
        `openpc-policy-generations:${participantId}:${privacyDomainId}`,
      ]);
      expect(await current()).toBe(false);
      await begin(writer);
      // This permitted SQL role still has no publication authority. Contention
      // rejects the statement before either rows or deferred receipts can change.
      await expect(insert(prepared.resourceId)).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-DATA-6007',
      });
      await writer.query('rollback');
      expect(await current()).toBe(false);
      await reader.query('rollback');

      // Preserve the original prepared intent; its public owner performs the
      // approval/step-up-bound publication once after the reader has released.
      const committed = await prepared.commit();
      expect(committed.status, JSON.stringify(committed)).toBe(202);
      expect(committed.body).toMatchObject({
        resourceRef: `urn:openpc:resource:${prepared.resourceId}`,
        state: 'SUCCEEDED',
      });
      const assertReadHeaders = (headers: Headers, trace: Record<string, string>) => {
        for (const [name, value] of Object.entries({
          'OpenPC-API-Version': '1',
          'ETag': `"${definitionDigest({ resourceId: prepared.resourceId, revision: '1' })}"`,
          'RateLimit-Limit': '100',
          'RateLimit-Remaining': '99',
          'RateLimit-Reset': '60',
          'Content-Type': 'application/json; charset=utf-8',
          ...trace,
        })) {
          expect(headers.get(name), name).toBe(value);
        }
      };
      const publishedTrace = { 'X-Request-ID': id(), 'X-Correlation-ID': id() };
      const published = await fixture.read(
        `cigl-settings/${committed.body.resourceRef}`,
        publishedTrace,
      );
      expect(published.status, JSON.stringify(published)).toBe(200);
      expect(published.body).toMatchObject({
        definition,
        definitionDigest: definitionDigest(definition),
        revision: '1',
        runtimePermission: 'NONE',
      });
      assertReadHeaders(published.headers, publishedTrace);
      await begin(reader);
      expect(await current()).toBe(true);
      await reader.query('rollback');
      await begin(reader, id());
      expect(await current()).toBe(false);
      await reader.query('rollback');
      expect(await prepared.commit()).toEqual(committed);
      await fixture.restartConfiguration();
      const restartedTrace = { 'X-Request-ID': id(), 'X-Correlation-ID': id() };
      const restarted = await fixture.read(
        `cigl-settings/${committed.body.resourceRef}`,
        restartedTrace,
      );
      // Compare complete durable output and explicit header values; Headers
      // instances also carry request/transport state that changes after restart.
      expect(restarted.status).toBe(published.status);
      expect(restarted.body).toEqual(published.body);
      assertReadHeaders(restarted.headers, restartedTrace);
      for (const name of ['Content-Length', 'Cache-Control', 'Vary']) {
        expect(restarted.headers.get(name), name).toBe(published.headers.get(name));
      }

      // Fence success cannot replace immutable settings or deferred provenance.
      await begin(writer);
      await expect(
        writer.query(
          'update control.cigl_settings set definition=definition where cigl_settings_id=$1',
          [prepared.resourceId],
        ),
      ).rejects.toMatchObject({ code: '42501' });
      await writer.query('rollback');
      await begin(writer);
      const unpublishedId = id();
      await insert(unpublishedId);
      await expect(writer.query('set constraints all immediate')).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-AUTH-0002-CIGL-SETTINGS-PROVENANCE',
      });
      await writer.query('rollback');
      expect(
        (
          await admin.query('select 1 from control.cigl_settings where cigl_settings_id=$1', [
            unpublishedId,
          ])
        ).rowCount,
      ).toBe(0);
      for (const table of ['cigl_settings', 'mutation_evidence', 'outbox_event']) {
        const column = table === 'cigl_settings' ? 'cigl_settings_id' : 'aggregate_id';
        expect(
          (
            await admin.query(
              `select count(*)::int n from control.${table} where participant_id=$1 and ${column}=$2`,
              [participantId, prepared.resourceId],
            )
          ).rows[0].n,
        ).toBe(1);
      }
    } finally {
      await reader.query('rollback');
      await writer.query('rollback');
      reader.release(true);
      writer.release(true);
      await fixture?.close();
      await runtime.end();
      await admin.end();
    }
  },
  120_000,
);
