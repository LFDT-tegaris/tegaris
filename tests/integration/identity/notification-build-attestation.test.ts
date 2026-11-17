import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import type { TLSSocket } from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import { expect, it } from 'vitest';
import {
  createNotificationBuildAttestationFixture,
  type NotificationBuildAttestationFixture,
} from '../local-runtime/notification-build-attestation-fixture.js';
import {
  canonical,
  digest,
  type QualificationOriginRequest,
  type QualificationSelection,
} from '../../../services/control-api/src/configuration/operations/notification-qualification-contract.js';
import type { NotificationQualificationPeer } from '../../../services/identity-service/src/domain/notification-qualification-peer.js';

const helpers = () =>
  import(
    new URL('../local-runtime/notification-build-attestation-build.mjs', import.meta.url).href
  );
const id = (n: number) => `019a0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const h = (value: string) => digest(Buffer.from(value));
const temporaryRoot = process.env.OPENPC_PNC_TMP_ROOT ?? tmpdir();
async function sourcePackage() {
  const { notificationBuildRecipe } = await helpers();
  return {
    version: 1,
    kind: 'HARNESS',
    recipe: notificationBuildRecipe('HARNESS'),
    files: [
      { path: 'pnpm-lock.yaml', bytes: Buffer.from('unit corpus only').toString('base64') },
      {
        path: 'scripts/operations/notification-qualification-harness.mjs',
        bytes: Buffer.from('throw new Error("never execute submitted source");').toString('base64'),
      },
    ],
  };
}
function request(): QualificationOriginRequest {
  return {
    schemaVersion: 1,
    mode: 'NEW_AUTHENTICATED_ORIGIN',
    originId: id(1),
    installationId: id(2),
    installationDigest: h('installation'),
    participantId: id(3),
    privacyDomainId: id(4),
    environmentId: 'local-test',
    kind: 'HARNESS',
    author: {
      principalId: id(5),
      credentialId: id(6),
      participantEpoch: '1',
      principalEpoch: '1',
      credentialEpoch: '1',
      workloadId: 'unit-author',
      keyDigest: h('key'),
      certificateDigest: h('certificate'),
    },
    operationId: id(7),
    sourceDigest: h('source'),
    buildDigest: h('build'),
    issuedAtMs: 1,
    deadlineAtMs: 2,
  };
}
async function unitFixture() {
  const directory = await mkdtemp(join(temporaryRoot, 'notification-build-unit-'));
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  // Undefined internal owners cannot manufacture a positive authentication.
  const options = {
    directory,
    temporaryRoot,
    repositoryRoot: '/unavailable',
    providerId: 'unit-external-builder',
    privateKeyPkcs8Der: key.privateKey.export({ type: 'pkcs8', format: 'der' }),
    ownerPool: undefined,
    kernel: undefined,
    authors: { SUBJECT: undefined, HARNESS: undefined },
  } as unknown as Parameters<typeof createNotificationBuildAttestationFixture>[0];
  return { directory, options, fixture: await createNotificationBuildAttestationFixture(options) };
}
it('fixes the two actual recipes and decodes source without executing it', async () => {
  const { notificationBuildRecipe, parseNotificationBuildSource } = await helpers();
  expect(notificationBuildRecipe('SUBJECT').entry).toBe(
    'services/control-api/src/local-runtime.ts',
  );
  expect(() => notificationBuildRecipe('CALLER_SCRIPT')).toThrow();
  const value = await sourcePackage();
  expect(parseNotificationBuildSource(Buffer.from(canonical(value)))).toEqual(value);
});
it.each(['traversal', 'absolute', 'duplicate', 'order', 'link', 'recipe', 'base64', 'missing'])(
  'rejects %s in the retained source package',
  async (mode) => {
    const value = await sourcePackage(),
      first = value.files[0]!;
    if (mode === 'traversal') first.path = '../pnpm-lock.yaml';
    if (mode === 'absolute') first.path = '/pnpm-lock.yaml';
    if (mode === 'duplicate') value.files.push({ ...first });
    if (mode === 'order') value.files.reverse();
    if (mode === 'link') Object.assign(first, { symlink: '/outside' });
    if (mode === 'recipe') value.recipe.esbuild = 'caller-tool';
    if (mode === 'base64') first.bytes = 'Zh==';
    if (mode === 'missing') value.files.shift();
    const { parseNotificationBuildSource } = await helpers();
    expect(() => parseNotificationBuildSource(Buffer.from(canonical(value)))).toThrow();
  },
);
it('rejects duplicate JSON keys, noncanonical and oversized source bytes', async () => {
  const { parseNotificationBuildSource } = await helpers();
  for (const bytes of [
    Buffer.from('{"version":1,"version":1}'),
    Buffer.from(JSON.stringify(await sourcePackage(), null, 2)),
    Buffer.alloc(16777217),
  ])
    expect(() => parseNotificationBuildSource(bytes)).toThrow();
});
it('does not treat matching caller hashes as a verified build', async () => {
  const f = await unitFixture();
  try {
    const source = Buffer.from(canonical(await sourcePackage())),
      build = Buffer.from('unit corpus');
    const r = { ...request(), sourceDigest: digest(source), buildDigest: digest(build) };
    await expect(f.fixture.buildAttestation(r, source, build)).rejects.toThrow('UNVERIFIED');
    expect(await f.fixture.readOriginal(r)).toEqual({ state: 'ABSENT' });
    await expect(f.fixture.buildAttestation(r, source, Buffer.from('different'))).rejects.toThrow(
      'BYTES',
    );
  } finally {
    await rm(f.directory, { recursive: true, force: true });
  }
});
it('keeps an interrupted provider reservation UNKNOWN across restart without signing', async () => {
  const f = await unitFixture();
  try {
    const r = request(),
      name = digest(
        Buffer.from(canonical([r.participantId, r.privacyDomainId, r.installationId, r.originId])),
      ).slice(7);
    // External fixture crash corpus only: no internal business state is seeded.
    await mkdir(join(f.directory, 'attempts', name), { mode: 0o700 });
    expect(await f.fixture.readOriginal(r)).toEqual({ state: 'UNKNOWN' });
    const reopened = await createNotificationBuildAttestationFixture(f.options);
    expect(await reopened.readOriginal(r)).toEqual({ state: 'UNKNOWN' });
  } finally {
    await rm(f.directory, { recursive: true, force: true });
  }
});
it('rejects fixture key replacement and symlinked original storage', async () => {
  const f = await unitFixture();
  try {
    const next = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    await expect(
      createNotificationBuildAttestationFixture({
        ...f.options,
        privateKeyPkcs8Der: next.privateKey.export({ type: 'pkcs8', format: 'der' }),
      }),
    ).rejects.toThrow('CONFLICT');
    const alias = join(f.directory, 'alias');
    await symlink(join(f.directory, 'attempts'), alias);
    await expect(
      createNotificationBuildAttestationFixture({ ...f.options, directory: alias }),
    ).rejects.toThrow();
  } finally {
    await rm(f.directory, { recursive: true, force: true });
  }
});

/** Real canonical connected acceptance, deliberately not run by the pure corpus.
 * All origins/author identities/installation state come from the real A12 and
 * Identity owners. The external builder is the only substituted service.
 * The integrator prepares actual bundles before installing pins/opening nonces. */
export async function exerciseNotificationBuildAttestation(input: {
  fixture: NotificationBuildAttestationFixture;
  foreignFixture: NotificationBuildAttestationFixture;
  peer: NotificationQualificationPeer;
  selection: QualificationSelection;
  actors: { SUBJECT: TLSSocket; HARNESS: TLSSocket };
  origins: {
    subject: { source: Buffer; build: Buffer };
    harness: { source: Buffer; build: Buffer };
  };
  reopen(): Promise<NotificationBuildAttestationFixture>;
}) {
  for (const kind of ['SUBJECT', 'HARNESS'] as const) {
    const artifact = kind === 'SUBJECT' ? input.origins.subject : input.origins.harness;
    const r = await input.peer.prepareOrigin(
      input.actors[kind],
      input.selection,
      kind,
      artifact.source,
      artifact.build,
    );
    await assert.rejects(input.foreignFixture.buildAttestation(r, artifact.source, artifact.build));
    assert.equal((await input.fixture.readOriginal(r)).state, 'ABSENT');
    await assert.rejects(
      input.fixture.buildAttestation(
        { ...r, operationId: id(999) },
        artifact.source,
        artifact.build,
      ),
    );
    assert.equal((await input.fixture.readOriginal(r)).state, 'ABSENT');
    // Discard first response to exercise durable lookup rather than re-signing.
    await input.fixture.buildAttestation(r, artifact.source, artifact.build);
    const original = await (await input.reopen()).readOriginal(r);
    assert.equal(original.state, 'ORIGINAL');
    assert.ok('signatureHex' in original);
    assert.equal(
      await input.fixture.buildAttestation(r, artifact.source, artifact.build),
      original.signatureHex,
    );
    await input.peer.retainOrigin(
      input.actors[kind],
      input.selection,
      r.originId,
      original.signatureHex,
    );
    await assert.rejects(
      input.fixture.buildAttestation(
        { ...r, environmentId: 'foreign' },
        artifact.source,
        artifact.build,
      ),
    );
  }
}
/** A separate fresh, real origin proves expiry denial; completed replay above
 * cannot prove it. No clock/authority override or replacement original. */
export async function exerciseExpiredNotificationBuildOrigin(input: {
  fixture: NotificationBuildAttestationFixture;
  peer: NotificationQualificationPeer;
  selection: QualificationSelection;
  actor: TLSSocket;
  artifact: { source: Buffer; build: Buffer };
  kind: 'SUBJECT' | 'HARNESS';
}) {
  const r = await input.peer.prepareOrigin(
    input.actor,
    input.selection,
    input.kind,
    input.artifact.source,
    input.artifact.build,
  );
  const wait = r.deadlineAtMs - Date.now() + 20;
  assert.ok(wait > 0 && wait <= 30100);
  await delay(wait);
  await assert.rejects(
    input.fixture.buildAttestation(r, input.artifact.source, input.artifact.build),
  );
  assert.notEqual((await input.fixture.readOriginal(r)).state, 'ORIGINAL');
}

it('preflights the actual canonical Docker/package recipe without compiling', async () => {
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const docker = await readFile(join(root, 'services/control-api/Dockerfile'), 'utf8');
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  const service = JSON.parse(
    await readFile(join(root, 'services/control-api/package.json'), 'utf8'),
  );
  const { assertNotificationBuildRecipe } = await helpers();
  expect(() => assertNotificationBuildRecipe(docker, pkg, service)).not.toThrow();
  expect(() =>
    assertNotificationBuildRecipe(
      docker.replace('src/local-runtime.ts --bundle', 'src/other.ts --bundle'),
      pkg,
      service,
    ),
  ).toThrow();
});
