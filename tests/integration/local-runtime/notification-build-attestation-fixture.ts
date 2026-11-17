import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { lstat, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { TLSSocket } from 'node:tls';
import type { Pool } from 'pg';
import { z } from 'zod';
import type { IdentityKernel } from '../../../services/identity-service/src/domain/identity-kernel.js';
import { withAuthenticatedWorkloadPeer } from '../../../services/identity-service/src/domain/workload-peer.js';
import {
  openVaultDirectory,
  putVaultFile,
  readVaultFile,
  syncVaultDirectory,
} from '../../../services/control-api/src/evidence/immutable-vault.js';
import {
  canonical,
  digest,
  qualificationOriginRequestSchema,
  qualificationPeerSchema,
  verifyQualificationOrigin,
  type QualificationOriginRequest,
} from '../../../services/control-api/src/configuration/operations/notification-qualification-contract.js';
import {
  assertQualificationActor,
  qualificationContext,
  qualificationNow,
} from '../../../services/control-api/src/configuration/operations/notification-qualification-store.js';
import { parseStrictJsonBytes } from '../../../services/control-api/src/privacy-explorer/strict-json.js';

const maximum = 16777216;
const domain = Buffer.from('pc.external.notification-build-origin.v1\0');
const fail = (reason: string) => new Error(`NOTIFICATION_BUILD_ATTESTATION_${reason}`);
const hashSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const originalSchema = z.strictObject({
  version: z.literal(1),
  request: qualificationOriginRequestSchema,
  builderKeyId: hashSchema,
  signatureHex: z.string().regex(/^[0-9a-f]{128}$/u),
});
const reservationSchema = z.strictObject({
  version: z.literal(1),
  request: qualificationOriginRequestSchema,
  builderKeyId: hashSchema,
});
const verifiedSchema = z.strictObject({
  version: z.literal(1),
  kind: z.enum(['SUBJECT', 'HARNESS']),
  sourceDigest: hashSchema,
  buildDigest: hashSchema,
  builderKeyId: hashSchema,
});
const serialized = (value: unknown) => Buffer.from(canonical(value));
async function optionalDirectory(path: string) {
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
  await openVaultDirectory(path);
  return true;
}
async function optionalFile(path: string, name: string, bound: number) {
  try {
    await lstat(join(path, name));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  return readVaultFile(path, name, bound);
}
async function exactWrite(directory: string, name: string, bytes: Buffer, bound: number) {
  await putVaultFile(directory, name, bytes);
  if (!(await readVaultFile(directory, name, bound)).equals(bytes)) throw fail('CONFLICT');
}
function boundedCopy(bytes: Buffer) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > maximum) throw fail('SIZE');
  return Buffer.from(bytes);
}
type Build = {
  kind: 'SUBJECT' | 'HARNESS';
  source: Buffer;
  build: Buffer;
  sourceDigest: string;
  buildDigest: string;
};
type Builder = {
  prepareNotificationBuilds(options: {
    repositoryRoot: string;
    temporaryRoot: string;
  }): Promise<Build[]>;
  parseNotificationBuildSource(bytes: Buffer): { kind: Build['kind'] };
};
async function builder(): Promise<Builder> {
  return import(new URL('./notification-build-attestation-build.mjs', import.meta.url).href);
}

/** Genuinely external build-service substitute, composed only by the canonical
 * root. Its protected files are provider originals, independent of PostgreSQL.
 * No callback can fake authentication/build success, and no HTTP input supplies
 * sockets, compiler settings, signers or a database connection. */
export async function createNotificationBuildAttestationFixture(options: {
  directory: string;
  repositoryRoot: string;
  temporaryRoot: string;
  providerId: string;
  privateKeyPkcs8Der: Buffer;
  ownerPool: Pool;
  kernel: IdentityKernel;
  authors: { SUBJECT: TLSSocket; HARNESS: TLSSocket };
}) {
  if (
    !Buffer.isBuffer(options.privateKeyPkcs8Der) ||
    options.privateKeyPkcs8Der.length > 4096 ||
    !options.providerId ||
    options.providerId.length > 128
  )
    throw fail('KEY');
  const key = createPrivateKey({ key: options.privateKeyPkcs8Der, type: 'pkcs8', format: 'der' });
  if (key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw fail('KEY');
  const publicKey = createPublicKey(key),
    publicBytes = publicKey.export({ type: 'spki', format: 'der' });
  const keyId = digest(publicBytes),
    directory = await openVaultDirectory(options.directory);
  // Reopening a fixture cannot replace its original public identity.
  await exactWrite(directory, 'builder.spki', publicBytes, 4096);
  const builds = await openVaultDirectory(join(directory, 'builds'));
  const attempts = await openVaultDirectory(join(directory, 'attempts'));
  const buildName = (source: Buffer, build: Buffer) =>
    digest(serialized([digest(source), digest(build)])).slice(7);
  const attemptName = (request: QualificationOriginRequest) =>
    digest(
      serialized([
        request.participantId,
        request.privacyDomainId,
        request.installationId,
        request.originId,
      ]),
    ).slice(7);

  async function verifiedBuild(request: QualificationOriginRequest, source: Buffer, build: Buffer) {
    if (digest(source) !== request.sourceDigest || digest(build) !== request.buildDigest)
      throw fail('BYTES');
    const decoded = (await builder()).parseNotificationBuildSource(source);
    if (decoded.kind !== request.kind) throw fail('KIND');
    const path = join(builds, buildName(source, build));
    if (!(await optionalDirectory(path))) throw fail('UNVERIFIED');
    const record = verifiedSchema.parse(
      parseStrictJsonBytes(await readVaultFile(path, 'verified.json', 4096), { maximumDepth: 8 }),
    );
    if (
      record.kind !== request.kind ||
      record.sourceDigest !== request.sourceDigest ||
      record.buildDigest !== request.buildDigest ||
      record.builderKeyId !== keyId ||
      !(await readVaultFile(path, 'source.json', maximum)).equals(source) ||
      !(await readVaultFile(path, 'build.mjs', maximum)).equals(build)
    )
      throw fail('UNVERIFIED');
  }
  async function readOriginal(
    value: unknown,
  ): Promise<{ state: 'ABSENT' | 'UNKNOWN' } | { state: 'ORIGINAL'; signatureHex: string }> {
    const request = qualificationOriginRequestSchema.parse(value),
      path = join(attempts, attemptName(request));
    if (!(await optionalDirectory(path))) return { state: 'ABSENT' };
    const reserved = await optionalFile(path, 'reservation.json', 16384);
    if (!reserved) return { state: 'UNKNOWN' }; // directory creation itself may have survived a crash
    const reservation = reservationSchema.parse(
      parseStrictJsonBytes(reserved, { maximumDepth: 8 }),
    );
    if (canonical(reservation.request) !== canonical(request) || reservation.builderKeyId !== keyId)
      throw fail('CONFLICT');
    const bytes = await optionalFile(path, 'original.json', 16384);
    if (!bytes) return { state: 'UNKNOWN' };
    const original = originalSchema.parse(parseStrictJsonBytes(bytes, { maximumDepth: 8 }));
    if (
      canonical(original.request) !== canonical(request) ||
      original.builderKeyId !== keyId ||
      !verify(
        'sha256',
        Buffer.concat([domain, serialized(request)]),
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(original.signatureHex, 'hex'),
      )
    )
      throw fail('ORIGINAL');
    return { state: 'ORIGINAL', signatureHex: original.signatureHex };
  }
  async function prepare() {
    const results = await (
      await builder()
    ).prepareNotificationBuilds({
      repositoryRoot: options.repositoryRoot,
      temporaryRoot: options.temporaryRoot,
    });
    if (results.length !== 2 || results[0]?.kind !== 'SUBJECT' || results[1]?.kind !== 'HARNESS')
      throw fail('BUILD');
    const subject = await retainBuild(results[0]);
    const harness = await retainBuild(results[1]);
    return { subject, harness };
  }
  async function retainBuild(result: Build) {
    const kind = result.kind;
    const source = boundedCopy(result.source),
      build = boundedCopy(result.build);
    if (result.sourceDigest !== digest(source) || result.buildDigest !== digest(build))
      throw fail('BUILD');
    const path = await openVaultDirectory(join(builds, buildName(source, build)));
    await exactWrite(path, 'source.json', source, maximum);
    await exactWrite(path, 'build.mjs', build, maximum);
    // Last write: incomplete preparation is never an authenticated build result.
    await exactWrite(
      path,
      'verified.json',
      serialized(
        verifiedSchema.parse({
          version: 1,
          kind,
          sourceDigest: digest(source),
          buildDigest: digest(build),
          builderKeyId: keyId,
        }),
      ),
      4096,
    );
    return { source, build };
  }
  async function buildAttestation(
    value: QualificationOriginRequest,
    submittedSource: Buffer,
    submittedBuild: Buffer,
  ) {
    const request = qualificationOriginRequestSchema.parse(value);
    const source = boundedCopy(submittedSource),
      build = boundedCopy(submittedBuild);
    if (digest(source) !== request.sourceDigest || digest(build) !== request.buildDigest)
      throw fail('BYTES');
    // Original provider truth survives expiry/withdrawal. This root-local lookup
    // grants no current adoption and cannot create a signature for another request.
    const prior = await readOriginal(request);
    if (prior.state === 'ORIGINAL') return prior.signatureHex;
    if (prior.state === 'UNKNOWN') throw fail('UNKNOWN');
    await verifiedBuild(request, source, build);
    const socket = options.authors[request.kind];
    return withAuthenticatedWorkloadPeer(
      options.ownerPool,
      options.kernel,
      socket,
      async (c, identity, confirm) => {
        const ctx = await qualificationContext(c, request);
        const raw = socket.getPeerCertificate(true).raw;
        if (!raw || socket.destroyed || !socket.authorized || socket.getProtocol() !== 'TLSv1.3')
          throw fail('TLS');
        const actual = qualificationPeerSchema.parse({
          principalId: identity.principalId,
          credentialId: identity.credentialId,
          participantEpoch: identity.participantEpoch,
          principalEpoch: identity.principalEpoch,
          credentialEpoch: identity.workloadEpoch,
          workloadId: identity.workloadId,
          keyDigest: identity.keyId,
          certificateDigest: digest(raw),
        });
        const pins = await assertQualificationActor(
          c,
          request,
          actual,
          request.kind === 'SUBJECT' ? 'subjectAuthor' : 'harnessAuthor',
        );
        if (
          canonical(actual) !== canonical(request.author) ||
          pins.builder.providerId !== options.providerId ||
          pins.builder.keyId !== keyId ||
          pins.builder.publicKeySpkiHex !== publicBytes.toString('hex')
        )
          throw fail('AUTHOR');
        const origin = await c.query<{
          body: unknown;
          body_bytes: Buffer;
          body_digest: string;
          source_bytes: Buffer;
          build_bytes: Buffer;
        }>(
          'select body,body_bytes,body_digest,source_bytes,build_bytes from control.notification_qualification_origin where participant_id=$1 and privacy_domain_id=$2 and installation_id=$3 and origin_id=$4',
          [
            request.participantId,
            request.privacyDomainId,
            request.installationId,
            request.originId,
          ],
        );
        const row = origin.rows[0];
        if (
          origin.rowCount !== 1 ||
          !row ||
          canonical(row.body) !== canonical(request) ||
          !row.body_bytes.equals(serialized(request)) ||
          row.body_digest !== digest(row.body_bytes) ||
          !row.source_bytes.equals(source) ||
          !row.build_bytes.equals(build)
        )
          throw fail('ORIGIN');
        await confirm();
        await ctx.confirm();
        const at = await qualificationNow(c);
        if (at < request.issuedAtMs || at >= request.deadlineAtMs) throw fail('EXPIRED');
        const path = join(attempts, attemptName(request));
        try {
          await mkdir(path, { mode: 0o700 });
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
          const competing = await readOriginal(request);
          if (competing.state === 'ORIGINAL') return competing.signatureHex;
          throw fail('UNKNOWN');
        }
        await syncVaultDirectory(attempts);
        await exactWrite(
          path,
          'reservation.json',
          serialized({ version: 1, request, builderKeyId: keyId }),
          16384,
        );
        await confirm();
        await ctx.confirm();
        if ((await qualificationNow(c)) >= request.deadlineAtMs) throw fail('EXPIRED');
        // No retry after this reservation. Failure or unknown fsync requires
        // original lookup even when PostgreSQL subsequently rolls back.
        const signatureHex = sign('sha256', Buffer.concat([domain, serialized(request)]), {
          key,
          dsaEncoding: 'ieee-p1363',
        }).toString('hex');
        verifyQualificationOrigin(request, signatureHex, pins);
        await exactWrite(
          path,
          'original.json',
          serialized({ version: 1, request, builderKeyId: keyId, signatureHex }),
          16384,
        );
        await confirm();
        await ctx.confirm();
        if ((await qualificationNow(c)) >= request.deadlineAtMs) throw fail('EXPIRED');
        return signatureHex;
      },
      request,
    );
  }
  return Object.freeze({
    prepare,
    buildAttestation,
    readOriginal,
    builder: Object.freeze({
      providerId: options.providerId,
      keyId,
      publicKeySpkiHex: publicBytes.toString('hex'),
    }),
  });
}

export type NotificationBuildAttestationFixture = Awaited<
  ReturnType<typeof createNotificationBuildAttestationFixture>
>;
/** Concrete canonical preparation entry. It must run under the existing heavy
 * owner BEFORE installing the source/build pins and opening either origin nonce.
 * Canonical mounts these exact artifacts; this does not attest their execution. */
export async function prepareNotificationBuildAttestation(
  options: Parameters<typeof createNotificationBuildAttestationFixture>[0],
) {
  const fixture = await createNotificationBuildAttestationFixture(options);
  const { subject, harness } = await fixture.prepare();
  return {
    fixture,
    origins: { subject, harness },
    builder: fixture.builder,
    buildAttestation: fixture.buildAttestation,
    approvedHarnessDigest: digest(harness.build),
  };
}
