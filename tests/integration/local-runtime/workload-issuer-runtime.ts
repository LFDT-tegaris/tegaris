import { createServer } from 'node:http';
import { lstat, open, readFile } from 'node:fs/promises';
import type { BigIntStats } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { constants as fsConstants } from 'node:fs';
import { createHash, timingSafeEqual, X509Certificate } from 'node:crypto';

import {
  localWorkloadIssuerProfileSchema,
  verifyIssuedWorkloadCertificate,
  workloadCertificateRequestDigest,
} from '../../../services/identity-service/src/domain/workload-credential-issuer.js';

import { z } from 'zod';

const entry = z.strictObject({
  credentialId: z.uuid(),
  participantId: z.uuid(),
  principalId: z.uuid(),
  workloadId: z.string().regex(/^urn:openpc:workload:[0-9a-f-]{36}$/u),
  publicKeySpkiDer: z.string().min(1),
  certificateDer: z.string().min(1),
});
const requestSchema = entry.omit({ certificateDer: true });
const manifestSchema = z.array(entry).min(1).max(10_000);
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
const observation = z.strictObject({
  credentialId: z.uuid(),
  requestDigest: digest,
  certificateFingerprint: digest,
});
const headerSchema = z.strictObject({
  kind: z.literal('HEADER'),
  schema: z.literal('pc.local.workload-issuer-journal.v1'),
  legacyManifestDigest: digest,
  originalCaptureDigest: digest,
  observations: z.array(observation).max(10_000),
});
const unknownRecoverySchema = z.strictObject({
  schema: z.literal('pc.local.workload-issuer-unknown-recovery.v1'),
  recoveryId: z.uuid(),
  reason: z.literal('ORIGINAL_PROCESS_RESTART_BEFORE_CAPTURE'),
  sourceBundleDigest: digest,
  lostProcessIdentity: z.strictObject({
    containerId: z.string().regex(/^[0-9a-f]{64}$/u),
    startedAt: z.iso.datetime(),
    hostPid: z.number().int().positive(),
  }),
  legacyManifestDigest: digest,
  profilesDigest: digest,
  quarantined: z
    .array(observation.extend({ outcome: z.literal('UNKNOWN') }))
    .min(1)
    .max(10_000),
});
const recoveryHeaderSchema = z.strictObject({
  kind: z.literal('RECOVERY_HEADER'),
  schema: z.literal('pc.local.workload-issuer-unknown-journal.v1'),
  recoveryId: z.uuid(),
  unknownRecoveryDigest: digest,
  legacyManifestDigest: digest,
});
const profilePin = z.strictObject({
  kind: z.literal('PROFILE'),
  profileId: z.uuid(),
  contentDigest: digest,
});
const claimSchema = observation.extend({
  kind: z.literal('CLAIM'),
  profileId: z.union([z.literal('LEGACY'), z.uuid()]),
});
const profilesSchema = z.strictObject({
  schema: z.literal('pc.local.workload-issuer-profiles.v1'),
  legacyManifestDigest: digest,
  profiles: z.array(localWorkloadIssuerProfileSchema).min(1).max(32),
});
const profileExtensionSchema = z.strictObject({
  schema: z.literal('pc.local.workload-issuer-profile-extension.v1'),
  baseProfilesDigest: digest,
  profiles: z.array(localWorkloadIssuerProfileSchema).min(1).max(31),
});
const hash = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
// The installer supplies the previously observed committed head. Never derive a
// cold-start expectation from the journal that happens to survive a crash.
export const localWorkloadIssuerJournalHeadSchema = z.strictObject({
  device: z.string().regex(/^\d+$/u),
  inode: z.string().regex(/^\d+$/u),
  owner: z.number().int().nonnegative(),
  mode: z.literal(0o600),
  bytes: z
    .number()
    .int()
    .min(1)
    .max(16 * 1024 * 1024),
  sha256: digest,
});
type JournalHead = z.infer<typeof localWorkloadIssuerJournalHeadSchema>;
function matchesHead(stat: BigIntStats, head: JournalHead): boolean {
  return (
    stat.isFile() &&
    !stat.isSymbolicLink() &&
    stat.nlink === 1n &&
    stat.dev.toString() === head.device &&
    stat.ino.toString() === head.inode &&
    stat.uid === BigInt(head.owner) &&
    head.owner === process.getuid?.() &&
    (stat.mode & 0o7777n) === BigInt(head.mode) &&
    stat.size === BigInt(head.bytes)
  );
}
function sameFileVersion(before: BigIntStats, after: BigIntStats): boolean {
  return before.ctimeNs === after.ctimeNs && before.mtimeNs === after.mtimeNs;
}
export function localWorkloadIssuerManifestDigest(value: unknown): string {
  return hash(JSON.stringify(manifestSchema.parse(value)));
}
function facts(candidate: z.infer<typeof entry>) {
  return {
    credentialId: candidate.credentialId,
    requestDigest: workloadCertificateRequestDigest({
      ...candidate,
      publicKeySpkiDer: Buffer.from(candidate.publicKeySpkiDer, 'base64'),
    }).toString('hex'),
    certificateFingerprint: hash(Buffer.from(candidate.certificateDer, 'base64')),
  };
}
export function readLocalWorkloadIssuerProfiles(bytes: Buffer, expectedDigest: string): unknown {
  digest.parse(expectedDigest);
  if (hash(bytes) !== expectedDigest) throw new Error('Installed issuer profiles digest mismatch');
  return profilesSchema.parse(JSON.parse(bytes.toString('utf8')));
}
export function readLocalWorkloadIssuerProfileExtension(bytes: Buffer, expectedDigest: string) {
  digest.parse(expectedDigest);
  if (hash(bytes) !== expectedDigest) throw new Error('Installed issuer extension digest mismatch');
  return profileExtensionSchema.parse(JSON.parse(bytes.toString('utf8')));
}
/** A separate installed quarantine never reconstructs a lost original CLAIM.
 * Its digest is supplied by the independent installation owner, like the
 * journal head. It grants no credential or business authority. */
export function readLocalWorkloadIssuerUnknownRecovery(bytes: Buffer, expectedDigest: string) {
  digest.parse(expectedDigest);
  if (hash(bytes) !== expectedDigest)
    throw new Error('Installed issuer quarantine digest mismatch');
  return unknownRecoverySchema.parse(JSON.parse(bytes.toString('utf8')));
}

const capturedClaimsSchema = z.strictObject({
  schema: z.literal('pc.local.workload-issuer-claims-capture.v1'),
  sourceBundleDigest: digest,
  legacyManifestDigest: digest,
  processIdentity: z.string().min(1).max(256),
  claims: z
    .array(z.strictObject({ credentialId: z.uuid(), requestJson: z.string().min(1).max(16_384) }))
    .max(10_000),
});
function capturedLegacyClaims(
  manifest: z.infer<typeof entry>[],
  input: { bytes: Buffer; expectedDigest: string },
) {
  digest.parse(input.expectedDigest);
  if (hash(input.bytes) !== input.expectedDigest)
    throw new Error('Original issuer capture digest mismatch');
  const captured = capturedClaimsSchema.parse(JSON.parse(input.bytes.toString('utf8')));
  if (
    captured.legacyManifestDigest !== localWorkloadIssuerManifestDigest(manifest) ||
    new Set(captured.claims.map((v) => v.credentialId)).size !== captured.claims.length
  )
    throw new Error('Original issuer capture manifest mismatch');
  return captured.claims
    .map((claim) => {
      const original = manifest.find((v) => v.credentialId === claim.credentialId);
      if (!original) throw new Error('Unknown original issuer claim');
      const { certificateDer, ...request } = original;
      void certificateDer;
      if (JSON.stringify(requestSchema.parse(request)) !== claim.requestJson)
        throw new Error('Original issuer claim request mismatch');
      return facts(original);
    })
    .sort((a, b) => a.credentialId.localeCompare(b.credentialId));
}

export async function createLocalWorkloadIssuerFixture(input: {
  manifest: unknown;
  token: string;
  profiles?: unknown;
  profileExtension?: { readonly bytes: Buffer; readonly expectedDigest: string };
  journalFile?: string;
  journalHead?: unknown;
  /** Isolated test barrier; the installed entrypoint never supplies callbacks. */
  afterJournalRead?: () => Promise<void>;
  originalClaimsCapture?: { readonly bytes: Buffer; readonly expectedDigest: string };
  unknownRecovery?: { readonly bytes: Buffer; readonly expectedDigest: string };
  localQaEnabled?: boolean;
}) {
  const manifest = manifestSchema.parse(input.manifest);
  if (new Set(manifest.map((v) => v.credentialId)).size !== manifest.length)
    throw new Error('Duplicate legacy issuer credential');
  const profiles = input.profiles === undefined ? undefined : profilesSchema.parse(input.profiles);
  if (input.originalClaimsCapture && input.unknownRecovery)
    throw new Error('Issuer history and quarantine sources are mutually exclusive');
  const unknownRecovery = input.unknownRecovery
    ? readLocalWorkloadIssuerUnknownRecovery(
        input.unknownRecovery.bytes,
        input.unknownRecovery.expectedDigest,
      )
    : undefined;
  if (unknownRecovery && (!profiles || !input.localQaEnabled || !input.journalFile))
    throw new Error(
      'Issuer quarantine requires independently installed local QA profiles and journal',
    );
  if (
    profiles &&
    (!input.localQaEnabled ||
      !input.journalFile ||
      (!input.originalClaimsCapture && !unknownRecovery))
  )
    throw new Error('Issuer profiles require installed local QA journal');
  if (profiles && profiles.legacyManifestDigest !== localWorkloadIssuerManifestDigest(manifest))
    throw new Error('Legacy issuer manifest changed');
  if (
    profiles &&
    new Set(profiles.profiles.map((v) => v.profileId)).size !== profiles.profiles.length
  )
    throw new Error('Duplicate issuer profile');
  if (unknownRecovery) {
    const original = manifest
      .map((certificate) => ({ ...facts(certificate), outcome: 'UNKNOWN' as const }))
      .sort((a, b) => a.credentialId.localeCompare(b.credentialId));
    const quarantined = [...unknownRecovery.quarantined].sort((a, b) =>
      a.credentialId.localeCompare(b.credentialId),
    );
    if (
      unknownRecovery.legacyManifestDigest !== localWorkloadIssuerManifestDigest(manifest) ||
      unknownRecovery.profilesDigest !== hash(JSON.stringify(profiles)) ||
      JSON.stringify(quarantined) !== JSON.stringify(original)
    )
      throw new Error('Issuer quarantine does not preserve every original unknown request');
    const reserved = new Set(manifest.map((certificate) => certificate.credentialId));
    for (const profile of profiles!.profiles) {
      if (reserved.has(profile.profileId))
        throw new Error('Recovered issuer profiles overlap reserved credential identities');
      reserved.add(profile.profileId);
      for (const certificate of profile.certificates) {
        if (reserved.has(certificate.credentialId))
          throw new Error('Recovered issuer profiles overlap reserved credential identities');
        reserved.add(certificate.credentialId);
      }
    }
  }
  let effectiveProfiles = profiles?.profiles ?? [];
  if (input.profileExtension) {
    if (
      !profiles ||
      !input.localQaEnabled ||
      !input.journalFile ||
      (!input.originalClaimsCapture && !unknownRecovery)
    )
      throw new Error('Issuer extension requires independently installed base custody');
    const extension = readLocalWorkloadIssuerProfileExtension(
      input.profileExtension.bytes,
      input.profileExtension.expectedDigest,
    );
    if (extension.baseProfilesDigest !== hash(JSON.stringify(profiles)))
      throw new Error('Issuer extension base profiles changed');
    if (profiles.profiles.length + extension.profiles.length > 32)
      throw new Error('Issuer extension exceeds profile limit');
    const reserved = new Set(manifest.map((certificate) => certificate.credentialId));
    for (const profile of profiles.profiles) {
      reserved.add(profile.profileId);
      for (const certificate of profile.certificates) reserved.add(certificate.credentialId);
    }
    for (const profile of extension.profiles) {
      if (reserved.has(profile.profileId))
        throw new Error('Issuer extension shadows retained identity');
      reserved.add(profile.profileId);
      for (const certificate of profile.certificates) {
        if (reserved.has(certificate.credentialId))
          throw new Error('Issuer extension shadows retained identity');
        reserved.add(certificate.credentialId);
      }
    }
    effectiveProfiles = [...profiles.profiles, ...extension.profiles];
  }
  const selected = new Map<
    string,
    { certificates: z.infer<typeof entry>[]; trustedCaPem: Buffer; contentDigest: string }
  >();
  for (const profile of effectiveProfiles) {
    if (
      new URL(profile.endpoint).pathname !== `/v1/certificates/${profile.profileId}` ||
      new URL(profile.endpoint).search !== '' ||
      new URL(profile.endpoint).hash !== ''
    )
      throw new Error('Issuer profile endpoint mismatch');
    const ca = Buffer.from(profile.trustedCaPem);
    if (
      new Set(profile.certificates.map((v) => v.credentialId)).size !== profile.certificates.length
    )
      throw new Error('Duplicate issuer profile credential');
    for (const certificate of profile.certificates) {
      const der = Buffer.from(certificate.certificateDer, 'base64'),
        spki = Buffer.from(certificate.publicKeySpkiDer, 'base64');
      if (
        der.toString('base64') !== certificate.certificateDer ||
        spki.toString('base64') !== certificate.publicKeySpkiDer
      )
        throw new Error('Noncanonical issuer profile encoding');
      const leaf = new X509Certificate(der),
        issuer = new X509Certificate(ca);
      const firstCurrent = new Date(
        Math.max(Date.parse(leaf.validFrom), Date.parse(issuer.validFrom)) + 1_000,
      );
      if (
        !verifyIssuedWorkloadCertificate(
          der,
          ca,
          { ...certificate, publicKeySpkiDer: spki },
          firstCurrent,
        )
      )
        throw new Error('Invalid issuer profile certificate');
    }
    selected.set(profile.profileId, {
      certificates: profile.certificates,
      trustedCaPem: ca,
      contentDigest: hash(JSON.stringify(profile)),
    });
  }
  const claims = new Map<string, z.infer<typeof observation> & { profileId: string }>();
  let journalPoisoned = false;
  let journalHead = input.journalFile
    ? localWorkloadIssuerJournalHeadSchema.parse(input.journalHead)
    : undefined;
  let tail = Promise.resolve();
  async function verifyJournal(): Promise<Buffer | undefined> {
    if (journalPoisoned) throw new Error('Issuer journal unavailable');
    if (!input.journalFile) return;
    const expected = journalHead!;
    try {
      const namedBefore = await lstat(input.journalFile, { bigint: true });
      if (!matchesHead(namedBefore, expected))
        throw new Error('Issuer journal identity or head changed');
      const file = await open(input.journalFile, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      try {
        const openedBefore = await file.stat({ bigint: true });
        if (!matchesHead(openedBefore, expected) || !sameFileVersion(namedBefore, openedBefore))
          throw new Error('Issuer journal opened identity changed');
        // Bound allocation and reads even if another process grows the file
        // between identity validation and the actual read.
        const buffer = Buffer.alloc(expected.bytes + 1);
        let length = 0;
        while (length < buffer.length) {
          const result = await file.read(buffer, length, buffer.length - length, length);
          if (result.bytesRead === 0) break;
          length += result.bytesRead;
        }
        const bytes = buffer.subarray(0, length);
        await input.afterJournalRead?.();
        const openedAfter = await file.stat({ bigint: true });
        const namedAfter = await lstat(input.journalFile, { bigint: true });
        if (
          bytes.length !== expected.bytes ||
          hash(bytes) !== expected.sha256 ||
          !matchesHead(openedAfter, expected) ||
          !matchesHead(namedAfter, expected) ||
          !sameFileVersion(namedBefore, openedAfter) ||
          !sameFileVersion(namedBefore, namedAfter)
        )
          throw new Error('Issuer journal committed contents changed');
        return bytes;
      } finally {
        await file.close();
      }
    } catch (error) {
      journalPoisoned = true;
      throw error;
    }
  }
  async function available(): Promise<boolean> {
    try {
      await verifyJournal();
      return true;
    } catch {
      return false;
    }
  }
  async function append(record: unknown) {
    if (!input.journalFile) return;
    const priorBytes = (await verifyJournal())!;
    const nextBytes = Buffer.from(JSON.stringify(record) + '\n');
    const nextHead = localWorkloadIssuerJournalHeadSchema.parse({
      ...journalHead!,
      bytes: priorBytes.length + nextBytes.length,
      sha256: hash(Buffer.concat([priorBytes, nextBytes])),
    });
    const file = await open(
      input.journalFile,
      fsConstants.O_APPEND | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
    );
    try {
      if (!matchesHead(await file.stat({ bigint: true }), journalHead!))
        throw new Error('Issuer journal append identity changed');
      await file.writeFile(nextBytes);
      await file.sync();
      journalHead = nextHead;
    } catch (error) {
      journalPoisoned = true;
      throw error;
    } finally {
      await file.close();
    }
    await verifyJournal();
  }
  if (input.journalFile) {
    const bytes = (await verifyJournal())!.toString('utf8');
    if (!bytes.endsWith('\n')) throw new Error('Incomplete issuer journal');
    const lines = bytes.trimEnd().split('\n');
    const headerInput: unknown = JSON.parse(lines.shift()!);
    if (unknownRecovery) {
      const header = recoveryHeaderSchema.parse(headerInput);
      if (
        header.recoveryId !== unknownRecovery.recoveryId ||
        header.unknownRecoveryDigest !== input.unknownRecovery!.expectedDigest ||
        header.legacyManifestDigest !== unknownRecovery.legacyManifestDigest
      )
        throw new Error('Installed issuer quarantine journal mismatch');
    } else {
      const header = headerSchema.parse(headerInput);
      if (
        !input.originalClaimsCapture ||
        header.originalCaptureDigest !== input.originalClaimsCapture.expectedDigest
      )
        throw new Error('Original issuer capture is missing or changed');
      const captured = capturedLegacyClaims(manifest, input.originalClaimsCapture);
      if (
        JSON.stringify(captured) !==
        JSON.stringify(
          [...header.observations].sort((a, b) => a.credentialId.localeCompare(b.credentialId)),
        )
      )
        throw new Error('Incomplete original issuer claim preservation');
      if (header.legacyManifestDigest !== localWorkloadIssuerManifestDigest(manifest))
        throw new Error('Issuer journal legacy manifest mismatch');
      if (
        new Set(header.observations.map((v) => v.credentialId)).size !== header.observations.length
      )
        throw new Error('Duplicate reconciled issuer observation');
      for (const observed of header.observations) {
        const original = manifest.find((v) => v.credentialId === observed.credentialId);
        if (!original || JSON.stringify(facts(original)) !== JSON.stringify(observed))
          throw new Error('Reconciled issuer observation mismatch');
        claims.set(observed.credentialId, { ...observed, profileId: 'LEGACY' });
      }
    }
    const pins = new Map<string, string>();
    for (const line of lines) {
      const record: unknown = JSON.parse(line);
      const pin = profilePin.safeParse(record);
      if (pin.success) {
        const current = selected.get(pin.data.profileId);
        if (
          pins.has(pin.data.profileId) ||
          !current ||
          current.contentDigest !== pin.data.contentDigest
        )
          throw new Error('Historical issuer profile changed');
        pins.set(pin.data.profileId, pin.data.contentDigest);
        continue;
      }
      const claim = claimSchema.parse(record);
      if (unknownRecovery && claim.profileId === 'LEGACY')
        throw new Error('Quarantined legacy issuer history cannot become a claim');
      const candidates =
        claim.profileId === 'LEGACY' ? manifest : selected.get(claim.profileId)?.certificates;
      const certificate = candidates?.find((v) => v.credentialId === claim.credentialId);
      if (claim.profileId !== 'LEGACY' && !pins.has(claim.profileId))
        throw new Error('Unpinned issuer claim');
      const observed = observation.parse({
        credentialId: claim.credentialId,
        requestDigest: claim.requestDigest,
        certificateFingerprint: claim.certificateFingerprint,
      });
      if (
        !certificate ||
        JSON.stringify(facts(certificate)) !== JSON.stringify(observed) ||
        claims.has(claim.credentialId)
      )
        throw new Error('Issuer claim history mismatch');
      claims.set(claim.credentialId, { ...observed, profileId: claim.profileId });
    }
    for (const [profileId, profile] of selected)
      if (!pins.has(profileId))
        await append({ kind: 'PROFILE', profileId, contentDigest: profile.contentDigest });
  }

  function equal(left: string, right: string): boolean {
    const a = Buffer.from(left);
    const b = Buffer.from(right);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  const server = createServer((request, response) => {
    if (request.method === 'GET' && request.url === '/healthz') {
      tail = tail.then(async () => {
        const ok = await available();
        response.writeHead(ok ? 200 : 503, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ status: ok ? 'ok' : 'unavailable' }));
      });
      return;
    }
    if (
      request.method === 'GET' &&
      request.url === '/v1/observations' &&
      equal(request.headers.authorization ?? '', `Bearer ${input.token}`)
    ) {
      tail = tail.then(async () => {
        const ok = await available();
        response.writeHead(ok ? 200 : 503, { 'content-type': 'application/json' });
        if (!ok) {
          response.end(JSON.stringify({ status: 'unavailable', durable: false }));
          return;
        }
        response.end(
          JSON.stringify({
            legacyManifestDigest: localWorkloadIssuerManifestDigest(manifest),
            durable: Boolean(input.journalFile),
            journalHead,
            claims: [...claims.values()].sort((a, b) =>
              a.credentialId.localeCompare(b.credentialId),
            ),
            ...(unknownRecovery
              ? { recoveryId: unknownRecovery.recoveryId, quarantined: unknownRecovery.quarantined }
              : {}),
            profiles: [...selected].map(([profileId, value]) => ({
              profileId,
              contentDigest: value.contentDigest,
            })),
          }),
        );
      });
      return;
    }
    if (
      request.method !== 'POST' ||
      (request.url !== '/v1/certificates' &&
        !(
          request.url?.startsWith('/v1/certificates/') &&
          selected.has(request.url.slice('/v1/certificates/'.length))
        )) ||
      !equal(request.headers.authorization ?? '', `Bearer ${input.token}`)
    ) {
      response.writeHead(403).end();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    request.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 16_384) request.destroy();
      else chunks.push(chunk);
    });
    request.on('end', () => {
      let parsed;
      try {
        parsed = requestSchema.parse(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        response.writeHead(422).end();
        return;
      }
      const profileId =
        request.url === '/v1/certificates'
          ? 'LEGACY'
          : (request.url ?? '').slice('/v1/certificates/'.length);
      if (unknownRecovery && profileId === 'LEGACY') {
        response.writeHead(409, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ outcome: 'UNKNOWN', issuance: 'QUARANTINED' }));
        return;
      }
      const profile = selected.get(profileId);
      const exact = (profile?.certificates ?? manifest).find(
        (candidate) =>
          candidate.credentialId === parsed.credentialId &&
          candidate.participantId === parsed.participantId &&
          candidate.principalId === parsed.principalId &&
          candidate.workloadId === parsed.workloadId &&
          candidate.publicKeySpkiDer === parsed.publicKeySpkiDer,
      );
      if (exact === undefined) {
        response.writeHead(403).end();
        return;
      }
      if (
        profile &&
        !verifyIssuedWorkloadCertificate(
          Buffer.from(exact.certificateDer, 'base64'),
          profile.trustedCaPem,
          { ...parsed, publicKeySpkiDer: Buffer.from(parsed.publicKeySpkiDer, 'base64') },
        )
      ) {
        response.writeHead(403).end();
        return;
      }
      const observed = facts(exact);
      const work = tail.then(async () => {
        if (!(await available())) {
          response.writeHead(503).end();
          return;
        }
        const prior = claims.get(parsed.credentialId);
        if (prior && JSON.stringify(prior) !== JSON.stringify({ ...observed, profileId })) {
          response.writeHead(409).end();
          return;
        }
        if (!prior) {
          try {
            await append({ kind: 'CLAIM', profileId, ...observed });
          } catch {
            journalPoisoned = true;
            response.writeHead(503).end();
            return;
          }
          claims.set(parsed.credentialId, { ...observed, profileId });
        }
        response.writeHead(201, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ certificateDer: exact.certificateDer }));
      });
      tail = work.catch(() => {
        journalPoisoned = true;
        if (!response.headersSent) response.writeHead(503);
        response.end();
      });
    });
  });

  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const environment = z
    .strictObject({
      OPENPC_WORKLOAD_ISSUER_LISTEN: z.string().default('0.0.0.0:3008'),
      OPENPC_WORKLOAD_ISSUER_MANIFEST: z.string().min(1),
      OPENPC_WORKLOAD_ISSUER_TOKEN_FILE: z.string().min(1),
      OPENPC_WORKLOAD_ISSUER_PROFILES_FILE: z.string().min(1).optional(),
      OPENPC_WORKLOAD_ISSUER_PROFILES_SHA256: digest.optional(),
      OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_FILE: z.string().min(1).optional(),
      OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_SHA256: digest.optional(),
      OPENPC_WORKLOAD_ISSUER_JOURNAL_FILE: z.string().min(1).optional(),
      OPENPC_WORKLOAD_ISSUER_JOURNAL_HEAD: z.string().min(1).max(2048).optional(),
      OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_FILE: z.string().min(1).optional(),
      OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_SHA256: digest.optional(),
      OPENPC_WORKLOAD_ISSUER_UNKNOWN_RECOVERY_FILE: z.string().min(1).optional(),
      OPENPC_WORKLOAD_ISSUER_UNKNOWN_RECOVERY_SHA256: digest.optional(),
      OPENPC_LOCAL_RUNTIME: z.literal('1').optional(),
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: z.literal('1').optional(),
    })
    .parse(
      Object.fromEntries(
        [
          'OPENPC_WORKLOAD_ISSUER_LISTEN',
          'OPENPC_WORKLOAD_ISSUER_MANIFEST',
          'OPENPC_WORKLOAD_ISSUER_TOKEN_FILE',
          'OPENPC_WORKLOAD_ISSUER_PROFILES_FILE',
          'OPENPC_WORKLOAD_ISSUER_PROFILES_SHA256',
          'OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_FILE',
          'OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_SHA256',
          'OPENPC_WORKLOAD_ISSUER_JOURNAL_FILE',
          'OPENPC_WORKLOAD_ISSUER_JOURNAL_HEAD',
          'OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_FILE',
          'OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_SHA256',
          'OPENPC_WORKLOAD_ISSUER_UNKNOWN_RECOVERY_FILE',
          'OPENPC_WORKLOAD_ISSUER_UNKNOWN_RECOVERY_SHA256',
          'OPENPC_LOCAL_RUNTIME',
          'OPENPC_LOCAL_RUNTIME_QA_FIXTURE',
        ].map((key) => [key, process.env[key]]),
      ),
    );
  const profileFields = [
    environment.OPENPC_WORKLOAD_ISSUER_PROFILES_FILE,
    environment.OPENPC_WORKLOAD_ISSUER_PROFILES_SHA256,
    environment.OPENPC_WORKLOAD_ISSUER_JOURNAL_FILE,
    environment.OPENPC_WORKLOAD_ISSUER_JOURNAL_HEAD,
  ];
  if (profileFields.some(Boolean) && !profileFields.every(Boolean))
    throw new Error('Incomplete installed issuer profile configuration');
  const extensionFields = [
    environment.OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_FILE,
    environment.OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_SHA256,
  ];
  if (
    (extensionFields.some(Boolean) && !extensionFields.every(Boolean)) ||
    (extensionFields.some(Boolean) && !profileFields.every(Boolean))
  )
    throw new Error('Incomplete installed issuer extension configuration');
  const captureFields = [
    environment.OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_FILE,
    environment.OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_SHA256,
  ];
  const unknownFields = [
    environment.OPENPC_WORKLOAD_ISSUER_UNKNOWN_RECOVERY_FILE,
    environment.OPENPC_WORKLOAD_ISSUER_UNKNOWN_RECOVERY_SHA256,
  ];
  if (
    (captureFields.some(Boolean) && !captureFields.every(Boolean)) ||
    (unknownFields.some(Boolean) && !unknownFields.every(Boolean)) ||
    (captureFields.some(Boolean) && unknownFields.some(Boolean)) ||
    profileFields.some(Boolean) !== (captureFields.every(Boolean) || unknownFields.every(Boolean))
  )
    throw new Error('Incomplete or conflicting installed issuer custody source');
  const server = await createLocalWorkloadIssuerFixture({
    manifest: JSON.parse(await readFile(environment.OPENPC_WORKLOAD_ISSUER_MANIFEST, 'utf8')),
    token: (await readFile(environment.OPENPC_WORKLOAD_ISSUER_TOKEN_FILE, 'utf8')).trim(),
    ...(environment.OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_FILE
      ? {
          profileExtension: {
            bytes: await readFile(environment.OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_FILE),
            expectedDigest: environment.OPENPC_WORKLOAD_ISSUER_PROFILE_EXTENSION_SHA256!,
          },
        }
      : {}),
    ...(environment.OPENPC_WORKLOAD_ISSUER_PROFILES_FILE
      ? {
          profiles: readLocalWorkloadIssuerProfiles(
            await readFile(environment.OPENPC_WORKLOAD_ISSUER_PROFILES_FILE),
            environment.OPENPC_WORKLOAD_ISSUER_PROFILES_SHA256!,
          ),
          journalFile: environment.OPENPC_WORKLOAD_ISSUER_JOURNAL_FILE!,
          journalHead: JSON.parse(environment.OPENPC_WORKLOAD_ISSUER_JOURNAL_HEAD!),
          ...(environment.OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_FILE
            ? {
                originalClaimsCapture: {
                  bytes: await readFile(environment.OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_FILE!),
                  expectedDigest: environment.OPENPC_WORKLOAD_ISSUER_ORIGINAL_CAPTURE_SHA256!,
                },
              }
            : {
                unknownRecovery: {
                  bytes: await readFile(environment.OPENPC_WORKLOAD_ISSUER_UNKNOWN_RECOVERY_FILE!),
                  expectedDigest: environment.OPENPC_WORKLOAD_ISSUER_UNKNOWN_RECOVERY_SHA256!,
                },
              }),
          localQaEnabled:
            environment.OPENPC_LOCAL_RUNTIME === '1' &&
            environment.OPENPC_LOCAL_RUNTIME_QA_FIXTURE === '1',
        }
      : {}),
  });
  const [host, port] = environment.OPENPC_WORKLOAD_ISSUER_LISTEN.split(':');
  await new Promise<void>((resolve) => server.listen(Number(port), host, resolve));
  const close = () => server.close(() => process.exit(0));
  process.on('SIGINT', close);
  process.on('SIGTERM', close);
}
