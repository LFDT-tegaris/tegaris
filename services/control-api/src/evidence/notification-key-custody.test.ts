import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  validateNotificationKeyPreparation,
  decodeNotificationKeyPreparation,
  notificationKeyPrepareInput,
  parseNotificationKey,
  notificationKeySelector,
  assertNotificationKeySelector,
  notificationOccurrenceUrn,
  notificationKeyFile,
  inspectNotificationKeyCiphertext,
} from './notification-key-contracts.js';
import { sealNotificationPayload, openNotificationPayload } from './notification-payload-crypto.js';
import { openVaultDirectory, putVaultFile, readVaultFile } from './immutable-vault.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const d = (n: string) => `sha256:${n.repeat(64)}`;
const spki = () =>
  generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .publicKey.export({ type: 'spki', format: 'der' })
    .toString('hex');
function sample() {
  const kms = {
    owner: 'LS-EVIDENCE-EXPORT',
    secretClass: 'SECRET-EVIDENCE-VAULT',
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    installationId: id(3),
    producerTrustDigest: d('1'),
    reference: 'secret://test-kms/evidence/kek#v1',
    version: 'v1',
    keyEpoch: '1',
    providerId: 'test-kms',
    providerOrigin: 'https://localhost:4433',
    providerTlsSpkiDigest: d('2'),
    profileIssuerSpkiHex: spki(),
    providerReceiptSpkiHex: spki(),
    recoveryAuthoritySpkiHex: spki(),
    providerKeyId: 'evidence-kek',
    providerKeyVersion: 'v1',
    wrapProfileDigest: d('3'),
    policyDigest: d('4'),
    recoveryProfileDigest: d('5'),
    profileDigest: d('6'),
    permissions: ['DECRYPT', 'ENCRYPT'],
    validFromMs: Date.now() - 1000,
    validUntilMs: Date.now() + 60000,
  };
  const plaintext = Buffer.from(
    canonicalJson({ body: 'Export urn:openpc:resource:' + id(4), subject: 'Export complete' }),
  );
  const p = validateNotificationKeyPreparation({
    purpose: 'NOTIFICATION_PAYLOAD',
    preparationId: id(5),
    occurrenceId: id(6),
    input: {
      scope: { participantId: id(1), privacyDomainId: id(2), streamId: 'original' },
      evidenceExportId: id(4),
      producerTrustDigest: d('1'),
      kmsInstallationDigest: sha256(kms),
      routing: { profileId: id(7), revision: '1', signedProfileDigest: d('7') },
    },
    sourceEventId: id(8),
    sourceDataDigest: d('8'),
    sourceReceiptDigest: d('9'),
    routingInstallationDigest: d('a'),
    kms,
    objectIntent: {
      environmentId: 'local',
      participantId: id(1),
      privacyDomainId: id(2),
      payloadObjectId: id(9),
      objectVersion: '1',
      notificationOccurrenceRef: notificationOccurrenceUrn(id(6)),
      routingProfileDigest: d('7'),
      templateDigest: d('b'),
      recipientSetDigest: d('c'),
      redactionProfileDigest: d('d'),
      preferenceGeneration: '1',
      payloadDigest: sha256(plaintext),
    },
  });
  const selector = {
    participantId: id(1),
    privacyDomainId: id(2),
    producerTrustDigest: d('1'),
    kmsInstallationDigest: sha256(kms),
    preparationId: id(5),
  };
  return { p, selector, plaintext };
}
it('accepts only source/installed-owner selectors; caller payload, occurrence and readiness claims are closed', () => {
  const { p } = sample();
  for (const extra of [
    { ready: true },
    { admitted: true },
    { payloadDigest: d('f') },
    { occurrenceId: id(99) },
    { purpose: 'EVIDENCE_KEY' },
    { plaintext: 'private' },
  ])
    expect(() =>
      parseNotificationKey(notificationKeyPrepareInput, { ...p.input, ...extra }),
    ).toThrow();
});
it('retains exact canonical original bytes and rejects re-encoding or same identity with different content', () => {
  const { p } = sample(),
    bytes = Buffer.from(canonicalJson(p)),
    digest = sha256(bytes);
  expect(decodeNotificationKeyPreparation(bytes, digest)).toEqual(p);
  expect(() =>
    decodeNotificationKeyPreparation(Buffer.from(JSON.stringify(p, null, 2)), digest),
  ).toThrow();
  const changed = Buffer.from(canonicalJson({ ...p, sourceDataDigest: d('f') }));
  expect(() => decodeNotificationKeyPreparation(changed, digest)).toThrow();
  const duplicate = Buffer.from(
    canonicalJson(p).replace('"purpose":', '"purpose":"NOTIFICATION_PAYLOAD","purpose":'),
  );
  expect(() => decodeNotificationKeyPreparation(duplicate, sha256(duplicate))).toThrow();
});
it('binds purpose, scope, original occurrence, policy and exact KEK identity independently of valid JSON', () => {
  const { p } = sample();
  for (const changed of [
    { ...p, purpose: 'AUDIT_EVIDENCE' },
    { ...p, occurrenceId: id(99) },
    { ...p, objectIntent: { ...p.objectIntent, objectVersion: '2' } },
    { ...p, objectIntent: { ...p.objectIntent, privacyDomainId: id(99) } },
    {
      ...p,
      objectIntent: {
        ...p.objectIntent,
        notificationOccurrenceRef: `urn:openpc:resource:${p.occurrenceId}`,
      },
    },
    { ...p, kms: { ...p.kms, policyDigest: d('f') } },
    { ...p, kms: { ...p.kms, providerKeyVersion: 'v2' } },
    { ...p, kms: { ...p.kms, keyEpoch: '2' } },
    { ...p, kms: { ...p.kms, reference: 'secret://test-kms/evidence/kek#v2', version: 'v2' } },
    { ...p, kms: { ...p.kms, secretClass: 'SECRET-NOTIFICATION-CREDENTIAL' } },
  ])
    expect(() => validateNotificationKeyPreparation(changed)).toThrow();
});
it('does not accept a copied preparation under a foreign selector or alias', () => {
  const { p, selector } = sample();
  expect(() => assertNotificationKeySelector(p, selector)).not.toThrow();
  for (const patch of [
    { preparationId: id(90) },
    { privacyDomainId: id(91) },
    { producerTrustDigest: d('f') },
    { kmsInstallationDigest: d('e') },
  ])
    expect(() => assertNotificationKeySelector(p, { ...selector, ...patch })).toThrow();
  expect(() =>
    parseNotificationKey(notificationKeySelector, { ...selector, keyId: 'latest' }),
  ).toThrow();
});
it('an authenticated object cannot be moved to another occurrence, template, recipient, version or key', () => {
  const { p, plaintext } = sample(),
    key = randomBytes(32),
    keyId = d('e');
  try {
    const sealed = sealNotificationPayload({ ...p.objectIntent, keyId }, plaintext, {
      keyId,
      bytes: key,
    });
    expect(inspectNotificationKeyCiphertext(p, keyId, sealed.bytes).encryptedObjectDigest).toBe(
      sealed.encryptedObjectDigest,
    );
    for (const patch of [
      { notificationOccurrenceRef: notificationOccurrenceUrn(id(90)) },
      { templateDigest: d('f') },
      { recipientSetDigest: d('f') },
      { preferenceGeneration: '2' },
      { payloadObjectId: id(91) },
    ]) {
      expect(() =>
        inspectNotificationKeyCiphertext(
          { ...p, objectIntent: { ...p.objectIntent, ...patch } },
          keyId,
          sealed.bytes,
        ),
      ).toThrow();
      expect(() =>
        openNotificationPayload(
          sealed.bytes,
          sealed.encryptedObjectDigest,
          { ...p.objectIntent, ...patch, keyId },
          { keyId, bytes: key },
        ),
      ).toThrow();
    }
    expect(() => inspectNotificationKeyCiphertext(p, d('f'), sealed.bytes)).toThrow();
    const corrupted = Buffer.from(sealed.bytes);
    corrupted[corrupted.length - 3] = corrupted[corrupted.length - 3]! ^ 1;
    expect(() =>
      openNotificationPayload(
        corrupted,
        sealed.encryptedObjectDigest,
        { ...p.objectIntent, keyId },
        { keyId, bytes: key },
      ),
    ).toThrow();
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
});
it('immutable vault preserves the exact original across concurrent puts and post-persist failure', async () => {
  const root = process.env.OPENPC_PNC_TMP_ROOT;
  if (!root) throw new Error('OPENPC_PNC_TMP_ROOT is required');
  const directory = await openVaultDirectory(await mkdtemp(join(root, 'notification-custody-')));
  const { p, plaintext } = sample(),
    key = randomBytes(32),
    keyId = d('e');
  try {
    const original = sealNotificationPayload({ ...p.objectIntent, keyId }, plaintext, {
      keyId,
      bytes: key,
    });
    const name = notificationKeyFile(p);
    // Filesystem mechanics only: no mock Identity/database/KMS admission is used.
    await Promise.all([
      putVaultFile(directory, name, original.bytes),
      putVaultFile(directory, name, original.bytes),
    ]);
    await expect(
      (async () => {
        await putVaultFile(directory, name, original.bytes);
        throw new Error('lost persistence acknowledgement');
      })(),
    ).rejects.toThrow();
    const other = sealNotificationPayload({ ...p.objectIntent, keyId }, plaintext, {
      keyId,
      bytes: key,
    });
    await putVaultFile(directory, name, other.bytes);
    const retained = await readVaultFile(directory, name, 131072);
    expect(retained).toEqual(original.bytes);
    expect(retained).not.toEqual(other.bytes);
    const opened = openNotificationPayload(
      retained,
      original.encryptedObjectDigest,
      original.binding,
      { keyId, bytes: key },
    );
    expect(opened).toEqual(plaintext);
    opened.fill(0);
  } finally {
    key.fill(0);
    plaintext.fill(0);
    await rm(directory, { recursive: true });
  }
});
