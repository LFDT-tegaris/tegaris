import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import type { PoolClient } from 'pg';
import {
  encodeNotificationDeliveryRequestedData,
  evidenceKeyId,
  signNotificationClaim,
  type NotificationWorkerProfileClaims,
  type NotificationOccurrenceReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
} from '@openpc/security-kernel';
import {
  signEvidenceKmsClaim,
  type EvidenceWrappedKeyClaims,
} from '../../../../packages/security-kernel/src/evidence-kms/codec.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  validateNotificationKeyPreparation,
  notificationOccurrenceUrn,
  NotificationKeyCustodyError,
} from './notification-key-contracts.js';
import { sealNotificationPayload } from './notification-payload-crypto.js';
import { validateNotificationWorkerInstallation } from '../notifications/worker-installation-contract.js';
import {
  verifyNotificationPayloadRetirementCustody,
  verifyNotificationPayloadRetirementProofs,
  verifyNotificationPayloadRetirementCiphertext,
  readNotificationPayloadRetirementPublication,
} from './notification-payload-retirement-source.js';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const d = (n: string) => `sha256:${n.repeat(64)}`;
const spki = () =>
  generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .publicKey.export({ type: 'spki', format: 'der' })
    .toString('hex');
function fixture() {
  const provider = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const providerSpki = provider.publicKey.export({ type: 'spki', format: 'der' });
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
    providerReceiptSpkiHex: providerSpki.toString('hex'),
    recoveryAuthoritySpkiHex: spki(),
    providerKeyId: 'evidence-kek',
    providerKeyVersion: 'v1',
    wrapProfileDigest: d('3'),
    policyDigest: d('4'),
    recoveryProfileDigest: d('5'),
    profileDigest: d('6'),
    permissions: ['DECRYPT', 'ENCRYPT'],
    validFromMs: 1000,
    validUntilMs: 100000,
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
  const request = Buffer.from(
    canonicalJson({
      operation: 'PREPARE',
      attemptId: p.preparationId,
      recipient: {
        participantId: selector.participantId,
        privacyDomainId: selector.privacyDomainId,
        producerTrustDigest: selector.producerTrustDigest,
        installationDigest: selector.kmsInstallationDigest,
      },
      objectIntent: p.objectIntent,
      challenge: 'a'.repeat(64),
    }),
  );
  const recordClaims: EvidenceWrappedKeyClaims = {
    environmentId: kms.environmentId,
    participantId: kms.participantId,
    privacyDomainId: kms.privacyDomainId,
    providerId: kms.providerId,
    reference: kms.reference,
    version: kms.version,
    providerKeyId: kms.providerKeyId,
    providerKeyVersion: kms.providerKeyVersion,
    keyEpoch: kms.keyEpoch,
    wrapProfileDigest: kms.wrapProfileDigest,
    policyDigest: kms.policyDigest,
    recoveryProfileDigest: kms.recoveryProfileDigest,
    attemptId: p.preparationId,
    originalRequestDigest: sha256(request),
    objectIntentDigest: sha256(p.objectIntent),
    profileDigest: kms.profileDigest,
    wrappedKey: 'a1'.repeat(60),
    createdAtMs: 2000,
    signerKeyId: evidenceKeyId(providerSpki),
  };
  const record = signEvidenceKmsClaim(
    'EvidenceWrappedKeyRecordV1',
    provider.privateKey.export({ type: 'pkcs8', format: 'der' }),
    providerSpki,
    recordClaims,
  );
  const keyId = sha256(record.payload),
    dek = randomBytes(32);
  const ciphertext = sealNotificationPayload({ ...p.objectIntent, keyId }, plaintext, {
    keyId,
    bytes: dek,
  });
  dek.fill(0);
  plaintext.fill(0);
  const preparationBytes = Buffer.from(canonicalJson(p));
  const row = {
    preparationId: p.preparationId,
    occurrenceId: p.occurrenceId,
    payloadObjectId: p.objectIntent.payloadObjectId,
    sourceEventId: p.sourceEventId,
    routingProfileId: p.input.routing.profileId,
    kmsInstallationDigest: p.input.kmsInstallationDigest,
    preparationHex: preparationBytes.toString('hex'),
    preparationDigest: sha256(preparationBytes),
    keyId,
    encryptionExchangeId: id(10),
    encryptedObjectDigest: ciphertext.encryptedObjectDigest,
    encryptionContextDigest: ciphertext.encryptionContextDigest,
    requestHex: request.toString('hex'),
    requestDigest: sha256(request),
    objectIntentDigest: sha256(p.objectIntent),
    installationDigest: p.input.kmsInstallationDigest,
    state: 'PROVED',
    recordHex: record.payload.toString('hex'),
    recordCoseHex: record.cose.toString('hex'),
    encryptionProved: true,
  };
  const custody = verifyNotificationPayloadRetirementCustody(row, selector);
  return { p, selector, row, custody, ciphertext };
}

function publication(f = fixture()) {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const issuerSpki = issuer.publicKey.export({ type: 'spki', format: 'der' });
  const signerSpki = signer.publicKey.export({ type: 'spki', format: 'der' });
  const signerKey = signer.privateKey.export({ type: 'pkcs8', format: 'der' });
  const { p, custody } = f;
  const profile: NotificationWorkerProfileClaims = {
    environmentId: p.objectIntent.environmentId,
    participantId: p.input.scope.participantId,
    privacyDomainId: p.input.scope.privacyDomainId,
    profileId: id(20),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 100000,
    sourceId: id(21),
    serviceId: 'LS-NOTIFICATION',
    processRole: 'ROLE-NOTIFICATION-WORKER',
    subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
    principalId: id(22),
    workloadCredentialId: id(23),
    workloadEpoch: '1',
    workloadId: 'notification-worker',
    producerTrustDigest: p.input.producerTrustDigest,
    routingProfileDigest: p.input.routing.signedProfileDigest,
    kmsInstallationDigest: p.input.kmsInstallationDigest,
    receiptSignerSpki: signerSpki.toString('hex'),
    issuerKeyId: evidenceKeyId(issuerSpki),
  };
  function installed(profile: NotificationWorkerProfileClaims) {
    const signed = signNotificationClaim(
      'NotificationWorkerProfileV1',
      issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
      issuerSpki,
      profile,
    );
    return validateNotificationWorkerInstallation(
      {
        pins: {
          issuerSpkiHex: issuerSpki.toString('hex'),
          signedProfileDigest: sha256(signed.cose),
          environmentId: profile.environmentId,
          participantId: profile.participantId,
          privacyDomainId: profile.privacyDomainId,
          profileId: profile.profileId,
          revision: profile.revision,
          serviceId: profile.serviceId,
          processRole: profile.processRole,
          subscriptionId: profile.subscriptionId,
          principalId: profile.principalId,
          workloadCredentialId: profile.workloadCredentialId,
          workloadEpoch: profile.workloadEpoch,
          workloadId: profile.workloadId,
          workloadKeyDigest: d('e'),
        },
        signed: {
          payloadHex: signed.payload.toString('hex'),
          coseHex: signed.cose.toString('hex'),
        },
        installationReference: 'retained-local-test',
      },
      3000,
    );
  }
  const occurrenceWorker = installed(profile);
  const claims: NotificationOccurrenceReceiptClaims = {
    environmentId: profile.environmentId,
    participantId: profile.participantId,
    privacyDomainId: profile.privacyDomainId,
    receiptId: id(24),
    operationId: id(25),
    notificationId: id(26),
    notificationOccurrenceId: p.occurrenceId,
    payloadObjectId: p.objectIntent.payloadObjectId,
    keyPreparationId: p.preparationId,
    sourceEventId: p.sourceEventId,
    sourceDataDigest: p.sourceDataDigest,
    sourceReceiptDigest: p.sourceReceiptDigest,
    routingProfileDigest: p.input.routing.signedProfileDigest,
    workerProfileDigest: occurrenceWorker.input.pins.signedProfileDigest,
    authoritySnapshotDigest: d('e'),
    custodyDigest: sha256({
      preparationDigest: custody.preparationDigest,
      keyId: custody.keyId,
      encryptionExchangeId: custody.encryptionExchangeId,
      encryptedObjectDigest: custody.encryptedObjectDigest,
      encryptionContextDigest: custody.encryptionContextDigest,
    }),
    endpointId: id(27),
    endpointRevision: '1',
    templateDigest: p.objectIntent.templateDigest,
    payloadDigest: p.objectIntent.payloadDigest,
    encryptedObjectDigest: custody.encryptedObjectDigest,
    keyId: custody.keyId,
    recordedAtMs: 3000,
    signerKeyId: evidenceKeyId(signerSpki),
  };
  const first = signNotificationClaim(
    'NotificationOccurrenceReceiptV1',
    signerKey,
    signerSpki,
    claims,
  );
  const deliveryWorker = installed({
    ...profile,
    profileId: id(30),
    principalId: id(31),
    workloadCredentialId: id(32),
    serviceId: 'LS-CONTROL-WORK',
    processRole: 'ROLE-CONTROL-WORKER',
    subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1',
  });
  const request: NotificationDeliveryRequestedReceiptClaims = {
    ...claims,
    operationId: id(33),
    receiptId: id(34),
    eventId: id(35),
    sourceId: profile.sourceId,
    workerProfileDigest: deliveryWorker.input.pins.signedProfileDigest,
    occurrenceReceiptDigest: sha256(first.payload),
    sequence: '1',
    dataDigest: sha256(
      encodeNotificationDeliveryRequestedData({
        notificationOccurrenceId: claims.notificationOccurrenceId,
        endpointId: claims.endpointId,
        templateDigest: claims.templateDigest,
        payloadDigest: claims.payloadDigest,
      }),
    ),
  };
  const second = signNotificationClaim(
    'NotificationDeliveryRequestedReceiptV1',
    signerKey,
    signerSpki,
    request,
  );
  const rows = (
    [
      ['NotificationOccurrenceReceiptV1', occurrenceWorker, claims, first, id(36)],
      ['NotificationDeliveryRequestedReceiptV1', deliveryWorker, request, second, id(37)],
    ] as const
  ).map(([family, worker, c, signed, preparationId]) => {
    const preparation = {
      schema: 'pc.notification.occurrence-preparation.v1',
      preparationId,
      family,
      input: {
        worker: {
          participantId: profile.participantId,
          privacyDomainId: profile.privacyDomainId,
          installationDigest: worker.installationDigest,
        },
        source: {
          scope: p.input.scope,
          evidenceExportId: p.input.evidenceExportId,
          eventId: p.sourceEventId,
        },
        keyPreparationId: p.preparationId,
      },
      workerProfile: worker.profile,
      workerProfileDigest: worker.input.pins.signedProfileDigest,
      workerAuthorityDigest: c.authoritySnapshotDigest,
      payloadHex: signed.payload.toString('hex'),
    };
    return {
      preparationId,
      family,
      preparationHex: Buffer.from(canonicalJson(preparation)).toString('hex'),
      preparationDigest: sha256(preparation),
      installationHex: worker.bytes.toString('hex'),
      installationDigest: worker.installationDigest,
      state: 'OBSERVED',
      operationId: c.operationId as string | null,
      receiptId: c.receiptId as string | null,
      receiptHex: signed.payload.toString('hex') as string | null,
      receiptDigest: sha256(signed.payload) as string | null,
      coseHex: signed.cose.toString('hex') as string | null,
    };
  });
  return { ...f, rows, claims, request };
}

it('verifies original wrapped-key signature and exact ciphertext/AAD without material or authority', () => {
  const f = fixture();
  expect(f.custody.preparation).toEqual(f.p);
  expect(() =>
    verifyNotificationPayloadRetirementCiphertext(f.custody, f.ciphertext.bytes),
  ).not.toThrow();
  expect(Object.isFrozen(f.custody)).toBe(true);
  expect(Object.isFrozen(f.custody.preparation.objectIntent)).toBe(true);
  f.row.keyId = sha256('changed');
  expect(f.custody.keyId).not.toBe(f.row.keyId);
  expect('retirementAllowed' in f.custody).toBe(false);
});
it.each([
  'keyId',
  'preparationId',
  'occurrenceId',
  'payloadObjectId',
  'sourceEventId',
  'routingProfileId',
  'kmsInstallationDigest',
  'installationDigest',
  'requestDigest',
  'objectIntentDigest',
  'preparationDigest',
] as const)('rejects changed custody %s', (field) => {
  const f = fixture();
  const replacement = field.endsWith('Digest') || field === 'keyId' ? d('f') : id(99);
  expect(() =>
    verifyNotificationPayloadRetirementCustody({ ...f.row, [field]: replacement }, f.selector),
  ).toThrow(NotificationKeyCustodyError);
});
it('rejects changed original wire, missing encryption proof and foreign selectors', () => {
  const f = fixture();
  for (const patch of [
    { requestHex: '00' },
    { recordHex: '00' },
    { recordCoseHex: '00' },
    {
      recordCoseHex:
        f.row.recordCoseHex.slice(0, -2) + (f.row.recordCoseHex.endsWith('00') ? '01' : '00'),
    },
    { state: 'UNKNOWN' },
    { encryptionProved: false },
    { extra: true },
  ]) {
    expect(() =>
      verifyNotificationPayloadRetirementCustody({ ...f.row, ...patch }, f.selector),
    ).toThrow(NotificationKeyCustodyError);
  }
  for (const patch of [
    { participantId: id(99) },
    { privacyDomainId: id(99) },
    { preparationId: id(99) },
    { producerTrustDigest: d('f') },
    { kmsInstallationDigest: d('f') },
    { ready: true },
  ]) {
    expect(() =>
      verifyNotificationPayloadRetirementCustody(f.row, { ...f.selector, ...patch }),
    ).toThrow(NotificationKeyCustodyError);
  }
});
it('rejects changed ciphertext, key, digest, AAD and object identity', () => {
  const f = fixture();
  const altered = Buffer.from(f.ciphertext.bytes);
  altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
  expect(() => verifyNotificationPayloadRetirementCiphertext(f.custody, altered)).toThrow(
    NotificationKeyCustodyError,
  );
  for (const patch of [
    { keyId: d('f') },
    { encryptedObjectDigest: d('f') },
    { encryptionContextDigest: d('f') },
    { preparation: { ...f.p, objectIntent: { ...f.p.objectIntent, payloadObjectId: id(99) } } },
  ]) {
    expect(() =>
      verifyNotificationPayloadRetirementCiphertext({ ...f.custody, ...patch }, f.ciphertext.bytes),
    ).toThrow(NotificationKeyCustodyError);
  }
});
it('binds both original signed families without equating proof with publication', () => {
  const f = publication();
  const event = verifyNotificationPayloadRetirementProofs(f.rows, f.custody)!;
  expect(event.claims).toEqual(f.request);
  expect(event.receiptPayload.toString('hex')).toBe(f.rows[1]!.receiptHex);
  expect('state' in event).toBe(false);
  expect(verifyNotificationPayloadRetirementProofs([], f.custody)).toBeUndefined();
  expect(verifyNotificationPayloadRetirementProofs([f.rows[0]], f.custody)).toBeUndefined();
});
it.each([0, 1])(
  'keeps historical publication protected with %i exact current cursors',
  async (count) => {
    const f = publication();
    const kinds = [
      'OCCURRENCE',
      'OBJECT',
      'REFERENCE',
      'METADATA',
      'EVENT',
      'INBOX',
      'INBOX',
      ...Array<string>(count).fill('CURSOR'),
    ];
    const results = [
      { rows: [{ installed: true }], rowCount: 1 },
      { rows: f.rows, rowCount: 2 },
      { rows: kinds.map((kind) => ({ kind })), rowCount: kinds.length },
    ];
    let calls = 0;
    const client = {
      async query(sql: string) {
        expect(sql.trim()).toMatch(/^select /u);
        expect(sql).not.toContain('check_notification_delivery_requested_event');
        expect(calls).toBeLessThan(results.length);
        return results[calls++];
      },
    } as unknown as PoolClient;
    expect(await readNotificationPayloadRetirementPublication(client, f.custody)).toEqual({
      state: 'UNKNOWN',
      blockers: ['OCCURRENCE_REFERENCE', 'PUBLICATION_CURSOR_HISTORY_UNRESOLVED'],
    });
    expect(calls).toBe(3);
  },
);
it.each(['PREPARED', 'DISPATCHED', 'UNKNOWN'])(
  'retains incomplete %s signing without proving closure',
  (state) => {
    const f = publication();
    const pending = {
      ...f.rows[1],
      state,
      operationId: null,
      receiptId: null,
      receiptHex: null,
      receiptDigest: null,
      coseHex: null,
    };
    expect(
      verifyNotificationPayloadRetirementProofs([f.rows[0], pending], f.custody),
    ).toBeUndefined();
    expect(() =>
      verifyNotificationPayloadRetirementProofs(
        [f.rows[0], { ...pending, receiptHex: f.rows[1]!.receiptHex }],
        f.custody,
      ),
    ).toThrow(NotificationKeyCustodyError);
  },
);
it.each([
  'preparationId',
  'operationId',
  'receiptId',
  'receiptDigest',
  'installationDigest',
  'family',
  'state',
  'receiptHex',
  'coseHex',
])('rejects changed publication %s', (field) => {
  const f = publication();
  expect(() =>
    verifyNotificationPayloadRetirementProofs(
      [{ ...f.rows[0], [field]: 'changed' }, f.rows[1]],
      f.custody,
    ),
  ).toThrow(NotificationKeyCustodyError);
});
it('rejects changed worker identity even with a recomputed installation digest', () => {
  const f = publication();
  const installation = JSON.parse(Buffer.from(f.rows[0]!.installationHex, 'hex').toString());
  installation.pins.principalId = id(99);
  expect(() =>
    verifyNotificationPayloadRetirementProofs(
      [
        {
          ...f.rows[0],
          installationHex: Buffer.from(canonicalJson(installation)).toString('hex'),
          installationDigest: sha256(installation),
        },
        f.rows[1],
      ],
      f.custody,
    ),
  ).toThrow(NotificationKeyCustodyError);
  for (const patch of [
    { keyId: d('f') },
    { encryptedObjectDigest: d('f') },
    { preparationDigest: d('f') },
    { preparation: { ...f.p, occurrenceId: id(99) } },
  ]) {
    expect(() =>
      verifyNotificationPayloadRetirementProofs(f.rows, { ...f.custody, ...patch }),
    ).toThrow(NotificationKeyCustodyError);
  }
});
it('rejects duplicate families, mismatched pairs, incomplete observations and prototype inputs', () => {
  const f = publication(),
    foreign = publication();
  for (const rows of [
    [f.rows[0], f.rows[0]],
    [f.rows[0], foreign.rows[1]],
    [f.rows[0], { ...f.rows[1], coseHex: null }],
    [{ ...f.rows[0], extra: true }],
    [Object.assign(Object.create({ injected: true }), f.rows[0])],
  ]) {
    expect(() => verifyNotificationPayloadRetirementProofs(rows, f.custody)).toThrow(
      NotificationKeyCustodyError,
    );
  }
  let calls = 0;
  const row = Object.defineProperty({ ...f.row }, 'keyId', {
    enumerable: true,
    get() {
      calls++;
      return f.row.keyId;
    },
  });
  expect(() => verifyNotificationPayloadRetirementCustody(row, f.selector)).toThrow(
    NotificationKeyCustodyError,
  );
  expect(calls).toBe(0);
});
