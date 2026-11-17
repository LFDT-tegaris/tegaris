import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationRoutingProfileClaims,
} from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import { notificationPayloadEncryptionProfileDigest } from '../evidence/notification-payload-crypto.js';
import { type NotificationRoutingInstallation } from './routing-installation-contract.js';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = `sha256:${'a'.repeat(64)}`;
function fixture(
  change: Partial<NotificationRoutingProfileClaims> = {},
  mutate?: (
    value: Pick<NotificationRoutingInstallation, 'template' | 'recipientSet' | 'redaction'>,
  ) => void,
) {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    spki = key.publicKey.export({ type: 'spki', format: 'der' });
  const template: NotificationRoutingInstallation['template'] = {
    schema: 'OPENPC_EVIDENCE_EXPORT_NOTIFICATION_TEMPLATE_V1',
    templateId: id(5),
    revision: '1',
    sourceEvent: 'EvidenceExportCompleted',
    format: 'PLAIN_TEXT',
    subject: [{ kind: 'TEXT', value: 'Evidence export completed' }],
    body: [
      { kind: 'FIELD', field: 'evidenceExportId' },
      { kind: 'FIELD', field: 'checkpoint' },
    ],
  };
  const recipientSet: NotificationRoutingInstallation['recipientSet'] = {
    schema: 'OPENPC_NOTIFICATION_ENDPOINT_RECIPIENT_V1',
    endpointId: id(4),
    channel: 'WEBHOOK',
    destinationRef: `urn:openpc:resource:${id(6)}`,
  };
  const redaction: NotificationRoutingInstallation['redaction'] = {
    schema: 'OPENPC_EVIDENCE_EXPORT_NOTIFICATION_FIELDS_V1',
    allowedFields: ['checkpoint', 'evidenceExportId'],
  };
  mutate?.({ template, recipientSet, redaction });
  const claims: NotificationRoutingProfileClaims = {
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    profileId: id(3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 2000,
    sourceEvent: 'EvidenceExportCompleted',
    endpointId: id(4),
    endpointRevision: '2',
    signedChannelProfileDigest: hash,
    templateDigest: sha256(template),
    recipientSetDigest: sha256(recipientSet),
    redactionProfileDigest: sha256(redaction),
    preferenceGeneration: '1',
    encryptionProfileDigest: notificationPayloadEncryptionProfileDigest,
    payloadKeyPolicyDigest: hash,
    issuerKeyId: evidenceKeyId(spki),
    ...change,
  };
  const signed = signNotificationClaim(
    'NotificationRoutingProfileV1',
    key.privateKey.export({ type: 'pkcs8', format: 'der' }),
    spki,
    claims,
  );
  return {
    template,
    recipientSet,
    redaction,
    producerTrustDigest: hash,
    installationReference: 'initial-local-trust',
    trust: {
      environmentId: 'local',
      participantId: id(1),
      privacyDomainId: id(2),
      signedProfileDigest: sha256(signed.cose),
      issuerSpkiHex: spki.toString('hex'),
    },
    signed: { payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
  };
}
import {
  renderEvidenceExportNotification,
  NotificationTemplateRenderError,
} from './template-renderer.js';

const data = () => ({
  evidenceExportId: `urn:openpc:resource:${id(7)}`,
  checkpoint: '18446744073709551615',
  outputDigest: hash,
  recordCount: '128',
});
const fullTemplate = () =>
  fixture({}, (value) => {
    value.redaction.allowedFields = [
      'checkpoint',
      'evidenceExportId',
      'outputDigest',
      'recordCount',
    ];
    value.template.subject = [
      { kind: 'TEXT', value: 'Export ' },
      { kind: 'FIELD', field: 'evidenceExportId' },
    ];
    value.template.body = [
      { kind: 'FIELD', field: 'checkpoint' },
      { kind: 'TEXT', value: '\n' },
      { kind: 'FIELD', field: 'outputDigest' },
      { kind: 'TEXT', value: '\t' },
      { kind: 'FIELD', field: 'recordCount' },
      { kind: 'TEXT', value: ' — সম্পন্ন ✅' },
    ];
  });

it('renders exact deterministic UTF-8 bytes with a distinct payload digest and no authority claims', () => {
  const installation = fullTemplate(),
    source = data();
  const original = structuredClone({ installation, source });
  const first = renderEvidenceExportNotification(installation, source);
  expect(first.subject).toBe(`Export ${source.evidenceExportId}`);
  expect(first.body).toBe(`${source.checkpoint}\n${source.outputDigest}\t128 — সম্পন্ন ✅`);
  expect(first.bytes).toEqual(
    Buffer.from(JSON.stringify({ body: first.body, subject: first.subject })),
  );
  expect(first.payloadDigest).toBe(sha256(first.bytes));
  expect(first.payloadDigest).not.toBe(sha256(installation.template));
  expect(first.payloadDigest).not.toBe(sha256(installation));
  expect(Object.keys(first).sort()).toEqual(['body', 'bytes', 'payloadDigest', 'subject']);
  expect(
    renderEvidenceExportNotification(installation, {
      recordCount: source.recordCount,
      outputDigest: source.outputDigest,
      checkpoint: source.checkpoint,
      evidenceExportId: source.evidenceExportId,
    }),
  ).toEqual(first);
  expect({ installation, source }).toEqual(original);
  first.bytes.fill(0);
  expect(renderEvidenceExportNotification(installation, source).bytes).not.toEqual(first.bytes);
});

it('copies TEXT literally once, without recursive interpolation or normalization', () => {
  const installation = fixture({}, (value) => {
    value.template.body = [{ kind: 'TEXT', value: '${checkpoint} {{recordCount}} e\u0301' }];
  });
  expect(renderEvidenceExportNotification(installation, data()).body).toBe(
    '${checkpoint} {{recordCount}} e\u0301',
  );
});

it.each([
  { extra: 'private' },
  { rawExportBytes: 'private' },
  { authorization: 'Bearer private' },
  { secret: 'secret://provider/private#1' },
  { checkpoint: 1 },
  { checkpoint: '01' },
  { checkpoint: '-1' },
  { checkpoint: '0' },
  { checkpoint: '18446744073709551616' },
  { checkpoint: '1\n' },
  { recordCount: '0' },
  { recordCount: '129' },
  { recordCount: 1 },
  { recordCount: '1e2' },
  { recordCount: ' 1' },
  { checkpoint: '1', recordCount: '2' },
  { evidenceExportId: id(7) },
  { evidenceExportId: `urn:openpc:participant:${id(7)}` },
  { evidenceExportId: `urn:openpc:resource:${id(7).toUpperCase()}` },
  { evidenceExportId: `urn:openpc:resource:${id(7)}\r\nBcc: private` },
  { evidenceExportId: 'https://private.invalid' },
  { outputDigest: 'sha256:' + 'A'.repeat(64) },
  { outputDigest: hash + '\n' },
])('rejects extra/unsafe fields and malformed registered wire values: %j', (change) => {
  expect(() => renderEvidenceExportNotification(fullTemplate(), { ...data(), ...change })).toThrow(
    NotificationTemplateRenderError,
  );
});

it.each(['evidenceExportId', 'checkpoint', 'outputDigest', 'recordCount'] as const)(
  'requires the complete registered source even when a field is not displayed: %s',
  (field) => {
    const source: Record<string, unknown> = data();
    delete source[field];
    expect(() => renderEvidenceExportNotification(fixture(), source)).toThrow(
      NotificationTemplateRenderError,
    );
  },
);

it.each(['HTML', 'URL', 'EXPRESSION', 'FIELD_PATH', 'RAW', 'EXTRA', 'FORMAT'])(
  'rejects forbidden template members: %s',
  (kind) => {
    const installation = fixture();
    const part =
      kind === 'FIELD_PATH'
        ? { kind: 'FIELD', field: 'checkpoint.toString' }
        : kind === 'RAW'
          ? { kind: 'FIELD', field: 'rawExportBytes' }
          : kind === 'EXTRA'
            ? { kind: 'TEXT', value: 'text', url: 'https://private.invalid' }
            : { kind, value: 'private' };
    const template =
      kind === 'FORMAT'
        ? { ...installation.template, format: 'HTML' }
        : { ...installation.template, body: [part] };
    expect(() => renderEvidenceExportNotification({ ...installation, template }, data())).toThrow(
      NotificationTemplateRenderError,
    );
  },
);

it.each([
  'redaction',
  'duplicate-fields',
  'header-cr',
  'header-lf',
  'header-unicode',
  'unicode',
  'capacity',
])('rejects unsafe rendering even with matching signed installation digests: %s', (kind) => {
  const installation = fixture({}, (value) => {
    if (kind === 'redaction') value.template.body.push({ kind: 'FIELD', field: 'outputDigest' });
    if (kind === 'duplicate-fields') value.redaction.allowedFields.push('checkpoint');
    if (kind.startsWith('header'))
      value.template.subject = [
        {
          kind: 'TEXT',
          value:
            'Subject' +
            (kind === 'header-cr' ? '\r' : kind === 'header-lf' ? '\n' : '\u2028') +
            'Bcc: private',
        },
      ];
    if (kind === 'unicode') value.template.body = [{ kind: 'TEXT', value: '\ud800' }];
    if (kind === 'capacity')
      value.template.body = Array.from({ length: 64 }, () => ({
        kind: 'TEXT' as const,
        value: '界'.repeat(1024),
      }));
  });
  expect(() => renderEvidenceExportNotification(installation, data())).toThrow(
    NotificationTemplateRenderError,
  );
});

it('does not disclose redacted values or append undeclared source fields', () => {
  const result = renderEvidenceExportNotification(fixture(), data());
  expect(result.body).toBe(data().evidenceExportId + data().checkpoint);
  expect(result.bytes.toString()).not.toContain(hash);
  expect(result.bytes.toString()).not.toContain('recordCount');
});

it('rejects mutated signed templates and non-JSON sources without evaluating getters or leaking values', () => {
  const installation = fixture();
  installation.template.body = [{ kind: 'TEXT', value: 'private-body' }];
  expect(() => renderEvidenceExportNotification(installation, data())).toThrow(
    'Notification template rendering unavailable',
  );
  let getterCalls = 0;
  const source = Object.defineProperty(data(), 'checkpoint', {
    enumerable: true,
    get() {
      getterCalls++;
      throw new Error('private-getter');
    },
  });
  expect(() => renderEvidenceExportNotification(fixture(), source)).toThrow(
    'Notification template rendering unavailable',
  );
  expect(getterCalls).toBe(0);
  for (const source of [null, [], { ...data(), secret: 'private-marker' }]) {
    try {
      renderEvidenceExportNotification(fixture(), source);
      throw new Error('Unexpected render');
    } catch (error) {
      expect(error).toBeInstanceOf(NotificationTemplateRenderError);
      expect(String(error)).not.toContain('private-marker');
      expect(Object.keys(error as object)).toEqual([]);
    }
  }
});
