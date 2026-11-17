import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationRoutingProfileClaims,
} from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import { notificationPayloadEncryptionProfileDigest } from '../evidence/notification-payload-crypto.js';
import {
  validateNotificationRoutingInstallation,
  type NotificationRoutingInstallation,
} from './routing-installation-contract.js';
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
it('retains authenticated exact template/recipient/redaction bytes without producing payload or key authority', () => {
  const value = fixture(),
    actual = validateNotificationRoutingInstallation(value);
  expect(actual.input).toEqual(value);
  expect(actual.installationDigest).toBe(sha256(actual.bytes));
  value.template.body[0] = { kind: 'TEXT', value: 'changed' };
  expect(actual.input.template.body[0]).toEqual({ kind: 'FIELD', field: 'evidenceExportId' });
  expect(Object.keys(actual).sort()).toEqual(['bytes', 'input', 'installationDigest', 'route']);
});
it.each(['templateDigest', 'recipientSetDigest', 'redactionProfileDigest'] as const)(
  'rejects a signed mismatched %s',
  (field) =>
    expect(() =>
      validateNotificationRoutingInstallation(fixture({ [field]: `sha256:${'b'.repeat(64)}` })),
    ).toThrow(),
);
it('rejects an independently valid other endpoint or source family', () => {
  for (const value of [
    fixture({ endpointId: id(9) }),
    fixture({ sourceEvent: 'NotificationDeliveryRequested' }),
  ])
    expect(() => validateNotificationRoutingInstallation(value)).toThrow();
});
it.each([
  'body',
  'recipient',
  'redaction',
  'extra',
  'subject-newline',
  'expression',
  'raw-field',
  'duplicate-field',
  'template-revision',
  'producer-trust',
  'issuer',
])('rejects malformed, over-disclosing or unauthenticated installation: %s', (kind) => {
  const value = fixture();
  let changed: unknown = value;
  if (kind === 'body') value.template.body.push({ kind: 'TEXT', value: 'changed' });
  if (kind === 'recipient') value.recipientSet.destinationRef = `urn:openpc:resource:${id(9)}`;
  if (kind === 'redaction') value.redaction.allowedFields.push('recordCount');
  if (kind === 'extra') changed = { ...value, ready: true };
  if (kind === 'subject-newline')
    value.template.subject = [{ kind: 'TEXT', value: 'Subject\r\nBcc: injected' }];
  if (kind === 'expression')
    changed = {
      ...value,
      template: { ...value.template, body: [{ kind: 'EXEC', expression: 'process.env' }] },
    };
  if (kind === 'raw-field')
    changed = {
      ...value,
      template: { ...value.template, body: [{ kind: 'FIELD', field: 'rawExportBytes' }] },
    };
  if (kind === 'duplicate-field') value.redaction.allowedFields.push('checkpoint');
  if (kind === 'template-revision') value.template.revision = '0';
  if (kind === 'producer-trust') value.producerTrustDigest = 'latest';
  if (kind === 'issuer') value.trust.issuerSpkiHex = '00'.repeat(91);
  expect(() => validateNotificationRoutingInstallation(changed)).toThrow(
    'Notification routing installation unavailable',
  );
});

it.each(['redacted-field', 'duplicate-fields', 'header-break', 'capacity'])(
  'rejects unsafe template semantics even with an authentic matching signed digest: %s',
  (kind) => {
    const input = fixture({}, (value) => {
      if (kind === 'redacted-field')
        value.template.body.push({ kind: 'FIELD', field: 'outputDigest' });
      if (kind === 'duplicate-fields') value.redaction.allowedFields.push('checkpoint');
      if (kind === 'header-break')
        value.template.subject = [{ kind: 'TEXT', value: 'Subject\r\nBcc: injected' }];
      if (kind === 'capacity')
        value.template.body = Array.from({ length: 64 }, () => ({
          kind: 'TEXT' as const,
          value: 'x'.repeat(1024),
        }));
    });
    expect(() => validateNotificationRoutingInstallation(input)).toThrow();
  },
);
