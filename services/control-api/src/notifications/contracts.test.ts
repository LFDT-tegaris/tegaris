import { notificationResponseSchema } from '../configuration/resource-contracts.js';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  acknowledgeNotificationSchema,
  createNotificationEndpointSchema,
  createNotificationSchema,
  updateNotificationEndpointSchema,
  updateNotificationSchema,
  verifyNotificationEndpointSchema,
} from './contracts.js';

const definitions = JSON.parse(
  readFileSync(
    new URL('../../../../schemas/json/control-api.schema.json', import.meta.url),
    'utf8',
  ),
).$defs;
const urn = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000001';
const digest = `sha256:${'ab'.repeat(32)}`;
const action = {
  actionIntentId: 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1',
  actionIntentDigest: digest,
  reason: 'Reviewable local notification.',
};
describe('registered notification mutation inputs', () => {
  it('installs the action semantics required by the metadata HTTP journey', () => {
    const installer = readFileSync(
      new URL('../../../../deploy/compose/local/migrate.sh', import.meta.url),
      'utf8',
    );
    // Catalogue presence is not a grant. Check the exact disclosure and
    // authority requirements before the journey allocates PostgreSQL.
    for (const row of [
      "('ACT-NOTIFICATIONS_CREATE_RESOURCE-V1','notifications','CREATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_NOTIFICATIONS')",
      "('ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1','notification','UPDATE','LOW',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_NOTIFICATION')",
      "('ACT-NOTIFICATIONS_READ_RESOURCE-V1','notifications','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_NOTIFICATIONS')",
      "('ACT-NOTIFICATIONS_READ_COLLECTION-V1','notifications','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_NOTIFICATIONS')",
    ])
      expect(installer).toContain(row);
  });
  it('keeps exactly the registered request fields', () => {
    for (const [schema, name] of [
      [createNotificationSchema, 'CreateNotificationRequest'],
      [createNotificationEndpointSchema, 'CreateNotificationEndpointRequest'],
      [updateNotificationSchema, 'UpdateNotificationRequest'],
      [updateNotificationEndpointSchema, 'UpdateNotificationEndpointRequest'],
      [acknowledgeNotificationSchema, 'CommandRequest'],
      [verifyNotificationEndpointSchema, 'CommandRequest'],
    ] as const) {
      expect(Object.keys(schema.shape).sort()).toEqual(definitions[name].required.toSorted());
      expect(Object.keys(schema.shape).sort()).toEqual(
        Object.keys(definitions[name].properties).sort(),
      );
    }
  });
  it('admits metadata and exact destination references without caller readiness or arbitrary egress', () => {
    const endpoint = {
      ...action,
      participantId: urn,
      channel: 'WEBHOOK',
      destinationRef: urn,
      arbitraryEgress: false,
    };
    const notification = {
      ...action,
      participantId: urn,
      severity: 'WARNING',
      resourceRef: null,
      messageKey: 'evidence.export.completed',
    };
    expect(createNotificationEndpointSchema.parse(endpoint)).toEqual(endpoint);
    expect(createNotificationSchema.parse(notification)).toEqual(notification);
    for (const extra of [
      { state: 'ACTIVE' },
      { ready: true },
      { verificationId: urn },
      { url: 'https://example.invalid' },
      { credential: 'private' },
    ])
      expect(createNotificationEndpointSchema.safeParse({ ...endpoint, ...extra }).success).toBe(
        false,
      );
    expect(
      createNotificationEndpointSchema.safeParse({ ...endpoint, arbitraryEgress: true }).success,
    ).toBe(false);
    for (const extra of [
      { state: 'ACKNOWLEDGED' },
      { payload: 'private body' },
      { recipient: urn },
      { acknowledged: true },
    ])
      expect(createNotificationSchema.safeParse({ ...notification, ...extra }).success).toBe(false);
  });
  it('rejects malformed counters and target references before owner lookup', () => {
    const command = { ...action, targetRef: urn, expectedRevision: '1', inputDigest: digest };
    expect(acknowledgeNotificationSchema.parse(command)).toEqual(command);
    for (const revision of ['01', '-1', '1\n', '18446744073709551616', 1])
      expect(
        acknowledgeNotificationSchema.safeParse({ ...command, expectedRevision: revision }).success,
      ).toBe(false);
    for (const targetRef of [urn.slice(-36), `${urn}\n`, null])
      expect(verifyNotificationEndpointSchema.safeParse({ ...command, targetRef }).success).toBe(
        false,
      );
  });
});

it('returns only registered public notification metadata and never delivery, signer or private payload material', () => {
  expect(Object.keys(notificationResponseSchema.shape).sort()).toEqual(
    definitions.Notification.required.toSorted(),
  );
  const record = {
    notificationId: urn,
    participantId: urn.replace(':resource:', ':participant:'),
    severity: 'WARNING',
    state: 'UNREAD',
    resourceRef: null,
    messageKey: 'evidence.export.completed',
    revision: '1',
    createdAt: '2026-09-24T00:00:00.000000Z',
    updatedAt: '2026-09-24T00:00:00.000000Z',
  };
  expect(notificationResponseSchema.parse(record)).toEqual(record);
  for (const extra of [
    { candidateDigest: digest },
    { privacyDomainId: urn },
    { payload: 'private' },
    { credentialRef: urn },
    { receipt: 'private' },
    { deliveryState: 'DELIVERED' },
  ])
    expect(notificationResponseSchema.safeParse({ ...record, ...extra }).success).toBe(false);
});
