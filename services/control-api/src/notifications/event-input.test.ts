import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import type { OpenPcEventEnvelopeV1 } from '../../../../generated/typescript/json-schema/event-envelope.js';
import type {
  EvidenceExportCompletedDataV1,
  NotificationDeliveryRequestedDataV1,
} from '../../../../generated/typescript/json-schema/event-payloads.js';
import {
  matchNotificationDeliveryRequestedData,
  parseEvidenceExportCompletedEnvelope,
  parseNotificationDeliveryRequestedEnvelope,
  matchNotificationEventEnvelope,
  matchRetainedNotificationEvent,
  NotificationEventInputError,
  parseEvidenceExportCompletedData,
  parseNotificationDeliveryRequestedData,
} from './event-input.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const resource = (n: number) => `urn:openpc:resource:${id(n)}`;
const digest = (n: number) => `sha256:${n.toString(16).padStart(2, '0').repeat(32)}`;
const requested: NotificationDeliveryRequestedDataV1 = {
  notificationOccurrenceId: resource(3),
  endpointId: resource(4),
  templateDigest: digest(5),
  payloadDigest: digest(6),
};
const exported: EvidenceExportCompletedDataV1 = {
  evidenceExportId: resource(7),
  checkpoint: '9007199254740993',
  outputDigest: digest(8),
  recordCount: '0',
};
const bindings = {
  trustedContext: { participantId: id(1), privacyDomainId: id(2) },
  occurrence: {
    participantId: id(1),
    privacyDomainId: id(2),
    notificationOccurrenceId: id(3),
    payloadDigest: digest(6),
  },
  endpoint: {
    participantId: id(1),
    privacyDomainId: id(2),
    endpointId: id(4),
    revision: '1',
    channel: 'WEBHOOK' as const,
    destinationRef: resource(9),
    channelProfileDigest: digest(10),
    credentialRef: resource(11),
  },
  templateDigest: digest(5),
  // A synthetic retained producer reference, not a declared occurrence namespace or authority.
  notificationOccurrenceRef: resource(3),
};
function reason(operation: () => unknown, expected: NotificationEventInputError['reason']) {
  expect(operation).toThrowError(new NotificationEventInputError(expected));
}

describe('registered notification event data inputs', () => {
  it('preserves the exact registered delivery fields and wire references', () => {
    const parsed: NotificationDeliveryRequestedDataV1 =
      parseNotificationDeliveryRequestedData(requested);
    expect(parsed).toEqual(requested);
    expect(Object.keys(parsed).sort()).toEqual([
      'endpointId',
      'notificationOccurrenceId',
      'payloadDigest',
      'templateDigest',
    ]);
    expect(parsed).not.toHaveProperty('occurrenceId');
    expect(matchNotificationDeliveryRequestedData(requested, bindings)).toEqual(requested);
  });

  it('returns export metadata without selecting any recipient, endpoint or transport state', () => {
    const parsed: EvidenceExportCompletedDataV1 = parseEvidenceExportCompletedData(exported);
    expect(parsed).toEqual(exported);
    expect(Object.keys(parsed).sort()).toEqual([
      'checkpoint',
      'evidenceExportId',
      'outputDigest',
      'recordCount',
    ]);
    expect(
      parseEvidenceExportCompletedData({
        ...exported,
        checkpoint: '0',
        recordCount: '18446744073709551615',
      }),
    ).toMatchObject({ checkpoint: '0', recordCount: '18446744073709551615' });
  });

  it('requires every registered field and rejects the legacy occurrenceId spelling', () => {
    for (const key of Object.keys(requested)) {
      const missing = { ...requested } as Record<string, unknown>;
      delete missing[key];
      reason(() => parseNotificationDeliveryRequestedData(missing), 'INVALID_DATA');
    }
    for (const key of Object.keys(exported)) {
      const missing = { ...exported } as Record<string, unknown>;
      delete missing[key];
      reason(() => parseEvidenceExportCompletedData(missing), 'INVALID_DATA');
    }
    const { notificationOccurrenceId, ...rest } = requested;
    reason(
      () =>
        parseNotificationDeliveryRequestedData({ ...rest, occurrenceId: notificationOccurrenceId }),
      'INVALID_DATA',
    );
    reason(
      () =>
        parseNotificationDeliveryRequestedData({
          ...requested,
          occurrenceId: notificationOccurrenceId,
        }),
      'INVALID_DATA',
    );
  });

  it.each(['recipient', 'credentials', 'payload', 'ready', 'acknowledged', 'data'])(
    'rejects the extra field %s',
    (field) => {
      reason(
        () => parseNotificationDeliveryRequestedData({ ...requested, [field]: 'not admitted' }),
        'INVALID_DATA',
      );
      reason(
        () => parseEvidenceExportCompletedData({ ...exported, [field]: 'not admitted' }),
        'INVALID_DATA',
      );
    },
  );

  it.each([null, undefined, false, [], 'json text', 1])('rejects non-object input %j', (value) => {
    reason(() => parseNotificationDeliveryRequestedData(value), 'INVALID_DATA');
    reason(() => parseEvidenceExportCompletedData(value), 'INVALID_DATA');
  });

  it.each([
    id(4),
    `URN:openpc:resource:${id(4)}`,
    `${resource(4)} `,
    `${resource(4)}\n`,
    resource(4).replace('-7000-', '-4000-'),
    `urn:openpc:resource:${id(4)}:extra`,
    'https://unapproved.example',
  ])('rejects malformed/noncanonical wire references %s', (value) => {
    reason(
      () => parseNotificationDeliveryRequestedData({ ...requested, endpointId: value }),
      'INVALID_DATA',
    );
    reason(
      () =>
        parseNotificationDeliveryRequestedData({ ...requested, notificationOccurrenceId: value }),
      'INVALID_DATA',
    );
    reason(
      () => parseEvidenceExportCompletedData({ ...exported, evidenceExportId: value }),
      'INVALID_DATA',
    );
  });

  it.each([
    `sha256:${'AA'.repeat(32)}`,
    'sha256:aa',
    digest(5).slice(7),
    `${digest(5)} `,
    `${digest(5)}\n`,
    null,
  ])('rejects malformed digests %j', (value) => {
    for (const field of ['templateDigest', 'payloadDigest'])
      reason(
        () => parseNotificationDeliveryRequestedData({ ...requested, [field]: value }),
        'INVALID_DATA',
      );
    reason(
      () => parseEvidenceExportCompletedData({ ...exported, outputDigest: value }),
      'INVALID_DATA',
    );
  });

  it.each(['00', '01', '-1', '+1', '1.0', '1e3', ' 1', '1\n', '18446744073709551616', 1])(
    'rejects noncanonical or out-of-range counters %j',
    (value) => {
      for (const field of ['checkpoint', 'recordCount'])
        reason(
          () => parseEvidenceExportCompletedData({ ...exported, [field]: value }),
          'INVALID_DATA',
        );
    },
  );

  it('does not equate the same UUID under a different endpoint or occurrence namespace', () => {
    const endpointAlias = { ...requested, endpointId: `urn:openpc:participant:${id(4)}` };
    const occurrenceAlias = {
      ...requested,
      notificationOccurrenceId: `urn:openpc:participant:${id(3)}`,
    };
    // Generic OpenPcUrn permits these strings syntactically; owner binding must not.
    expect(parseNotificationDeliveryRequestedData(endpointAlias)).toEqual(endpointAlias);
    expect(parseNotificationDeliveryRequestedData(occurrenceAlias)).toEqual(occurrenceAlias);
    reason(
      () => matchNotificationDeliveryRequestedData(endpointAlias, bindings),
      'BINDING_MISMATCH',
    );
    reason(
      () => matchNotificationDeliveryRequestedData(occurrenceAlias, bindings),
      'BINDING_MISMATCH',
    );
    reason(
      () =>
        matchNotificationDeliveryRequestedData(requested, {
          ...bindings,
          notificationOccurrenceRef: `urn:openpc:participant:${id(3)}`,
        }),
      'BINDING_MISMATCH',
    );
  });

  it.each(['participantId', 'privacyDomainId'] as const)(
    'compares trusted %s independently for both retained owners',
    (field) => {
      reason(
        () =>
          matchNotificationDeliveryRequestedData(requested, {
            ...bindings,
            trustedContext: { ...bindings.trustedContext, [field]: id(20) },
          }),
        'SCOPE_MISMATCH',
      );
      reason(
        () =>
          matchNotificationDeliveryRequestedData(requested, {
            ...bindings,
            occurrence: { ...bindings.occurrence, [field]: id(20) },
          }),
        'SCOPE_MISMATCH',
      );
      reason(
        () =>
          matchNotificationDeliveryRequestedData(requested, {
            ...bindings,
            endpoint: { ...bindings.endpoint, [field]: id(20) },
          }),
        'SCOPE_MISMATCH',
      );
    },
  );

  it('rejects mismatched occurrence, endpoint, template and payload identities', () => {
    for (const change of [
      { notificationOccurrenceId: resource(20) },
      { endpointId: resource(20) },
      { templateDigest: digest(20) },
      { payloadDigest: digest(20) },
    ]) {
      reason(
        () => matchNotificationDeliveryRequestedData({ ...requested, ...change }, bindings),
        'BINDING_MISMATCH',
      );
    }
    reason(
      () =>
        matchNotificationDeliveryRequestedData(requested, {
          ...bindings,
          occurrence: { ...bindings.occurrence, notificationOccurrenceId: id(20) },
        }),
      'BINDING_MISMATCH',
    );
    reason(
      () =>
        matchNotificationDeliveryRequestedData(requested, {
          ...bindings,
          occurrence: { ...bindings.occurrence, payloadDigest: digest(20) },
        }),
      'BINDING_MISMATCH',
    );
    reason(
      () =>
        matchNotificationDeliveryRequestedData(requested, {
          ...bindings,
          endpoint: { ...bindings.endpoint, endpointId: id(20) },
        }),
      'BINDING_MISMATCH',
    );
    reason(
      () =>
        matchNotificationDeliveryRequestedData(requested, {
          ...bindings,
          templateDigest: digest(20),
        }),
      'BINDING_MISMATCH',
    );
  });

  it('requires an owner-retained occurrence reference instead of guessing it from the event or UUID', () => {
    reason(
      () =>
        matchNotificationDeliveryRequestedData(requested, {
          ...bindings,
          notificationOccurrenceRef: undefined,
        }),
      'MISSING_OCCURRENCE_REFERENCE',
    );
    reason(
      () =>
        matchNotificationDeliveryRequestedData(requested, {
          ...bindings,
          notificationOccurrenceRef: id(3),
        }),
      'INVALID_BINDING',
    );
  });

  it('rejects invalid retained bindings without exposing their content in errors', () => {
    for (const changed of [
      { ...bindings, trustedContext: { ...bindings.trustedContext, participantId: 'invalid' } },
      {
        ...bindings,
        occurrence: { ...bindings.occurrence, notificationOccurrenceId: resource(3) },
      },
      { ...bindings, endpoint: { ...bindings.endpoint, endpointId: resource(4) } },
      { ...bindings, trustedContext: { ...bindings.trustedContext, participantId: `${id(1)}\n` } },
      {
        ...bindings,
        occurrence: { ...bindings.occurrence, notificationOccurrenceId: `${id(3)}\n` },
      },
      { ...bindings, endpoint: { ...bindings.endpoint, endpointId: `${id(4)}\n` } },
      { ...bindings, notificationOccurrenceRef: `${resource(3)}\n` },
      { ...bindings, templateDigest: 'private supplied value' },
    ])
      reason(() => matchNotificationDeliveryRequestedData(requested, changed), 'INVALID_BINDING');
  });

  it('does not mutate supplied payloads or bindings and does not add authority claims', () => {
    const original = JSON.stringify(bindings);
    const wire = Object.freeze({ ...requested });
    const parsed = matchNotificationDeliveryRequestedData(wire, bindings);
    expect(JSON.stringify(bindings)).toBe(original);
    expect(parsed).toEqual(wire);
    expect(parsed).not.toBe(wire);
    expect(parsed).not.toHaveProperty('authorized');
    expect(parsed).not.toHaveProperty('verified');
  });
});

const envelopeSchema = JSON.parse(
  readFileSync(
    new URL('../../../../schemas/json/event-envelope.schema.json', import.meta.url),
    'utf8',
  ),
) as {
  properties: Record<string, unknown>;
  required: string[];
};
function event(kind: 'export' | 'request'): OpenPcEventEnvelopeV1 {
  return {
    specversion: '1.0',
    id: id(31),
    source: `urn:openpc:service:${id(32)}`,
    type:
      kind === 'export'
        ? 'io.openpc.evidence.export.completed.v1'
        : 'io.openpc.notification.delivery.requested.v1',
    subject: resource(33),
    time: '2026-09-24T22:35:00.000001Z',
    datacontenttype: 'application/json',
    dataschema: `https://schemas.openpc.local/event-payloads.schema.json#/$defs/${kind === 'export' ? 'EvidenceExportCompleted' : 'NotificationDeliveryRequested'}`,
    participantid: `urn:openpc:participant:${id(1)}`,
    privacydomainid: `urn:openpc:privacy-domain:${id(2)}`,
    correlationid: id(34),
    causationid: id(35),
    authoritygeneration: digest(36),
    sequence: '9007199254740993',
    datadigest: digest(37),
    data: kind === 'export' ? { ...exported } : { ...requested },
  };
}
function position(kind: 'export' | 'request') {
  const value = event(kind);
  return {
    ...bindings.trustedContext,
    source: value.source,
    partition: kind === 'export' ? exported.evidenceExportId : requested.notificationOccurrenceId,
    sequence: value.sequence,
    dataDigest: value.datadigest,
  };
}
const parsers = {
  export: parseEvidenceExportCompletedEnvelope,
  request: parseNotificationDeliveryRequestedEnvelope,
};
// These are decoded structural examples, not signed producer events or admitted
// work. Their declared digest is a sentinel; this boundary must not invent the
// missing producer hash/signing contract or claim current delivery authority.
describe.each(['export', 'request'] as const)('registered %s source envelope', (kind) => {
  const parse = parsers[kind];
  it('preserves every canonical envelope member and implements the generated public type', () => {
    const value = event(kind);
    const parsed: OpenPcEventEnvelopeV1 = parse(value);
    expect(parsed).toEqual(value);
    expect(Object.keys(parsed).sort()).toEqual(Object.keys(envelopeSchema.properties).sort());
    expect(matchNotificationEventEnvelope(value, position(kind))).toEqual(parsed);
    expect(parsed).not.toHaveProperty('partition');
    expect(parsed).not.toHaveProperty('authenticated');
  });
  it('requires exactly the mandatory members listed by the canonical schema', () => {
    for (const key of envelopeSchema.required) {
      const value = { ...event(kind) } as Record<string, unknown>;
      delete value[key];
      reason(() => parse(value), 'INVALID_ENVELOPE');
    }
    const optional = { ...event(kind) };
    delete optional.privacydomainid;
    delete optional.causationid;
    delete optional.authoritygeneration;
    expect(parse(optional)).toEqual(optional);
    reason(() => matchNotificationEventEnvelope(optional, position(kind)), 'SCOPE_MISMATCH');
  });
  it.each([
    'partition',
    'producer',
    'signature',
    'authorized',
    'recipient',
    'payload',
    'sequenceNumber',
  ])('rejects unregistered envelope member %s', (key) => {
    reason(() => parse({ ...event(kind), [key]: 'private-canary' }), 'INVALID_ENVELOPE');
  });
  it.each(['privacydomainid', 'causationid', 'authoritygeneration'])(
    'rejects null/undefined optional member %s instead of erasing it',
    (key) => {
      for (const value of [null, undefined, '', 'private-canary'])
        reason(() => parse({ ...event(kind), [key]: value }), 'INVALID_ENVELOPE');
    },
  );
  it.each([null, undefined, [], true, 0, 'serialized body'])(
    'rejects non-object envelope %j',
    (value) => {
      reason(() => parse(value), 'INVALID_ENVELOPE');
    },
  );
  it('rejects changed event type/schema/content type and cross-family data', () => {
    const wrong = event(kind === 'export' ? 'request' : 'export');
    for (const key of ['type', 'dataschema', 'data'] as const)
      reason(() => parse({ ...event(kind), [key]: wrong[key] }), 'INVALID_ENVELOPE');
    for (const change of [
      { specversion: '1.1' },
      { datacontenttype: 'application/cloudevents+json' },
      { type: event(kind).type + '\n' },
      { dataschema: event(kind).dataschema + '#extra' },
      { data: { ...event(kind).data, protectedPayload: 'private-canary' } },
      { data: null },
      { data: [] },
    ])
      reason(() => parse({ ...event(kind), ...change }), 'INVALID_ENVELOPE');
  });
  it('checks all UUID, URN and digest fields without trimming or namespace substitution', () => {
    for (const key of ['id', 'correlationid', 'causationid'] as const)
      for (const value of [
        id(31).replace('-7000-', '-4000-'),
        id(31) + '\n',
        resource(31),
        'private-canary',
      ])
        reason(() => parse({ ...event(kind), [key]: value }), 'INVALID_ENVELOPE');
    for (const key of ['source', 'subject', 'participantid', 'privacydomainid'] as const)
      for (const value of [
        id(1),
        resource(1) + '\n',
        'urn:openpc:service:LS-NOTIFICATION',
        'https://private-canary',
      ])
        reason(() => parse({ ...event(kind), [key]: value }), 'INVALID_ENVELOPE');
    for (const key of ['datadigest', 'authoritygeneration'] as const)
      for (const value of [digest(1) + '\n', 'sha256:' + 'AA'.repeat(32), digest(1).slice(7)])
        reason(() => parse({ ...event(kind), [key]: value }), 'INVALID_ENVELOPE');
  });
  it.each([
    '2026-09-24T22:35:00Z',
    '2026-09-24T22:35:00.000Z',
    '2026-09-24T22:35:00.0000000Z',
    '2026-09-24T22:35:00.000001+00:00',
    '2026-02-30T22:35:00.000001Z',
    '2026-09-24T22:35:00.000001Z\n',
  ])('rejects noncanonical timestamp %s', (time) => {
    reason(() => parse({ ...event(kind), time }), 'INVALID_ENVELOPE');
  });
  it('retains the full public u64 sequence range without rounding or inventing a first position', () => {
    for (const sequence of ['0', '1', '9007199254740993', '18446744073709551615']) {
      const value = { ...event(kind), sequence };
      expect(parse(value).sequence).toBe(sequence);
      expect(matchNotificationEventEnvelope(value, { ...position(kind), sequence }).sequence).toBe(
        sequence,
      );
    }
    for (const sequence of [0, 1, '01', '-1', '+1', '1.0', '1e3', '1\n', '18446744073709551616'])
      reason(() => parse({ ...event(kind), sequence }), 'INVALID_ENVELOPE');
  });
  it('separates generic public URN syntax from the selected participant/privacy binding', () => {
    for (const change of [
      { participantid: `urn:openpc:participant:${id(20)}` },
      { privacydomainid: `urn:openpc:privacy-domain:${id(20)}` },
      { participantid: resource(1) },
      { privacydomainid: resource(2) },
    ]) {
      const value = { ...event(kind), ...change };
      expect(parse(value)).toEqual(value);
      reason(() => matchNotificationEventEnvelope(value, position(kind)), 'SCOPE_MISMATCH');
    }
  });
  it('binds the exact retained source, DATA ordering partition, sequence and digest', () => {
    const value = event(kind),
      expected = position(kind);
    for (const change of [
      { source: `urn:openpc:resource:${id(32)}` },
      { source: `urn:openpc:service:${id(20)}` },
      { partition: resource(20) },
      { partition: value.subject },
      { sequence: '9007199254740992' },
      { sequence: '9007199254740994' },
      { dataDigest: digest(20) },
    ])
      reason(
        () => matchNotificationEventEnvelope(value, { ...expected, ...change }),
        'BINDING_MISMATCH',
      );
    if (kind === 'request')
      reason(
        () =>
          matchNotificationEventEnvelope(value, { ...expected, partition: requested.endpointId }),
        'BINDING_MISMATCH',
      );
    // Declared data digest equality is not a calculation/authentication claim.
    expect(parse({ ...value, datadigest: digest(99) }).datadigest).toBe(digest(99));
    reason(
      () => matchNotificationEventEnvelope({ ...value, datadigest: digest(99) }, expected),
      'BINDING_MISMATCH',
    );
  });
  it('requires complete canonical binding inputs and rejects claimed authority fields', () => {
    const expected = position(kind);
    for (const key of Object.keys(expected)) {
      const missing = { ...expected } as Record<string, unknown>;
      delete missing[key];
      reason(
        () => matchNotificationEventEnvelope(event(kind), missing as never),
        'INVALID_BINDING',
      );
    }
    for (const change of [
      { participantId: `urn:openpc:participant:${id(1)}` },
      { privacyDomainId: id(2) + '\n' },
      { source: id(32) },
      { partition: id(3) },
      { sequence: 1 },
      { dataDigest: 'private-canary' },
      { authorized: true },
      { producer: 'LS-NOTIFICATION' },
    ])
      reason(
        () => matchNotificationEventEnvelope(event(kind), { ...expected, ...change } as never),
        'INVALID_BINDING',
      );
  });
  it('does not infer an occurrence/export namespace or change its complete ordering reference', () => {
    const original = event(kind),
      field = kind === 'export' ? 'evidenceExportId' : 'notificationOccurrenceId';
    const retainedRef = `urn:openpc:custom-ordering:${kind === 'export' ? id(7) : id(3)}`;
    const value = { ...original, data: { ...original.data, [field]: retainedRef } };
    expect(parse(value).data[field]).toBe(retainedRef);
    reason(() => matchNotificationEventEnvelope(value, position(kind)), 'BINDING_MISMATCH');
    expect(
      matchNotificationEventEnvelope(value, { ...position(kind), partition: retainedRef }),
    ).toEqual(value);
  });
  it('rejects same-ID changed envelope/data even when the declared digest is copied or changed', () => {
    const retained = event(kind);
    const data =
      kind === 'export'
        ? { ...exported, outputDigest: digest(99) }
        : { ...requested, payloadDigest: digest(99) };
    const changed = [
      { source: resource(32) },
      { subject: resource(99) },
      { time: '2026-09-24T22:35:00.000002Z' },
      { participantid: `urn:openpc:participant:${id(99)}` },
      { privacydomainid: `urn:openpc:privacy-domain:${id(99)}` },
      { correlationid: id(99) },
      { causationid: id(99) },
      { authoritygeneration: digest(99) },
      { sequence: '9007199254740994' },
      { datadigest: digest(99) },
      { data },
      { data, datadigest: digest(99) },
    ];
    for (const change of changed)
      reason(
        () => matchRetainedNotificationEvent({ ...retained, ...change }, retained),
        'REPLAY_MISMATCH',
      );
    for (const field of ['privacydomainid', 'causationid', 'authoritygeneration'] as const) {
      const missing = { ...retained };
      delete missing[field];
      reason(() => matchRetainedNotificationEvent(missing, retained), 'REPLAY_MISMATCH');
      reason(() => matchRetainedNotificationEvent(retained, missing), 'REPLAY_MISMATCH');
    }
    reason(
      () =>
        matchRetainedNotificationEvent(event(kind === 'export' ? 'request' : 'export'), retained),
      'REPLAY_MISMATCH',
    );
    reason(
      () => matchRetainedNotificationEvent({ ...retained, id: id(99) }, retained),
      'BINDING_MISMATCH',
    );
  });
  it('validates both sides before replay comparison and exposes no supplied content', () => {
    const retained = event(kind);
    for (const invalid of [
      null,
      { ...retained, data: { private: 'secret-canary' } },
      { ...retained, secret: 'secret-canary' },
    ]) {
      for (const operation of [
        () => matchRetainedNotificationEvent(invalid, retained),
        () => matchRetainedNotificationEvent(retained, invalid),
      ]) {
        reason(operation, 'INVALID_ENVELOPE');
        try {
          operation();
        } catch (error) {
          expect(error).toBeInstanceOf(NotificationEventInputError);
          expect(String(error)).not.toContain('secret-canary');
          expect(Object.keys(error as object)).toEqual(['reason']);
        }
      }
    }
  });
  it('accepts semantic key-order replay without mutating frozen values or inventing a byte receipt', () => {
    const retained = Object.freeze({ ...event(kind), data: Object.freeze(event(kind).data) });
    const reordered = Object.fromEntries(Object.entries(retained).reverse());
    reordered.data = Object.fromEntries(Object.entries(retained.data).reverse());
    const before = JSON.stringify(retained);
    const parsed = matchRetainedNotificationEvent(reordered, retained);
    expect(parsed).toEqual(retained);
    expect(parsed).not.toBe(retained);
    expect(JSON.stringify(retained)).toBe(before);
    expect(parsed).not.toHaveProperty('receipt');
    expect(parsed).not.toHaveProperty('authorized');
  });
});
it('connects a request envelope to the existing exact endpoint/occurrence binding without renaming IDs', () => {
  const original = event('request');
  const scoped = matchNotificationEventEnvelope(original, position('request'));
  expect(matchNotificationDeliveryRequestedData(scoped.data, bindings)).toEqual(requested);
  const alias = {
    ...original,
    data: { ...requested, notificationOccurrenceId: `urn:openpc:custom-ordering:${id(3)}` },
  };
  const aliasScope = matchNotificationEventEnvelope(alias, {
    ...position('request'),
    partition: String(alias.data.notificationOccurrenceId),
  });
  reason(
    () => matchNotificationDeliveryRequestedData(aliasScope.data, bindings),
    'BINDING_MISMATCH',
  );
  expect(
    matchNotificationDeliveryRequestedData(aliasScope.data, {
      ...bindings,
      notificationOccurrenceRef: alias.data.notificationOccurrenceId,
    }),
  ).toEqual(alias.data);
  reason(
    () =>
      matchNotificationDeliveryRequestedData(scoped.data, {
        ...bindings,
        notificationOccurrenceRef: undefined,
      }),
    'MISSING_OCCURRENCE_REFERENCE',
  );
});
