import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import {
  handoverAdmissionRegistration,
  handoverPreservedAllocations,
  handoverPreservedRegistryEntries,
} from './handover-admission-profile.mjs';
import { handoverAdmissionAuthorizationContext } from '../src/workload-signing-handover/generated.ts';

const definition = () =>
  JSON.parse(
    readFileSync(
      new URL(
        '../../../schemas/canonical/workload-signing-handover-admission-authorization-v1.json',
        import.meta.url,
      ),
      'utf8',
    ),
  );

it('registers the exact adopted tuple and frozen generated definition', () => {
  const { entry, context } = handoverAdmissionRegistration(definition(), []);
  expect(context).toEqual(handoverAdmissionAuthorizationContext);
  expect(entry.schemaId).toBe(24042);
  expect(entry.purposeCode).toBe(379);
  expect(handoverAdmissionRegistration(definition(), [entry]).entry).toEqual(entry);
  const changed = definition();
  changed.invariants.push('changed semantics');
  expect(() => handoverAdmissionRegistration(changed, [entry])).toThrow('frozen definition');
});

it.each([
  'schemaId',
  'purpose',
  'purposeCode',
  'typeName',
  'ownerLane',
  'schemaVersion',
  'schemaDigest',
  'signatureContextRule',
  'signed',
  'projectionRefs',
])('rejects changed registry %s and duplicates', (field) => {
  const { entry } = handoverAdmissionRegistration(definition(), []);
  expect(() =>
    handoverAdmissionRegistration(definition(), [
      {
        ...entry,
        [field]:
          field === 'schemaId'
            ? 24999
            : field === 'purposeCode'
              ? 999
              : field === 'signed'
                ? false
                : field === 'projectionRefs'
                  ? []
                  : 'changed',
      },
    ]),
  ).toThrow();
  expect(() => handoverAdmissionRegistration(definition(), [entry, entry])).toThrow();
});

it.each(handoverPreservedAllocations)(
  'preserves absent producer ownership for $schemaId/$purposeCode',
  (reserved) => {
    const admitted = handoverPreservedRegistryEntries.find(
      (entry) => entry.schemaId === reserved.schemaId,
    );
    if (admitted)
      expect(() => handoverAdmissionRegistration(definition(), [admitted])).not.toThrow();
    expect(() => handoverAdmissionRegistration(definition(), [reserved])).toThrow(
      'ownership drift',
    );
    for (const field of ['schemaId', 'purposeCode', 'purpose', 'typeName']) {
      const changed = {
        ...reserved,
        [field]: field === 'schemaId' ? 24999 : field === 'purposeCode' ? 999 : 'changed',
      };
      expect(() => handoverAdmissionRegistration(definition(), [changed])).toThrow(
        'ownership drift',
      );
    }
    const swapped = { ...definition(), schemaId: reserved.schemaId };
    expect(() => handoverAdmissionRegistration(swapped, [])).toThrow('reserved');
  },
);

it.each([
  'name',
  'typeName',
  'schemaId',
  'schemaVersion',
  'semanticVersion',
  'ownerLane',
  'extensionAuthority',
])('rejects unadopted definition %s', (field) => {
  expect(() =>
    handoverAdmissionRegistration(
      {
        ...definition(),
        [field]: field === 'schemaId' ? 24999 : field === 'schemaVersion' ? 2 : 'changed',
      },
      [],
    ),
  ).toThrow();
});

it('rejects canonical-name, purpose, numeric and projection collisions', () => {
  const current = definition();
  for (const other of [
    current,
    { ...current, name: 'different' },
    { ...current, schemaId: 24999 },
    { ...current, purpose: { name: 'other', code: 999 } },
  ])
    expect(() => handoverAdmissionRegistration(current, [], [other])).toThrow('collision');
  const { entry } = handoverAdmissionRegistration(current, []);
  expect(() =>
    handoverAdmissionRegistration(current, [
      { ...entry, schemaId: 24999, purposeCode: 999, purpose: 'other', typeName: 'Other' },
    ]),
  ).toThrow('collision');
  for (const change of [
    { algorithm: 'ES256' },
    { algorithmCode: -7 },
    { signatureProfileVersion: 1 },
    { externalAadHex: '' },
    { contentType: 'text/plain' },
  ])
    expect(() =>
      handoverAdmissionRegistration({ ...current, cose: { ...current.cose, ...change } }, []),
    ).toThrow();
});

it('rejects every reserved registry metadata change and frozen canonical digest conflict', () => {
  for (const original of handoverPreservedRegistryEntries) {
    for (const field of [
      'ownerLane',
      'schemaVersion',
      'schemaDigest',
      'signed',
      'signatureContextRule',
      'projectionRefs',
    ]) {
      const changed = {
        ...original,
        [field]: field === 'signed' ? false : field === 'projectionRefs' ? [] : 'changed',
      };
      expect(() => handoverAdmissionRegistration(definition(), [changed])).toThrow(
        'ownership drift',
      );
    }
    const conflicting = {
      ...definition(),
      schemaId: original.schemaId,
      purpose: { name: original.purpose, code: original.purposeCode },
      typeName: original.typeName,
    };
    expect(() => handoverAdmissionRegistration(definition(), [], [conflicting])).toThrow(
      'canonical ownership drift',
    );
  }
});
