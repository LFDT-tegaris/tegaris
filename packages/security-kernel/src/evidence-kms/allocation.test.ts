import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { evidenceKmsAllocations, assertEvidenceKmsAllocations } from './allocation.js';

const admitted = evidenceKmsAllocations.map((a) => ({
  ...a,
  schemaVersion: a.semanticVersion,
  projectionRefs: [a.projectionRef],
}));

it('reserves distinct canonical identities without enrolling unfinished KMS definitions', () => {
  const registry = JSON.parse(
    readFileSync(
      new URL('../../../../schemas/json/schema-identity-registry.json', import.meta.url),
      'utf8',
    ),
  ) as { entries: unknown[] };
  assertEvidenceKmsAllocations(registry.entries);
  assertEvidenceKmsAllocations(admitted);
  for (const key of ['schemaId', 'purposeCode', 'purpose', 'typeName'] as const)
    expect(new Set(evidenceKmsAllocations.map((a) => a[key])).size).toBe(3);
  expect(Object.isFrozen(evidenceKmsAllocations)).toBe(true);
  expect(evidenceKmsAllocations.every(Object.isFrozen)).toBe(true);
});

it('rejects any reserved identity collision, wrong version/owner/projection and duplicate admission', () => {
  for (const entry of admitted) {
    for (const key of [
      'schemaId',
      'purposeCode',
      'purpose',
      'typeName',
      'schemaVersion',
      'ownerLane',
      'projectionRefs',
    ]) {
      expect(() => assertEvidenceKmsAllocations([{ ...entry, [key]: 'foreign' }])).toThrow();
      const isolated = { [key]: entry[key as keyof typeof entry] };
      if (['schemaId', 'purposeCode', 'purpose', 'typeName'].includes(key))
        expect(() => assertEvidenceKmsAllocations([isolated])).toThrow();
    }
    expect(() => assertEvidenceKmsAllocations([entry, entry])).toThrow();
  }
  expect(() => assertEvidenceKmsAllocations([null])).toThrow();
});
