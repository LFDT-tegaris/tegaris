import { readFileSync } from 'node:fs';
import { it, expect } from 'vitest';
import {
  identityEnvelopeRegistration,
  identityEnvelopeProfileRegistration,
} from './identity-envelope-profile.mjs';
import { identityEnvelopeContext } from '../src/identity-envelope/generated.ts';
it('admits only the exact adopted tuple and rejects allocation collisions and every frozen entry change', () => {
  const definition = JSON.parse(
    readFileSync(
      new URL('../../../schemas/canonical/identity-authority-envelope-v1.json', import.meta.url),
      'utf8',
    ),
  );
  const { entry } = identityEnvelopeRegistration(definition, []);
  expect(identityEnvelopeRegistration(definition, [entry]).context.definitionDigest).toBe(
    identityEnvelopeContext.definitionDigest,
  );
  for (const field of [
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
  ]) {
    expect(() =>
      identityEnvelopeRegistration(definition, [
        {
          ...entry,
          [field]:
            field === 'schemaId'
              ? 24035
              : field === 'purposeCode'
                ? 372
                : field === 'signed'
                  ? false
                  : field === 'projectionRefs'
                    ? []
                    : 'changed',
        },
      ]),
    ).toThrow();
  }
  expect(() => identityEnvelopeRegistration(definition, [entry, entry])).toThrow();
  expect(() =>
    identityEnvelopeRegistration(definition, [], [{ ...definition, schemaId: 24999 }]),
  ).toThrow('canonical name collision');
  const drift = structuredClone(definition);
  drift.invariants.push('different semantics');
  expect(() => identityEnvelopeRegistration(drift, [entry])).toThrow();
  expect(() =>
    identityEnvelopeRegistration({ ...definition, ownerLane: 'LANE-CONTROL' }, []),
  ).toThrow();
});
it('generates only the exact explicitly admitted envelope signing profile', () => {
  const profile = JSON.parse(
    readFileSync(
      new URL(
        '../../../schemas/canonical/identity-envelope-signing-profiles/authority-envelope-v1.json',
        import.meta.url,
      ),
      'utf8',
    ),
  );
  expect(identityEnvelopeProfileRegistration(profile, identityEnvelopeContext).profile).toEqual(
    profile,
  );
  for (const change of [
    { schemaId: 24001 },
    { purposeCode: 338 },
    { profileVersion: 2 },
    { actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
    { extra: 'unadmitted' },
  ])
    expect(() =>
      identityEnvelopeProfileRegistration({ ...profile, ...change }, identityEnvelopeContext),
    ).toThrow();
});
