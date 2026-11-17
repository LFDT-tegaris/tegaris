import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { definitionDigest } from '../business-transition/definition.js';
import { encodeCbor, type CborValue } from '../canonical-cbor.js';
import { signConsumerCose, verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { operationsConfigurationCoseProfiles as profiles } from './generated.js';

const families = [
  ['operations-qualification-input-v1', 'OperationsQualificationInputV1', 24024, 361],
  [
    'operations-qualification-executed-receipt-v1',
    'OperationsQualificationExecutedReceiptV1',
    24025,
    362,
  ],
  ['operations-qualification-keyset-v1', 'OperationsQualificationKeysetV1', 24026, 363],
  ['operations-qualification-revocations-v1', 'OperationsQualificationRevocationsV1', 24027, 364],
] as const;
const definitions = families.map(([file]) =>
  JSON.parse(
    readFileSync(new URL(`../../../../schemas/canonical/${file}.json`, import.meta.url), 'utf8'),
  ),
);
const registry = JSON.parse(
  readFileSync(
    new URL('../../../../schemas/json/schema-identity-registry.json', import.meta.url),
    'utf8',
  ),
) as {
  entries: { schemaId: number; purposeCode: number; typeName: string; schemaDigest: string }[];
};
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const key = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
// Framing interoperability only. These artificial fields grant no qualification,
// root trust, independent reviewer evidence, key custody or current generation.
function sample(type: string): CborValue {
  if (type === 'H32') return Buffer.alloc(32, 1);
  if (type === 'uuidv7') return Buffer.from('01900000000070008000000000000001', 'hex');
  if (type === 'u64p') return 1n;
  if (type === 'safe_uint' || type === 'uint_0_3' || type.startsWith('enum ')) return 1;
  return 'bound-test';
}
it.each(families)(
  '%s has one collision-free frozen identity and interoperable isolated COSE purpose',
  (file, name, schemaId, purposeCode) => {
    const definition = definitions[families.findIndex(([item]) => item === file)];
    const profile = profiles[name];
    expect(profile).toMatchObject({
      schemaId,
      purposeCode,
      schemaVersion: 1,
      signatureProfileVersion: 2,
    });
    expect(profile.definitionDigest).toBe(`sha256:${definitionDigest(definition).toString('hex')}`);
    for (const selector of [
      (entry: (typeof registry.entries)[number]) => entry.schemaId === schemaId,
      (entry: (typeof registry.entries)[number]) => entry.purposeCode === purposeCode,
      (entry: (typeof registry.entries)[number]) => entry.typeName === name,
    ]) {
      expect(registry.entries.filter(selector)).toHaveLength(1);
    }
    expect(profile.fields.map((f) => f.key)).toEqual(profile.fields.map((_, i) => i));
    expect(new Set(profile.fields.map((f) => f.name)).size).toBe(profile.fields.length);
    const payload = encodeCbor(
      new Map<number, CborValue>(
        profile.fields.map((field) => [
          field.key,
          field.key === 0
            ? Buffer.from(profile.definitionDigest.slice(7), 'hex')
            : sample(field.type),
        ]),
      ),
    );
    const cose = signConsumerCose(profile, key, spki, payload);
    expect(verifyConsumerCose(profile, spki, payload, cose)).toBe(true);
    for (const context of [
      profiles.OperationsSiteDocumentV1,
      profiles.OperationsSecretResolutionV1,
      ...families.filter(([, n]) => n !== name).map(([, n]) => profiles[n]),
    ])
      expect(verifyConsumerCose(context, spki, payload, cose)).toBe(false);
    expect(
      verifyConsumerCose(profile, spki, Buffer.concat([payload, Buffer.from([0])]), cose),
    ).toBe(false);
    const altered = Buffer.from(cose);
    altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
    expect(verifyConsumerCose(profile, spki, payload, altered)).toBe(false);
  },
);
it('keeps reference construction acyclic and exact input bindings distinct from executed acceptance', () => {
  const names = (index: number): string[] =>
    definitions[index].fields.map((f: { name: string }) => f.name);
  expect(names(0)).toEqual([
    'schemaDefinitionDigest',
    'authorityId',
    'environmentId',
    'profile',
    'inputId',
    'slot',
    'setting',
    'value',
    'method',
    'methodClass',
    'methodProfileDigest',
    'workloadIdentityDigest',
    'environmentIdentityDigest',
    'subjectArtifactDigest',
    'buildDigest',
    'sourceTreeDigest',
    'configurationSchemaDigest',
    'namedProfileDigest',
    'issuerKeyId',
    'issuerEpoch',
    'validFromMs',
    'validUntilMs',
  ]);
  expect(names(0).some((name) => /receipt|qualificationRef|generation|effective/i.test(name))).toBe(
    false,
  );
  expect(names(1)).toContain('inputPayloadDigest');
  expect(names(1)).toContain('receiptDocumentDigest');
  expect(names(2)).toContain('revocationPayloadDigest');
  expect(names(3)).not.toContain('keysetPayloadDigest');
  expect(definitions[0].fields.find((f: { name: string }) => f.name === 'value').type).toBe(
    'uint_0_3',
  );
  expect(definitions[0].fields.find((f: { name: string }) => f.name === 'methodClass').type).toBe(
    'enum RETRY_SAFE_READ=1',
  );
});
