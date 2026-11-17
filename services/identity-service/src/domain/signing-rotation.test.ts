import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { identityEnvelopeContext } from '@openpc/security-kernel';
import { businessSigningPurpose } from './business-signing-provider.js';
import {
  envelopeSigningRotationRequestSchema,
  signingRotationActions,
  signingRotationRequestSchema,
} from './signing-rotation.js';

const envelope = {
  actionIntentId: signingRotationActions.create,
  actionIntentDigest: 'sha256:' + '11'.repeat(32),
  secretClass: 'SECRET-SIGNING-KEY',
  signerRole: 'IDENTITY_ENVELOPE',
  purpose: identityEnvelopeContext.purpose,
  environmentId: 'retained-qa',
  workloadCredentialId: '01990000-0000-7000-8000-000000000001',
  oldReference: 'secret://local/envelope-issuer#1',
  oldFingerprint: 'sha256:' + '22'.repeat(32),
  newReference: 'secret://local/envelope-issuer#2',
  reason: 'Repair issuer trust using independent custody',
};

describe('purpose-bound signing rotation targets', () => {
  it('accepts an envelope target without acquiring receipt role grants', () => {
    expect(signingRotationRequestSchema.parse(envelope)).toEqual(envelope);
    expect(envelopeSigningRotationRequestSchema.parse(envelope)).toEqual(envelope);
  });
  it('also rejects an unchanged target when parsing a stored envelope candidate directly', () => {
    expect(
      envelopeSigningRotationRequestSchema.safeParse({
        ...envelope,
        newReference: envelope.oldReference,
      }).success,
    ).toBe(false);
    expect(
      envelopeSigningRotationRequestSchema.safeParse({
        ...envelope,
        newFingerprint: envelope.oldFingerprint,
      }).success,
    ).toBe(false);
  });
  it.each(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE'])(
    'preserves %s receipt requests',
    (signerRole) => {
      const request = { ...envelope, signerRole, purpose: businessSigningPurpose };
      expect(signingRotationRequestSchema.parse(request)).toEqual(request);
    },
  );
  it.each([
    { signerRole: 'BUSINESS_EFFECT' },
    { signerRole: 'LIFECYCLE_EVIDENCE' },
    { purpose: businessSigningPurpose },
    { purpose: 'unknown' },
    { newReference: envelope.oldReference },
    { newFingerprint: envelope.oldFingerprint },
    { newReference: 'secret://local/envelope-issuer#latest' },
    { issuerParticipantEpoch: '7' },
    { issuerSnapshot: {} },
    { privateKey: 'forbidden' },
  ])('rejects purpose substitution, stale aliases and caller-invented provenance: %j', (change) => {
    expect(signingRotationRequestSchema.safeParse({ ...envelope, ...change }).success).toBe(false);
  });
});

describe('public signing rotation schema matches target purpose admission', () => {
  const document = JSON.parse(
    readFileSync(
      new URL('../../../../schemas/json/signing-key-rotation.schema.json', import.meta.url),
      'utf8',
    ),
  );
  const validate = new Ajv2020({ strict: false })
    .addSchema(document)
    .getSchema(`${document.$id}#/$defs/Request`)!;
  it('accepts the separate envelope request and both receipt roles', () => {
    expect(validate(envelope)).toBe(true);
    for (const signerRole of ['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE'])
      expect(validate({ ...envelope, signerRole, purpose: businessSigningPurpose })).toBe(true);
  });
  it.each([
    { signerRole: 'BUSINESS_EFFECT' },
    { purpose: businessSigningPurpose },
    { workloadCredentialId: undefined },
    { actionIntentId: undefined },
    { issuerSnapshot: {} },
  ])(
    'rejects wrong purpose pairs, missing required fields and invented authority: %j',
    (change) => {
      expect(validate({ ...envelope, ...change })).toBe(false);
    },
  );
});
