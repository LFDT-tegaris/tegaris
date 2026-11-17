import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeCbor, encodeCbor, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { identityEnvelopeContext } from './generated.js';
import {
  assertEnvelopeProposalNarrowing,
  assertEnvelopeScopeNarrowing,
  authorityEnvelopeDigest,
  decodeEnvelopeProposal,
  decodeIdentityAuthorityEnvelope,
  encodeEnvelopeProposal,
  encodeIdentityAuthorityEnvelope,
} from './codec.js';
import {
  identityEnvelopeProtectedHeader,
  signIdentityAuthorityEnvelopeCose,
  verifyIdentityAuthorityEnvelopeCose,
} from './cose.js';
import {
  envelopeFixtureDigest as digest,
  envelopeFixtureId as id,
  envelopeFixtureScope,
  identityEnvelopeFixture,
} from './fixture.js';
import type { EnvelopeProposal, IdentityAuthorityEnvelope } from './types.js';

const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const spki = keys.publicKey.export({ format: 'der', type: 'spki' });
const pkcs8 = keys.privateKey.export({ format: 'der', type: 'pkcs8' });
const fixture = () => identityEnvelopeFixture(evidenceKeyId(spki));
const proposal = () => decodeEnvelopeProposal(fixture().proposalBytes);
function child(parent = fixture(), rotation = false): EnvelopeProposal {
  const value = decodeEnvelopeProposal(parent.proposalBytes);
  value.issuance = rotation ? 'ROTATION' : 'CHILD';
  value.issuer.kind = 'PARTICIPANT';
  value.issuer.parent = {
    envelopeId: value.envelopeId,
    activeVersion: parent.activation.activeVersion,
    semanticRevision: value.semanticRevision,
    artifactDigest: authorityEnvelopeDigest(encodeIdentityAuthorityEnvelope(parent)),
    authorityEpoch: value.authorityEpoch,
    delegationEpoch: value.delegationEpoch,
  };
  value.issuer.authority.authorityEnvelopeId = value.envelopeId;
  if (rotation) value.semanticRevision = '2';
  else {
    value.envelopeId = id(61);
    value.usable.onwardDelegationDepth--;
    value.grantable.onwardDelegationDepth--;
  }
  return value;
}
describe('adopted typed authority envelope', () => {
  it('round-trips exact submitted bytes and distinct proposal versus ACTIVE digests without a cycle', () => {
    const value = fixture();
    const payload = encodeIdentityAuthorityEnvelope(value);
    const decoded = decodeIdentityAuthorityEnvelope(payload);
    expect(decoded).toEqual(value);
    expect(decoded.proposalBytes).toEqual(value.proposalBytes);
    expect(value.proposalDigest).toBe(authorityEnvelopeDigest(value.proposalBytes));
    expect(authorityEnvelopeDigest(payload)).not.toBe(value.proposalDigest);
    expect(decodeEnvelopeProposal(value.proposalBytes).issuer.parent).toBeNull();
    value.activation.candidateDigest = digest(400);
    expect(encodeIdentityAuthorityEnvelope(value)).not.toEqual(payload);
    expect(value.proposalBytes).toEqual(decoded.proposalBytes);
  });
  it('preserves domain UUID encodings while rejecting unknown fields, getters, omitted dimensions and alternate bytes', () => {
    const value = proposal();
    value.envelopeId = '550e8400-e29b-41d4-a716-446655440000';
    expect(decodeEnvelopeProposal(encodeEnvelopeProposal(value))).toEqual(value);
    expect(() =>
      encodeEnvelopeProposal({ ...value, recipientPrincipalId: id(10) } as EnvelopeProposal),
    ).toThrow();
    const getter = { ...value };
    Object.defineProperty(getter, 'envelopeId', { get: () => value.envelopeId });
    expect(() => encodeEnvelopeProposal(getter)).toThrow();
    const missing = proposal();
    Reflect.deleteProperty(missing.usable.administration, 'dataClasses');
    expect(() => encodeEnvelopeProposal(missing)).toThrow();
    for (const malformed of [
      Buffer.from('a100f6', 'hex'),
      Buffer.from('a100f5', 'hex'),
      Buffer.from('bf00ff', 'hex'),
      Buffer.concat([encodeEnvelopeProposal(value), Buffer.from([0])]),
    ])
      expect(() => decodeEnvelopeProposal(malformed)).toThrow();
    const map = decodeCbor(encodeEnvelopeProposal(value)) as Map<number, CborValue>;
    map.set(0, Buffer.alloc(32));
    expect(() => decodeEnvelopeProposal(encodeCbor(map))).toThrow();
  });
  it.each([
    'participantIds',
    'privacyDomainIds',
    'resourceIds',
    'dataClasses',
    'targetProfileIds',
    'riskClasses',
  ] as const)(
    'denies broader %s in either module, independently of usable authority',
    (dimension) => {
      for (const kind of ['administration', 'runtime'] as const) {
        const original = envelopeFixtureScope();
        const broader = envelopeFixtureScope();
        (broader[kind][dimension] as string[]) = [
          dimension.endsWith('DomainIds') || dimension === 'participantIds'
            ? id(99)
            : dimension === 'riskClasses'
              ? 'LOW'
              : 'other',
        ];
        expect(() => assertEnvelopeScopeNarrowing(original, broader)).toThrow();
      }
    },
  );
  it('separates child strict narrowing, same-identity rotation, absent grants and parent digest/epochs', () => {
    const parent = fixture();
    expect(() => assertEnvelopeProposalNarrowing(parent, child(parent))).not.toThrow();
    expect(() => assertEnvelopeProposalNarrowing(parent, child(parent, true))).not.toThrow();
    const equal = child(parent);
    equal.usable.onwardDelegationDepth = 2;
    equal.grantable.onwardDelegationDepth = 2;
    expect(() => assertEnvelopeProposalNarrowing(parent, equal)).toThrow();
    const wrongRotation = child(parent, true);
    wrongRotation.envelopeId = id(62);
    expect(() => assertEnvelopeProposalNarrowing(parent, wrongRotation)).toThrow();
    for (const field of [
      'artifactDigest',
      'authorityEpoch',
      'delegationEpoch',
      'activeVersion',
    ] as const) {
      const wrong = child(parent);
      wrong.issuer.parent![field] = field === 'artifactDigest' ? digest(999) : '999';
      expect(() => assertEnvelopeProposalNarrowing(parent, wrong)).toThrow();
    }
    const noGrant = fixture();
    const semantics = decodeEnvelopeProposal(noGrant.proposalBytes);
    semantics.grantable.administration.actionIntentIds = [];
    noGrant.proposalBytes = encodeEnvelopeProposal(semantics);
    noGrant.proposalDigest = authorityEnvelopeDigest(noGrant.proposalBytes);
    expect(() => assertEnvelopeProposalNarrowing(noGrant, child(noGrant))).toThrow();
    const parentless = child(parent);
    parentless.issuer.parent = null;
    expect(() => encodeEnvelopeProposal(parentless)).toThrow();
  });
  it('denies action/runtime substitution, wildcard, unsorted/duplicate sets, widened validity and weaker obligations', () => {
    const parent = envelopeFixtureScope();
    for (const mutate of [
      (v: typeof parent) => {
        v.administration.actionIntentIds = ['CALL_RESULT_DISCLOSURE'];
      },
      (v: typeof parent) => {
        v.administration.resourceIds = ['*'];
      },
      (v: typeof parent) => {
        v.runtime.dataClasses = ['z', 'a'];
      },
      (v: typeof parent) => {
        v.runtime.dataClasses = ['a', 'a'];
      },
      (v: typeof parent) => {
        v.validUntilNs = '1800003600000001000';
      },
      (v: typeof parent) => {
        v.validFromNs = '1799999999999999000';
      },
      (v: typeof parent) => {
        v.validFromNs = '1800000000000000001';
      },
      (v: typeof parent) => {
        v.makerCheckerRequired = false;
      },
      (v: typeof parent) => {
        v.stepUpRequired = false;
      },
    ]) {
      const next = envelopeFixtureScope();
      mutate(next);
      expect(() => assertEnvelopeScopeNarrowing(parent, next)).toThrow();
    }
  });
  it('rejects consumed candidate/approval reuse, revision mutation, self-approval, repeated step-up and mismatched issuer', () => {
    const changes: ((v: IdentityAuthorityEnvelope) => void)[] = [
      (v) => {
        v.proposalDigest = digest(99);
      },
      (v) => {
        v.signer.participantId = id(99);
      },
      (v) => {
        v.activation.candidateId = v.submission.candidateId;
      },
      (v) => {
        v.activation.approvalRequestId = v.submission.approvalRequestId;
      },
      (v) => {
        v.activation.operationId = v.submission.operationId;
      },
      (v) => {
        v.activation.expectedApprovedVersion = '2';
      },
      (v) => {
        v.activation.activeVersion = '9';
      },
      (v) => {
        v.submission.approvedVersion = '1';
      },
      (v) => {
        v.submission.checker.authority.principalId = v.submission.maker.authority.principalId;
      },
      (v) => {
        v.activation.checker.stepUpChallengeId = v.submission.checker.stepUpChallengeId;
      },
      (v) => {
        v.submission.maker.authority.assignmentVersion = '10';
      },
    ];
    for (const mutate of changes) {
      const value = fixture();
      mutate(value);
      expect(() => encodeIdentityAuthorityEnvelope(value)).toThrow();
    }
  });
  it('accepts real ES256 and rejects genuinely signed wrong purpose/schema/profile/AAD, unprotected fields and keys', () => {
    const payload = encodeIdentityAuthorityEnvelope(fixture());
    const cose = signIdentityAuthorityEnvelopeCose(pkcs8, spki, payload);
    expect(verifyIdentityAuthorityEnvelopeCose(spki, payload, cose)).toBe(true);
    for (const [field, replacement] of [
      [1, -8],
      [100, 24001],
      [101, 2],
      [102, 338],
      [103, 1],
    ] as const) {
      const map = decodeCbor(identityEnvelopeProtectedHeader(spki)) as Map<number, CborValue>;
      map.set(field, replacement);
      const header = encodeCbor(map);
      const signature = sign(
        'sha256',
        encodeCbor(
          [
            'Signature1',
            header,
            Buffer.from(identityEnvelopeContext.externalAadHex, 'hex'),
            payload,
          ],
          66560,
        ),
        { key: keys.privateKey, dsaEncoding: 'ieee-p1363' },
      );
      const wrong = Buffer.concat([
        Buffer.from([0xd2]),
        encodeCbor([header, new Map(), payload, signature], 66560),
      ]);
      expect(verifyIdentityAuthorityEnvelopeCose(spki, payload, wrong)).toBe(false);
    }
    const header = identityEnvelopeProtectedHeader(spki);
    const signature = sign(
      'sha256',
      encodeCbor(['Signature1', header, Buffer.from('wrong'), payload], 66560),
      { key: keys.privateKey, dsaEncoding: 'ieee-p1363' },
    );
    expect(
      verifyIdentityAuthorityEnvelopeCose(
        spki,
        payload,
        Buffer.concat([
          Buffer.from([0xd2]),
          encodeCbor([header, new Map(), payload, signature], 66560),
        ]),
      ),
    ).toBe(false);
    const altered = decodeCbor(cose.subarray(1), 66560) as CborValue[];
    altered[1] = new Map([[4, Buffer.from('unprotected')]]);
    expect(
      verifyIdentityAuthorityEnvelopeCose(
        spki,
        payload,
        Buffer.concat([Buffer.from([0xd2]), encodeCbor(altered, 66560)]),
      ),
    ).toBe(false);
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
      format: 'der',
      type: 'spki',
    });
    expect(verifyIdentityAuthorityEnvelopeCose(other, payload, cose)).toBe(false);
    expect(() => signIdentityAuthorityEnvelopeCose(pkcs8, other, payload)).toThrow();
    expect(verifyIdentityAuthorityEnvelopeCose(spki, payload, cose.subarray(1))).toBe(false);
  });
});
