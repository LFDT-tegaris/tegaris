// Fresh independent crypto input for the ordinary pc-policy-core test. Private
// keys remain in this process; stdout contains public claims/bytes only.
import { generateKeyPairSync, sign } from 'node:crypto';
import { encodeCbor, decodeCbor } from '../canonical-cbor.ts';
import { evidenceKeyId } from '../business-transition/cose.ts';
import { identityEnvelopeContext } from './generated.ts';
import { identityEnvelopeFixture } from './fixture.ts';
import { encodeIdentityAuthorityEnvelope } from './codec.ts';
import { identityEnvelopeProtectedHeader, signIdentityAuthorityEnvelopeCose } from './cose.ts';

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const spki = publicKey.export({ format: 'der', type: 'spki' });
const value = identityEnvelopeFixture(evidenceKeyId(spki));
const payload = encodeIdentityAuthorityEnvelope(value);
const cose = signIdentityAuthorityEnvelopeCose(
  privateKey.export({ format: 'der', type: 'pkcs8' }),
  spki,
  payload,
);
const wrongCose = [];
for (const mutation of [
  (header) => header.set(1, -8),
  (header) => header.set(100, 24001),
  (header) => header.set(101, 2),
  (header) => header.set(102, 338),
  (header) => header.set(103, 1),
  (header) => header.set(2, [100, 101, 102]),
]) {
  const map = decodeCbor(identityEnvelopeProtectedHeader(spki));
  mutation(map);
  const header = encodeCbor(map);
  const signature = sign(
    'sha256',
    encodeCbor(
      ['Signature1', header, Buffer.from(identityEnvelopeContext.externalAadHex, 'hex'), payload],
      66560,
    ),
    { key: privateKey, dsaEncoding: 'ieee-p1363' },
  );
  wrongCose.push([
    ...Buffer.concat([
      Buffer.from([0xd2]),
      encodeCbor([header, new Map(), payload, signature], 66560),
    ]),
  ]);
}
const header = identityEnvelopeProtectedHeader(spki);
const signature = sign(
  'sha256',
  encodeCbor(['Signature1', header, Buffer.from('wrong-aad'), payload], 66560),
  { key: privateKey, dsaEncoding: 'ieee-p1363' },
);
wrongCose.push([
  ...Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([header, new Map(), payload, signature], 66560),
  ]),
]);
process.stdout.write(
  JSON.stringify({
    envelope: { ...value, proposalBytes: [...value.proposalBytes] },
    payload: [...payload],
    cose: [...cose],
    spki: [...spki],
    wrongCose,
  }),
);
