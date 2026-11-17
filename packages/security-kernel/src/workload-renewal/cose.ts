import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_CBOR_BYTES, type CborValue } from '../canonical-cbor.js';
import { workloadRenewalRequestContext } from './generated-request.js';
import { workloadRenewalAuthorizationContext } from './generated-authorization.js';
import {
  decodeWorkloadRenewalRequest,
  decodeWorkloadRenewalPolicyAuthorization,
  workloadRenewalDigest,
} from './codec.js';

type Kind = 'REQUEST' | 'POLICY_AUTHORIZATION';
const budget = MAX_CBOR_BYTES + 1024;
function keyId(spki: Buffer) {
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  if (
    key.asymmetricKeyType !== 'ec' ||
    key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
    !key.export({ format: 'der', type: 'spki' }).equals(spki)
  )
    throw new Error('Invalid renewal P256 key');
  return workloadRenewalDigest(spki);
}
export function workloadRenewalProtectedHeader(kind: Kind, spki: Buffer): Buffer {
  const context =
    kind === 'REQUEST' ? workloadRenewalRequestContext : workloadRenewalAuthorizationContext;
  if (kind !== 'REQUEST' && kind !== 'POLICY_AUTHORIZATION')
    throw new Error('Invalid renewal signature kind');
  return encodeCbor(
    new Map<number, CborValue>([
      [1, -7],
      [2, [100, 101, 102, 103]],
      [3, context.contentType],
      [4, Buffer.from(keyId(spki))],
      [100, context.schemaId],
      [101, context.schemaVersion],
      [102, context.purposeCode],
      [103, context.signatureProfileVersion],
    ]),
  );
}
export function workloadRenewalSigStructure(kind: Kind, spki: Buffer, payload: Buffer) {
  const id = keyId(spki);
  if (kind === 'REQUEST') {
    if (decodeWorkloadRenewalRequest(payload).newKeyDigest !== id)
      throw new Error('Renewal successor key mismatch');
  } else if (kind === 'POLICY_AUTHORIZATION') {
    if (decodeWorkloadRenewalPolicyAuthorization(payload).signer.keyId !== id)
      throw new Error('Renewal authorization key mismatch');
  } else throw new Error('Invalid renewal signature kind');
  const context =
    kind === 'REQUEST' ? workloadRenewalRequestContext : workloadRenewalAuthorizationContext;
  return encodeCbor(
    [
      'Signature1',
      workloadRenewalProtectedHeader(kind, spki),
      Buffer.from(context.externalAadHex, 'hex'),
      payload,
    ],
    budget,
  );
}
/** Provider/client primitive only. The policy assertion owner must first
 * authenticate current signing admission and all current business fences. */
export function signWorkloadRenewalCose(kind: Kind, pkcs8: Buffer, spki: Buffer, payload: Buffer) {
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  if (!createPublicKey(key).export({ format: 'der', type: 'spki' }).equals(spki))
    throw new Error('Renewal key pair mismatch');
  const signature = sign('sha256', workloadRenewalSigStructure(kind, spki, payload), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  if (signature.length !== 64) throw new Error('Invalid renewal signature format');
  return Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([workloadRenewalProtectedHeader(kind, spki), new Map(), payload, signature], budget),
  ]);
}
/** Exact cryptographic proof only, never policy/current signer admission. */
export function verifyWorkloadRenewalCose(
  kind: Kind,
  spki: Buffer,
  payload: Buffer,
  cose: Buffer,
): boolean {
  try {
    if (cose.length > budget || cose[0] !== 0xd2) return false;
    const value = decodeCbor(cose.subarray(1), budget);
    if (!Array.isArray(value) || value.length !== 4) return false;
    const [header, unprotected, embedded, signature] = value;
    if (
      !Buffer.isBuffer(header) ||
      !header.equals(workloadRenewalProtectedHeader(kind, spki)) ||
      !(unprotected instanceof Map) ||
      unprotected.size !== 0 ||
      !Buffer.isBuffer(embedded) ||
      !embedded.equals(payload) ||
      !Buffer.isBuffer(signature) ||
      signature.length !== 64
    )
      return false;
    return verify(
      'sha256',
      workloadRenewalSigStructure(kind, spki, payload),
      {
        key: createPublicKey({ key: spki, format: 'der', type: 'spki' }),
        dsaEncoding: 'ieee-p1363',
      },
      signature,
    );
  } catch {
    return false;
  }
}
