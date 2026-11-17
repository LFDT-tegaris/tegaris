import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';

import { decodeCbor, encodeCbor, MAX_CBOR_BYTES, type CborValue } from './cbor.js';
import { businessTransitionCoseContext as context } from './generated.js';
import { businessTransitionCoseContextV2 } from './generated-v2.js';

const businessContextV1 = context;
const maxContainerBytes = MAX_CBOR_BYTES + 1024;
const externalAad = Buffer.from(context.externalAadHex, 'hex');

function p256(key: KeyObject): void {
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
    throw new Error('Control evidence key must be P-256');
}
export function evidenceKeyId(publicKeySpkiDer: Buffer): string {
  const key = createPublicKey({ key: publicKeySpkiDer, format: 'der', type: 'spki' });
  p256(key);
  if (!key.export({ format: 'der', type: 'spki' }).equals(publicKeySpkiDer))
    throw new Error('Control evidence SPKI is not canonical DER');
  return `sha256:${createHash('sha256').update(publicKeySpkiDer).digest('hex')}`;
}
export function receiptProtectedHeader(publicKeySpkiDer: Buffer): Buffer {
  return protectedHeader(publicKeySpkiDer, 1);
}
export function receiptProtectedHeaderV2(publicKeySpkiDer: Buffer): Buffer {
  return protectedHeader(publicKeySpkiDer, 2);
}
function protectedHeader(publicKeySpkiDer: Buffer, version: 1 | 2): Buffer {
  const context = version === 1 ? businessContextV1 : businessTransitionCoseContextV2;
  return encodeCbor(
    new Map<number, CborValue>([
      [1, -7],
      [2, [100, 101, 102, 103]],
      [3, context.contentType],
      [4, Buffer.from(evidenceKeyId(publicKeySpkiDer), 'utf8')],
      [100, context.schemaId],
      [101, context.schemaVersion],
      [102, context.purposeCode],
      [103, context.signatureProfileVersion],
    ]),
  );
}
export function receiptSigStructure(publicKeySpkiDer: Buffer, payload: Buffer): Buffer {
  return sigStructure(publicKeySpkiDer, payload, 1);
}
export function receiptSigStructureV2(publicKeySpkiDer: Buffer, payload: Buffer): Buffer {
  return sigStructure(publicKeySpkiDer, payload, 2);
}
function sigStructure(publicKeySpkiDer: Buffer, payload: Buffer, version: 1 | 2): Buffer {
  if (payload.length === 0 || payload.length > MAX_CBOR_BYTES)
    throw new Error('Invalid receipt payload size');
  return encodeCbor(
    ['Signature1', protectedHeader(publicKeySpkiDer, version), externalAad, payload],
    maxContainerBytes,
  );
}

/** Crypto primitive only; the committing owner must separately fence admitted key trust. */
export function signReceiptCose(
  privateKeyPkcs8Der: Buffer,
  publicKeySpkiDer: Buffer,
  payload: Buffer,
): Buffer {
  return signCose(privateKeyPkcs8Der, publicKeySpkiDer, payload, 1);
}
export function signReceiptCoseV2(
  privateKeyPkcs8Der: Buffer,
  publicKeySpkiDer: Buffer,
  payload: Buffer,
): Buffer {
  return signCose(privateKeyPkcs8Der, publicKeySpkiDer, payload, 2);
}
function signCose(
  privateKeyPkcs8Der: Buffer,
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  version: 1 | 2,
): Buffer {
  const key = createPrivateKey({ key: privateKeyPkcs8Der, format: 'der', type: 'pkcs8' });
  p256(key);
  if (!createPublicKey(key).export({ format: 'der', type: 'spki' }).equals(publicKeySpkiDer))
    throw new Error('Control evidence key pair mismatch');
  const structure = sigStructure(publicKeySpkiDer, payload, version);
  const signature = sign('sha256', structure, { key, dsaEncoding: 'ieee-p1363' });
  if (signature.length !== 64) throw new Error('Invalid P1363 signature');
  return Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor(
      [protectedHeader(publicKeySpkiDer, version), new Map(), payload, signature],
      maxContainerBytes,
    ),
  ]);
}

/** Verifies exact signature bytes/context only, never current or historical signing authority. */
export function verifyReceiptCose(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
): boolean {
  return verifyCose(publicKeySpkiDer, payload, coseSign1, 1);
}
export function verifyReceiptCoseV2(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
): boolean {
  return verifyCose(publicKeySpkiDer, payload, coseSign1, 2);
}
function verifyCose(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
  version: 1 | 2,
): boolean {
  try {
    if (coseSign1.length > maxContainerBytes || coseSign1[0] !== 0xd2) return false;
    const value = decodeCbor(coseSign1.subarray(1), maxContainerBytes);
    if (!Array.isArray(value) || value.length !== 4) return false;
    const [protectedBytes, unprotected, embeddedPayload, signature] = value;
    if (
      !Buffer.isBuffer(protectedBytes) ||
      !protectedBytes.equals(protectedHeader(publicKeySpkiDer, version)) ||
      !(unprotected instanceof Map) ||
      unprotected.size !== 0 ||
      !Buffer.isBuffer(embeddedPayload) ||
      !embeddedPayload.equals(payload) ||
      !Buffer.isBuffer(signature) ||
      signature.length !== 64
    )
      return false;
    return verify(
      'sha256',
      sigStructure(publicKeySpkiDer, payload, version),
      {
        key: createPublicKey({ key: publicKeySpkiDer, format: 'der', type: 'spki' }),
        dsaEncoding: 'ieee-p1363',
      },
      signature,
    );
  } catch {
    return false;
  }
}
