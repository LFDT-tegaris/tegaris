import { evidenceKeyId } from '../business-transition/cose.js';
import { factConsumerFailureContext as context } from './failure-generated.js';
import { decodeFactConsumerFailure } from './failure.js';
import { consumerProtectedHeader, signConsumerCose, verifyConsumerCose } from './cose-framing.js';

export const factConsumerFailureProtectedHeader = (spki: Buffer): Buffer =>
  consumerProtectedHeader(context, spki);
function assertSigner(spki: Buffer, payload: Buffer): void {
  if (decodeFactConsumerFailure(payload).signerKeyId !== evidenceKeyId(spki))
    throw new Error('Fact consumer failure signer mismatch');
}
/** Cryptography only. No source, workload or signing-grant authority is inferred. */
export function signFactConsumerFailure(privateKey: Buffer, spki: Buffer, payload: Buffer): Buffer {
  assertSigner(spki, payload);
  return signConsumerCose(context, privateKey, spki, payload);
}
export function verifyFactConsumerFailureSignature(
  spki: Buffer,
  payload: Buffer,
  cose: Buffer,
): boolean {
  try {
    assertSigner(spki, payload);
    return verifyConsumerCose(context, spki, payload, cose);
  } catch {
    return false;
  }
}
