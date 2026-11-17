import { decodeCbor } from './cbor.js';
import { businessTransitionProfiles } from './profiles.generated.js';
import { businessTransitionCoseContext } from './generated.js';
import { businessTransitionCoseContextV2 } from './generated-v2.js';
import {
  decodeReceiptStructure,
  decodeReceiptStructureV2,
  encodeReceiptStructure,
  encodeReceiptStructureV2,
  type BusinessTransitionReceipt,
} from './payload.js';
import { verifyReceiptCose, verifyReceiptCoseV2 } from './cose.js';

/** Exact immutable profile selection; never infer a compatible version from a COSE header. */
export function admittedReceiptSchemaVersion(receipt: BusinessTransitionReceipt): 1 | 2 {
  const p = businessTransitionProfiles.find(
    (p) =>
      p.profileId === receipt.transitionProfileId &&
      p.profileVersion === receipt.transitionProfileVersion &&
      receipt.transitionProfileDigest.equals(Buffer.from(p.profileDigest.slice(7), 'hex')),
  );
  if (
    p === undefined ||
    p.actionIntentId !== receipt.actionIntentId ||
    p.catalogOperationId !== receipt.catalogOperationId ||
    p.aggregateType !== receipt.aggregateType ||
    p.transitionKind !== receipt.transitionKind ||
    !receipt.schemaDefinitionDigest.equals(Buffer.from(p.schemaDefinitionDigest.slice(7), 'hex'))
  )
    throw new Error('Unadmitted receipt profile binding');
  if (p.schemaDefinitionDigest === businessTransitionCoseContext.definitionDigest) return 1;
  if (p.schemaDefinitionDigest === businessTransitionCoseContextV2.definitionDigest) return 2;
  throw new Error('Unadmitted receipt schema version');
}
export function encodeAdmittedReceipt(receipt: BusinessTransitionReceipt): Buffer {
  return admittedReceiptSchemaVersion(receipt) === 1
    ? encodeReceiptStructure(receipt)
    : encodeReceiptStructureV2(receipt);
}
export function decodeAdmittedReceipt(payload: Buffer): BusinessTransitionReceipt {
  const value = decodeCbor(payload);
  if (!(value instanceof Map)) throw new Error('Invalid receipt map');
  const p = businessTransitionProfiles.find(
    (p) => p.profileId === value.get(2) && BigInt(p.profileVersion) === value.get(3),
  );
  if (p === undefined) throw new Error('Unadmitted receipt profile');
  const receipt =
    p.schemaDefinitionDigest === businessTransitionCoseContext.definitionDigest
      ? decodeReceiptStructure(payload)
      : p.schemaDefinitionDigest === businessTransitionCoseContextV2.definitionDigest
        ? decodeReceiptStructureV2(payload)
        : undefined;
  if (receipt === undefined) throw new Error('Unadmitted receipt schema version');
  admittedReceiptSchemaVersion(receipt);
  return receipt;
}
export function verifyAdmittedReceiptCose(
  publicKey: Buffer,
  payload: Buffer,
  cose: Buffer,
): boolean {
  try {
    return admittedReceiptSchemaVersion(decodeAdmittedReceipt(payload)) === 1
      ? verifyReceiptCose(publicKey, payload, cose)
      : verifyReceiptCoseV2(publicKey, payload, cose);
  } catch {
    return false;
  }
}
