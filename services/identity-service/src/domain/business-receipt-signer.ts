import {
  assertBusinessSigningGrant,
  businessSigningTrustDigest,
  encodeAdmittedReceipt,
  verifyAdmittedReceiptCose,
  admittedReceiptSchemaVersion,
  businessSigningSchemaVersion,
  type BusinessSigningTrust,
  type BusinessTransitionReceipt,
} from '@openpc/security-kernel';

/** A purpose-bound signature capability; private key material never crosses this port. */
export interface BusinessReceiptSigningCapability {
  sign(request: {
    readonly payload: Buffer;
    readonly trust: BusinessSigningTrust;
  }): Promise<Buffer>;
}

/** Called only within the owning transaction after the live signing-store fence. */
export async function signBusinessReceipt(
  receipt: BusinessTransitionReceipt,
  trust: BusinessSigningTrust,
  signer: BusinessReceiptSigningCapability,
): Promise<{ readonly payload: Buffer; readonly coseSign1: Buffer }> {
  assertBusinessSigningGrant(trust, {
    participantId: receipt.participantId,
    privacyDomainId: receipt.privacyDomainId,
    environmentId: receipt.environmentId,
    profileId: receipt.transitionProfileId,
    profileVersion: receipt.transitionProfileVersion,
    profileDigest: receipt.transitionProfileDigest,
    actionIntentId: receipt.actionIntentId,
    catalogOperationId: receipt.catalogOperationId,
    nowNs: receipt.recordedAtNs,
  });
  if (
    receipt.signerId !== trust.signerId ||
    !receipt.signerTrustSnapshotDigest.equals(businessSigningTrustDigest(trust)) ||
    admittedReceiptSchemaVersion(receipt) !== businessSigningSchemaVersion(trust)
  ) {
    throw new Error('Receipt signing trust binding mismatch');
  }
  const payload = encodeAdmittedReceipt(receipt);
  const coseSign1 = await signer.sign({ payload, trust });
  if (!verifyAdmittedReceiptCose(trust.publicKeySpkiDer, payload, coseSign1))
    throw new Error('Receipt self-verification failed');
  return { payload, coseSign1 };
}
