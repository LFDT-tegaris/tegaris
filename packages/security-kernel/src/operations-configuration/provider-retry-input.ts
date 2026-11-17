import {
  ProviderRetryQualificationError,
  copyQualificationBytes,
  decodeProviderRetryQualification,
  qualificationDigest,
  requireQualificationIssuerKey,
  verifyProviderRetryEnvelope,
  type QualificationEnvelope,
  type QualificationInputClaims,
  type VerifiedQualificationAuthority,
} from './provider-retry-qualification.js';

export interface VerifiedProviderRetryInput {
  readonly input: Readonly<QualificationInputClaims>;
  readonly inputPayloadDigest: string;
  readonly qualificationRef: string;
}

/** Authenticate an original input for a NEW database-local reservation against
 * already authenticated current trust. Require an ACTIVE input key: historical
 * receipt verification/rotation remains with verifyProviderRetryReceipt.
 * Signature authentication does not establish the claimed method, workload,
 * build, isolation, non-exportable key custody, execution or review provenance.
 */
export function verifyProviderRetryInput(
  original: QualificationEnvelope,
  current: VerifiedQualificationAuthority,
  nowMs: number,
): VerifiedProviderRetryInput {
  const envelope = {
    payload: copyQualificationBytes(original.payload, 65536),
    cose: copyQualificationBytes(original.cose, 66560),
  };
  const input = decodeProviderRetryQualification('input', envelope.payload);
  if (
    !Number.isSafeInteger(nowMs) ||
    Object.is(nowMs, -0) ||
    nowMs < 0 ||
    input.validFromMs > nowMs ||
    input.validUntilMs <= nowMs ||
    input.validFromMs >= input.validUntilMs ||
    input.slot !== `QINPUT-${input.profile.toUpperCase()}-PROVIDER-READ-RETRY-V1` ||
    current.keyset.authorityId !== input.authorityId ||
    current.revocations.authorityId !== input.authorityId ||
    current.keyset.issuedAtMs > nowMs ||
    current.keyset.validUntilMs <= nowMs ||
    current.revocations.issuedAtMs > nowMs ||
    current.revocations.validUntilMs <= nowMs
  )
    throw new ProviderRetryQualificationError();
  const key = requireQualificationIssuerKey(
    current,
    input.issuerKeyId,
    input.issuerEpoch,
    'pc.cose.operations-qualification-input.v1',
    input.validFromMs,
    input.validUntilMs,
    nowMs,
    true,
  );
  verifyProviderRetryEnvelope('input', envelope, Buffer.from(key.publicKeySpkiHex, 'hex'));
  const inputPayloadDigest = qualificationDigest(envelope.payload);
  return Object.freeze({
    input: Object.freeze(input),
    inputPayloadDigest,
    qualificationRef: `qualification://${input.authorityId}/${input.inputId}@${inputPayloadDigest}`,
  });
}
