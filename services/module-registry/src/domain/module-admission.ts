import { verify } from 'node:crypto';
import { sha256 } from './digest.js';
import { ContractError } from './errors.js';

export interface AdmissionEnvelope {
  manifestBytes: Buffer;
  manifestDigest: string;
  signatureP1363: Buffer;
  signerPublicKeyPem: string;
  signerState: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  sbomBytes: Buffer;
  sbomDigest: string;
  provenanceBytes: Buffer;
  provenanceDigest: string;
  buildReceiptBytes: Buffer;
  buildReceiptDigest: string;
}

export function verifyModuleAdmission(input: AdmissionEnvelope): Readonly<{
  manifestDigest: string;
  sbomDigest: string;
  provenanceDigest: string;
  buildReceiptDigest: string;
}> {
  if (input.signerState !== 'ACTIVE')
    throw new ContractError('PC-MODULE-7008', 'signer not active');
  const exact = [
    [input.manifestBytes, input.manifestDigest],
    [input.sbomBytes, input.sbomDigest],
    [input.provenanceBytes, input.provenanceDigest],
    [input.buildReceiptBytes, input.buildReceiptDigest],
  ] as const;
  if (exact.some(([bytes, digest]) => sha256(bytes) !== digest))
    throw new ContractError('PC-MODULE-7008', 'supply-chain digest mismatch');
  if (
    !verify(
      'sha256',
      input.manifestBytes,
      { key: input.signerPublicKeyPem, dsaEncoding: 'ieee-p1363' },
      input.signatureP1363,
    )
  )
    throw new ContractError('PC-MODULE-7008', 'invalid manifest signature');
  return Object.freeze({
    manifestDigest: input.manifestDigest,
    sbomDigest: input.sbomDigest,
    provenanceDigest: input.provenanceDigest,
    buildReceiptDigest: input.buildReceiptDigest,
  });
}
