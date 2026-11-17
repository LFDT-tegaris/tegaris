import { createHash } from 'node:crypto';

export interface ConfigurationRequestBinding {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
  readonly actionIntentId: string;
  readonly catalogOperationId: string;
  readonly aggregateType: string;
  readonly aggregateId: string;
  readonly expectedRevision: string;
  readonly candidateDigest: Buffer;
  readonly idempotencyKey: string;
}

/** Digest of the normalized mutation request, distinct from the candidate document digest. */
export function configurationRequestDigest(binding: ConfigurationRequestBinding): Buffer {
  if (
    !/^(0|[1-9][0-9]{0,19})$/u.test(binding.expectedRevision) ||
    BigInt(binding.expectedRevision) > 18446744073709551615n ||
    !Buffer.isBuffer(binding.candidateDigest) ||
    binding.candidateDigest.length !== 32
  )
    throw new Error('Invalid request binding');
  const values = [
    binding.participantId,
    binding.privacyDomainId,
    binding.principalId,
    binding.actionIntentId,
    binding.catalogOperationId,
    binding.aggregateType,
    binding.aggregateId,
    binding.expectedRevision,
    `sha256:${binding.candidateDigest.toString('hex')}`,
    binding.idempotencyKey,
  ];
  const hash = createHash('sha256').update('pc.control.configuration-request.v1\0');
  for (const value of values) {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value.normalize('NFC') !== value ||
      Buffer.byteLength(value) > 256
    )
      throw new Error('Invalid request binding');
    const bytes = Buffer.from(value);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest();
}
