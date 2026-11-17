import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { EvidenceCustodyError } from './segment.js';
import {
  openVaultDirectory,
  readVaultFile,
  putVaultFile,
  syncVaultDirectory,
} from './immutable-vault.js';
import {
  protectedCiphertext,
  protectedVaultObject,
  protectedSinkReceipt,
  type ProtectedVaultObject,
  type ProtectedCiphertext,
} from './protected-custody-contracts.js';

const storedObject = z.strictObject({
  identity: protectedVaultObject,
  payload: protectedCiphertext,
});

/** Archive only the already encrypted exact proof copy. This owner never loads
 * protected proof keys or treats the source occurrence's receipt as its custody. */
export class LocalProtectedProofVault {
  private constructor(
    private readonly directory: string,
    readonly sinkId: string,
  ) {}

  static async open(directory: string, sinkId: string) {
    protectedVaultObject.shape.sinkId.parse(sinkId);
    return new LocalProtectedProofVault(await openVaultDirectory(directory), sinkId);
  }

  private identity(value: ProtectedVaultObject) {
    const identity = protectedVaultObject.parse(value);
    if (identity.sinkId !== this.sinkId) throw new EvidenceCustodyError('INVALID');
    return identity;
  }

  private name(identity: ProtectedVaultObject) {
    return `proof-${sha256({
      sinkId: identity.sinkId,
      participantId: identity.participantId,
      privacyDomainId: identity.privacyDomainId,
      objectRef: identity.objectRef,
      objectVersion: identity.objectVersion,
    }).slice(7)}.raw`;
  }

  private validate(identity: ProtectedVaultObject, value: ProtectedCiphertext) {
    const payload = protectedCiphertext.parse(value);
    const nonce = Buffer.from(payload.nonceBase64, 'base64');
    const ciphertext = Buffer.from(payload.ciphertextBase64, 'base64');
    if (
      nonce.length !== 12 ||
      ciphertext.length !== identity.ciphertextBytes ||
      nonce.toString('base64') !== payload.nonceBase64 ||
      ciphertext.toString('base64') !== payload.ciphertextBase64 ||
      sha256(payload) !== identity.payloadDigest
    )
      throw new EvidenceCustodyError('INTEGRITY');
    return payload;
  }

  async read(value: ProtectedVaultObject) {
    const identity = this.identity(value);
    try {
      const stored = storedObject.parse(
        JSON.parse(
          (await readVaultFile(this.directory, this.name(identity), 100000)).toString('utf8'),
        ),
      );
      if (canonicalJson(stored.identity) !== canonicalJson(identity))
        throw new EvidenceCustodyError('INTEGRITY');
      return this.validate(identity, stored.payload);
    } catch (error) {
      if (error instanceof EvidenceCustodyError) throw error;
      throw new EvidenceCustodyError('INTEGRITY');
    }
  }

  async verify(value: ProtectedVaultObject) {
    const identity = this.identity(value);
    await this.read(identity);
    await syncVaultDirectory(this.directory);
    const body = {
      object: identity,
      versionId: identity.payloadDigest,
      assurance: 'LOCAL_FSYNC_READBACK' as const,
    };
    return protectedSinkReceipt.parse({ ...body, receiptDigest: sha256(body) });
  }

  async put(value: ProtectedVaultObject, valuePayload: ProtectedCiphertext) {
    const identity = this.identity(value);
    const payload = this.validate(identity, valuePayload);
    await putVaultFile(
      this.directory,
      this.name(identity),
      Buffer.from(canonicalJson({ identity, payload })),
    );
    return this.verify(identity);
  }
}
