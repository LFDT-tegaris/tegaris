import {
  openVaultDirectory,
  readVaultFile,
  putVaultFile,
  syncVaultDirectory,
} from './immutable-vault.js';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { acknowledgeLocalHold, type VaultHold } from './hold-vault.js';
import {
  digest,
  EvidenceCustodyError,
  evidenceScope,
  inspectSegment,
  MAX_SEGMENT_BYTES,
  sequence,
  type SegmentHeader,
} from './segment.js';

const objectSchema = evidenceScope.extend({
  sinkId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  segmentId: z.uuid(),
  objectDigest: digest,
  firstSequence: sequence,
  throughSequence: sequence,
  previousSegmentDigest: digest.nullable(),
  keyId: z.string().min(1).max(160),
  retentionUntil: z.iso.datetime({ precision: 6 }),
});
export type VaultObject = z.infer<typeof objectSchema>;
const storedSchema = z.strictObject({ identity: objectSchema, encryptedSegment: z.string() });

/** This assurance is intentionally limited to the local filesystem adapter. */
export const sinkDurabilityReceipt = z.strictObject({
  object: objectSchema,
  versionId: digest,
  assurance: z.literal('LOCAL_FSYNC_READBACK'),
  receiptDigest: digest,
});
export type SinkDurabilityReceipt = z.infer<typeof sinkDurabilityReceipt>;
export function vaultObject(sinkId: string, header: SegmentHeader, objectDigest: string) {
  return objectSchema.parse({
    sinkId,
    objectDigest,
    participantId: header.participantId,
    privacyDomainId: header.privacyDomainId,
    streamId: header.streamId,
    segmentId: header.segmentId,
    firstSequence: header.firstSequence,
    throughSequence: header.throughSequence,
    previousSegmentDigest: header.previousSegmentDigest,
    keyId: header.keyId,
    retentionUntil: header.retentionUntil,
  });
}
function receipt(identity: VaultObject): SinkDurabilityReceipt {
  const body = {
    object: identity,
    versionId: identity.objectDigest,
    assurance: 'LOCAL_FSYNC_READBACK' as const,
  };
  return { ...body, receiptDigest: sha256(body) };
}
/**
 * Private, content-verified immutable versions. Admission uses a no-replace link
 * after file fsync, then directory fsync and exact readback before acknowledgement.
 * A transport loss can repeat put; a conflicting identity can never overwrite it.
 * Governance/holds/deletion belong to the lifecycle owner, not this adapter.
 */
export class LocalEvidenceVault {
  private constructor(
    private readonly directory: string,
    readonly sinkId: string,
  ) {}

  static async open(directory: string, sinkId: string): Promise<LocalEvidenceVault> {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u.test(sinkId))
      throw new EvidenceCustodyError('INVALID');
    return new LocalEvidenceVault(await openVaultDirectory(directory), sinkId);
  }

  private identity(value: VaultObject): VaultObject {
    const parsed = objectSchema.parse(value);
    if (
      parsed.sinkId !== this.sinkId ||
      BigInt(parsed.firstSequence) === 0n ||
      BigInt(parsed.throughSequence) < BigInt(parsed.firstSequence) ||
      BigInt(parsed.throughSequence) - BigInt(parsed.firstSequence) >= 128n ||
      (parsed.firstSequence === '1') !== (parsed.previousSegmentDigest === null)
    )
      throw new EvidenceCustodyError('INVALID');
    return parsed;
  }

  private path(identity: VaultObject) {
    return `${sha256({
      sinkId: identity.sinkId,
      participantId: identity.participantId,
      privacyDomainId: identity.privacyDomainId,
      streamId: identity.streamId,
      segmentId: identity.segmentId,
    }).slice(7)}.segment`;
  }

  async read(value: VaultObject): Promise<Buffer> {
    const identity = this.identity(value);
    try {
      const stored = storedSchema.parse(
        JSON.parse(
          (
            await readVaultFile(this.directory, this.path(identity), MAX_SEGMENT_BYTES * 2)
          ).toString('utf8'),
        ),
      );
      const bytes = Buffer.from(stored.encryptedSegment, 'base64');
      const segment = inspectSegment(bytes);
      if (
        canonicalJson(stored.identity) !== canonicalJson(identity) ||
        canonicalJson(vaultObject(this.sinkId, segment.header, segment.objectDigest)) !==
          canonicalJson(identity) ||
        bytes.length > MAX_SEGMENT_BYTES ||
        bytes.toString('base64') !== stored.encryptedSegment ||
        sha256(bytes) !== identity.objectDigest
      )
        throw new EvidenceCustodyError('INTEGRITY');
      return bytes;
    } catch (error) {
      if (error instanceof EvidenceCustodyError) throw error;
      throw new EvidenceCustodyError('INTEGRITY');
    }
  }

  async verify(value: VaultObject): Promise<SinkDurabilityReceipt> {
    const identity = this.identity(value);
    await this.read(identity);
    // Recovery may encounter a link whose creating process died before directory
    // fsync. Establish durability here too, before issuing a recovered receipt.
    await syncVaultDirectory(this.directory);
    return receipt(identity);
  }

  async acknowledgeHold(value: VaultObject, hold: VaultHold) {
    const identity = this.identity(value);
    await this.verify(identity);
    return acknowledgeLocalHold(this.directory, identity, hold);
  }

  async put(value: VaultObject, encryptedSegment: Buffer): Promise<SinkDurabilityReceipt> {
    const identity = this.identity(value);
    const inspected = inspectSegment(encryptedSegment);
    if (
      canonicalJson(vaultObject(this.sinkId, inspected.header, inspected.objectDigest)) !==
      canonicalJson(identity)
    )
      throw new EvidenceCustodyError('INTEGRITY');
    await putVaultFile(
      this.directory,
      this.path(identity),
      Buffer.from(
        canonicalJson({
          identity,
          encryptedSegment: encryptedSegment.toString('base64'),
        }),
      ),
    );
    return this.verify(identity);
  }
}
