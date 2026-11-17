import { constants } from 'node:fs';
import { link, open, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { digest, EvidenceCustodyError } from './segment.js';
import type { VaultObject } from './local-vault.js';

export const vaultHold = z
  .strictObject({
    holdId: z.uuidv7(),
    selectorDigest: digest,
    creationOperationId: z.uuidv7(),
    releaseOperationId: z.uuidv7().nullable(),
    state: z.enum(['ACTIVE', 'RELEASED']),
    revision: z.enum(['1', '2']),
  })
  .refine((value) =>
    value.state === 'ACTIVE'
      ? value.revision === '1' && value.releaseOperationId === null
      : value.revision === '2' && value.releaseOperationId !== null,
  );
export type VaultHold = z.infer<typeof vaultHold>;

/** Called only after exact object readback, under the durable owner's lifecycle lock.
 * A release appends a second receipt; it never erases the original preservation rule.
 */
export async function acknowledgeLocalHold(
  directory: string,
  object: VaultObject,
  input: VaultHold,
) {
  const hold = vaultHold.parse(input);
  const base = sha256({ object, holdId: hold.holdId }).slice(7);
  let acknowledged;
  for (const revision of hold.revision === '1' ? (['1'] as const) : (['1', '2'] as const)) {
    const body = {
      version: 'OPENPC_EVIDENCE_HOLD_ACK_V1',
      object,
      holdId: hold.holdId,
      selectorDigest: hold.selectorDigest,
      revision,
      state: revision === '1' ? 'ACTIVE' : 'RELEASED',
      operationId: revision === '1' ? hold.creationOperationId : hold.releaseOperationId!,
      assurance: 'LOCAL_FSYNC_READBACK' as const,
    };
    const expected = canonicalJson(body);
    const path = join(directory, `${base}.hold-${revision}`);
    const temporary = join(directory, `.pending-hold-${randomUUID()}`);
    let file;
    try {
      file = await open(
        temporary,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      await file.writeFile(expected);
      await file.sync();
      await file.close();
      file = undefined;
      try {
        await link(temporary, path);
      } catch (error) {
        if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
      }
      await unlink(temporary);
      const parent = await open(
        directory,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
      file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = await file.stat();
      if (
        !stat.isFile() ||
        (stat.mode & 0o077) !== 0 ||
        stat.size !== Buffer.byteLength(expected) ||
        (await file.readFile('utf8')) !== expected
      )
        throw new EvidenceCustodyError('INTEGRITY');
      acknowledged = { ...body, receiptDigest: sha256(body) };
    } catch (error) {
      if (error instanceof EvidenceCustodyError) throw error;
      throw new EvidenceCustodyError('UNAVAILABLE');
    } finally {
      await file?.close();
      await unlink(temporary).catch((error) => {
        if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT'))
          throw new EvidenceCustodyError('UNAVAILABLE');
      });
    }
  }
  return acknowledged!;
}
