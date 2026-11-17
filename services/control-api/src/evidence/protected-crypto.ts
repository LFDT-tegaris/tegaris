import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { protectedDisclosure, protectedObjectBinding } from './protected-contracts.js';

const keyIdSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u);
export interface ProtectedProofKeys {
  readonly activeKeyId: string;
  readonly keys: ReadonlyMap<string, Buffer>;
}
type Binding = z.infer<typeof protectedObjectBinding> & {
  participantId: string;
  privacyDomainId: string;
};
const aad = (binding: Binding) =>
  Buffer.from(
    canonicalJson({
      domain: 'pc.evidence.protected-proof.v1',
      participantId: z.uuid().parse(binding.participantId),
      privacyDomainId: z.uuid().parse(binding.privacyDomainId),
      ...protectedObjectBinding.parse({
        objectRef: binding.objectRef,
        objectVersion: binding.objectVersion,
        objectDigest: binding.objectDigest,
        source: binding.source,
      }),
    }),
  );

function keyFor(keys: ProtectedProofKeys, keyId: string) {
  keyIdSchema.parse(keyId);
  const key = keys.keys.get(keyId);
  if (key?.length !== 32) throw new ConfigurationRepositoryError('PC-OPS-9002');
  return key;
}
export function encryptProtectedProof(keys: ProtectedProofKeys, binding: Binding, payload: Buffer) {
  if (payload.length > 65536 || sha256(payload) !== binding.objectDigest)
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyFor(keys, keys.activeKeyId), nonce);
  cipher.setAAD(aad(binding));
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
  return { keyId: keys.activeKeyId, nonce, ciphertext };
}
export function decryptProtectedProof(
  keys: ProtectedProofKeys,
  binding: Binding,
  encrypted: { keyId: string; nonce: Buffer; ciphertext: Buffer },
) {
  const key = keyFor(keys, encrypted.keyId);
  let plaintext: Buffer | undefined;
  try {
    if (
      encrypted.nonce.length !== 12 ||
      encrypted.ciphertext.length < 17 ||
      encrypted.ciphertext.length > 65552
    )
      throw new Error('invalid object');
    const decipher = createDecipheriv('aes-256-gcm', key, encrypted.nonce);
    decipher.setAAD(aad(binding));
    decipher.setAuthTag(encrypted.ciphertext.subarray(-16));
    plaintext = Buffer.concat([
      decipher.update(encrypted.ciphertext.subarray(0, -16)),
      decipher.final(),
    ]);
    if (sha256(plaintext) !== binding.objectDigest) throw new Error('digest mismatch');
    const payload = protectedDisclosure.parse(JSON.parse(plaintext.toString('utf8')));
    if (
      payload.participantId !== binding.participantId ||
      payload.privacyDomainId !== binding.privacyDomainId ||
      canonicalJson(payload.source) !== canonicalJson(binding.source) ||
      !Buffer.from(canonicalJson(payload)).equals(plaintext)
    )
      throw new Error('binding mismatch');
    return payload;
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  } finally {
    plaintext?.fill(0);
  }
}

/** Dedicated key ring; ordinary catalogue/export workers receive no protected key. */
export async function loadProtectedProofKeys(path: string): Promise<ProtectedProofKeys> {
  const configFile = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let config;
  try {
    const stat = await configFile.stat();
    if (!stat.isFile() || stat.size > 65536)
      throw new Error('invalid protected vault configuration');
    config = z
      .strictObject({
        activeKeyId: keyIdSchema,
        keys: z
          .array(
            z.strictObject({
              keyId: keyIdSchema,
              keyFile: z.string().min(1),
            }),
          )
          .min(1)
          .max(16),
      })
      .parse(JSON.parse(await configFile.readFile('utf8')));
  } finally {
    await configFile.close();
  }
  const keys = new Map<string, Buffer>();
  for (const item of config.keys) {
    if (keys.has(item.keyId)) throw new Error('duplicate protected vault key');
    const file = await open(item.keyFile, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await file.stat();
      if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size !== 32)
        throw new Error('invalid protected vault key file');
      keys.set(item.keyId, await file.readFile());
    } finally {
      await file.close();
    }
  }
  const result = { activeKeyId: config.activeKeyId, keys };
  keyFor(result, result.activeKeyId);
  return result;
}
