import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { sha256 } from '../configuration/digest.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { LocalProtectedProofVault } from './protected-vault.js';
import { protectedVaultObject } from './protected-custody-contracts.js';

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});
async function fixture() {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT!, 'protected-vault-'));
  roots.push(root);
  const payload = {
    keyId: 'protected-key',
    nonceBase64: randomBytes(12).toString('base64'),
    ciphertextBase64: randomBytes(64).toString('base64'),
  };
  const hash = sha256('source');
  const identity = protectedVaultObject.parse({
    dataClass: 'RAW_SOURCE_BODY',
    participantId: randomUUID(),
    privacyDomainId: randomUUID(),
    sinkId: 'raw-archive',
    objectRef: `urn:openpc:resource:${uuidv7()}`,
    objectVersion: '1',
    objectDigest: hash,
    payloadDigest: sha256(payload),
    ciphertextBytes: 64,
    retainUntil: '2027-01-01T00:00:00.000000Z',
    source: {
      evidenceId: `urn:openpc:resource:${uuidv7()}`,
      occurrenceId: uuidv7(),
      operationId: uuidv7(),
      sourceReceiptDigest: hash,
      proofDigest: hash,
      assertionDigest: hash,
      signatureDigest: hash,
      signerKeyDigest: hash,
      occurredAt: '2026-09-23T00:00:00.000000Z',
      materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
      evidenceClass: 'AUTHENTICATION',
      sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
      occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
      proofIntegrity: 'IDENTITY_COSE_ED25519',
      finality: 'NOT_APPLICABLE',
      authorityEffect: 'NONE',
    },
  });
  return {
    root,
    payload,
    identity,
    vault: await LocalProtectedProofVault.open(root, identity.sinkId),
  };
}

it('recovers the identical encrypted raw version after lost acknowledgement without replacing it', async () => {
  const { root, payload, identity, vault } = await fixture();
  const original = await vault.put(identity, payload);
  const restarted = await LocalProtectedProofVault.open(root, identity.sinkId);
  expect(await restarted.put(identity, payload)).toEqual(original);
  expect(await restarted.verify(identity)).toEqual(original);
  expect(await restarted.read(identity)).toEqual(payload);
  expect(await readdir(root)).toHaveLength(1);
  expect(original.object.dataClass).toBe('RAW_SOURCE_BODY');
  expect(original.versionId).toBe(identity.payloadDigest);
  expect(original.receiptDigest).not.toBe(identity.source.sourceReceiptDigest);
  const replacement = { ...payload, ciphertextBase64: randomBytes(64).toString('base64') };
  await expect(
    vault.put({ ...identity, payloadDigest: sha256(replacement) }, replacement),
  ).rejects.toMatchObject({ code: 'INTEGRITY' });
  expect(await vault.read(identity)).toEqual(payload);
});

it('denies wrong scope, source, version, sink, malformed packet and changed archived bytes', async () => {
  const { root, payload, identity, vault } = await fixture();
  await vault.put(identity, payload);
  await expect(vault.read({ ...identity, participantId: randomUUID() })).rejects.toMatchObject({
    code: 'UNAVAILABLE',
  });
  await expect(vault.read({ ...identity, privacyDomainId: randomUUID() })).rejects.toMatchObject({
    code: 'UNAVAILABLE',
  });
  await expect(
    vault.read({ ...identity, source: { ...identity.source, assertionDigest: sha256('other') } }),
  ).rejects.toMatchObject({ code: 'INTEGRITY' });
  await expect(vault.read({ ...identity, sinkId: 'other' })).rejects.toMatchObject({
    code: 'INVALID',
  });
  await expect(vault.read({ ...identity, objectVersion: '2' } as never)).rejects.toThrow();
  await expect(
    vault.put(identity, { ...payload, nonceBase64: randomBytes(11).toString('base64') }),
  ).rejects.toMatchObject({ code: 'INTEGRITY' });
  const path = join(root, (await readdir(root))[0]!);
  const stored = JSON.parse(await readFile(path, 'utf8'));
  stored.payload.ciphertextBase64 = randomBytes(64).toString('base64');
  await writeFile(path, JSON.stringify(stored));
  await expect(vault.verify(identity)).rejects.toMatchObject({ code: 'INTEGRITY' });
});

it('refuses a symlinked object and leaves an existing conflicting version intact', async () => {
  const { root, payload, identity, vault } = await fixture();
  await vault.put(identity, payload);
  const path = join(root, (await readdir(root))[0]!);
  const bytes = await readFile(path);
  await rm(path);
  const target = join(root, 'target');
  await writeFile(target, bytes, { mode: 0o600 });
  await symlink(target, path);
  await expect(vault.put(identity, payload)).rejects.toMatchObject({ code: 'INTEGRITY' });
  expect(await readFile(target)).toEqual(bytes);
  expect((await readdir(root)).some((name) => name.startsWith('.pending-'))).toBe(false);
});
