import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  createLocalProfileAuthenticator,
  canonicalize,
  sha256,
} from './profile-authentication.mjs';
import { createProfileFixture, definition } from './profile-authentication.fixture.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'tegaris-profile-receipts-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const data = await createProfileFixture(root);
  const authenticate = createLocalProfileAuthenticator(definition);
  return {
    ...data,
    root,
    authenticate: (profilePath, expectedPurpose = definition.allowed[profilePath]?.[0]) =>
      authenticate({ repositoryRoot: root, profilePath, expectedPurpose }),
  };
}

test('local profile receipts authenticate all exact-purpose versions with synthetic keys', async (t) => {
  const data = await fixture(t);
  for (const [path, [purpose]] of Object.entries(definition.allowed)) {
    const value = await data.authenticate(path);
    assert.deepEqual(value.profile, data.profiles.get(path));
    assert.equal(value.receipt.purpose, purpose);
    assert.equal(value.receipt.claimCeiling, 'LOCAL_NON_PRODUCTION_TECHNICAL_PROOF_ONLY');
    assert.match(value.registrySha256, /^[a-f0-9]{64}$/u);
  }
  const first = (await data.authenticate('profiles/recovery-v1.json')).profile;
  const second = (await data.authenticate('profiles/recovery-v2.json')).profile;
  const expected = structuredClone(first);
  expected.profileId = definition.recovery.profiles[2].profileId;
  expected.stores[1].mechanism = definition.recovery.profiles[2].mechanism;
  assert.deepEqual(second, expected);
});

test('profile paths and purposes reject traversal, aliases and unknown inputs before loading files', async (t) => {
  const data = await fixture(t);
  for (const path of [
    '../profiles/recovery-v1.json',
    './profiles/recovery-v1.json',
    '/profiles/recovery-v1.json',
    'profiles/../profiles/recovery-v1.json',
    'profiles/unknown.json',
  ])
    await assert.rejects(data.authenticate(path, 'RECOVERY'), /canonical|allowlisted/u);
  await assert.rejects(data.authenticate('profiles/recovery-v1.json', 'SUPPLY_CHAIN'), /purpose/u);
});

test('profile registry rejects missing, unknown, version, algorithm, stage and promoted claim metadata', async (t) => {
  const data = await fixture(t);
  for (const version of [1, 2]) {
    for (const mutate of [
      (value) => {
        delete value.schemaVersion;
      },
      (value) => {
        value.extra = true;
      },
      (value) => {
        value.schemaVersion = '2.0';
      },
      (value) => {
        value.profileId = 'UNKNOWN-SIGNER';
      },
      (value) => {
        value.stage = 'PRODUCTION';
      },
      (value) => {
        value.algorithm = 'none';
      },
      (value) => {
        value.claimCeiling = 'PRODUCTION_QUALIFIED';
      },
    ]) {
      const changed = structuredClone(data.registries.get(version));
      mutate(changed);
      await data.writeRegistry(version, changed);
      await assert.rejects(
        data.authenticate(`profiles/recovery-v${version}.json`),
        /fields|authority mismatch/u,
      );
    }
  }
});

test('profile registry requires the exact receipt set for each signer version', async (t) => {
  const data = await fixture(t);
  for (const mutate of [
    (value) => {
      value.receipts = [];
    },
    (value) => {
      value.receipts.push(value.receipts[0]);
    },
    (value) => {
      value.receipts[0].path = 'profiles/unapproved.json';
    },
    (value) => {
      value.receipts = data.registries.get(2).receipts;
    },
  ]) {
    const changed = structuredClone(data.registries.get(1));
    mutate(changed);
    await data.writeRegistry(1, changed);
    await assert.rejects(data.authenticate('profiles/recovery-v1.json'), /allowlist mismatch/u);
  }
});

test('profile receipts reject unknown fields, wrong scope, digest, signature and substituted public keys', async (t) => {
  const data = await fixture(t);
  for (const mutate of [
    (value) => {
      value.receipts[0].extra = true;
    },
    (value) => {
      delete value.receipts[0].authority;
    },
    (value) => {
      value.receipts[0].stage = 'OTHER_STAGE';
    },
    (value) => {
      value.receipts[0].purpose = 'SUPPLY_CHAIN';
    },
    (value) => {
      value.receipts[0].authority = 'OTHER_AUTHORITY';
    },
    (value) => {
      value.receipts[0].claimCeiling = 'PRODUCTION_QUALIFIED';
    },
    (value) => {
      value.receipts[0].sha256 = '0'.repeat(64);
    },
    (value) => {
      value.receipts[0].signatureBase64 = 'AA==';
    },
    (value) => {
      value.publicKeyJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
        format: 'jwk',
      });
    },
  ]) {
    const changed = structuredClone(data.registries.get(1));
    mutate(changed);
    await data.writeRegistry(1, changed);
    await assert.rejects(
      data.authenticate('profiles/recovery-v1.json'),
      /fields|digest mismatch|signature/u,
    );
  }
});

test('profile byte tampering and version substitution fail before profile consumption', async (t) => {
  const data = await fixture(t);
  const path = 'profiles/recovery-v2.json';
  for (const changed of [
    data.profiles.get('profiles/recovery-v1.json'),
    { ...data.profiles.get(path), injected: true },
  ]) {
    await writeFile(join(data.root, path), JSON.stringify(changed));
    await assert.rejects(data.authenticate(path), /digest mismatch/u);
  }
});

test('valid signatures cannot change the recovery profile version, cache mechanism or authority', async (t) => {
  const data = await fixture(t);
  for (const version of [1, 2]) {
    const path = `profiles/recovery-v${version}.json`;
    for (const mutate of [
      (value) => {
        value.profileId = definition.recovery.profiles[version === 1 ? 2 : 1].profileId;
      },
      (value) => {
        value.stores[1].mechanism = definition.recovery.profiles[version === 1 ? 2 : 1].mechanism;
      },
      (value) => {
        value.stores[1].authority = 'AUTHORITATIVE';
      },
      (value) => {
        value.stores.push(value.stores[1]);
      },
      (value) => {
        value.stores = [value.stores[0]];
      },
    ]) {
      const changed = structuredClone(data.profiles.get(path));
      mutate(changed);
      await data.writeProfile(path, changed);
      await assert.rejects(data.authenticate(path), /version or Valkey mechanism/u);
    }
  }
});

test('valid signatures cannot admit empty or canonically duplicated required collections', async (t) => {
  const data = await fixture(t);
  for (const [path, [purpose]] of Object.entries(definition.allowed)) {
    for (const field of definition.collections[purpose]) {
      for (const duplicate of [false, true]) {
        const changed = structuredClone(data.profiles.get(path));
        const first = changed[field][0];
        const repeated =
          first !== null && typeof first === 'object'
            ? Object.fromEntries(Object.entries(first).reverse())
            : first;
        changed[field] = duplicate ? [...changed[field], repeated] : [];
        await data.writeProfile(path, changed);
        await assert.rejects(
          data.authenticate(path),
          /collection is empty or duplicated|Valkey mechanism/u,
        );
      }
    }
  }
});

test('profile admission snapshots its owning definition and canonical hashing has known answers', async (t) => {
  const data = await fixture(t);
  const original = structuredClone(definition);
  const authenticate = createLocalProfileAuthenticator(original);
  original.allowed = {};
  original.stage = 'CHANGED_AFTER_CREATION';
  const value = await authenticate({
    repositoryRoot: data.root,
    profilePath: 'profiles/recovery-v1.json',
    expectedPurpose: 'RECOVERY',
  });
  assert.equal(value.receipt.stage, definition.stage);
  const document = { z: null, a: [{ c: 2, b: 1 }] };
  assert.equal(canonicalize(document), '{"a":[{"b":1,"c":2}],"z":null}');
  assert.deepEqual(document, { z: null, a: [{ c: 2, b: 1 }] });
  assert.equal(
    sha256(Buffer.from('abc')),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
  const registry = await readFile(join(data.root, definition.registries[1].path));
  assert.equal(value.registrySha256, sha256(registry));
});
