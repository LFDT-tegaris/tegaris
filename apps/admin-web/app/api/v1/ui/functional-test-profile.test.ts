import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import {
  functionalActor,
  functionalContext,
  functionalTestProfileSchema,
  readFunctionalTestProfile,
  withFunctionalAssertion,
} from './functional-test-profile';

let root = '';
afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
});

it('is off by default and rejects activation outside an explicitly configured local QA installation', async () => {
  expect(await readFunctionalTestProfile({})).toBeUndefined();
  expect(await readFunctionalTestProfile({ OPENPC_FUNCTIONAL_TEST: '0' })).toBeUndefined();
  for (const environment of [
    { OPENPC_FUNCTIONAL_TEST: 'yes' },
    { OPENPC_FUNCTIONAL_TEST: '1', OPENPC_LOCAL_RUNTIME: '1' },
    {
      OPENPC_FUNCTIONAL_TEST: '1',
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    },
  ])
    await expect(readFunctionalTestProfile(environment)).rejects.toThrow();
  expect(functionalActor(undefined)).toBe('operator');
  expect(functionalActor('viewer')).toBe('viewer');
  expect(functionalActor('administrator')).toBeUndefined();
  expect(functionalContext(undefined)).toBe('PARTICIPANT');
  expect(functionalContext('PLATFORM')).toBe('PLATFORM');
  expect(functionalContext('administrator')).toBeUndefined();
});

it('preserves the original profile and requires distinct Platform sessions for both actors', () => {
  const participantId = '018f0000-0000-7000-8000-000000000101';
  const actor = (suffix: '1' | '2') => ({
    sessionToken: `${participantId}.018f0000-0000-7000-8000-00000000040${suffix}`,
    principalId: `018f0000-0000-7000-8000-00000000011${suffix}`,
    participantId,
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    credentialId: `018f0000-0000-7000-8000-00000000030${suffix}`,
    assertionCredentialId: `018f0000-0000-7000-8000-00000000030${suffix}`,
    privateKeyFile: `/private/${suffix}.der`,
    counterFile: `/private/${suffix}.counter`,
  });
  const original = { version: 1, actors: { operator: actor('1'), viewer: actor('2') } };
  expect(functionalTestProfileSchema.parse(original)).toEqual(original);
  const platform = {
    version: 1,
    actors: {
      operator: {
        ...original.actors.operator,
        platformSessionToken: `${participantId}.018f0000-0000-7000-8000-000000000501`,
      },
      viewer: {
        ...original.actors.viewer,
        platformSessionToken: `${participantId}.018f0000-0000-7000-8000-000000000502`,
      },
    },
  };
  expect(functionalTestProfileSchema.parse(platform)).toEqual(platform);
  for (const changed of [
    { ...platform, actors: { ...platform.actors, viewer: original.actors.viewer } },
    {
      ...platform,
      actors: {
        ...platform.actors,
        operator: {
          ...platform.actors.operator,
          platformSessionToken: original.actors.operator.sessionToken,
        },
      },
    },
    {
      ...platform,
      actors: {
        ...platform.actors,
        viewer: {
          ...platform.actors.viewer,
          platformSessionToken: platform.actors.operator.platformSessionToken,
        },
      },
    },
  ])
    expect(functionalTestProfileSchema.safeParse(changed).success).toBe(false);
});

it('signs the exact challenge and origin, durably advances the counter and excludes concurrent use', async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-functional-key-'));
  const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const actor = {
    sessionToken: '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000401',
    principalId: '018f0000-0000-7000-8000-000000000111',
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    credentialId: '018f0000-0000-7000-8000-000000000301',
    assertionCredentialId: '018f0000-0000-7000-8000-000000000301',
    privateKeyFile: join(root, 'key.der'),
    counterFile: join(root, 'counter'),
  };
  await writeFile(actor.privateKeyFile, keys.privateKey.export({ format: 'der', type: 'pkcs8' }));
  await writeFile(actor.counterFile, '7\n');
  const input = {
    challenge: 'bound-challenge-000000000000000001',
    origin: 'http://localhost:8080',
  };
  await withFunctionalAssertion(actor, input, async (assertion) => {
    const data = Buffer.from(assertion.authenticatorData, 'base64url');
    const client = Buffer.from(assertion.clientDataJson, 'base64url');
    expect(JSON.parse(client.toString())).toEqual({
      type: 'webauthn.get',
      ...input,
      crossOrigin: false,
    });
    expect(data.subarray(0, 32)).toEqual(createHash('sha256').update('localhost').digest());
    expect(data.readUInt32BE(33)).toBe(8);
    expect(await readFile(actor.counterFile, 'utf8')).toBe('8\n');
    expect(
      verify(
        'sha256',
        Buffer.concat([data, createHash('sha256').update(client).digest()]),
        keys.publicKey,
        Buffer.from(assertion.signature, 'base64url'),
      ),
    ).toBe(true);
    await expect(
      withFunctionalAssertion(actor, input, async () => undefined),
    ).rejects.toMatchObject({ code: 'EEXIST' });
  });
  await expect(readFile(`${actor.counterFile}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
  await expect(
    withFunctionalAssertion(actor, input, async () => {
      throw new Error('Native verification denied');
    }),
  ).rejects.toThrow('Native verification denied');
  expect(await readFile(actor.counterFile, 'utf8')).toBe('9\n');
  await expect(readFile(`${actor.counterFile}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
});
