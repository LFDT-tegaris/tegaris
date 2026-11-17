import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { expect, it } from 'vitest';

import { selectProfiles, type AssertionProfile } from './resolver.js';

const profilesPath = resolve(import.meta.dirname, 'fixtures/assertion-profiles.jsonl');

it('selects every applicable profile conjunctively', async () => {
  const profiles = (await readFile(profilesPath, 'utf8'))
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as AssertionProfile);

  const selected = selectProfiles(profiles, 'AF30_R1', {
    expected: { error: 'DENIED', result: 'NO_PRODUCT_STATE_CHANGE' },
    requirementIds: [],
  });

  expect(selected.map((profile) => profile.assertionProfileId)).toEqual(
    expect.arrayContaining(['AP-SUCCESS-CONTRACT', 'AP-TYPED-ERROR']),
  );
});
