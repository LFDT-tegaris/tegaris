import { expect, it } from 'vitest';
import { closeFixtureResources } from '../../../../tests/integration/identity/close-fixture-resources.js';

it.each([0, 1, 2])('closes every later owner after resource %i fails', async (failed) => {
  const calls: number[] = [];
  const original = new Error('Original assertion failure');
  const cleanup = new Error('Resource close failure');
  await expect(
    closeFixtureResources(
      [0, 1, 2].map((index) => async () => {
        calls.push(index);
        if (index === failed) throw cleanup;
      }),
      { error: original },
    ),
  ).rejects.toMatchObject({ errors: [original, cleanup] });
  expect(calls).toEqual([0, 1, 2]);
});

it('retains every synchronous/asynchronous failure, including undefined thrown values', async () => {
  const first = new Error('Synchronous close failure');
  const last = new Error('Asynchronous close failure');
  await expect(
    closeFixtureResources(
      [
        () => {
          throw first;
        },
        async () => {
          throw last;
        },
      ],
      { error: undefined },
    ),
  ).rejects.toMatchObject({ errors: [undefined, first, last] });
});

it('awaits each successful owner and leaves the original test outcome to its caller', async () => {
  const calls: string[] = [];
  await expect(
    closeFixtureResources(
      [
        async () => {
          await Promise.resolve();
          calls.push('participant');
        },
        () => {
          calls.push('identity');
        },
      ],
      { error: new Error('Original failure remains owned by the test') },
    ),
  ).resolves.toBeUndefined();
  expect(calls).toEqual(['participant', 'identity']);
});
