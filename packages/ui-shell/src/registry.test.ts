import { expect, it } from 'vitest';

import { actionIntents, findRoute, routes, truthStates } from './registry';

it('registers every process route, truth state and action intent', () => {
  expect(routes).toHaveLength(24);
  expect(new Set(routes.map((route) => route.path)).size).toBe(24);
  expect(truthStates).toHaveLength(20);
  expect(actionIntents).toHaveLength(14);
  expect(findRoute('/operate/privacy-explorer')?.domain).toBe('privacy-explorer-integration');
  expect(findRoute('/unregistered')).toBeUndefined();
});
