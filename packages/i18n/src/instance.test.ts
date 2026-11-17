import { expect, it } from 'vitest';

import { createOpenPcI18n } from './instance.js';

it('falls back to English and escapes interpolated values', async () => {
  const instance = await createOpenPcI18n('unknown-language');

  expect(instance.t('action.continue')).toBe('Continue');
  expect(instance.t('common.greeting', { name: '<script>' })).toContain('&lt;script&gt;');
});
