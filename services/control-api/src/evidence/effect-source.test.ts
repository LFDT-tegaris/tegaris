import { expect, it } from 'vitest';
import { effectOccurrenceTime } from './effect-source.js';

it('projects signed event time to UTC microseconds without replacing or rounding it', () => {
  expect(effectOccurrenceTime('2026-09-21T00:00:00Z')).toBe('2026-09-21T00:00:00.000000Z');
  expect(effectOccurrenceTime('2026-09-21T05:30:00.123456789+05:30')).toBe(
    '2026-09-21T00:00:00.123456Z',
  );
  expect(effectOccurrenceTime('2026-09-21T23:59:59.999999999Z')).toBe(
    '2026-09-21T23:59:59.999999Z',
  );
  expect(() => effectOccurrenceTime('2026-09-21T00:00:00')).toThrow();
  expect(() => effectOccurrenceTime('2026-02-30T00:00:00Z')).toThrow();
});
