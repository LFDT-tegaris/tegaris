import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
// Static ownership regression only. Real UNKNOWN/COMMIT/TLS acceptance belongs
// to the existing PostgreSQL fixture, never mocked internal persistence.
it('keeps provider perform behind committed one-use claim and recovery lookup-only', () => {
  const text = readFileSync(
    new URL('./completion-disposition-runtime.ts', import.meta.url),
    'utf8',
  );
  const lookup = text.slice(text.indexOf('async reconcile('));
  expect(lookup).toContain('provider.lookup(');
  expect(lookup).not.toContain('.perform(');
  expect(text).toContain('consumeNotificationCompletionSigningClaim(cap)');
  expect(text.indexOf('consumeNotificationCompletionSigningClaim(cap)')).toBeLessThan(
    text.indexOf('provider.perform('),
  );
  expect(text).toContain('createHttpNotificationCompletionDispositionProvider');
  expect(text).not.toMatch(/setTimeout|fetch\(|https\.request|authorized:\s*true/u);
});
