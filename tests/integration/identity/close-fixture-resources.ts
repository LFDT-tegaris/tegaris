/** Close dependent test owners in order, even after an earlier failure. Keep
 * the original test failure when cleanup also fails; never log private inputs. */
export async function closeFixtureResources(
  resources: readonly (() => void | Promise<void>)[],
  originalFailure?: { error: unknown },
) {
  const failures: unknown[] = [];
  for (const close of resources) {
    try {
      await close();
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0)
    throw new AggregateError(
      [...(originalFailure ? [originalFailure.error] : []), ...failures],
      'Fixture resource cleanup failed; original material must be retained',
    );
}
