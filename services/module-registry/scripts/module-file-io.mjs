/** Close an owned handle without losing the operation's original failure. */
export async function withModuleFile(handle, operation) {
  let failed = false;
  let original;
  let result;
  try {
    result = await operation(handle);
  } catch (error) {
    failed = true;
    original = error;
  }
  try {
    await handle.close();
  } catch (closing) {
    if (failed)
      throw new AggregateError([original, closing], 'Module file operation and close failed');
    throw closing;
  }
  if (failed) throw original;
  return result;
}
