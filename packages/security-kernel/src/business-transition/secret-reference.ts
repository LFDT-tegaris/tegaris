/** SecretRef syntax from configuration.schema.json, with explicit versions and no aliases. */
export const signingSecretReferencePattern =
  '^secret://[a-z][a-z0-9-]{1,31}/[A-Za-z0-9._/-]{1,192}#[A-Za-z0-9._-]{1,96}$';
export const signingSecretReferenceMaxLength = 331;
const referencePattern = new RegExp(signingSecretReferencePattern, 'u');

export function isExactSigningSecretReference(reference: unknown, version: unknown): boolean {
  return (
    typeof reference === 'string' &&
    typeof version === 'string' &&
    referencePattern.exec(reference)?.[0] === reference &&
    reference.split('#')[1] === version &&
    !['latest', 'current'].includes(version.toLowerCase())
  );
}
