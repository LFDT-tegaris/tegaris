/** Drizzle emits the new composite FK before the UNIQUE on its existing parent.
 * Move that exact generated prerequisite only; no hand-authored DDL or history. */
export function orderIdentityEnvelopeSigningPrerequisite(base) {
  if (!base.includes('CREATE TABLE "control"."identity_envelope_signing_grant"')) return base;
  const unique =
    /ALTER TABLE "control"\."business_signing_key" ADD CONSTRAINT "business_signing_key_purpose_uq" UNIQUE[^;]+;/gu;
  const statements = [...base.matchAll(unique)];
  const foreignKey =
    /ALTER TABLE "control"\."identity_envelope_signing_grant" ADD CONSTRAINT "identity_envelope_signing_grant_key_fk" FOREIGN KEY/u;
  const binding = base.match(foreignKey);
  if (
    statements.length !== 1 ||
    binding === null ||
    !base.includes('ADD COLUMN "signing_purpose_code"')
  )
    throw new Error('Missing generated identity envelope signing prerequisite');
  if (statements[0].index < binding.index) return base;
  return base
    .replace(statements[0][0], '')
    .replace(foreignKey, (match) => `${statements[0][0]}\n${match}`);
}
