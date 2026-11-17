/** Drizzle 0.31 emits DROP/ADD for a changed stored generated expression and
 * puts a composite FK before its new UNIQUE parent key. PostgreSQL 18 supports
 * SET EXPRESSION: preserve the existing column, its values and dependent FKs.
 * Transform only this exact new owning-schema migration, never historical SQL. */
export function orderIdentityEnvelopeProposalUpgrade(base) {
  if (!base.includes('CREATE TABLE "control"."identity_envelope_proposal"')) return base;
  const issuer =
    'ALTER TABLE "control"."authority_envelope" ADD COLUMN "issuer_participant_id" uuid;';
  const drop = 'ALTER TABLE "control"."authority_envelope" drop column "creator_participant_id";';
  const addition =
    'ALTER TABLE "control"."authority_envelope" ADD COLUMN "creator_participant_id" uuid GENERATED ALWAYS AS (coalesce(issuer_participant_id,bootstrap_platform_participant_id,participant_id)) STORED NOT NULL;';
  const alteration =
    'ALTER TABLE "control"."authority_envelope" ALTER COLUMN "creator_participant_id" SET EXPRESSION AS (coalesce(issuer_participant_id,bootstrap_platform_participant_id,participant_id));';
  const count = (value) => base.split(value).length - 1;
  if (count(issuer) !== 1) throw new Error('Missing or ambiguous envelope issuer column');
  if (count(drop) === 1 && count(addition) === 1 && count(alteration) === 0) {
    base = base.replace(issuer, '').replace(addition, '').replace(drop, `${issuer}\n${alteration}`);
  } else if (
    count(drop) !== 0 ||
    count(addition) !== 0 ||
    count(alteration) !== 1 ||
    base.indexOf(issuer) > base.indexOf(alteration)
  ) {
    throw new Error('Unsupported envelope generated-column migration');
  }
  const key =
    /ALTER TABLE "control"\."authority_envelope" ADD CONSTRAINT "authority_envelope_typed_issuer_uq" UNIQUE\("participant_id","issuer_participant_id","issuer_privacy_domain_id","authority_envelope_id"\);/gu;
  const keys = [...base.matchAll(key)];
  const reference =
    /ALTER TABLE "control"\."identity_envelope_proposal" ADD CONSTRAINT "identity_envelope_proposal_target_fk" FOREIGN KEY/gu;
  const references = [...base.matchAll(reference)];
  if (keys.length !== 1 || references.length !== 1)
    throw new Error('Missing or ambiguous envelope composite FK prerequisite');
  if (keys[0].index < references[0].index) return base;
  return base
    .replace(keys[0][0], '')
    .replace(references[0][0], `${keys[0][0]}\n${references[0][0]}`);
}
