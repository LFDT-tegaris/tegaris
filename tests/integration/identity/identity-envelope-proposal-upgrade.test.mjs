import assert from 'node:assert/strict';
import test from 'node:test';
import { orderIdentityEnvelopeProposalUpgrade as order } from '../../../services/identity-service/src/db/identity-envelope-proposal-upgrade.mjs';

const issuer =
  'ALTER TABLE "control"."authority_envelope" ADD COLUMN "issuer_participant_id" uuid;';
const key =
  'ALTER TABLE "control"."authority_envelope" ADD CONSTRAINT "authority_envelope_typed_issuer_uq" UNIQUE("participant_id","issuer_participant_id","issuer_privacy_domain_id","authority_envelope_id");';
const input = `CREATE TABLE "control"."identity_envelope_proposal" ("envelope_id" uuid PRIMARY KEY);
ALTER TABLE "control"."authority_envelope" drop column "creator_participant_id";
ALTER TABLE "control"."authority_envelope" ADD COLUMN "creator_participant_id" uuid GENERATED ALWAYS AS (coalesce(issuer_participant_id,bootstrap_platform_participant_id,participant_id)) STORED NOT NULL;
${issuer}
ALTER TABLE "control"."authority_envelope" ADD COLUMN "issuer_privacy_domain_id" uuid;
ALTER TABLE "control"."identity_envelope_proposal" ADD CONSTRAINT "identity_envelope_proposal_target_fk" FOREIGN KEY ("target_participant_id","participant_id","privacy_domain_id","envelope_id") REFERENCES "control"."authority_envelope"("participant_id","issuer_participant_id","issuer_privacy_domain_id","authority_envelope_id");
${key}`;

test('keeps the generated column and its dependent FKs while ordering exact generated prerequisites', () => {
  const output = order(input);
  assert.doesNotMatch(output, /drop column|ADD COLUMN "creator_participant_id"/u);
  assert.match(output, /ALTER COLUMN "creator_participant_id" SET EXPRESSION AS/u);
  assert.ok(output.indexOf(issuer) < output.indexOf('SET EXPRESSION'));
  assert.ok(output.indexOf('issuer_privacy_domain_id" uuid') < output.indexOf(key));
  assert.ok(
    output.indexOf(key) < output.indexOf('ADD CONSTRAINT "identity_envelope_proposal_target_fk"'),
  );
  assert.equal(order(output), output);
  assert.equal(order('unrelated generated migration'), 'unrelated generated migration');
});
test('rejects changed, missing or ambiguous generated DDL instead of guessing an upgrade', () => {
  for (const changed of [
    input.replace(issuer, ''),
    input + issuer,
    input.replace(key, ''),
    input + key,
    input.replace(
      'coalesce(issuer_participant_id,bootstrap_platform_participant_id,participant_id)',
      'coalesce(participant_id,issuer_participant_id)',
    ),
    input.replace('drop column "creator_participant_id"', 'drop column "another_column"'),
  ]) {
    assert.throws(() => order(changed));
  }
});
