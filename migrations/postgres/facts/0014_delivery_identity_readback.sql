-- Original-event verification needs only scoped identity and original time.
-- Keep retained payload digests, lifecycle attempts and mutation privileges
-- outside the policy reader's delivery-readback capability.
CREATE POLICY delivery_identity_read_context ON facts.retained_fact_identity
  FOR SELECT TO openpc_policy_fact_reader
  USING (facts.matches_context(participant_id,privacy_domain_id));
GRANT SELECT (candidate_id,participant_id,privacy_domain_id,admitted_at)
  ON facts.retained_fact_identity TO openpc_policy_fact_reader;
