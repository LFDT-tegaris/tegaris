// Shape/signature test inputs only; never a governed retirement case.
import {
  retirementAttempt,
  retirementAttemptDigest,
  retirementHost,
  retirementSelectionDigest,
} from './store-retirement-wire.js';

const digest = 'a'.repeat(64);
export function retirementWireFixture() {
  const scope = { participant_id: 'participant', privacy_domain_id: 'privacy' };
  const selection = {
    class: 'ADMITTED_FACT' as const,
    source: {
      profile_id: 'source-profile',
      generation_id: 'source-generation',
      partition_id: 'partition',
      identity_digest: digest,
    },
    fact_generation_id: 'fact-generation',
    canonical_generation: 18446744073709551615n,
    rows: [
      {
        candidate_id: 'candidate',
        fact_id: 'fact',
        fact_delta_sequence: 18446744073709551615n,
        candidate_feed_sequence: 20n,
        payload_digest: digest,
        payload_bytes: 40n,
        signed_fact_digest: digest,
        lineage_digest: digest,
        checkpoint_digest: digest,
      },
    ],
  };
  const attempt = retirementAttempt.parse({
    scope,
    store: 'openpc_facts',
    business_intent_id: 'intent',
    attempt_id: 'attempt',
    governance: {
      retention_policy_digest: digest,
      archive_manifest_digest: digest,
      archive_acknowledgement_digest: digest,
      approval_digest: digest,
      lifecycle_revision: 9n,
      retention_not_before_ms: 1700000000000n,
    },
    selection,
    selection_digest: retirementSelectionDigest(scope, selection),
  });
  const host = retirementHost.parse({
    environment_id: 'local',
    target_id: 'facts',
    scope,
    store: 'openpc_facts',
  });
  const request = {
    version: 1n as const,
    host,
    attempt,
    admission_receipt_digest: digest,
    committed_admission_digest: digest,
    issued_at_ms: 1800000000000n,
    expires_at_ms: 1800000060000n,
  };
  const outcome = {
    version: 1n as const,
    host,
    business_intent_id: 'intent',
    attempt_id: 'attempt',
    outcome: {
      attempt_digest: retirementAttemptDigest(attempt),
      effect: {
        state: 'APPLIED' as const,
        retired_rows: 1n,
        retired_payload_bytes: 40n,
        retained_lineage_digest: digest,
        outbox_event_digest: digest,
      },
    },
    completed_at_ms: 1800000000010n,
  };
  return { attempt, host, request, outcome };
}
