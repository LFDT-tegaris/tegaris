import assert from 'node:assert/strict';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';

/** Observe the real producer transition; never seed an ACK or change eligibility. */
export async function verifyProducerFactDelivery(facts, participant, privacy, events) {
  let rows;
  for (let attempt = 0; attempt < 30; attempt++) {
    rows = (
      await facts.query(
        `select f.candidate_id,e.event_id::text,o.delivery_state,p.delivery_state publication_state,
        f.fact_digest,o.fact_digest outbox_digest,g.shard_cose_sign1,p.manifest_digest,p.content_digest,g.shard_digest,
        p.descriptor,c.event_id::text control_event,a.event_id::text fleet_event
        from facts.canonical_fact f join facts.outbox o using(candidate_id,participant_id,privacy_domain_id)
        join facts.admission_delivery_event e using(candidate_id,participant_id,privacy_domain_id,generation_id)
        join facts.shard_publication p using(participant_id,privacy_domain_id,generation_id)
        join facts.readiness_gate g using(participant_id,privacy_domain_id,generation_id)
        join facts.control_admission_custody_ack c using(candidate_id,participant_id,privacy_domain_id)
        join facts.fleet_admission_ack a using(candidate_id,participant_id,privacy_domain_id)
        where f.participant_id=$1 and f.privacy_domain_id=$2 order by candidate_id`,
        [participant, privacy],
      )
    ).rows;
    if (
      rows.length === events.length &&
      rows.every(
        (row) => row.delivery_state === 'DELIVERED' && row.publication_state === 'DELIVERED',
      )
    )
      break;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  assert.equal(rows.length, events.length);
  for (const row of rows) {
    assert.ok(events.some((event) => event.event_id === row.event_id));
    assert.equal(row.delivery_state, 'DELIVERED');
    assert.equal(row.publication_state, 'DELIVERED');
    assert.equal(row.control_event, row.event_id);
    assert.equal(row.fleet_event, row.event_id);
    assert.deepEqual(row.fact_digest, row.outbox_digest);
    assert.deepEqual(row.shard_digest, row.content_digest);
    assert.equal(sha256(row.shard_cose_sign1), `sha256:${row.manifest_digest.toString('hex')}`);
    assert.deepEqual(row.descriptor, {
      mediaType: 'application/vnd.openpc.fact-shard-manifest.v1+cbor',
      digest: sha256(row.shard_cose_sign1),
      size: row.shard_cose_sign1.length,
    });
  }
  process.stdout.write(
    `FACT_PRODUCER_DELIVERY|PASS|originals=${rows.length}|both_consumers|publication=DELIVERED\n`,
  );
  return rows;
}
