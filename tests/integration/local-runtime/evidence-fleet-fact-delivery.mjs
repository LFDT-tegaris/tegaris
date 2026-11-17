import assert from 'node:assert/strict';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';

/** Observe real native Fleet commits and independent producer reconciliation.
 * This driver creates no admission, acknowledgement or current authority. */
export async function verifyFleetFactDelivery(control, factReader, participant, privacy, events) {
  assert.ok(events.length > 0);
  const scope = [participant, privacy];
  const snapshot = async () => {
    const client = await factReader.connect();
    try {
      await client.query('begin read only');
      await client.query(
        "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
        scope,
      );
      return (
        await client.query(
          `select a.candidate_id,a.event_id::text,a.material,a.material_digest,a.acknowledged_at::text,
        'sha256:'||encode(f.fact_digest,'hex') fact_digest,'sha256:'||encode(sha256(f.cose_sign1),'hex') signed_fact_digest,
        f.generation_id from facts.fleet_admission_ack a
        join facts.canonical_fact f using(candidate_id,participant_id,privacy_domain_id)
        where a.participant_id=$1 and a.privacy_domain_id=$2 order by event_id`,
          scope,
        )
      ).rows;
    } finally {
      await client.query('rollback');
      client.release();
    }
  };
  let acknowledgements;
  for (let attempt = 0; attempt < 30; attempt++) {
    acknowledgements = await snapshot();
    if (acknowledgements.length === events.length) break;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  assert.equal(
    acknowledgements.length,
    events.length,
    'native producer observes every original Fleet admission',
  );
  const inbox = (
    await control.query(
      `select i.event_id::text,i.material,i.material_digest,i.sequence::text,c.sequence::text cursor
    from control.fleet_fact_admission_inbox i join control.fleet_fact_admission_cursor c using(participant_id,privacy_domain_id,fact_type)
    where i.participant_id=$1 and i.privacy_domain_id=$2 order by event_id`,
      scope,
    )
  ).rows;
  assert.equal(inbox.length, events.length);
  for (const ack of acknowledgements) {
    const retained = inbox.find((row) => row.event_id === ack.event_id);
    const original = events.find((row) => row.event_id === ack.event_id);
    assert.ok(retained && original);
    assert.deepEqual(ack.material, retained.material);
    assert.deepEqual(ack.material_digest, retained.material_digest);
    assert.equal(sha256(ack.material), `sha256:${ack.material_digest.toString('hex')}`);
    const material = JSON.parse(ack.material.toString('utf8'));
    assert.equal(material.consumerId, 'LS-FLEET-CONTROL');
    assert.equal(material.participantId, participant);
    assert.equal(material.privacyDomainId, privacy);
    assert.equal(material.candidateId, ack.candidate_id);
    assert.equal(material.factDigest, ack.fact_digest);
    assert.equal(material.signedFactDigest, ack.signed_fact_digest);
    assert.deepEqual(material.envelope, original.envelope);
    assert.equal(material.sequence, retained.sequence);
    assert.ok(BigInt(retained.cursor) >= BigInt(retained.sequence));
  }
  process.stdout.write(
    `FLEET_FACT_DELIVERY|PASS|original_admissions=${inbox.length}|producer_acks=${acknowledgements.length}|authority=NONE\n`,
  );
  return acknowledgements;
}
