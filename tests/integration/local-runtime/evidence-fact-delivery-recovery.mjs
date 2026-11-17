import assert from 'node:assert/strict';
import { verifyFleetFactDelivery } from './evidence-fleet-fact-delivery.mjs';
import { verifyProducerFactDelivery } from './evidence-producer-fact-delivery.mjs';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import { readFactEvidenceBatch } from '../../../services/control-api/src/evidence/fact-source.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';

// Joined recovery of existing real admissions: no Fact, approval, lifecycle
// result, delivery ACK or retired projection is created by this driver. The
// real Fact maintenance owner must acknowledge committed Control custody.
export async function exerciseFactDeliveryRecovery(secretRoot, configPath, fault = true) {
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  assert.equal(config.database.host, '127.0.0.1');
  const worker = new Pool({
    ...config.database,
    password: (await readFile(config.database.passwordFile, 'utf8')).trim(),
    max: 2,
  });
  const admin = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  const factReader = new Pool({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_policy_fact_runtime',
    password: (await readFile(join(secretRoot, 'policy_fact_db_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  const factAdmin = new Pool({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_facts',
    password: (await readFile(join(secretRoot, 'fact_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  const participantId = config.scopes[0].participantId,
    privacyDomainId = config.scopes[0].privacyDomainId;
  for (const entry of config.scopes) {
    assert.equal(entry.participantId, participantId);
    assert.equal(entry.privacyDomainId, privacyDomainId);
  }
  const scopeValues = [participantId, privacyDomainId];
  const snapshot = async () =>
    (
      await admin.query(
        `select c.stream_id,c.record_id,c.receipt_digest,c.segment_id,c.sequence::text,f.projection_digest,
  exists(select 1 from control.evidence_segment_payload p where p.participant_id=c.participant_id and p.privacy_domain_id=c.privacy_domain_id and p.stream_id=c.stream_id and p.segment_id=c.segment_id) payload
  from control.evidence_catalogue c left join control.evidence_fact_provenance f using(participant_id,privacy_domain_id,stream_id,record_id)
  where c.participant_id=$1 and c.privacy_domain_id=$2 and c.source_format='OPENPC_CANONICAL_FACT_V1' order by c.stream_id,c.sequence`,
        scopeValues,
      )
    ).rows;
  const inbox = async () =>
    (
      await admin.query(
        'select event_id,envelope,envelope_digest,stream_id,record_id from control.evidence_fact_admission_inbox where participant_id=$1 and privacy_domain_id=$2 order by event_id',
        scopeValues,
      )
    ).rows;
  const cleanupFault = () =>
    admin.query(
      'drop trigger if exists test_fact_inbox_commit_loss on control.evidence_fact_admission_inbox; drop function if exists openpc.test_fact_inbox_commit_loss()',
    );
  const acknowledgements = async () => {
    const client = await factReader.connect();
    try {
      await client.query('begin read only');
      await client.query(
        "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
        scopeValues,
      );
      return (
        await client.query(
          `select candidate_id,event_id::text,material,material_digest,acknowledged_at::text
           from facts.control_admission_custody_ack where participant_id=$1 and privacy_domain_id=$2 order by event_id`,
          scopeValues,
        )
      ).rows;
    } finally {
      await client.query('rollback');
      client.release();
    }
  };
  try {
    const priorAcks = await acknowledgements();
    const before = await snapshot();
    assert.ok(before.length > 0);
    assert.ok(before.every((row) => row.payload));
    const originals = await factReader.connect();
    let events;
    try {
      await originals.query('begin read only');
      await originals.query(
        "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
        scopeValues,
      );
      events = (
        await originals.query(
          `select e.event_id::text,e.envelope from facts.admission_delivery_event e where e.participant_id=$1 and e.privacy_domain_id=$2 order by e.event_id`,
          scopeValues,
        )
      ).rows;
    } finally {
      await originals.query('rollback');
      originals.release();
    }
    assert.equal(events.length, before.length);
    const originalOutbox = (
      await factAdmin.query(
        'select candidate_id,delivery_state from facts.outbox where participant_id=$1 and privacy_domain_id=$2 order by candidate_id',
        scopeValues,
      )
    ).rows;
    assert.equal(originalOutbox.length, events.length);
    assert.ok(originalOutbox.every((row) => ['PENDING', 'DELIVERED'].includes(row.delivery_state)));
    if (fault) assert.ok(originalOutbox.every((row) => row.delivery_state === 'PENDING'));
    if (fault)
      assert.equal(
        (await inbox()).length,
        0,
        'fault test requires the original unconsumed identities',
      );
    if (fault) assert.equal(priorAcks.length, 0);
    const until = new Date(Date.now() + 86400000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
    for (const [index, entry] of config.scopes.entries()) {
      const scope = { participantId, privacyDomainId, streamId: entry.streamId };
      const key = entry.keys.find((key) => key.keyId === entry.activeKeyId);
      assert.ok(key);
      const encryption = { keyId: key.keyId, key: await readFile(key.keyFile) };
      if (fault && index === 0) {
        const client = await worker.connect();
        let page;
        try {
          await client.query('begin');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            [...scopeValues, uuidv7()],
          );
          page = await readFactEvidenceBatch(client, scope, entry.fact);
        } finally {
          await client.query('rollback');
          client.release();
        }
        assert.ok(page.length > 0);
        assert.ok(page.every((row) => row.admissionDelivery));
        const target = page.at(-1).provenance.candidateId;
        assert.match(target, /^[0-9a-f-]{36}$/u);
        await assert.rejects(
          () =>
            new EvidenceCustody(worker).ingestFact(
              scope,
              entry.fact,
              { ...encryption, key: randomBytes(32) },
              until,
              entry.capacityBytes,
            ),
          /integrity/u,
        );
        assert.equal((await inbox()).length, 0);
        assert.equal((await acknowledgements()).length, 0);
        await admin.query(`create function openpc.test_fact_inbox_commit_loss() returns trigger language plpgsql as $$ begin if NEW.candidate_id::text=TG_ARGV[0] then raise exception 'TEST_FACT_INBOX_COMMIT_LOSS'; end if;return NEW;end $$;
      create trigger test_fact_inbox_commit_loss after insert on control.evidence_fact_admission_inbox for each row execute function openpc.test_fact_inbox_commit_loss('${target}')`);
        try {
          await assert.rejects(
            () =>
              new EvidenceCustody(worker).ingestFact(
                scope,
                entry.fact,
                encryption,
                until,
                entry.capacityBytes,
              ),
            /TEST_FACT_INBOX_COMMIT_LOSS/u,
          );
        } finally {
          await cleanupFault();
        }
        assert.equal((await inbox()).length, 0);
        assert.equal((await acknowledgements()).length, 0);
        assert.deepEqual(await snapshot(), before);
      }
      assert.deepEqual(
        await Promise.all(
          [0, 1].map(() =>
            new EvidenceCustody(worker).ingestFact(
              scope,
              entry.fact,
              encryption,
              until,
              entry.capacityBytes,
            ),
          ),
        ),
        [null, null],
      );
      assert.equal(
        await new EvidenceCustody(worker).ingestFact(
          scope,
          entry.fact,
          encryption,
          until,
          entry.capacityBytes,
        ),
        null,
      );
    }
    const retained = await inbox();
    assert.equal(retained.length, events.length);
    for (const row of retained) {
      const original = events.find((event) => event.event_id === row.event_id);
      assert.ok(original);
      assert.deepEqual(row.envelope, original.envelope);
      assert.equal(row.envelope_digest, sha256(original.envelope));
    }
    const cursor = (
      await admin.query(
        `select fact_type,sequence::text from control.evidence_fact_admission_cursor where participant_id=$1 and privacy_domain_id=$2`,
        scopeValues,
      )
    ).rows;
    for (const row of cursor) {
      const maximum = await factReader.connect();
      try {
        await maximum.query('begin read only');
        await maximum.query(
          "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
          scopeValues,
        );
        const head =
          (
            await maximum.query(
              'select sequence::text from facts.admission_delivery_head where participant_id=$1 and privacy_domain_id=$2 and fact_type=$3',
              [...scopeValues, row.fact_type],
            )
          ).rows[0]?.sequence ?? '0';
        assert.equal(row.sequence, head);
      } finally {
        await maximum.query('rollback');
        maximum.release();
      }
    }
    let acks;
    for (let attempt = 0; attempt < 30; attempt++) {
      acks = await acknowledgements();
      if (acks.length === events.length) break;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    assert.equal(
      acks.length,
      events.length,
      'native producer must observe committed Control custody',
    );
    for (const ack of acks) {
      const entry = retained.find((row) => row.event_id === ack.event_id);
      assert.ok(entry);
      const material = JSON.parse(ack.material.toString('utf8'));
      assert.equal(sha256(ack.material), `sha256:${ack.material_digest.toString('hex')}`);
      assert.equal(material.consumerId, 'LS-CONTROL-WORK');
      assert.equal(material.candidateId, ack.candidate_id);
      assert.equal(material.participantId, participantId);
      assert.equal(material.privacyDomainId, privacyDomainId);
      assert.equal(material.streamId, entry.stream_id);
      assert.equal(material.recordId, entry.record_id);
      assert.deepEqual(material.envelope, entry.envelope);
      const prior = priorAcks.find((row) => row.event_id === ack.event_id);
      if (prior) assert.deepEqual(ack, prior, 'restart/replay retains original ACK bytes and time');
    }
    assert.deepEqual(
      await snapshot(),
      before,
      'original catalogue, payload custody and retired projection absence survive recovery',
    );
    await verifyFleetFactDelivery(admin, factReader, participantId, privacyDomainId, events);
    await verifyProducerFactDelivery(factAdmin, participantId, privacyDomainId, events);
    return {
      facts: events.length,
      retiredProjections: before.filter((row) => row.projection_digest === null).length,
      controlCustodyAcks: acks.length,
      outboxState: 'DELIVERED',
      faultRecovery: fault,
    };
  } finally {
    await cleanupFault();
    await Promise.all([worker.end(), admin.end(), factReader.end(), factAdmin.end()]);
  }
}
if (process.argv[1]?.endsWith('/evidence-fact-delivery-recovery.mjs')) {
  const result = await exerciseFactDeliveryRecovery(
    process.argv[2],
    process.argv[3],
    process.argv[4] !== 'replay',
  );
  process.stdout.write(`FACT_CONSUMER_RECOVERY|PASS|${JSON.stringify(result)}\n`);
}
