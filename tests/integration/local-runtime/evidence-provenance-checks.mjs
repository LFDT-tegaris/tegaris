import { readFile, writeFile, chmod } from 'node:fs/promises';
import { createECDH } from 'node:crypto';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { readEvidenceProvenance } from '../../../services/control-api/src/evidence/provenance.ts';
import { readDeploymentProvenance } from '../../../services/control-api/src/evidence/deployment-provenance.ts';
import {
  readAuthenticationProvenance,
  readBusinessProvenance,
  readRejectionProvenance,
} from '../../../services/control-api/src/evidence/receipt-provenance.ts';
import {
  businessSourceSelect,
  verifyBusinessSource,
} from '../../../services/control-api/src/evidence/business-source.ts';
import { verifyAuthenticationSource } from '../../../services/control-api/src/evidence/authentication-source.ts';
import {
  readRpcProvenance,
  verifyRpcProjection,
} from '../../../services/control-api/src/evidence/rpc-provenance.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';

export async function verifyRpcProjectionSqlGuards(pool, scope) {
  const client = await pool.connect();
  const values = [scope.participantId, scope.privacyDomainId, scope.streamId];
  try {
    await client.query('begin');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,'018f0000-0000-7000-8000-000000000301','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      values.slice(0, 2),
    );
    const source = (
      await client.query(
        `select record_id,projection from control.evidence_rpc_provenance
      where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by record_id limit 1`,
        values,
      )
    ).rows[0];
    assert.ok(source, 'actual reconciled RPC source');
    const insert = (projection) =>
      client.query(
        `insert into control.evidence_rpc_provenance
      (participant_id,privacy_domain_id,stream_id,record_id,projection,projection_digest)
      values($1,$2,$3,$4,$5,$6) on conflict do nothing`,
        [...values, source.record_id, projection, sha256(projection)],
      );
    // Valid exact replay traverses the complete guard before ON CONFLICT.
    // Malformed inputs can fail before a broken source/activation join.
    await insert(source.projection);
    for (const projection of [
      { ...source.projection, raw: 'forbidden unminimized field' },
      { ...source.projection, sourceDigest: `sha256:${'0'.repeat(64)}` },
      {
        ...source.projection,
        activation: {
          ...source.projection.activation,
          attemptId: '018f0000-0000-7000-8000-000000000901',
        },
      },
      {
        ...source.projection,
        transition: { ...source.projection.transition, raw: 'forbidden nested field' },
      },
    ]) {
      await client.query('savepoint guard');
      await assert.rejects(insert(projection), /PC-DATA-6007/u);
      await client.query('rollback to savepoint guard');
    }
    for (const sql of [
      'update control.evidence_rpc_provenance set projection=projection where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
      'delete from control.evidence_rpc_provenance where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
    ]) {
      await client.query('savepoint immutable');
      await assert.rejects(client.query(sql, values), (error) => error.code === '42501');
      await client.query('rollback to savepoint immutable');
    }
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,'018f0000-0000-7000-8000-000000000301','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',true)",
      values.slice(0, 2),
    );
    await client.query('savepoint action');
    await assert.rejects(insert(source.projection), /PC-AUTH-0005/u);
    await client.query('rollback to savepoint action');
    for (const [participant, privacy] of [
      [scope.participantId, '018f0000-0000-7000-8000-000000000202'],
      ['018f0000-0000-7000-8000-000000000102', scope.privacyDomainId],
    ]) {
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,'018f0000-0000-7000-8000-000000000301','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',true)",
        [participant, privacy],
      );
      assert.equal(
        (
          await client.query(
            'select 1 from control.evidence_rpc_provenance where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
            values,
          )
        ).rowCount,
        0,
      );
    }
  } finally {
    await client.query('rollback');
    client.release();
  }
}

// Verify retained source records without provisioning
// intermediate state. Callers name required families; each has a distinct oracle.
export async function verifyReceiptProvenanceSources(
  client,
  participantId,
  privacyDomainId,
  formats,
) {
  const selected = await client.query(
    `with originals as (select distinct on(source_format,record_id) evidence_id::text id,record_id as "recordId",receipt_digest as "recordDigest",
     source_format as "sourceFormat",stream_id as "streamId",
     to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
     from control.evidence_catalogue c where participant_id=$1 and privacy_domain_id=$2 and source_format=any($3::text[])
      and (source_format<>'PC-DEPLOYMENT-RESERVATION-REJECTION-1' or exists(select 1 from control.deployment_result r
       where r.participant_id=c.participant_id and r.privacy_domain_id=c.privacy_domain_id
        and c.record_id='deployment:'||r.command_id::text||':'||r.sequence::text and c.receipt_digest=r.result_digest))
     order by source_format,record_id,created_at), ranked as (select o.*,row_number() over(partition by o."sourceFormat",a.method,a.context_mode order by o."recordId") n
      from originals o left join control.authentication_occurrence a on o."sourceFormat"='OPENPC_AUTHENTICATION_OCCURRENCE_V1'
       and a.occurrence_id::text=o."recordId" and a.participant_id=$1 and a.privacy_domain_id=$2)
     select * from ranked where n<=case when "sourceFormat"='OPENPC_AUTHENTICATION_OCCURRENCE_V1' then 8 else 32 end order by "sourceFormat","recordId"`,
    [participantId, privacyDomainId, formats],
  );
  for (const format of formats)
    assert.ok(
      selected.rows.some((row) => row.sourceFormat === format),
      `actual ${format} prerequisite`,
    );
  if (formats.includes('PC-DEPLOYMENT-RESERVATION-REJECTION-1')) {
    // Earlier rejection/deletion adversarial scenarios deliberately retain
    // forged metadata. It remains visible, and must fail source verification.
    const invalid = await client.query(
      `select evidence_id::text id from control.evidence_catalogue c
      where participant_id=$1 and privacy_domain_id=$2 and source_format='PC-DEPLOYMENT-RESERVATION-REJECTION-1'
      and not exists(select 1 from control.deployment_result r where r.participant_id=c.participant_id
       and r.privacy_domain_id=c.privacy_domain_id and c.record_id='deployment:'||r.command_id::text||':'||r.sequence::text
       and c.receipt_digest=r.result_digest) limit 16`,
      [participantId, privacyDomainId],
    );
    for (const row of invalid.rows)
      await assert.rejects(readEvidenceProvenance(client, row.id, participantId, privacyDomainId));
  }
  const views = [];
  const checked = new Set();
  for (const row of selected.rows) {
    const source = { ...row, participantId, privacyDomainId };
    const view = await readEvidenceProvenance(client, row.id, participantId, privacyDomainId);
    let read;
    if (row.sourceFormat === 'OPENPC_AUTHENTICATION_OCCURRENCE_V1') {
      assert.equal(view.status, 'VERIFIED_AUTHENTICATION_OCCURRENCE');
      assert.equal(view.authentication.integrity, 'CONTROL_DATABASE_IMMUTABLE');
      assert.equal(view.authentication.authority, 'NONE');
      assert.equal(view.authentication.chainFinality, 'NOT_APPLICABLE');
      assert.equal(view.authentication.occurrenceId, row.recordId);
      read = (value) => readAuthenticationProvenance(client, value);
      if (!checked.has(row.sourceFormat)) {
        const original = (
          await client.query(
            'select occurrence_id::text id,receipt,receipt_digest as "receiptDigest" from control.authentication_occurrence where occurrence_id=$1',
            [row.recordId],
          )
        ).rows[0];
        assert.throws(() =>
          verifyAuthenticationSource(
            { ...original, receipt: Buffer.from('wrong occurrence') },
            source,
          ),
        );
        assert.throws(() =>
          verifyAuthenticationSource({ ...original, receiptDigest: Buffer.alloc(32) }, source),
        );
      }
    } else if (row.sourceFormat.startsWith('COSE_SIGN1_24001_')) {
      assert.equal(view.status, 'VERIFIED_BUSINESS_TRANSITION');
      assert.equal(view.business.integrity, 'VERIFIED_PROFILE_COSE');
      assert.equal(view.business.providerEffect, 'NOT_ESTABLISHED');
      assert.equal(view.business.currentObjectState, 'NOT_QUERIED');
      assert.ok(BigInt(view.business.after.revision) > 0n);
      assert.equal(
        view.business.outboxReferences.every((event) => event.payloadDigest.startsWith('sha256:')),
        true,
      );
      read = (value) => readBusinessProvenance(client, value, row.sourceFormat);
      if (!checked.has(row.sourceFormat)) {
        const original = (
          await client.query(`${businessSourceSelect} and e.evidence_record_id=$3`, [
            participantId,
            privacyDomainId,
            row.recordId,
          ])
        ).rows[0];
        for (const mutation of [
          { publicKey: Buffer.alloc(original.publicKey.length) },
          { trustDigest: Buffer.alloc(32) },
          {
            coseSign1: Buffer.from(original.coseSign1).map((byte, index) =>
              index === original.coseSign1.length - 1 ? byte ^ 1 : byte,
            ),
          },
          { payloadDigest: Buffer.alloc(32) },
          { evidenceFormat: row.sourceFormat.replace('_338', '_339') },
          { operationId: '018f0000-0000-7000-8000-000000000901' },
        ])
          assert.throws(() => verifyBusinessSource({ ...original, ...mutation }, source));
        await assert.rejects(readBusinessProvenance(client, source, 'COSE_SIGN1_24001_99_338'));
      }
    } else if (row.sourceFormat === 'PC-DEPLOYMENT-RESERVATION-REJECTION-1') {
      assert.equal(view.status, 'VERIFIED_TERMINAL_REJECTION');
      assert.equal(view.rejection.execution, 'NO_HANDOFF');
      assert.equal(view.rejection.state, 'REJECTED');
      assert.equal(view.rejection.truthState, 'DENIED');
      assert.equal(view.rejection.chainFinality, 'NOT_APPLICABLE');
      read = (value) => readRejectionProvenance(client, value);
    } else if (row.sourceFormat === 'OPENPC_RPC_DECISION_TRANSITION_V1') {
      assert.equal(view.status, 'VERIFIED_RPC_CUSTODY_PROJECTION');
      assert.equal(view.rpc.integrity, 'AEAD_CHAIN_VERIFIED_AT_CUSTODY');
      assert.equal(view.rpc.activationIntegrity, 'ACTIVATION_COSE_VERIFIED_AT_CUSTODY');
      assert.equal(view.rpc.providerEffect, 'NOT_ESTABLISHED');
      assert.equal(view.rpc.sourceSequence, view.custody.sequence);
      read = async (value) => {
        const result = await readRpcProvenance(client, value);
        assert.ok(result, 'exact original projection required');
        return result;
      };
      if (!checked.has(row.sourceFormat)) {
        for (const mutation of [
          { sourceDigest: `sha256:${'0'.repeat(64)}` },
          { sourceSequence: '999' },
          { targetRuntimeId: '018f0000-0000-7000-8000-000000000901' },
          { transition: { ...view.rpc.transition, raw: 'private' } },
        ]) {
          const changed = { ...view.rpc, ...mutation };
          assert.throws(() => verifyRpcProjection(source, changed, sha256(changed)));
        }
      }
    } else assert.fail('no family oracle');
    assert.equal(
      /receiptBase64|signedBytes|encryptedSegment|privateKey|secretReference|keyFile|payloadCbor|sessionId/u.test(
        JSON.stringify(view),
      ),
      false,
    );
    if (!checked.has(row.sourceFormat)) {
      for (const mutation of [
        { recordDigest: `sha256:${'0'.repeat(64)}` },
        { occurredAt: '2000-01-01T00:00:00.000000Z' },
        { participantId: '018f0000-0000-7000-8000-000000000102' },
        { privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
      ])
        await assert.rejects(read({ ...source, ...mutation }));
      checked.add(row.sourceFormat);
    }
    views.push(view);
  }
  return views;
}

// SEM-058/061 and PQ-000273: consume real publicly governed deployment history.
// These checks never create command, approval, observation or custody state.
export async function verifyDeploymentProvenanceSources(client, participantId, privacyDomainId) {
  const records = (
    await client.query(
      `select distinct on (r.signed_bytes::text)
    c.evidence_id::text id, c.stream_id as "streamId", c.record_id as "recordId", c.receipt_digest as "recordDigest",
    to_char(c.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
    from control.evidence_catalogue c join control.deployment_result r
    on r.participant_id=c.participant_id and r.privacy_domain_id=c.privacy_domain_id
     and c.record_id='deployment:'||r.command_id::text||':'||r.sequence::text
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.source_format='PC-DEPLOYMENT-JOURNAL-PROJECTION-1'
     and not exists(select 1 from control.evidence_projection_retirement t join control.deletion_job j
      using(participant_id,privacy_domain_id,deletion_job_id) where t.participant_id=c.participant_id
       and t.privacy_domain_id=c.privacy_domain_id and t.stream_id=c.stream_id and t.record_id=c.record_id
       and t.data_class='NORMALIZED_JSON_PROJECTION' and j.state='SUCCEEDED'
       and t.retirement_digest=openpc.projection_retirement_digest(t))
    order by r.signed_bytes::text,c.created_at limit 64`,
      [participantId, privacyDomainId],
    )
  ).rows;
  assert.ok(records.length > 0, 'real archived signed deployment observations required');
  const views = [];
  for (const record of records) {
    const view = await readEvidenceProvenance(client, record.id, participantId, privacyDomainId);
    assert.equal(view.status, 'VERIFIED_DEPLOYMENT_OBSERVATION');
    assert.equal(view.recordDigest, view.deployment.historical.receiptDigest);
    assert.equal(view.deployment.currentChainTruth, 'NOT_QUERIED');
    assert.equal(view.deployment.authority, 'OBSERVATION_ONLY');
    assert.equal(view.deployment.history.journalCompleteness, 'NOT_ESTABLISHED');
    assert.equal(view.custody.archiveAvailability, 'NOT_RECHECKED');
    assert.equal(
      /receiptBase64|signedBytes|encryptedSegment|keyId/u.test(JSON.stringify(view)),
      false,
    );
    views.push(view);
  }
  const record = records[0];
  const source = { ...record, participantId, privacyDomainId };
  for (const changed of [
    { ...source, recordDigest: `sha256:${'0'.repeat(64)}` },
    { ...source, recordId: source.recordId.replace(/:[0-9]+$/u, ':18446744073709551615') },
    { ...source, occurredAt: '2000-01-01T00:00:00.000000Z' },
    { ...source, privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
    { ...source, participantId: '018f0000-0000-7000-8000-000000000102' },
  ])
    await assert.rejects(readDeploymentProvenance(client, changed));
  return views;
}

// SEM-059: match preservation against original signed observations, including
// the block invalidated by a later reorg. Current chain truth is irrelevant.
export async function verifyDeploymentHoldSources(client, participantId, privacyDomainId, views) {
  const records = (
    await client.query(
      `select c.record_id,c.stream_id,p.projection,openpc.evidence_hold_record_metadata(c) metadata
     from control.evidence_catalogue c left join control.evidence_deployment_lineage p
       using(participant_id,privacy_domain_id,stream_id,record_id)
     where c.participant_id=$1 and c.privacy_domain_id=$2
       and c.source_format='PC-DEPLOYMENT-JOURNAL-PROJECTION-1' order by c.stream_id,c.sequence limit 129`,
      [participantId, privacyDomainId],
    )
  ).rows;
  assert.ok(records.length > 0 && records.length <= 128);
  let anchored = 0,
    reorg = 0;
  for (const record of records) {
    const view = views.find((view) => view.recordId === record.record_id);
    assert.ok(view, 'each retained source has independently verified provenance');
    const source = view.deployment;
    assert.deepEqual(record.projection, {
      chainId: source.chainId,
      genesisDigest: source.genesisDigest,
      historical: source.historical,
    });
    let occurrence = source.historical.occurrence;
    if (source.historical.invalidation) {
      const reference = source.historical.invalidation;
      const matches = views.filter(
        (previous) =>
          previous.deployment.operationId === source.operationId &&
          previous.deployment.chainId === source.chainId &&
          previous.deployment.genesisDigest === source.genesisDigest &&
          BigInt(previous.deployment.historical.sourceVersion) <
            BigInt(source.historical.sourceVersion) &&
          previous.deployment.historical.occurrence?.occurrenceId === reference.occurrenceId &&
          previous.deployment.historical.occurrence?.occurrenceDigest ===
            reference.occurrenceDigest,
      );
      assert.ok(matches.length > 0, 'real earlier occurrence resolves the invalidation');
      occurrence = matches[0].deployment.historical.occurrence;
      for (const match of matches)
        assert.deepEqual(match.deployment.historical.occurrence, occurrence);
      if (source.historical.finality === 'REORG') reorg++;
    }
    if (!occurrence) {
      assert.equal(
        record.metadata,
        null,
        'no block authority is invented for a pending observation',
      );
      continue;
    }
    anchored++;
    const block = {
      chainId: source.chainId,
      genesisDigest: source.genesisDigest,
      blockNumber: occurrence.blockNumber,
    };
    assert.deepEqual(record.metadata, { blocks: [block] });
    for (const [selector, expected] of [
      [
        {
          type: 'BLOCK_RANGE',
          chainId: block.chainId,
          genesisDigest: block.genesisDigest,
          fromBlock: block.blockNumber,
          throughBlock: block.blockNumber,
        },
        true,
      ],
      [
        {
          type: 'BLOCK_RANGE',
          chainId: block.chainId === '1' ? '2' : '1',
          genesisDigest: block.genesisDigest,
          fromBlock: block.blockNumber,
          throughBlock: block.blockNumber,
        },
        false,
      ],
      [
        {
          type: 'BLOCK_RANGE',
          chainId: block.chainId,
          genesisDigest: block.genesisDigest,
          fromBlock: (BigInt(block.blockNumber) + 1n).toString(),
          throughBlock: null,
        },
        false,
      ],
    ])
      assert.equal(
        (
          await client.query('select openpc.evidence_hold_source_match($1,$2) matched', [
            selector,
            record.metadata,
          ])
        ).rows[0].matched,
        expected,
      );
  }
  for (const changed of [
    { receipt_digest: 'sha256:' + '00'.repeat(32) },
    { occurred_at: '2000-01-01T00:00:00Z' },
    { privacy_domain_id: '018f0000-0000-7000-8000-000000000202' },
    { participant_id: '018f0000-0000-7000-8000-000000000102' },
    { stream_id: 'unbound-source-stream' },
  ])
    assert.equal(
      (
        await client.query(
          `select openpc.evidence_hold_record_metadata(jsonb_populate_record(null::control.evidence_catalogue,to_jsonb(c)||$4::jsonb)) metadata
     from control.evidence_catalogue c where participant_id=$1 and privacy_domain_id=$2 and record_id=$3 limit 1`,
          [participantId, privacyDomainId, records[0].record_id, changed],
        )
      ).rows[0].metadata,
      null,
    );
  return { records: records.length, anchored, reorg };
}

export async function verifyPublicProvenance(read, records, secretRoot) {
  const views = [];
  for (const record of records) {
    const path = `evidence-records/${encodeURIComponent(record.evidenceId)}/provenance`;
    const response = await read(path);
    assert.equal(response.status, 200, 'authorized provenance API');
    assert.equal(response.body.evidenceId, record.evidenceId);
    assert.equal(response.body.recordDigest, record.recordDigest);
    assert.deepEqual(response.body, record, 'API agrees with independently read signed source');
    for (const context of [
      { participantId: '018f0000-0000-7000-8000-000000000102' },
      { privacyDomainId: '018f0000-0000-7000-8000-000000004201' },
    ]) {
      const denial = await read(path, context);
      assert.equal(denial.status, 403);
      assert.equal(denial.body.code, 'PC-AUTH-0005');
      assert.equal(JSON.stringify(denial.body).includes(record.recordId), false);
    }
    views.push(response.body);
  }
  for (const [family, filename] of [
    ['deployment', 'runtime_agent_projection_public_key.txt'],
    ['rejection', 'fleet_deployment_rejection_public_key.txt'],
  ]) {
    const first = records.find((record) => record[family]);
    if (!first) continue;
    const path = `evidence-records/${encodeURIComponent(first.evidenceId)}/provenance`;
    const file = join(secretRoot, filename),
      original = await readFile(file);
    const key = createECDH('secp256k1');
    key.generateKeys();
    await chmod(file, 0o644);
    try {
      await writeFile(file, key.getPublicKey('hex', 'compressed'));
      const denied = await read(path);
      assert.notEqual(denied.status, 200);
      assert.equal(denied.body.code, 'PC-FACT-4001');
      assert.equal(JSON.stringify(denied.body).includes(first.recordId), false);
    } finally {
      await writeFile(file, original);
      await chmod(file, 0o444);
    }
    assert.deepEqual((await read(path)).body, first);
  }
  return views;
}
