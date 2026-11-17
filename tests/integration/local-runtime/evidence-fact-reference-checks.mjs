import assert from 'node:assert/strict';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.ts';

/** Independent graph oracle over actual purpose-verified Fact readbacks. */
export async function verifyFactReferenceClosure(client, views, requireReferences = false) {
  const lineages = views.map((view) => view.fact.lineage);
  let referenced = 0;
  const sorted = (values) => values.map(canonicalJson).sort();
  for (const view of views) {
    const seen = new Map(),
      visiting = new Set();
    let unresolved = false;
    const visit = (lineage) => {
      if (visiting.has(lineage.factDigest)) {
        unresolved = true;
        return;
      }
      if (seen.has(lineage.factDigest)) return;
      if (seen.size >= 64) {
        unresolved = true;
        return;
      }
      visiting.add(lineage.factDigest);
      seen.set(lineage.factDigest, lineage);
      for (const reference of new Set(
        [
          lineage.predecessorDigest,
          lineage.relationshipPredecessorDigest,
          lineage.reorgReplacementOf,
        ].filter(Boolean),
      )) {
        referenced++;
        const matches = lineages.filter(
          (candidate) => candidate.factDigest === reference || candidate.factId === reference,
        );
        if (!matches.length) unresolved = true;
        else {
          for (const match of matches) assert.deepEqual(match, matches[0]);
          visit(matches[0]);
        }
      }
      visiting.delete(lineage.factDigest);
    };
    visit(view.fact.lineage);
    const rows = [...seen.values()];
    const metadata = (
      await client.query(
        'select openpc.evidence_hold_record_metadata(c) metadata from control.evidence_catalogue c where evidence_id=$1',
        [view.evidenceId.slice(-36)],
      )
    ).rows[0]?.metadata;
    assert.ok(metadata);
    assert.equal(metadata.unresolvedReferences, unresolved);
    assert.deepEqual(sorted(metadata.projections), sorted(rows.map((row) => row.projectionId)));
    assert.deepEqual(
      sorted(metadata.facts),
      sorted(
        rows.map(({ factType, factProfileId, factKeyDigest }) => ({
          factType,
          factProfileId,
          factKeyDigest,
        })),
      ),
    );
    assert.deepEqual(
      sorted(metadata.blocks),
      sorted(
        rows.map(({ chainId, genesisDigest, blockNumber }) => ({
          chainId,
          genesisDigest,
          blockNumber,
        })),
      ),
    );
    assert.deepEqual(
      sorted(metadata.generations.CANONICAL_FACT),
      sorted(
        rows.map(({ factProfileId, canonicalGeneration }) => ({
          kind: 'CANONICAL_FACT',
          factProfileId,
          canonicalGeneration,
        })),
      ),
    );
  }
  if (requireReferences)
    assert.ok(
      referenced > 0,
      'actual independently admitted predecessor or replacement reference required',
    );
  process.stdout.write(
    'OPENPC_FACT_REFERENCE_CLOSURE|PASS|records=' +
      views.length +
      '|references=' +
      referenced +
      '|independent-graph-oracle\n',
  );
}

/** Rollback-only corruption tests of derived custody metadata. Original Fact,
 * receipt, catalogue, approval, runtime and candidate state never changes. The
 * admin connection injects faults; every observation uses the installed worker
 * role, and rollback restores both projections and the immutable trigger. */
export async function verifyFactReferenceFaults(pool, participantId, privacyDomainId, views) {
  const linked = views.find(
    (v) => v.fact.lineage.predecessorDigest || v.fact.lineage.relationshipPredecessorDigest,
  );
  assert.ok(linked, 'real admitted reference required before fault injection');
  const a = linked.fact.lineage;
  const b = views
    .map((v) => v.fact.lineage)
    .find((l) => l.factDigest === (a.predecessorDigest ?? a.relationshipPredecessorDigest));
  const c = views
    .map((v) => v.fact.lineage)
    .find((l) => l.factDigest !== a.factDigest && l.factDigest !== b?.factDigest);
  assert.ok(b && c, 'three distinct actual Facts required for the shared-reference cycle');
  const scope = [participantId, privacyDomainId];
  const client = await pool.connect();
  const worker = async () => {
    await client.query('set local role openpc_control_worker');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
      [...scope, '018f0012-0000-7000-8000-000000000141'],
    );
  };
  const metadata = async () =>
    (
      await client.query(
        'select openpc.evidence_hold_record_metadata(c) value from control.evidence_catalogue c where participant_id=$1 and privacy_domain_id=$2 and evidence_id=$3',
        [...scope, linked.evidenceId.slice(-36)],
      )
    ).rows[0].value;
  let original;
  try {
    await client.query('begin');
    await worker();
    original = await metadata();
    assert.equal(original.unresolvedReferences, false);
    for (const sql of [
      'update control.evidence_fact_provenance set projection=projection where participant_id=$1 and privacy_domain_id=$2',
      'delete from control.evidence_fact_provenance where participant_id=$1 and privacy_domain_id=$2',
    ]) {
      await client.query('savepoint immutable');
      await assert.rejects(client.query(sql, scope), (error) => error.code === '42501');
      await client.query('rollback to savepoint immutable');
    }
    await client.query('rollback');
    for (const fault of ['missing', 'ambiguous', 'shared-dag', 'shared-cycle']) {
      await client.query('begin');
      try {
        await client.query(
          'alter table control.evidence_fact_provenance disable trigger evidence_fact_provenance_guard',
        );
        if (fault === 'missing') {
          const removed = await client.query(
            "delete from control.evidence_fact_provenance where participant_id=$1 and privacy_domain_id=$2 and projection->'lineage'->>'factDigest'=$3 returning record_id",
            [...scope, b.factDigest],
          );
          assert.ok(removed.rowCount > 0 && removed.rowCount <= 128);
        } else if (fault === 'ambiguous') {
          const rows = (
            await client.query(
              "select stream_id,record_id,projection from control.evidence_fact_provenance where participant_id=$1 and privacy_domain_id=$2 and projection->'lineage'->>'factDigest'=$3",
              [...scope, c.factDigest],
            )
          ).rows;
          assert.ok(rows.length > 0 && rows.length <= 128);
          for (const row of rows) {
            const projection = structuredClone(row.projection);
            projection.lineage.factDigest = b.factDigest;
            await client.query(
              'update control.evidence_fact_provenance set projection=$5,projection_digest=$6 where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4',
              [...scope, row.stream_id, row.record_id, projection, sha256(projection)],
            );
          }
        } else {
          const rows = (
            await client.query(
              "select stream_id,record_id,projection from control.evidence_fact_provenance where participant_id=$1 and privacy_domain_id=$2 and projection->'lineage'->>'factDigest'=any($3::text[])",
              [...scope, [a.factDigest, b.factDigest, c.factDigest]],
            )
          ).rows;
          assert.ok(rows.length >= 3 && rows.length <= 128);
          for (const row of rows) {
            const projection = structuredClone(row.projection),
              lineage = projection.lineage;
            lineage.predecessorDigest =
              lineage.factDigest === a.factDigest
                ? b.factDigest
                : lineage.factDigest === b.factDigest
                  ? c.factDigest
                  : fault === 'shared-cycle'
                    ? b.factDigest
                    : null;
            lineage.relationshipPredecessorDigest =
              lineage.factDigest === a.factDigest ? c.factDigest : null;
            lineage.reorgReplacementOf = null;
            await client.query(
              'update control.evidence_fact_provenance set projection=$5,projection_digest=$6 where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4',
              [...scope, row.stream_id, row.record_id, projection, sha256(projection)],
            );
          }
        }
        await client.query(
          'alter table control.evidence_fact_provenance enable trigger evidence_fact_provenance_guard',
        );
        await worker();
        const actual = await metadata();
        assert.equal(actual.unresolvedReferences, fault !== 'shared-dag', fault);
        const positive = { type: 'PROJECTION', projectionId: a.projectionId };
        const negative = {
          type: 'PROJECTION',
          projectionId: 'urn:openpc:resource:018fdead-0000-7000-8000-000000000001',
        };
        for (const [selector, expected] of [
          [positive, true],
          [negative, fault === 'shared-dag' ? false : null],
        ]) {
          assert.equal(
            (
              await client.query('select openpc.evidence_hold_source_match($1,$2) matched', [
                selector,
                actual,
              ])
            ).rows[0].matched,
            expected,
            fault,
          );
        }
        process.stdout.write(
          'OPENPC_FACT_REFERENCE_FAULT|PASS|' + fault + '|worker-role|rollback-only\n',
        );
      } finally {
        await client.query('rollback');
      }
      await client.query('begin read only');
      await worker();
      assert.deepEqual(
        await metadata(),
        original,
        'fault rollback preserves original verified lineage',
      );
      await client.query('rollback');
    }
  } finally {
    await client.query('rollback');
    client.release();
  }
}
