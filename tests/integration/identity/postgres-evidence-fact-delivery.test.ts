import { uncustodiedFactSources } from '../../../services/control-api/src/evidence/fact-custody-recovery.js';
import { randomBytes } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { retainFactAdmissionDelivery } from '../../../services/control-api/src/evidence/fact-delivery.js';
import { factAdmissionDelivery } from '../../../services/control-api/src/evidence/fact-delivery-contract.js';
import { factProvenance } from '../../../services/control-api/src/evidence/fact-provenance-contract.js';
import { retainFactProvenance } from '../../../services/control-api/src/evidence/fact-source.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import type {
  EvidenceScope,
  SourceReceipt,
} from '../../../services/control-api/src/evidence/segment.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && workerUrl && runtimeUrl ? it : it.skip;

// SQL/custody segment acceptance only: synthetic source bytes deliberately do
// not establish native Fact authentication, public admission or producer ACK.
integration(
  'binds immutable Fact inbox effects to actual custody and advances only contiguous scoped sequences',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const participantId = id(),
      privacyDomainId = id();
    const encryption = { keyId: 'fact-inbox-test', key: randomBytes(32) };
    const custody = new EvidenceCustody(worker);
    const stamp = '2026-09-24T00:00:00.000001Z',
      digest = sha256('fixture');
    async function transaction<T>(
      pool: Pool,
      scope: EvidenceScope,
      work: (client: PoolClient) => Promise<T>,
      action = 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
    ) {
      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          scope.participantId,
          scope.privacyDomainId,
          id(),
          action,
        ]);
        const result = await work(client);
        await client.query('commit');
        return result;
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
    }
    function fixture(sequence: string) {
      const sourceProfileId = id(),
        candidateId = id(),
        factId = id();
      const scope = { participantId, privacyDomainId, streamId: `fact-${sourceProfileId}` };
      const bytes = Buffer.from(`opaque component fixture ${candidateId}`);
      const source: SourceReceipt = {
        recordId: `fact:${sha256([participantId, privacyDomainId, sourceProfileId]).slice(7)}:1`,
        evidenceClass: 'EFFECT',
        sourceFormat: 'OPENPC_CANONICAL_FACT_V1',
        receiptBase64: bytes.toString('base64'),
        receiptDigest: sha256(bytes),
        occurredAt: stamp,
      };
      const provenance = factProvenance.parse({
        candidateId,
        sourceProfileId,
        sourceSequence: '1',
        receiptDigest: source.receiptDigest,
        admittedAt: stamp,
        integrity: 'FACT_COSE_VERIFIED_AT_CUSTODY',
        authority: 'NONE',
        currentReadiness: 'NOT_ESTABLISHED',
        verificationKeyId: digest,
        verificationKeyDigest: digest,
        lineage: {
          factId: `urn:openpc:fact:${factId}`,
          factDigest: digest,
          factType: 'CONTRACT_STATE_CALL',
          factProfileId: `urn:openpc:fact-profile:${id()}`,
          factKeyDigest: digest,
          canonicalGeneration: '1',
          projectionId: `urn:openpc:resource:${id()}`,
          chainId: '31337',
          genesisDigest: digest,
          blockNumber: '1',
          blockHash: digest,
          predecessorDigest: null,
          relationshipPredecessorDigest: null,
          reorgReplacementOf: null,
        },
      });
      const data = {
        candidateId: `urn:openpc:resource:${candidateId}`,
        factArtifactId: `urn:openpc:resource:${candidateId}`,
        artifactDigest: digest,
        sourceProfileDigest: digest,
        sourceNeutral: true,
      };
      const admissionDelivery = factAdmissionDelivery.parse({
        specversion: '1.0',
        id: factId,
        source: 'urn:openpc:service:LS-FACT-BRIDGE',
        type: 'io.openpc.fact.candidate.admitted.v1',
        subject: data.candidateId,
        // Producer persistence time is distinct from signed identity allocation.
        time: '2026-09-24T00:00:00.000002Z',
        datacontenttype: 'application/json',
        dataschema:
          'https://schemas.openpc.local/event-payloads.schema.json#/$defs/FactCandidateAdmitted',
        participantid: `urn:openpc:participant:${participantId}`,
        privacydomainid: `urn:openpc:privacy-domain:${privacyDomainId}`,
        correlationid: candidateId,
        authoritygeneration: digest,
        sequence,
        datadigest: sha256(data),
        data,
      });
      return { scope, entry: { source, provenance, admissionDelivery } };
    }
    const first = fixture('1'),
      second = fixture('2'),
      third = fixture('3');
    const record = async (value: ReturnType<typeof fixture>) =>
      transaction(worker, value.scope, async (client) => {
        await retainFactProvenance(client, value.scope, [value.entry]);
        await retainFactAdmissionDelivery(client, value.scope, [value.entry]);
      });
    const head = async () =>
      (
        await admin.query(
          "select sequence::text from control.evidence_fact_admission_cursor where participant_id=$1 and privacy_domain_id=$2 and fact_type='CONTRACT_STATE_CALL'",
          [participantId, privacyDomainId],
        )
      ).rows[0]?.sequence;
    const count = async (table: string) =>
      (
        await admin.query(
          `select count(*)::int as n from control.${table} where participant_id=$1`,
          [participantId],
        )
      ).rows[0].n;
    try {
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Fact inbox initial trust','ACTIVE',1)",
        [participantId],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Fact inbox','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [privacyDomainId, participantId],
      );
      await admin.query(
        'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
        [participantId, privacyDomainId],
      );
      // A caller cannot produce a custody effect from an event or provenance alone.
      await expect(record(first)).rejects.toThrow();
      await expect(
        transaction(worker, first.scope, (client) =>
          retainFactAdmissionDelivery(client, first.scope, [first.entry]),
        ),
      ).rejects.toThrow('FACT-INBOX-CUSTODY-BINDING');
      expect(await count('evidence_fact_admission_inbox')).toBe(0);
      for (const value of [first, second, third])
        await custody.admit(
          value.scope,
          [value.entry.source],
          encryption,
          '2027-01-01T00:00:00.000000Z',
          65536,
        );
      expect(
        await transaction(worker, first.scope, (client) =>
          uncustodiedFactSources(client, first.scope, [first.entry], encryption),
        ),
      ).toEqual([]);
      await expect(
        transaction(worker, first.scope, (client) =>
          uncustodiedFactSources(client, first.scope, [first.entry], {
            ...encryption,
            key: randomBytes(32),
          }),
        ),
      ).rejects.toThrow('integrity');
      const substituted = structuredClone(first.entry);
      substituted.source.receiptBase64 = Buffer.from('different original').toString('base64');
      await expect(
        transaction(worker, first.scope, (client) =>
          uncustodiedFactSources(client, first.scope, [substituted], encryption),
        ),
      ).rejects.toThrow('integrity');
      await record(second);
      expect(await head()).toBe('0');
      await expect(
        transaction(worker, second.scope, (client) =>
          client.query(
            "update control.evidence_fact_admission_cursor set sequence=2 where participant_id=$1 and privacy_domain_id=$2 and fact_type='CONTRACT_STATE_CALL'",
            [participantId, privacyDomainId],
          ),
        ),
      ).rejects.toThrow('FACT-INBOX-GAP');
      await expect(
        transaction(worker, first.scope, async (client) => {
          await retainFactProvenance(client, first.scope, [first.entry]);
          const event = { ...first.entry.admissionDelivery, id: id() };
          await client.query(
            `insert into control.evidence_fact_admission_inbox(participant_id,privacy_domain_id,event_id,fact_type,sequence,candidate_id,stream_id,record_id,source_receipt_digest,envelope,envelope_digest)
          values($1,$2,$3,'CONTRACT_STATE_CALL',1,$4,$5,$6,$7,$8,$9)`,
            [
              participantId,
              privacyDomainId,
              first.entry.admissionDelivery.id,
              first.entry.provenance.candidateId,
              first.scope.streamId,
              first.entry.source.recordId,
              first.entry.source.receiptDigest,
              event,
              sha256(event),
            ],
          );
        }),
      ).rejects.toThrow('FACT-INBOX-CUSTODY-BINDING');
      expect(await count('evidence_fact_provenance')).toBe(1);
      await record(first);
      await transaction(worker, first.scope, async (client) => {
        const metadata = async (change: Record<string, unknown>) =>
          (
            await client.query(
              `select openpc.evidence_hold_record_metadata(
                jsonb_populate_record(null::control.evidence_catalogue,to_jsonb(c)||$4::jsonb)) metadata
               from control.evidence_catalogue c
               where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$5`,
              [
                participantId,
                privacyDomainId,
                first.scope.streamId,
                change,
                first.entry.source.recordId,
              ],
            )
          ).rows[0]!.metadata;
        expect(await metadata({})).toMatchObject({ unresolvedReferences: false });
        for (const change of [
          { receipt_digest: 'sha256:' + 'ef'.repeat(32) },
          { sequence: '999999' },
          { occurred_at: '2000-01-01T00:00:00Z' },
          { evidence_class: 'AUTHENTICATION' },
          { source_format: 'OPENPC_AUTHENTICATION_OCCURRENCE_V1' },
          { evidence_id: id() },
          { segment_id: id() },
        ])
          expect(await metadata(change), `Reject changed ${Object.keys(change)[0]}`).toBeNull();
      });
      expect(await head()).toBe('2');
      await Promise.all([record(first), record(second)]);
      expect(await count('evidence_fact_admission_inbox')).toBe(2);
      const changed = structuredClone(first);
      changed.entry.admissionDelivery.authoritygeneration = sha256('changed');
      await expect(record(changed)).rejects.toThrow('conflict');
      expect(await head()).toBe('2');
      // A lost metadata transaction rolls back both projection and inbox/cursor.
      await expect(
        transaction(worker, third.scope, async (client) => {
          await retainFactProvenance(client, third.scope, [third.entry]);
          await retainFactAdmissionDelivery(client, third.scope, [third.entry]);
          throw new Error('SIMULATED_COMMIT_LOSS');
        }),
      ).rejects.toThrow('SIMULATED_COMMIT_LOSS');
      expect(await count('evidence_fact_provenance')).toBe(2);
      expect(await count('evidence_fact_admission_inbox')).toBe(2);
      expect(await head()).toBe('2');
      await record(third);
      expect(await head()).toBe('3');
      for (const statement of [
        "update control.evidence_fact_admission_inbox set envelope='{}'",
        'delete from control.evidence_fact_admission_inbox',
      ])
        await expect(
          transaction(worker, first.scope, (client) => client.query(statement)),
        ).rejects.toThrow('permission denied');
      await expect(
        transaction(runtime, first.scope, (client) =>
          retainFactAdmissionDelivery(client, first.scope, [first.entry]),
        ),
      ).rejects.toThrow('permission denied');
      await expect(
        transaction(
          worker,
          first.scope,
          (client) =>
            client.query(
              "update control.evidence_fact_admission_cursor set sequence=4 where participant_id=$1 and privacy_domain_id=$2 and fact_type='CONTRACT_STATE_CALL'",
              [participantId, privacyDomainId],
            ),
          'ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
        ),
      ).rejects.toThrow('PC-AUTH-0005');
      for (const scope of [
        { ...first.scope, participantId: id() },
        { ...first.scope, privacyDomainId: id() },
      ])
        expect(
          await transaction(
            worker,
            scope,
            async (client) =>
              (await client.query('select event_id from control.evidence_fact_admission_inbox'))
                .rowCount,
          ),
        ).toBe(0);
      // Existing exact replay uses its immutable committed identity; it does not
      // need permission to reread or resurrect the separately governed payload.
      await admin.query(
        'revoke select on control.evidence_segment_payload from openpc_control_worker',
      );
      try {
        await transaction(worker, first.scope, (client) =>
          retainFactAdmissionDelivery(client, first.scope, [first.entry]),
        );
      } finally {
        await admin.query(
          'grant select on control.evidence_segment_payload to openpc_control_worker',
        );
      }
      expect(await head()).toBe('3');
      expect(await count('evidence_fact_admission_inbox')).toBe(3);
    } finally {
      await Promise.all([admin.end(), worker.end(), runtime.end()]);
    }
  },
  60000,
);
