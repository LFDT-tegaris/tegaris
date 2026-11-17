import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { sealSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';

// Populated predecessor fixture only; no business-journey acceptance is claimed.
// The real migration owner must preserve bytes despite its forced-RLS scope.
const [path] = process.argv.slice(2);
const participant = '018f0000-0000-7000-8000-000000000101';
const privacy = '018f0000-0000-7000-8000-000000000201';
const segment = '018f0000-0000-7000-8000-000000000901';
const record = Buffer.from('Populated evidence payload migration fixture');
const sealed = sealSegment(
  {
    version: 'OPENPC_EVIDENCE_SEGMENT_V1',
    participantId: participant,
    privacyDomainId: privacy,
    streamId: 'payload-upgrade',
    segmentId: segment,
    firstSequence: '1',
    throughSequence: '1',
    previousSegmentDigest: null,
    keyId: 'payload-upgrade-test-key',
    retentionUntil: '2027-01-01T00:00:00.000000Z',
  },
  [
    {
      recordId: 'payload-upgrade-fixture',
      evidenceClass: 'AUTHENTICATION',
      sourceFormat: 'MIGRATION_FIXTURE',
      receiptDigest: sha256(record),
      receiptBase64: record.toString('base64'),
      occurredAt: '2026-09-21T00:00:00.000000Z',
    },
  ],
  randomBytes(32),
);
await writeFile(
  path,
  `SET ROLE openpc_control_worker;
SELECT openpc.set_request_context('PARTICIPANT','${participant}','${privacy}',
 '018f0000-0000-7000-8000-000000000902','ACT-EVIDENCE_EXPORT_RECORDS-V1',true);
INSERT INTO control.evidence_stream(participant_id,privacy_domain_id,stream_id,capacity_bytes)
 VALUES('${participant}','${privacy}','payload-upgrade',65536);
INSERT INTO control.evidence_segment(participant_id,privacy_domain_id,stream_id,segment_id,
 first_sequence,through_sequence,object_digest,key_id,retention_until,encrypted_segment)
 VALUES('${participant}','${privacy}','payload-upgrade','${segment}',1,1,'${sealed.objectDigest}',
 'payload-upgrade-test-key','2027-01-01T00:00:00.000000Z',decode('${sealed.bytes.toString('hex')}','hex'));
UPDATE control.evidence_stream SET last_sequence=1,last_segment_digest='${sealed.objectDigest}',used_bytes=${sealed.bytes.length}
 WHERE participant_id='${participant}' AND privacy_domain_id='${privacy}' AND stream_id='payload-upgrade';
RESET ROLE;
CREATE TABLE openpc_local.evidence_payload_upgrade_expected AS
 SELECT * FROM control.evidence_segment WHERE segment_id='${segment}';
`,
  { mode: 0o600, flag: 'wx' },
);
