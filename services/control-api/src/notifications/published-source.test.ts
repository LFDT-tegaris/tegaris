import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  encodeEvidenceExportCompletedData,
  encodeEvidenceExportCompletion,
  evidenceExportCompletionEnvelope,
  signEvidenceExportCompletion,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { validateEvidenceExportProducerInstallation } from '../evidence/export-producer-installation.js';
import {
  readPublishedNotificationSource,
  PublishedNotificationSourceError,
  type PublishedNotificationSourceSelector,
} from './published-source.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
const privateKey = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
const scope = { participantId: id(1), privacyDomainId: id(2), streamId: 'CONTROL-BUSINESS' };
const selection = { scope, evidenceExportId: id(3), eventId: id(6) };

// SQL projection doubles exercise the REAL shared readers, codec and signature.
// They cannot establish RLS, SQL constraint enforcement or transaction isolation;
// the separate joined helper consumes the genuine PostgreSQL publication caller.
function fixture() {
  const installation = validateEvidenceExportProducerInstallation({
    owner: 'LS-EVIDENCE-EXPORT',
    purpose: 'pc.cose.evidence-export-completion-receipt.v1',
    environmentId: 'local-export',
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    sourceId: id(7),
    principalId: id(8),
    workloadCredentialId: id(9),
    workloadEpoch: '1',
    workloadId: 'export-worker',
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://test-export/signer#v1',
    secretVersion: 'v1',
    publicKeySpkiHex: spki.toString('hex'),
    keyEpoch: '1',
    // Historical validity deliberately expired; this is not current authority.
    validFromNs: '1000000000000000000',
    validUntilNs: '1000000600000000000',
    installationReference: 'local-initial-trust',
  });
  const source = {
    ...scope,
    evidenceExportId: selection.evidenceExportId,
    startOperationId: id(4),
    causationId: id(5),
    requestDigest: sha256('request'),
    checkpoint: '9007199254740993',
    outputDigest: sha256('output'),
    recordCount: '3',
  };
  const authoritySnapshot = Buffer.from(canonicalJson({ installationDigest: installation.digest }));
  const data = encodeEvidenceExportCompletedData({
    evidenceExportId: source.evidenceExportId,
    checkpoint: source.checkpoint,
    outputDigest: source.outputDigest,
    recordCount: source.recordCount,
  });
  const { streamId, ...sourceClaims } = source;
  expect(streamId).toBe(scope.streamId);
  const claims = {
    ...sourceClaims,
    environmentId: installation.pins.environmentId,
    sourceId: installation.pins.sourceId,
    signerKeyId: installation.signerKeyId,
    signerTrustSnapshotDigest: installation.digest,
    authoritySnapshotDigest: sha256(authoritySnapshot),
    dataDigest: sha256(data),
    eventId: selection.eventId,
    sequence: '1',
    recordedAtNs: '1000000000000001000',
  };
  const receiptPayload = encodeEvidenceExportCompletion(claims);
  const eventPayload = Buffer.from(canonicalJson(evidenceExportCompletionEnvelope(claims)));
  const retained = {
    trustDigest: installation.digest,
    claims,
    receiptPayload,
    receiptPayloadDigest: sha256(receiptPayload),
    authoritySnapshot,
    sourceData: data,
    eventPayload,
    eventPayloadDigest: sha256(eventPayload),
    state: 'PUBLISHED',
    coseSign1: signEvidenceExportCompletion(claims, privateKey, spki) as Buffer | null,
  };
  const installed = {
    trust: installation.trust,
    trust_bytes: installation.bytes,
    state: 'REVOKED',
  };
  const controls = { context: true, completionCount: 1, trustCount: 1, outboxCount: 1, fault: '' };
  const query = vi.fn(async (sql: string, values?: unknown[]) => {
    if (controls.fault && sql.includes(controls.fault)) throw new Error('private SQL canary');
    if (sql.startsWith('savepoint ') || sql.startsWith('release savepoint '))
      return { rowCount: null, rows: [] };
    if (sql.includes('from pg_roles')) {
      expect(values).toEqual([
        scope.participantId,
        scope.privacyDomainId,
        `evidence-lifecycle:${scope.participantId}`,
      ]);
      expect(sql).toContain("l.mode='ExclusiveLock'");
      expect(sql).toContain("current_setting('row_security')='on'");
      return { rowCount: 1, rows: [{ allowed: controls.context }] };
    }
    if (sql.includes('from control.evidence_export_completion ')) {
      expect(values).toEqual([
        scope.participantId,
        scope.privacyDomainId,
        scope.streamId,
        selection.evidenceExportId,
      ]);
      return { rowCount: controls.completionCount, rows: [retained] };
    }
    if (sql.includes('from control.evidence_export_producer_installation')) {
      expect(values).toEqual([scope.participantId, scope.privacyDomainId, retained.trustDigest]);
      expect(sql).not.toContain("state='ACTIVE'");
      return { rowCount: controls.trustCount, rows: [installed] };
    }
    if (sql.includes('check_evidence_export_completion_event')) {
      expect(values).toEqual([
        scope.participantId,
        scope.privacyDomainId,
        selection.eventId,
        selection.evidenceExportId,
      ]);
      return { rowCount: controls.outboxCount, rows: [{}] };
    }
    if (sql === 'select openpc.evidence_export_completion_source($1::uuid) source')
      return { rowCount: 1, rows: [{ source }] };
    throw new Error('Unexpected query');
  });
  return {
    retained,
    installed,
    source,
    controls,
    query,
    client: { query } as unknown as PoolClient,
  };
}

const unavailable = new PublishedNotificationSourceError('PUBLICATION_UNAVAILABLE');
describe('retained published notification source', () => {
  it('reads the original after producer expiry/withdrawal without acquiring current authority', async () => {
    const f = fixture();
    const result = await readPublishedNotificationSource(f.client, selection);
    expect(result.source).toEqual(f.source);
    expect(result.payload).toEqual(f.retained.receiptPayload);
    expect(result.cose).toEqual(f.retained.coseSign1);
    expect(result.claims).toEqual(f.retained.claims);
    const sql = f.query.mock.calls.map(([statement]) => statement).join('\n');
    expect(sql).not.toMatch(
      /insert |update |delete |set_config|set role|producer_authority|pg_advisory_xact_lock|\bbegin\b|\bcommit\b/iu,
    );
    expect(result).not.toHaveProperty('authorized');
  });

  it('preserves original bytes across concurrent calls and mutations of returned buffers/objects', async () => {
    const f = fixture();
    const [first, second] = await Promise.all([
      readPublishedNotificationSource(f.client, selection),
      readPublishedNotificationSource(f.client, selection),
    ]);
    expect(first).toEqual(second);
    first.payload.fill(0);
    first.cose.fill(0);
    first.claims.sourceId = id(50);
    first.envelope.data.outputDigest = sha256('changed');
    first.source.outputDigest = sha256('changed');
    expect(await readPublishedNotificationSource(f.client, selection)).toEqual(second);
  });

  it.each(['PREPARED', 'OBSERVED'])(
    'denies %s before publication or source reads',
    async (state) => {
      const f = fixture();
      f.retained.state = state;
      if (state === 'PREPARED') f.retained.coseSign1 = null;
      await expect(readPublishedNotificationSource(f.client, selection)).rejects.toEqual(
        unavailable,
      );
      expect(
        f.query.mock.calls.some(([sql]) => sql.includes('check_evidence_export_completion_event')),
      ).toBe(false);
    },
  );

  it.each(['completionCount', 'trustCount', 'outboxCount'] as const)(
    'requires exactly one %s',
    async (key) => {
      for (const count of [0, 2]) {
        const f = fixture();
        f.controls[key] = count;
        await expect(readPublishedNotificationSource(f.client, selection)).rejects.toEqual(
          unavailable,
        );
      }
    },
  );

  it('denies the same event identity with changed original data or substituted signature/source', async () => {
    for (const change of [
      (f: ReturnType<typeof fixture>) => {
        f.retained.sourceData[0] = f.retained.sourceData[0]! ^ 1;
      },
      (f: ReturnType<typeof fixture>) => {
        f.retained.receiptPayloadDigest = sha256('other');
      },
      (f: ReturnType<typeof fixture>) => {
        const cose = f.retained.coseSign1!;
        cose[cose.length - 1] = cose[cose.length - 1]! ^ 1;
      },
      (f: ReturnType<typeof fixture>) => {
        f.source.outputDigest = sha256('other');
      },
      (f: ReturnType<typeof fixture>) => {
        f.retained.authoritySnapshot.fill(0);
      },
      (f: ReturnType<typeof fixture>) => {
        f.retained.eventPayload.fill(0);
      },
      (f: ReturnType<typeof fixture>) => {
        f.installed.trust_bytes.fill(0);
      },
      (f: ReturnType<typeof fixture>) => {
        f.installed.trust.sourceId = id(50);
      },
    ]) {
      const f = fixture();
      change(f);
      await expect(readPublishedNotificationSource(f.client, selection)).rejects.toEqual(
        unavailable,
      );
    }
  });

  it('requires the actual scoped context/fence and minimizes checker errors', async () => {
    const missingContext = fixture();
    missingContext.controls.context = false;
    await expect(readPublishedNotificationSource(missingContext.client, selection)).rejects.toEqual(
      new PublishedNotificationSourceError('CONTEXT_UNAVAILABLE'),
    );
    for (const fault of [
      'savepoint notification_',
      'from pg_roles',
      'check_evidence_export_completion_event',
      'evidence_export_completion_source',
    ]) {
      const f = fixture();
      f.controls.fault = fault;
      await expect(readPublishedNotificationSource(f.client, selection)).rejects.toEqual(
        new PublishedNotificationSourceError(
          fault.startsWith('savepoint') || fault === 'from pg_roles'
            ? 'CONTEXT_UNAVAILABLE'
            : 'PUBLICATION_UNAVAILABLE',
        ),
      );
    }
  });

  it('rejects extra caller authority, malformed scope and unrelated event selectors', async () => {
    for (const value of [
      { ...selection, completion: {} },
      { ...selection, trust: {} },
      { ...selection, ready: true },
      { ...selection, scope: { ...scope, locked: true } },
      { ...selection, eventId: 'bad' },
    ]) {
      const f = fixture();
      await expect(
        readPublishedNotificationSource(f.client, value as PublishedNotificationSourceSelector),
      ).rejects.toEqual(new PublishedNotificationSourceError('INVALID_SELECTOR'));
      expect(f.query).not.toHaveBeenCalled();
    }
    const f = fixture();
    await expect(
      readPublishedNotificationSource(f.client, { ...selection, eventId: id(50) }),
    ).rejects.toEqual(unavailable);
  });
});
