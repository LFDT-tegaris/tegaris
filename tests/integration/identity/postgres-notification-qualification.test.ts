import assert from 'node:assert/strict';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import type { TLSSocket } from 'node:tls';
import type { NotificationQualificationPeer } from '../../../services/identity-service/src/domain/notification-qualification-peer.js';
import type {
  NotificationQualificationSelector,
  QualificationOriginal,
  QualificationSelection,
} from '../../../services/control-api/src/configuration/operations/notification-qualification-contract.js';
import {
  digest,
  qualificationReviewSchema,
} from '../../../services/control-api/src/configuration/operations/notification-qualification-contract.js';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
const tables = ['installation', 'origin', 'origin_proof', 'run', 'record'].map(
  (n) => 'notification_qualification_' + n,
);
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
integration('rejects ordinary runtime creation/mutation of qualification originals', async () => {
  const admin = new Pool({ connectionString: adminUrl, max: 1 }),
    runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
  const participantId = localOperationId(),
    privacyDomainId = localOperationId();
  try {
    // Initial trust only, never a run, review, signed result or generation.
    await admin.query(
      "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Qualification denial initial trust','ACTIVE',1)",
      [participantId],
    );
    await admin.query(
      "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Qualification denial initial trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
      [privacyDomainId, participantId],
    );
    for (const table of tables) {
      const privilege = await admin.query(
        "select has_table_privilege('openpc_identity_runtime',$1,'INSERT') allowed",
        ['control.' + table],
      );
      expect(privilege.rows[0]?.allowed).toBe(false);
      for (const statement of [`delete from control.${table}`, `truncate control.${table}`])
        await expect(
          runScopedTransaction(
            runtime,
            {
              participantId,
              privacyDomainId,
              actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
            },
            localOperationId,
            (c) => c.query(statement),
          ),
        ).rejects.toMatchObject({ code: '42501' });
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.${table} where participant_id=$1`,
            [participantId],
          )
        ).rows[0]?.n,
      ).toBe(0);
    }
  } finally {
    await runtime.end();
    await admin.end();
  }
});

/** Canonical runtime supplies actual host/native/B-C owners, installed trust,
 * signed369 issuance and isolated governed producer/gateway scenarios. This
 * exported vertical deliberately has no fallback fixtures or injected results.
 * It is NOT executed by the database privilege-denial test above. */
export interface NotificationQualificationVertical {
  selector: NotificationQualificationSelector;
  peer: NotificationQualificationPeer;
  actors: {
    subject: TLSSocket;
    harness: TLSSocket;
    executor: TLSSocket;
    reviewer: TLSSocket;
    signer: TLSSocket;
    foreign: TLSSocket;
  };
  origins: {
    subject: { source: Buffer; build: Buffer };
    harness: { source: Buffer; build: Buffer };
  };
  /** Actual external service executes/verifies exact retained source→artifact
   * and authenticates this author/request. A blind hash-signing callback is not
   * a permissible fixture or acceptance result. */
  buildAttestation(
    request: Awaited<ReturnType<NotificationQualificationPeer['prepareOrigin']>>,
    source: Buffer,
    build: Buffer,
  ): Promise<string>;
  /** Canonical purpose-bound SIGN/ORIGINAL_LOOKUP, owner-derived intent only. */
  issueOriginal(
    family: 'input' | 'capacity',
    selector: NotificationQualificationSelector,
  ): Promise<void>;
  /** Runs scripts/operations/notification-qualification-harness.mjs with the
   * real createNotificationQualificationCases driver and required native owner. */
  execute(selector: NotificationQualificationSelector): Promise<QualificationOriginal>;
  /** Reopen pools, actual transports and same original storage, no reseeding. */
  reopen(): Promise<{
    peer: NotificationQualificationPeer;
    actors: NotificationQualificationVertical['actors'];
  }>;
  gatewayEffects(): Promise<unknown>;
}
const originalBytes = (value: QualificationOriginal) => ({
  request: value.request,
  records: value.records.map((r) => ({
    record: r.record,
    hex: r.bytes.toString('hex'),
    digest: r.digest,
  })),
});
export async function exerciseNotificationQualificationOriginals(
  input: NotificationQualificationVertical,
) {
  const { selector: s } = input;
  const selection: QualificationSelection = {
    participantId: s.participantId,
    privacyDomainId: s.privacyDomainId,
    installationId: s.installationId,
  };
  for (const kind of ['SUBJECT', 'HARNESS'] as const) {
    const artifact = kind === 'SUBJECT' ? input.origins.subject : input.origins.harness;
    const actor = kind === 'SUBJECT' ? input.actors.subject : input.actors.harness;
    const request = await input.peer.prepareOrigin(
      actor,
      selection,
      kind,
      artifact.source,
      artifact.build,
    );
    assert.equal(request.sourceDigest, digest(artifact.source));
    assert.equal(request.buildDigest, digest(artifact.build));
    const proof = await input.buildAttestation(request, artifact.source, artifact.build);
    await assert.rejects(
      input.peer.retainOrigin(actor, selection, request.originId, '00'.repeat(64)),
    );
    await input.peer.retainOrigin(actor, selection, request.originId, proof);
    await assert.rejects(
      input.peer.prepareOrigin(
        input.actors.foreign,
        selection,
        kind,
        artifact.source,
        artifact.build,
      ),
    );
  }
  const reservation = await input.peer.reserve(input.actors.executor, s);
  assert.equal(reservation.created, true);
  const before = await input.gatewayEffects();
  await assert.rejects(
    input.peer.dispatch(input.actors.executor, s),
    'No dispatch before genuine signed369',
  );
  assert.deepEqual(await input.gatewayEffects(), before);
  await input.issueOriginal('input', s);
  const executed = await input.execute(s);
  assert.equal(
    executed.records.find((r) => r.record.kind === 'NORMALIZED')?.record.value !== undefined,
    true,
  );
  await assert.rejects(
    input.peer.review(input.actors.executor, s),
    'Executor cannot independently review itself',
  );
  await assert.rejects(
    input.peer.review(input.actors.subject, s),
    'Subject author cannot independently review',
  );
  const review = qualificationReviewSchema.parse(await input.peer.review(input.actors.reviewer, s));
  assert.equal(review.decision, 'ACCEPTED');
  await input.issueOriginal('capacity', s);
  const original = await input.peer.readOriginal(s);
  assert.equal(original.records.filter((r) => r.record.kind === 'CAPACITY').length, 1);
  const effects = await input.gatewayEffects(),
    reopened = await input.reopen();
  assert.deepEqual(originalBytes(await reopened.peer.readOriginal(s)), originalBytes(original));
  assert.equal((await reopened.peer.dispatch(reopened.actors.executor, s)).execute, false);
  assert.deepEqual(
    await input.gatewayEffects(),
    effects,
    'Original dispatched run is never resubmitted',
  );
  assert.deepEqual(await reopened.peer.review(reopened.actors.reviewer, s), review);
  await assert.rejects(reopened.peer.reserve(reopened.actors.foreign, s));
  assert.deepEqual(originalBytes(await reopened.peer.readOriginal(s)), originalBytes(original));
}
