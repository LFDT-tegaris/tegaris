// @ts-check
import assert from 'node:assert/strict';
import { exerciseNotificationAsyncWorkerCase } from '../identity/notification-async-worker-cases.ts';
import {
  enqueueNotificationAsyncWork,
  readNotificationAsyncWork,
  claimNotificationAsyncBatch,
  settleNotificationAsyncWork,
} from '../../../services/control-api/src/notifications/async-worker-state.ts';
import { NotificationAsyncWorker } from '../../../services/control-api/src/notifications/async-worker.ts';
import { withNotificationDeliveryRequest } from '../../../services/control-api/src/notifications/delivery-admission.ts';
/** prepareCase is the existing privileged runtime producer setup: it must run
 * genuine governed endpoint/producer/approval owners, isolated actors and state
 * for each case. Canonical qualification-purpose splice must already be wired.
 * This driver never supplies qualification claims, limits, SQL roles or seeds. */
/** @param {{prepareCase: (caseId: import('../../../services/control-api/src/configuration/operations/notification-qualification-contract.js').QualificationCase, selector: import('../../../services/control-api/src/configuration/operations/notification-qualification-contract.js').NotificationQualificationSelector) => Promise<import('../identity/notification-async-worker-cases.js').NotificationAsyncWorkerCaseInput>}} options
 * @returns {import('../../../scripts/operations/notification-qualification-harness.d.mts').NotificationQualificationDriver} */
export function createNotificationQualificationCases({ prepareCase }) {
  /** @type {import('../../../scripts/operations/notification-qualification-harness.d.mts').NotificationQualificationDriver} */
  const driver = {
    async prepare(caseId, selector) {
      const input = await prepareCase(caseId, selector);
      const sources = input.current();
      assert.ok(sources.length > 0);
      return { sourceEventIds: sources.map((s) => s.source.eventId), input };
    },
    async execute(caseId, prepared) {
      const input =
        /** @type {import('../identity/notification-async-worker-cases.js').NotificationAsyncWorkerCaseInput} */ (
          prepared.input
        );
      if (caseId === 'POSITIVE')
        return exerciseNotificationAsyncWorkerCase('BATCH_PROOF_CUSTODY', input);
      if (caseId === 'CRASH_LEASE')
        return exerciseNotificationAsyncWorkerCase('CLAIM_CRASH', input);
      if (caseId === 'POISON_QUARANTINE')
        return exerciseNotificationAsyncWorkerCase('EXPIRED_SOURCE_DISCOVERY', input);
      if (caseId === 'DUPLICATE_REPLAY') {
        for (const source of input.current()) {
          const enqueue = () =>
            source.withDeliveryPeer((socket) =>
              enqueueNotificationAsyncWork(source.pool, source.kernel, socket, source.source),
            );
          const original = await enqueue();
          assert.deepEqual(
            await enqueue(),
            original,
            'Replay preserves exact original queue/proof',
          );
        }
        return exerciseNotificationAsyncWorkerCase('BATCH_PROOF_CUSTODY', input);
      }
      assert.equal(caseId, 'SATURATION_CANCEL');
      const sources = input.current(),
        first = sources[0],
        before = input.gateway.stats();
      assert.ok(first);
      assert.ok(
        sources.length > 1,
        'Saturation requires genuine distinct sources exceeding actual signed bounds',
      );
      let denied;
      for (const source of sources) {
        try {
          await source.withDeliveryPeer((socket) =>
            enqueueNotificationAsyncWork(source.pool, source.kernel, socket, source.source),
          );
        } catch (error) {
          const code =
            error && typeof error === 'object' && 'code' in error ? error.code : undefined;
          assert.equal(code, 'BUSY', 'Only actual queue-capacity denial proves saturation');
          denied = source;
          break;
        }
      }
      assert.ok(denied, 'Actual intended queue items/bytes must be reached before overflow');
      assert.equal(
        await denied.withDeliveryPeer((socket) =>
          readNotificationAsyncWork(denied.pool, denied.kernel, socket, denied.source),
        ),
        null,
        'Overflow leaves durable source undispatched',
      );
      assert.deepEqual(input.gateway.stats(), before);
      const claimed = await first.withDeliveryPeer((socket) =>
        claimNotificationAsyncBatch(first.pool, first.kernel, socket, first.source),
      );
      assert.ok(claimed.items.length > 0);
      const item = claimed.items[0];
      assert.ok(item);
      const source = sources.find((s) => s.source.eventId === item.original.source.eventId);
      assert.ok(source && item.lease);
      const revision = await source.withDeliveryPeer((socket) =>
        withNotificationDeliveryRequest(
          source.pool,
          source.kernel,
          socket,
          source.source,
          async (c) => {
            const r = await c.query(
              'select revision::text from control.notification_delivery where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3',
              [
                source.source.worker.participantId,
                source.source.worker.privacyDomainId,
                source.source.notificationOccurrenceId,
              ],
            );
            assert.equal(r.rowCount, 1);
            return r.rows[0].revision;
          },
        ),
      );
      const cause = await input.governEndpointChange(source);
      const worker = new NotificationAsyncWorker({
        pool: source.pool,
        kernel: source.kernel,
        vaultDirectory: source.vaultDirectory,
        kmsTls: source.kmsTls,
        signerTls: source.transport,
        credentialProvider: source.credentialProvider,
        signers: {
          start: source.startSignerInstallationDigest,
          outcome: source.outcomeSignerInstallationDigest,
        },
        cancellationSignerInstallationDigest: input.cancellationSignerInstallationDigest,
      });
      try {
        const result = await source.withDeliveryPeer((delivery) =>
          source.withRecipientPeer((recipient) =>
            worker.cancelLeased({ delivery, recipient }, item.lease, {
              source: source.source,
              causeOperationId: cause,
              expectedRevision: revision,
            }),
          ),
        );
        assert.equal(result.receipt.disposition, 'CANCELLED_BEFORE_START');
        assert.equal(result.after.state, 'CANCELLED');
        await source.withDeliveryPeer((socket) =>
          settleNotificationAsyncWork(
            source.pool,
            source.kernel,
            socket,
            source.source,
            item.lease,
          ),
        );
      } finally {
        await worker.close();
      }
      const retained = await source.withDeliveryPeer((socket) =>
        readNotificationAsyncWork(source.pool, source.kernel, socket, source.source),
      );
      assert.equal(retained?.state, 'CANCELLED');
      assert.deepEqual(
        input.gateway.stats(),
        before,
        'Cancellation before first start has no gateway effect',
      );
      await input.reopen();
      const reopened = input.current().find((s) => s.source.eventId === source.source.eventId);
      assert.ok(reopened);
      assert.deepEqual(
        await reopened.withDeliveryPeer((socket) =>
          readNotificationAsyncWork(reopened.pool, reopened.kernel, socket, reopened.source),
        ),
        retained,
      );
    },
  };
  return Object.freeze(driver);
}
