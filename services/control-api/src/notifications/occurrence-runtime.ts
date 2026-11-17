import { NotificationPayloadReferenceGate } from './payload-reference.js';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import {
  withNotificationWorkerPeer,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import type { PoolClient } from 'pg';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import {
  notificationOccurrencePrepareInput,
  notificationOccurrenceSelector,
  parseNotificationOccurrence,
  NotificationOccurrenceError,
  type NotificationOccurrenceSelector,
} from './occurrence-contract.js';
import {
  prepareNotificationOccurrence,
  dispatchNotificationOccurrence,
  markNotificationOccurrenceUnknown,
  observeNotificationOccurrence,
  readNotificationOccurrence,
  readNotificationOccurrencePublication,
  publishNotificationOccurrence,
} from './occurrence-state.js';

const observation = notificationOccurrenceSelector
  .extend({
    coseHex: z
      .string()
      .regex(/^(?:[0-9a-f]{2})+$/u)
      .min(130)
      .max(262144),
  })
  .strict();
/** Real installed worker/TLS composition. Every callback finishes before returning
 * to an external signer. No injected callback can fabricate a signed result.
 * A DISPATCHED result is returned only after its transaction commits. On lost
 * acknowledgment the caller must read the original; never dispatch a new attempt.
 *
 * Publication uses the trusted vault configuration and committed current-key gate.
 * It never performs external signing, provider delivery or automatic resubmission.
 */
export class NotificationOccurrenceRuntime {
  constructor(
    private readonly pool: Pool,
    private readonly kernel: IdentityKernel,
    private readonly vaultDirectory?: string,
  ) {}
  private async admitted<T>(
    socket: TLSSocket,
    selector: NotificationOccurrenceSelector['worker'],
    run: (client: PoolClient, admission: NotificationWorkerAdmission) => Promise<T>,
  ) {
    return withNotificationWorkerPeer(
      this.pool,
      this.kernel,
      socket,
      selector,
      async (client, admission) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        await lockEvidenceLifecycle(client, selector.participantId, selector.privacyDomainId);
        const result = await run(client, admission);
        // The shared worker owner performs its mandatory final installation and
        // Identity recheck under its own action. Restore it before returning.
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        );
        return result;
      },
    );
  }
  async readPublication(socket: TLSSocket, value: unknown) {
    const input = parseNotificationOccurrence(notificationOccurrenceSelector, value);
    try {
      return await this.admitted(socket, input.worker, (client, admission) =>
        readNotificationOccurrencePublication(client, admission, input),
      );
    } catch {
      throw new NotificationOccurrenceError('UNAVAILABLE');
    }
  }
  async publish(socket: TLSSocket, value: unknown) {
    const input = parseNotificationOccurrence(notificationOccurrenceSelector, value);
    if (!this.vaultDirectory) throw new NotificationOccurrenceError('UNAVAILABLE');
    const gate = new NotificationPayloadReferenceGate(this.vaultDirectory);
    try {
      return await this.admitted(socket, input.worker, (client, admission) =>
        publishNotificationOccurrence(client, admission, input, gate),
      );
    } catch {
      throw new NotificationOccurrenceError('UNKNOWN');
    }
  }
  async prepare(socket: TLSSocket, value: unknown) {
    const input = parseNotificationOccurrence(notificationOccurrencePrepareInput, value);
    try {
      return await this.admitted(socket, input.worker, (client, admission) =>
        prepareNotificationOccurrence(client, admission, input),
      );
    } catch (error) {
      if (error instanceof NotificationOccurrenceError) throw error;
      throw new NotificationOccurrenceError('UNAVAILABLE');
    }
  }
  async readOriginal(socket: TLSSocket, value: unknown) {
    const input = parseNotificationOccurrence(notificationOccurrenceSelector, value);
    try {
      return await this.admitted(socket, input.worker, (client, admission) =>
        readNotificationOccurrence(client, admission, input),
      );
    } catch (error) {
      if (error instanceof NotificationOccurrenceError) throw error;
      throw new NotificationOccurrenceError('UNAVAILABLE');
    }
  }
  async dispatch(socket: TLSSocket, value: unknown) {
    const input = parseNotificationOccurrence(notificationOccurrenceSelector, value);
    try {
      return await this.admitted(socket, input.worker, (client, admission) =>
        dispatchNotificationOccurrence(client, admission, input),
      );
    } catch {
      throw new NotificationOccurrenceError('UNKNOWN');
    }
  }
  async markUnknown(socket: TLSSocket, value: unknown) {
    const input = parseNotificationOccurrence(notificationOccurrenceSelector, value);
    try {
      return await this.admitted(socket, input.worker, (client, admission) =>
        markNotificationOccurrenceUnknown(client, admission, input),
      );
    } catch {
      throw new NotificationOccurrenceError('UNKNOWN');
    }
  }
  async observe(socket: TLSSocket, value: unknown) {
    const input = parseNotificationOccurrence(observation, value),
      { coseHex, ...selector } = input;
    const cose = Buffer.from(coseHex, 'hex');
    try {
      return await this.admitted(socket, input.worker, (client, admission) =>
        observeNotificationOccurrence(client, admission, selector, cose),
      );
    } catch {
      throw new NotificationOccurrenceError('UNKNOWN');
    }
  }
}
