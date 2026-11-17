import type { TLSSocket } from 'node:tls';
import type { NotificationAsyncWorkerCaseInput } from '../../tests/integration/identity/notification-async-worker-cases.js';
import type { NotificationQualificationPeer } from '../../services/identity-service/src/domain/notification-qualification-peer.js';
import type {
  NotificationQualificationSelector,
  QualificationCase,
  QualificationOriginal,
} from '../../services/control-api/src/configuration/operations/notification-qualification-contract.js';
export interface QualificationHarnessPrepared {
  readonly sourceEventIds: readonly string[];
  readonly input: unknown;
}
/** Implemented by the existing local runtime driver; never deserialized from a
 * caller document or replaced by a mock in internal-owner acceptance. */
export interface NotificationQualificationDriver {
  prepare(
    caseId: QualificationCase,
    selector: NotificationQualificationSelector,
  ): Promise<QualificationHarnessPrepared>;
  execute(
    caseId: QualificationCase,
    prepared: QualificationHarnessPrepared,
    selector: NotificationQualificationSelector,
  ): Promise<void>;
}
export function runNotificationQualificationHarness(options: {
  peer: NotificationQualificationPeer;
  executorSocket: TLSSocket;
  selector: NotificationQualificationSelector;
  prepareCase: (
    caseId: QualificationCase,
    selector: NotificationQualificationSelector,
  ) => Promise<NotificationAsyncWorkerCaseInput>;
  approvedHarnessDigest: string;
  heartbeatMs: number;
  deadlineAtMs: number;
}): Promise<QualificationOriginal>;
