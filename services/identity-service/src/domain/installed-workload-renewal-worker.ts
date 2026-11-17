import {
  createWorkloadRenewalStore,
  type WorkloadRenewalInstallation,
} from '../db/workload-renewal-store.js';
import { createHttpWorkloadRenewalProvider } from './workload-renewal-provider.js';
import { runWorkloadRenewalWorkerOnce } from './workload-renewal-worker.js';
import type { WorkloadRenewalDigest } from './workload-renewal-worker-contract.js';

/** Real store/provider composition for one bounded original. This does not
 * install worker authority, manufacture admitted intents, schedule a new
 * request, adopt credentials or claim operational renewal qualification. */
export function createInstalledWorkloadRenewalWorker(input: {
  readonly installation?: WorkloadRenewalInstallation;
  readonly endpoint: string;
  readonly authorizationToken: string;
  readonly qualificationDigest: WorkloadRenewalDigest;
  readonly fetch?: typeof fetch;
}) {
  const store = createWorkloadRenewalStore(input.installation);
  const provider = createHttpWorkloadRenewalProvider({
    endpoint: input.endpoint,
    authorizationToken: input.authorizationToken,
    qualificationDigest: input.qualificationDigest,
    checkCommittedPermit: (permit, binding) => store.checkCommittedPermit(permit, binding),
    ...(input.fetch ? { fetch: input.fetch } : {}),
  });
  return { runOnce: (workerId: string) => runWorkloadRenewalWorkerOnce(store, provider, workerId) };
}
