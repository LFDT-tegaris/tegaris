import type { PrivacyExplorerEvidenceDigestRecordV1 } from '../contracts/privacy-explorer-adapter.js';
import {
  createPrivacyExplorerExecutionOracle,
  type ExecutionEventId,
  type OraclePayload,
  type PrivacyExplorerExecutionOracle,
} from './execution-oracle.js';
import type { ExecutionHandle, ExecutionSnapshot } from './execution-repository.js';
import type { GovernedProjectionBoundary } from './request.js';

/** Only metadata reaches custody. Candidate bodies remain in the request's oracle. */
export interface ExecutionPersistence {
  create(boundary: GovernedProjectionBoundary, initial: ExecutionSnapshot): Promise<void>;
  transition(
    boundary: GovernedProjectionBoundary,
    previous: ExecutionSnapshot,
    next: ExecutionSnapshot,
    evidence?: PrivacyExplorerEvidenceDigestRecordV1,
  ): Promise<void>;
}

/** The existing reducer is the sole state machine; each effect waits for durable CAS. */
export const createPersistedExecutionOracle = (persistence?: ExecutionPersistence) => {
  if (!persistence && process.env.NODE_ENV !== 'test')
    throw new Error('Privacy Explorer durable execution custody required');
  const testOracle = persistence ? undefined : createPrivacyExplorerExecutionOracle();
  const owners = new WeakMap<
    ExecutionHandle,
    {
      oracle: PrivacyExplorerExecutionOracle;
      boundary: GovernedProjectionBoundary;
      busy: boolean;
      failed: boolean;
    }
  >();
  const owned = (handle: ExecutionHandle) => {
    const owner = owners.get(handle);
    if (!owner || owner.failed || owner.busy)
      throw new Error('Privacy Explorer execution unavailable');
    return owner;
  };
  return Object.freeze({
    async create(boundary: GovernedProjectionBoundary) {
      // A production request has no process-global occurrence cache or replay path.
      const oracle = testOracle ?? createPrivacyExplorerExecutionOracle();
      const handle = oracle.create(boundary);
      await persistence?.create(boundary, oracle.inspect(handle));
      owners.set(handle, { oracle, boundary, busy: false, failed: false });
      return handle;
    },
    inspect(handle: ExecutionHandle) {
      return owned(handle).oracle.inspect(handle);
    },
    async apply(
      handle: ExecutionHandle,
      revision: number,
      event: ExecutionEventId,
      payload?: OraclePayload,
    ) {
      const owner = owned(handle);
      owner.busy = true;
      try {
        const previous = owner.oracle.inspect(handle);
        const result = owner.oracle.apply(handle, revision, event, payload);
        if (result.snapshot.revision !== previous.revision)
          await persistence?.transition(owner.boundary, previous, result.snapshot, result.evidence);
        return result;
      } catch (error) {
        // An ambiguous write cannot be retried by the in-memory computation.
        owner.failed = true;
        throw error;
      } finally {
        owner.busy = false;
      }
    },
  });
};
