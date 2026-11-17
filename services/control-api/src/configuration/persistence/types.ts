import type { StateRef } from '@openpc/security-kernel/business-transition/state';
import type { PoolClient } from 'pg';
import type {
  AuthorityFence,
  BoundAuthority,
} from '../../../../identity-service/src/db/authority-fence.js';
import type { OperationResult } from '../../../../../generated/typescript/json-schema/signing-key-rotation.js';

export type OperationClass = 'CREATE' | 'UPDATE' | 'APPROVE' | 'ACTIVATE' | 'RECOVER' | 'EXPORT';

import type { MutationAuthorization } from '../../../../identity-service/src/domain/control-mutation-authorization.js';
export type { MutationAuthorization } from '../../../../identity-service/src/domain/control-mutation-authorization.js';

export interface MutationContext {
  readonly authorization: Exclude<MutationAuthorization, { readonly evidenceKind: 'READ_CONTEXT' }>;
  /** Transient sender binding; never persisted, emitted, or logged. */
  readonly sessionToken?: string;
  readonly actionIntentId: string;
  readonly actionIntentDigest: string;
  readonly idempotencyKey: string;
  readonly catalogOperationId: string;
  readonly resourceType: string;
  readonly operationClass: OperationClass;
  readonly aggregateType: string;
  readonly resourceId: string;
  readonly expectedRevision: string;
  readonly expectedEtag?: string;
  readonly candidate: unknown;
}

export interface MutationBusinessState {
  readonly before: { readonly reference: StateRef; readonly preimage: Buffer };
  readonly after: { readonly reference: StateRef; readonly preimage: Buffer };
}

export interface MutationWrite<T> {
  readonly businessState?: MutationBusinessState;
  readonly result: T;
  readonly revision: string;
  readonly outboxEventType: string;
  readonly asynchronous?: boolean;
}

export interface OperationRecord {
  readonly operationId: string;
  readonly resourceRef: string | null;
  readonly actionIntentId: string;
  readonly intentDigest: string;
  readonly idempotencyKey: string;
  readonly state: 'ACCEPTED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'WRITE_AMBIGUITY';
  readonly truthState: 'SUCCESS' | 'UNKNOWN' | 'FAILED' | 'WRITE_AMBIGUITY';
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly revision: string;
  readonly signingResult?: OperationResult;
}

export type MutationWriter<T> = (
  client: PoolClient,
  resourceId: string,
  operationId: string,
  authority: { readonly authorities: readonly BoundAuthority[]; readonly fence: AuthorityFence },
) => Promise<MutationWrite<T>>;

/** Only the initial runtime-source producer gate may use this classification.
 * A later matching database error never makes an effect safe to retry. */
export function isRuntimeSourceProducerContention(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === '55P03' &&
    'message' in error &&
    error.message === 'RUNTIME-DISPOSITION-PRODUCER-CONTENTION'
  );
}

export class ConfigurationRepositoryError extends Error {
  constructor(
    readonly code:
      | 'PC-AUTH-0003'
      | 'PC-AUTH-0005'
      | 'PC-DATA-6001'
      | 'PC-DATA-6004'
      | 'PC-DATA-6007'
      | 'PC-FACT-4001'
      | 'PC-OPS-9002'
      | 'PC-INTEGRATION-5001',
    readonly statusOverride?: number,
    readonly diagnosticBoundary?: string,
  ) {
    super(code);
  }
}
