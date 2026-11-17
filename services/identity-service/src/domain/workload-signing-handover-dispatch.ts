import type { Pool } from 'pg';
import { identityEnvelopeContext } from '@openpc/security-kernel';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import type { BusinessSigningProvider } from './business-signing-provider.js';
import {
  validateIdentityEnvelopeRotationLookup,
  type IdentityEnvelopeRotationProvider,
} from './identity-envelope-rotation-provider.js';
import {
  validateHandoverProviderResult,
  type HandoverProviderResult,
} from './workload-signing-handover-result.js';
import { localOperationId } from './local-operation-id.js';
import {
  claimWorkloadSigningHandoverDispatch,
  loadWorkloadSigningHandoverAttempt,
  WorkloadSigningHandoverStoreError,
  type WorkloadSigningHandoverScope,
  type WorkloadSigningHandoverAttemptScope,
} from '../db/workload-signing-handover-store.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { recordWorkloadSigningHandoverObservation } from '../db/workload-signing-handover-observations.js';

/** Server configuration, never a provider URL or readiness claim from a caller. */
export interface WorkloadSigningHandoverProviders {
  ids: { receipt: string; envelope: string };
  receipt: BusinessSigningProvider;
  envelope: IdentityEnvelopeRotationProvider;
}
type Command = Awaited<ReturnType<typeof loadWorkloadSigningHandoverAttempt>>;
async function observe(
  command: Command,
  providers: WorkloadSigningHandoverProviders,
  dispatch: boolean,
): Promise<HandoverProviderResult> {
  const { attempt, binding } = command;
  const via = dispatch ? 'DISPATCH' : 'LOOKUP';
  try {
    let result: HandoverProviderResult;
    if (attempt.purpose === identityEnvelopeContext.purpose) {
      if (dispatch) {
        result = {
          state: 'OBSERVED',
          via,
          observation: await providers.envelope.perform(attempt.request),
        };
      } else {
        // Do not pass a previous answer to the adapter: retain a changed, valid
        // answer as a permanent conflict rather than disguising it as a timeout.
        const lookup = validateIdentityEnvelopeRotationLookup(
          attempt.request,
          await providers.envelope.lookup(attempt.request),
        );
        result =
          lookup.state === 'OBSERVED'
            ? { state: 'OBSERVED', via, observation: lookup.observation }
            : { state: 'UNOBSERVED', via: 'LOOKUP', reason: lookup.state };
      }
    } else {
      const observation = dispatch
        ? await providers.receipt.perform(attempt.request)
        : await providers.receipt.lookup(attempt.request.attemptId);
      result = observation
        ? { state: 'OBSERVED', via, observation }
        : { state: 'UNOBSERVED', via: 'LOOKUP', reason: 'ABSENT' };
    }
    return validateHandoverProviderResult(binding, attempt, result, command.generation);
  } catch {
    return { state: 'UNKNOWN', via, reason: 'TRANSPORT_OR_PROTOCOL_UNKNOWN' };
  }
}

/** One dispatch after its claim commits. A crash between claim and I/O leaves
 * an unresolved intent; neither an absent lookup nor a new session retries it. */
export async function dispatchWorkloadSigningHandoverProviderAttempt(
  pool: Pool,
  scope: WorkloadSigningHandoverScope,
  attemptId: string,
  providers: WorkloadSigningHandoverProviders,
) {
  const command = await claimWorkloadSigningHandoverDispatch(pool, scope, attemptId, providers.ids);
  const result = await observe(command, providers, command.dispatch);
  // Database custody failure is deliberately outside the external-call catch.
  // Recovery reads the provider's original attempt instead of issuing it again.
  const observations = await recordWorkloadSigningHandoverObservation(
    pool,
    scope,
    attemptId,
    command.dispatchId,
    result,
  );
  return { dispatchId: command.dispatchId, attemptId, ...observations };
}

/** Internal recovery may collect historical truth after a maker lease expires.
 * It cannot claim a dispatch, alter its caller, admit trust or move selections. */
export async function reconcileWorkloadSigningHandoverProviderAttempt(
  pool: Pool,
  scope: WorkloadSigningHandoverAttemptScope,
  attemptId: string,
  dispatchId: string,
  providers: WorkloadSigningHandoverProviders,
) {
  const exactScope = { participantId: scope.participantId, privacyDomainId: scope.privacyDomainId };
  const command = await runScopedTransaction(
    pool,
    { ...exactScope, actionIntentId: signingRotationActions.create },
    localOperationId,
    async (client) => {
      const saved = await loadWorkloadSigningHandoverAttempt(client, exactScope, attemptId);
      const expected =
        saved.attempt.signerRole === 'IDENTITY_ENVELOPE'
          ? providers.ids.envelope
          : providers.ids.receipt;
      if (saved.binding.providerId !== expected)
        throw new WorkloadSigningHandoverStoreError('CONFLICT');
      const dispatch = await client.query<{ attemptId: string }>(
        `select attempt_id::text as "attemptId" from control.workload_signing_handover_dispatch
       where participant_id=$1 and privacy_domain_id=$2 and dispatch_id=$3`,
        [scope.participantId, scope.privacyDomainId, dispatchId],
      );
      if (dispatch.rowCount !== 1 || dispatch.rows[0]!.attemptId !== attemptId)
        throw new WorkloadSigningHandoverStoreError('NOT_FOUND');
      return saved;
    },
  );
  const result = await observe(command, providers, false);
  return {
    dispatchId,
    attemptId,
    ...(await recordWorkloadSigningHandoverObservation(
      pool,
      exactScope,
      attemptId,
      dispatchId,
      result,
    )),
  };
}
// Preserve the existing internal preparation callers and their original IDs.
export const dispatchWorkloadSigningHandoverPreparation =
  dispatchWorkloadSigningHandoverProviderAttempt;
export const reconcileWorkloadSigningHandoverPreparation =
  reconcileWorkloadSigningHandoverProviderAttempt;
