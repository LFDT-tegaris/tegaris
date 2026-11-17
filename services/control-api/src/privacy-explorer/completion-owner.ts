import type { CompletionContribution, EvidenceLifecycleOwner } from './evidence.js';
import {
  type ExecutionRepository,
  type ExecutionSnapshot,
  requireExecutionSnapshot,
} from './execution-repository.js';
import {
  requirePublicResponseCandidate,
  type PublicResponseCandidate,
} from './result-candidate.js';

export type CompletionOwner = Readonly<{
  contribution(
    snapshot: ExecutionSnapshot,
    candidate: PublicResponseCandidate,
  ): CompletionContribution;
}>;

export const createCompletionOwner = (
  repository: ExecutionRepository,
  evidenceOwner: EvidenceLifecycleOwner,
): CompletionOwner =>
  Object.freeze({
    contribution(snapshot, candidate) {
      const admittedSnapshot = repository.requireOwnedSnapshot(requireExecutionSnapshot(snapshot));
      const admittedCandidate = requirePublicResponseCandidate(candidate);
      const terminal =
        admittedSnapshot.state === 'RELEASED'
          ? admittedSnapshot.delivery === 'RELEASED' && admittedCandidate.delivery === 'PENDING'
          : admittedSnapshot.state === 'CANCELLED_CLOSED' &&
            admittedSnapshot.delivery === 'SUPPRESSED' &&
            admittedCandidate.delivery === 'SUPPRESSED';
      if (
        !terminal ||
        admittedSnapshot.occurrenceId !== admittedCandidate.occurrenceId ||
        admittedSnapshot.correlationId !== admittedCandidate.correlationId ||
        admittedSnapshot.requestDigest !== admittedCandidate.requestDigest ||
        admittedSnapshot.profileDigest !== admittedCandidate.profileDigest ||
        admittedSnapshot.queryDigest !== admittedCandidate.queryDigest ||
        admittedSnapshot.resultDigest !== admittedCandidate.resultDigest
      )
        throw new Error('completion contribution identity rejected');
      return evidenceOwner.completionContribution(admittedCandidate, admittedSnapshot.revision + 1);
    },
  });
