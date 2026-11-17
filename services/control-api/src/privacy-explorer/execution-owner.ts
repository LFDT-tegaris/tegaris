import {
  type AdapterContribution,
  type EvidenceLifecycleOwner,
  type RawStateWitness,
} from './evidence.js';
import {
  type ExecutionRepository,
  type ExecutionSnapshot,
  type RawTransitionPermit,
  requireExecutionSnapshot,
} from './execution-repository.js';
import {
  requirePublicResponseCandidate,
  type PublicResponseCandidate,
} from './result-candidate.js';

export type ExecutionOwner = Readonly<{
  authorizeCapture(snapshot: ExecutionSnapshot): RawTransitionPermit;
  authorizeDisposal(snapshot: ExecutionSnapshot): RawTransitionPermit;
  adapterContribution(
    snapshot: ExecutionSnapshot,
    candidate: PublicResponseCandidate,
  ): AdapterContribution;
  rawStateWitness(snapshot: ExecutionSnapshot, candidate: PublicResponseCandidate): RawStateWitness;
}>;

const matchingIdentity = (snapshot: ExecutionSnapshot, candidate: PublicResponseCandidate) =>
  snapshot.occurrenceId === candidate.occurrenceId &&
  snapshot.correlationId === candidate.correlationId &&
  snapshot.requestDigest === candidate.requestDigest &&
  snapshot.profileDigest === candidate.profileDigest &&
  snapshot.queryDigest === candidate.queryDigest &&
  snapshot.resultDigest === candidate.resultDigest;

export const createExecutionOwner = (
  repository: ExecutionRepository,
  evidenceOwner: EvidenceLifecycleOwner,
): ExecutionOwner =>
  Object.freeze({
    authorizeCapture(snapshot) {
      return repository.issueRawPermit(requireExecutionSnapshot(snapshot), 'NEVER_CREATED_TO_LIVE');
    },
    authorizeDisposal(snapshot) {
      return repository.issueRawPermit(requireExecutionSnapshot(snapshot), 'LIVE_TO_DISPOSED');
    },
    adapterContribution(snapshot, candidate) {
      const admittedSnapshot = repository.requireOwnedSnapshot(requireExecutionSnapshot(snapshot));
      const admittedCandidate = requirePublicResponseCandidate(candidate);
      if (
        (admittedSnapshot.state !== 'RELEASED' && admittedSnapshot.state !== 'CANCELLED_CLOSED') ||
        !matchingIdentity(admittedSnapshot, admittedCandidate)
      )
        throw new Error('execution contribution identity rejected');
      return evidenceOwner.adapterContribution(admittedCandidate, admittedSnapshot.revision);
    },
    rawStateWitness(snapshot, candidate) {
      const admittedSnapshot = repository.requireOwnedSnapshot(requireExecutionSnapshot(snapshot));
      const admittedCandidate = requirePublicResponseCandidate(candidate);
      if (
        (admittedSnapshot.rawState !== 'NEVER_CREATED' &&
          admittedSnapshot.rawState !== 'DISPOSED') ||
        !matchingIdentity(admittedSnapshot, admittedCandidate)
      )
        throw new Error('execution raw witness rejected');
      return evidenceOwner.rawStateWitness(
        admittedCandidate,
        admittedSnapshot.rawState,
        admittedSnapshot.revision + 2,
      );
    },
  });
