import {
  validateIdentityEnvelopeRotationLookup,
  validateIdentityEnvelopeRotationObservation,
  identityEnvelopeRotationRequestSchema,
  type IdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationProvider,
  type IdentityEnvelopeRotationRequest,
} from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';

export interface ClaimedIdentityEnvelopeRotationAttempt {
  readonly request: IdentityEnvelopeRotationRequest;
  readonly mode: 'PERFORM' | 'LOOKUP';
  readonly firstObservation?: IdentityEnvelopeRotationObservation;
}

export interface IdentityEnvelopeRotationAttemptStore {
  /** Return PERFORM only after the exact READY -> STARTED claim has committed.
   * Existing STARTED/ambiguous attempts are always LOOKUP, never write retries. */
  claimNext(): Promise<ClaimedIdentityEnvelopeRotationAttempt | undefined>;
  recordFirst(
    request: IdentityEnvelopeRotationRequest,
    observation: IdentityEnvelopeRotationObservation,
  ): Promise<void>;
  recordResolved(
    request: IdentityEnvelopeRotationRequest,
    observation: IdentityEnvelopeRotationObservation,
  ): Promise<void>;
  recordAmbiguous(
    request: IdentityEnvelopeRotationRequest,
    kind: 'LOOKUP_UNAVAILABLE' | 'NOT_FOUND' | 'UNKNOWN',
  ): Promise<void>;
}

/** Participant alone owns provider mTLS custody. This loop performs no ordinary
 * governance, trust selection, epoch recapture, consumer acceptance or replay. */
export class IdentityEnvelopeRotationWorker {
  constructor(
    private readonly store: IdentityEnvelopeRotationAttemptStore,
    private readonly provider: IdentityEnvelopeRotationProvider,
  ) {}

  async runOnce() {
    const claim = await this.store.claimNext();
    if (!claim) return false;
    const request = identityEnvelopeRotationRequestSchema.parse(claim.request);
    let first = claim.firstObservation;
    if (claim.mode === 'PERFORM') {
      if (first !== undefined) throw new Error('invalid original envelope rotation claim');
      let performed: IdentityEnvelopeRotationObservation | undefined;
      try {
        performed = validateIdentityEnvelopeRotationObservation(
          request,
          await this.provider.perform(request),
        );
      } catch {
        // Ambiguous transport/effect results always reconcile the exact original
        // request. Failure is not evidence that another write is safe.
      }
      if (performed !== undefined) {
        // Persistence failure propagates; the next owner will LOOKUP the same
        // already STARTED attempt, even if this first response was lost.
        await this.store.recordFirst(request, performed);
        first = performed;
      }
    }
    let lookup;
    try {
      lookup = validateIdentityEnvelopeRotationLookup(
        request,
        await this.provider.lookup(request, first),
        first,
      );
    } catch {
      await this.store.recordAmbiguous(request, 'LOOKUP_UNAVAILABLE');
      return true;
    }
    if (lookup.state !== 'OBSERVED') {
      await this.store.recordAmbiguous(request, lookup.state);
      return true;
    }
    const observation = lookup.observation;
    if (first === undefined) await this.store.recordFirst(request, observation);
    await this.store.recordResolved(request, observation);
    return true;
  }
}
