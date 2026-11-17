import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  archiveKey,
  archiveProtection,
  protectionState,
  remoteArchiveIntent,
  remoteArchiveLocator,
  remoteArchiveProfile,
  remoteArchiveReceipt,
  remoteVersionId,
  retainUntil,
  retentionMicros,
  validateArchivePayload,
  RemoteArchiveError,
  type ArchiveAttemptBinding,
  type ArchiveProtection,
  type RemoteArchiveAttemptOwner,
  type RemoteArchiveIntent,
  type RemoteArchiveLocator,
  type RemoteArchiveProfile,
  type RemoteArchiveReceipt,
} from './remote-archive-contracts.js';
import { S3ArchiveTransport, type S3ArchiveCredentials } from './remote-archive-s3.js';

function safe<T>(action: () => T): T {
  try {
    return action();
  } catch (error) {
    if (error instanceof RemoteArchiveError) throw error;
    throw new RemoteArchiveError('INVALID');
  }
}

/** An external I/O adapter only. It never signs business evidence, advances a
 * checkpoint, determines eligibility, deletes objects, or destroys keys.
 * It sends original encrypted bytes; it never resolves a decryption key.
 */
export class RemoteEvidenceArchive {
  private readonly profile: RemoteArchiveProfile;
  private readonly transport: S3ArchiveTransport;
  readonly profileDigest: string;

  constructor(
    profile: RemoteArchiveProfile,
    credentials: () => Promise<S3ArchiveCredentials>,
    private readonly attempts: RemoteArchiveAttemptOwner,
  ) {
    this.profile = safe(() => remoteArchiveProfile.parse(structuredClone(profile)));
    this.profileDigest = sha256(this.profile);
    this.transport = new S3ArchiveTransport(this.profile, credentials);
    if (!attempts || typeof attempts.run !== 'function') throw new RemoteArchiveError('INVALID');
  }

  /** Caller cancellation and the installed signed timeout cover all requests,
   * including version discovery and readback. An interrupted durable attempt
   * remains original-identity reconciliation only. */
  withinDeadline<T>(work: () => Promise<T>, signal?: AbortSignal, deadlineMs?: number) {
    return this.transport.withinDeadline(work, signal, deadlineMs);
  }

  private intent(value: RemoteArchiveIntent) {
    const intent = safe(() => remoteArchiveIntent.parse(structuredClone(value)));
    if (
      intent.profileDigest !== this.profileDigest ||
      intent.source.object.sinkId !== this.profile.sinkId
    )
      throw new RemoteArchiveError('INVALID');
    if (
      intent.source.kind === 'SEGMENT' &&
      intent.payloadDigest !== intent.source.object.objectDigest
    )
      throw new RemoteArchiveError('INTEGRITY');
    if (
      intent.source.kind === 'PROTECTED_PROOF' &&
      intent.payloadDigest !== intent.source.object.payloadDigest
    )
      throw new RemoteArchiveError('INTEGRITY');
    return intent;
  }

  private locator(intent: RemoteArchiveIntent, versionId: string): RemoteArchiveLocator {
    return safe(() =>
      remoteArchiveLocator.parse({
        sinkId: this.profile.sinkId,
        profileDigest: this.profileDigest,
        bucket: this.profile.bucket,
        key: archiveKey(this.profile, intent),
        versionId,
      }),
    );
  }

  private exactLocator(intent: RemoteArchiveIntent, value: RemoteArchiveLocator) {
    const locator = safe(() => remoteArchiveLocator.parse(structuredClone(value)));
    if (canonicalJson(locator) !== canonicalJson(this.locator(intent, locator.versionId)))
      throw new RemoteArchiveError('INTEGRITY');
    return locator;
  }

  private metadata(intent: RemoteArchiveIntent) {
    return {
      'openpc-intent': sha256(intent),
      'openpc-source': sha256(intent.source),
      'openpc-profile': intent.profileDigest,
      'openpc-payload': intent.payloadDigest,
      'openpc-length': String(intent.payloadBytes),
    };
  }

  async readExact(value: RemoteArchiveIntent, valueLocator: RemoteArchiveLocator): Promise<Buffer> {
    const intent = this.intent(value),
      locator = this.exactLocator(intent, valueLocator);
    const result = await this.transport.readExact(locator.key, locator.versionId);
    for (const [name, expected] of Object.entries(this.metadata(intent))) {
      if (result.headers.get(`x-amz-meta-${name}`) !== expected)
        throw new RemoteArchiveError('INTEGRITY');
    }
    validateArchivePayload(intent, result.bytes);
    return result.bytes;
  }

  private async verifyRetention(locator: RemoteArchiveLocator, intent: RemoteArchiveIntent) {
    const observation = await this.transport.protection(locator.key, locator.versionId);
    if (
      intent.source.kind === 'PROTECTED_PROOF'
        ? retentionMicros(observation.retainUntil) !== retentionMicros(retainUntil(intent))
        : retentionMicros(observation.retainUntil) < retentionMicros(retainUntil(intent))
    )
      throw new RemoteArchiveError('PROTECTION_MISMATCH');
    return observation;
  }

  async verifyExact(
    value: RemoteArchiveIntent,
    valueLocator: RemoteArchiveLocator,
    valueProtection: ArchiveProtection = value.initialProtection,
  ): Promise<RemoteArchiveReceipt> {
    return this.withinDeadline(() =>
      this.verifyExactWithinDeadline(value, valueLocator, valueProtection).then(
        (result) => result.receipt,
      ),
    );
  }

  async readVerified(
    value: RemoteArchiveIntent,
    locator: RemoteArchiveLocator,
    protection: ArchiveProtection,
  ) {
    return this.withinDeadline(() =>
      this.verifyExactWithinDeadline(value, locator, protection).then((result) => result.bytes),
    );
  }

  private async verifyExactWithinDeadline(
    value: RemoteArchiveIntent,
    valueLocator: RemoteArchiveLocator,
    valueProtection: ArchiveProtection,
  ) {
    const intent = this.intent(value),
      locator = this.exactLocator(intent, valueLocator);
    const protection = safe(() => archiveProtection.parse(structuredClone(valueProtection)));
    const bytes = await this.readExact(intent, locator);
    const observation = await this.verifyRetention(locator, intent);
    if (observation.legalHold !== protectionState(protection))
      throw new RemoteArchiveError('PROTECTION_MISMATCH');
    const body = {
      version: 'OPENPC_REMOTE_ARCHIVE_RECEIPT_V1' as const,
      intent,
      intentDigest: sha256(intent),
      locator,
      assurance: 'REMOTE_INTERFACE_VERIFIED' as const,
      providerQualification: 'NOT_ESTABLISHED' as const,
      observedRetention: { mode: observation.mode, retainUntil: observation.retainUntil },
      protection,
      protectionDigest: sha256(protection),
      observedLegalHold: observation.legalHold,
    };
    return { receipt: remoteArchiveReceipt.parse({ ...body, receiptDigest: sha256(body) }), bytes };
  }

  /** No successful result for absence, including a complete empty listing.
   * In particular, STARTED/AMBIGUOUS recovery never falls back to another PUT.
   */
  async reconcilePut(
    value: RemoteArchiveIntent,
    protection: ArchiveProtection = value.initialProtection,
  ) {
    const intent = this.intent(value);
    const versions = await this.transport.discoverVersions(archiveKey(this.profile, intent));
    if (versions.length !== 1) throw new RemoteArchiveError('AMBIGUOUS');
    return this.verifyExact(intent, this.locator(intent, versions[0]!), protection);
  }

  private async governed(
    binding: ArchiveAttemptBinding,
    perform: (dispatch: 'INITIAL_SEND' | 'RECONCILE') => Promise<RemoteArchiveReceipt>,
  ) {
    safe(() => z.uuidv7().parse(binding.attemptId));
    let called = false,
      observed: RemoteArchiveReceipt | undefined;
    // Defensive copies prevent owner callbacks from changing the bound request.
    const result = await this.attempts.run(structuredClone(binding), async (dispatch, window) => {
      if (called || !['INITIAL_SEND', 'RECONCILE'].includes(dispatch))
        throw new RemoteArchiveError('INVALID');
      called = true;
      observed = await this.withinDeadline(
        () => perform(dispatch),
        window?.signal,
        window?.deadlineMs,
      );
      return structuredClone(observed);
    });
    if (!observed || canonicalJson(result) !== canonicalJson(observed))
      throw new RemoteArchiveError('INTEGRITY');
    return observed;
  }

  async put(
    value: RemoteArchiveIntent,
    valueBytes: Buffer,
    attemptId: string,
    valueProtection: ArchiveProtection = value.initialProtection,
  ) {
    const intent = this.intent(value),
      bytes = Buffer.from(valueBytes);
    const protection = safe(() => archiveProtection.parse(structuredClone(valueProtection)));
    validateArchivePayload(intent, bytes);
    return this.governed(
      {
        attemptId,
        intent,
        intentDigest: sha256(intent),
        action: 'PUT',
        locator: null,
        protection,
        protectionDigest: sha256(protection),
      },
      async (dispatch) => {
        if (dispatch === 'RECONCILE') return this.reconcilePut(intent, protection);
        const key = archiveKey(this.profile, intent);
        // This read is conflict detection, not permission to retry an older send.
        const existing = await this.transport.discoverVersions(key);
        if (existing.length)
          return this.verifyExact(intent, this.locator(intent, existing[0]!), protection);
        const versionId = await this.transport.put(
          key,
          bytes,
          this.metadata(intent),
          retainUntil(intent),
          protectionState(protection),
        );
        // A conditional conflict still requires full version and metadata verification.
        if (versionId === null) return this.reconcilePut(intent, protection);
        remoteVersionId.parse(versionId);
        return this.verifyExact(intent, this.locator(intent, versionId), protection);
      },
    );
  }

  async reconcileProtection(
    value: RemoteArchiveIntent,
    valueLocator: RemoteArchiveLocator,
    valueProtection: ArchiveProtection,
    attemptId: string,
  ) {
    const intent = this.intent(value),
      locator = this.exactLocator(intent, valueLocator);
    const protection = safe(() => archiveProtection.parse(structuredClone(valueProtection)));
    return this.governed(
      {
        attemptId,
        intent,
        intentDigest: sha256(intent),
        action: 'PROTECTION',
        locator,
        protection,
        protectionDigest: sha256(protection),
      },
      async (dispatch) => {
        await this.readExact(intent, locator);
        const before = await this.verifyRetention(locator, intent);
        if (before.legalHold !== protectionState(protection)) {
          if (dispatch === 'RECONCILE') throw new RemoteArchiveError('AMBIGUOUS');
          await this.transport.setLegalHold(
            locator.key,
            locator.versionId,
            protectionState(protection),
          );
        }
        return this.verifyExact(intent, locator, protection);
      },
    );
  }
}
