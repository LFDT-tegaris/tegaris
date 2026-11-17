import { z } from 'zod';
import type { IdentityEnvelopeRotationWorker } from './identity-envelope-rotation-worker.js';
import type { IdentityEnvelopeRotationProvider } from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';

/** Installation selects transport custody, never business authority. The SQL
 * queue separately authenticates this key against the immutable signed lease. */
export function installedIdentityEnvelopeRotationScope(input: {
  subjectAltName: string | undefined;
  privacyDomainId: string;
  environmentId: string;
  callerWorkloadCredentialId: string;
  callerWorkloadKeyDigest: string;
}) {
  const match = /^URI:urn:openpc:participant:([0-9a-f-]{36}):workload:([0-9a-f-]{36})$/u.exec(
    input.subjectAltName ?? '',
  );
  if (!match || !z.uuidv7().safeParse(match[2]).success)
    throw new Error('invalid installed envelope rotation identity');
  return z
    .strictObject({
      participantId: z.uuidv7(),
      privacyDomainId: z.uuidv7(),
      environmentId: z.string().min(1).max(160),
      callerWorkloadCredentialId: z.uuidv7(),
      callerWorkloadKeyDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    })
    .parse({
      participantId: match[1],
      privacyDomainId: input.privacyDomainId,
      environmentId: input.environmentId,
      callerWorkloadCredentialId: input.callerWorkloadCredentialId,
      callerWorkloadKeyDigest: input.callerWorkloadKeyDigest,
    });
}

/** One attempt per cycle; no overlap or timer accumulation during provider I/O.
 * A persistence failure stops this process's loop: restart reconciles the
 * already STARTED original attempt rather than automatically repeating writes. */
export class IdentityEnvelopeRotationRuntime {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running: Promise<void> | undefined;
  private started = false;
  private stopped = false;
  private closed = false;

  constructor(
    private readonly worker: Pick<IdentityEnvelopeRotationWorker, 'runOnce'>,
    private readonly provider: Pick<IdentityEnvelopeRotationProvider, 'close'>,
    private readonly onFailure: () => void,
    private readonly intervalMs = 1000,
  ) {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 100 || intervalMs > 10000)
      throw new Error('invalid envelope rotation polling interval');
  }

  start() {
    if (this.started || this.stopped || this.closed) return;
    this.started = true;
    this.schedule(0);
  }

  /** Process health only; this is never rotation or consumer acceptance. */
  get available() {
    return this.started && !this.stopped && !this.closed;
  }

  private schedule(delay: number) {
    if (this.stopped || this.closed) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.running = this.cycle();
    }, delay);
    this.timer.unref();
  }

  private async cycle() {
    try {
      await this.worker.runOnce();
    } catch {
      this.stopped = true;
      // Diagnostics never receive the request, TLS material or raw exception.
      this.onFailure();
    } finally {
      this.running = undefined;
      this.schedule(this.intervalMs);
    }
  }

  async stop() {
    this.stopped = true;
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    if (!this.closed) {
      this.closed = true;
      // Close rejects active/queued TLS calls while the runtime DB is still
      // available to retain the resulting original-attempt ambiguity.
      this.provider.close();
    }
    await this.running;
  }
}
