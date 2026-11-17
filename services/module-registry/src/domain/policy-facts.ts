import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

import type { PolicySemanticDocument } from './policy-semantics.js';
import { pcCbor1 } from './digest.js';

const digestBytes = z.array(z.number().int().min(0).max(255)).length(32);
const snapshotSchema = z.strictObject({
  outcome: z.enum([
    'PRESENT',
    'ABSENT_CONFIRMED',
    'DENIED',
    'UNKNOWN',
    'NOT_READY',
    'UNAVAILABLE',
    'STALE',
    'REORG',
    'PARTIAL',
    'CONFLICTING',
    'TAMPERED',
  ]),
  participantId: z.string(),
  privacyDomainId: z.string(),
  candidateId: z.string(),
  generationId: z.string(),
  factDigest: digestBytes,
  shardDigest: digestBytes.nullable(),
  observedAtMs: z.number().safe(),
  freshUntilMs: z.number().safe(),
  snapshotAtMs: z.number().safe(),
  conditions: z
    .array(
      z.strictObject({
        conditionDigest: z.string().regex(/^[0-9a-f]{64}$/u),
        workloadId: z.string(),
        outcome: z.enum([
          'MEMBER_CONFIRMED',
          'NON_MEMBER_CONFIRMED',
          'DENIED',
          'UNRESOLVED',
          'NOT_CAUGHT_UP',
          'STALE',
          'REORG_PENDING',
          'PARTIAL',
          'CONFLICTING',
          'UNAVAILABLE',
          'TAMPERED',
          'RETIRED',
        ]),
      }),
    )
    .max(16)
    .optional(),
});
export type PolicyFactSnapshot = z.infer<typeof snapshotSchema>;

const factRequest = (document: PolicySemanticDocument, workloadId?: string) => {
  const conditions = [
    ...new Map(
      [
        ...(document.factConditions ?? []),
        ...(document.visibilityPolicies ?? []).flatMap((policy) => policy.conditions),
      ].map((condition) => [pcCbor1(condition).digest.toString('hex'), condition]),
    ).values(),
  ];
  return JSON.stringify({
    participantId: document.participantId,
    privacyDomainId: document.privacyDomainId,
    candidateIds: document.requiredFacts.map((fact) => fact.candidateId),
    ...(conditions.length ? { conditions, workloadId } : {}),
  });
};

const decodeFacts = (output: string, document: PolicySemanticDocument, identity: string) => {
  const result = z
    .strictObject({ identity: z.literal(identity), snapshots: z.array(snapshotSchema.nullable()) })
    .parse(JSON.parse(output));
  if (result.snapshots.length !== document.requiredFacts.length)
    throw new Error('fact owner response rejected');
  for (const [index, snapshot] of result.snapshots.entries()) {
    if (
      snapshot !== null &&
      (snapshot.participantId !== document.participantId ||
        snapshot.privacyDomainId !== document.privacyDomainId ||
        snapshot.candidateId !== document.requiredFacts[index]?.candidateId)
    )
      throw new Error('fact owner scope rejected');
  }
  return result.snapshots;
};

export interface HeldPolicyFacts {
  readonly snapshots: readonly (PolicyFactSnapshot | null)[];
  revalidate(): Promise<void>;
  assertHeld(): void;
}

export class PolicyFactReader {
  constructor(
    private readonly executable = process.env.OPENPC_POLICY_FACT_READER_BIN ??
      fileURLToPath(new URL('../../../../target/debug/policy_fact_reader', import.meta.url)),
  ) {}

  async read(
    document: PolicySemanticDocument,
    workloadId?: string,
  ): Promise<readonly (PolicyFactSnapshot | null)[]> {
    if (document.requiredFacts.length === 0) return [];
    const source = factRequest(document, workloadId);
    // execFile's service-configured environment contains only the reader's
    // connection and public verification trust. User input goes through stdin.
    const child = execFile(this.executable, [], { timeout: 10_000, maxBuffer: 4 * 1024 * 1024 });
    const completed = new Promise<string>((resolve, reject) => {
      let output = '';
      child.stdout?.setEncoding('utf8');
      child.stdout?.on('data', (value: string) => {
        output += value;
      });
      child.on('error', reject);
      child.stdin?.on('error', reject);
      child.on('close', (code) =>
        code === 0 ? resolve(output) : reject(new Error('fact owner unavailable')),
      );
    });
    child.stdin?.end(source);
    return decodeFacts(await completed, document, 'OPENPC-FACT-OWNER-READ-1');
  }

  /** The callback must finish within the Fact owner's five-second custody window.
   * Its returned snapshots confer no authority once the callback has returned.
   */
  async withLease<T>(
    document: PolicySemanticDocument,
    workloadId: string | undefined,
    work: (lease: HeldPolicyFacts) => Promise<T>,
  ): Promise<T> {
    if (document.requiredFacts.length === 0)
      return work(
        Object.freeze({ snapshots: [], revalidate: async () => {}, assertHeld: () => {} }),
      );
    const started = performance.now();
    const child = execFile(this.executable, ['--lease'], {
      timeout: 10_000,
      maxBuffer: 4 * 1024 * 1024,
    });
    let buffered = '';
    let unavailable = false;
    let pending: { resolve: (line: string) => void; reject: (reason: Error) => void } | undefined;
    const fail = () => {
      unavailable = true;
      pending?.reject(new Error('fact lease unavailable'));
      pending = undefined;
    };
    const receive = () =>
      new Promise<string>((resolve, reject) => {
        if (unavailable || pending) {
          reject(new Error('fact lease unavailable'));
          return;
        }
        pending = { resolve, reject };
      });
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      buffered += chunk;
      if (buffered.length > 4 * 1024 * 1024) {
        fail();
        child.kill();
        return;
      }
      const newline = buffered.indexOf('\n');
      if (newline < 0) return;
      if (!pending || buffered.slice(newline + 1).length !== 0) {
        fail();
        child.kill();
        return;
      }
      const waiter = pending;
      pending = undefined;
      const line = buffered.slice(0, newline);
      buffered = '';
      waiter.resolve(line);
    });
    child.on('error', fail);
    child.stdin?.on('error', fail);
    child.on('close', fail);
    const completed = new Promise<void>((resolve) => child.once('close', () => resolve()));
    try {
      const ready = receive();
      child.stdin?.write(`${factRequest(document, workloadId)}\n`);
      const snapshots = decodeFacts(await ready, document, 'OPENPC-FACT-OWNER-LEASE-1');
      if (snapshots.some((snapshot) => snapshot?.outcome !== 'PRESENT'))
        throw new Error('fact lease unavailable');
      const assertHeld = () => {
        if (
          unavailable ||
          child.exitCode !== null ||
          child.signalCode !== null ||
          performance.now() - started >= 5000 ||
          snapshots.some((snapshot) => !snapshot || Date.now() >= snapshot.freshUntilMs)
        )
          throw new Error('fact lease unavailable');
      };
      return await work(
        Object.freeze({
          snapshots,
          assertHeld,
          revalidate: async () => {
            assertHeld();
            const checked = receive();
            child.stdin?.write('CHECK\n');
            z.strictObject({
              identity: z.literal('OPENPC-FACT-OWNER-LEASE-1'),
              state: z.literal('HELD'),
            }).parse(JSON.parse(await checked));
            assertHeld();
          },
        }),
      );
    } finally {
      unavailable = true;
      child.stdin?.end('RELEASE\n');
      // Release is cleanup, not permission to deliver. A stuck owner is bounded
      // by its protocol deadline and the process timeout above.
      await completed;
    }
  }
}
