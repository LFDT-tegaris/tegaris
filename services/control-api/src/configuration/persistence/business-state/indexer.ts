import { createHash } from 'node:crypto';

import {
  transitionStatePreimage,
  type CborValue,
  type StateRef,
  type TransitionStateContext,
} from '@openpc/security-kernel/business-transition/state';
import type { PoolClient } from 'pg';
import { z } from 'zod';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const indexerState = z.strictObject({
  engine: z.enum(['CLIENT_INDEXER', 'EXTERNAL_ENGINE_ADAPTER']),
  engineVersion: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u),
  methodProfileDigest: digest,
  state: z.enum(['REGISTERED', 'SHADOW', 'QUALIFIED', 'ACTIVE', 'QUARANTINED', 'RETIRED']),
  policyGenerationDigest: digest.nullable(),
  revision: z
    .string()
    .regex(/^[1-9][0-9]{0,19}$/u)
    .refine((value) => BigInt(value) <= 18_446_744_073_709_551_615n),
});

export class IndexerBusinessTransitionError extends Error {}

export type IndexerBusinessState = z.infer<typeof indexerState>;
export type IndexerStateScope = Pick<
  TransitionStateContext,
  'participantId' | 'privacyDomainId' | 'aggregateId'
>;

/** Called by the state owner inside the commit transaction, after authority locks. */
export async function readIndexerBusinessState(
  client: PoolClient,
  scope: IndexerStateScope,
): Promise<IndexerBusinessState | undefined> {
  const selected = await client.query(
    `select engine,engine_version as "engineVersion",method_profile_digest as "methodProfileDigest",
            state,policy_generation_digest as "policyGenerationDigest",revision::text as revision
       from control.indexer_profile
      where participant_id=$1 and privacy_domain_id=$2 and indexer_profile_id=$3 for update`,
    [scope.participantId, scope.privacyDomainId, scope.aggregateId],
  );
  if (selected.rowCount === 0) return undefined;
  if (selected.rowCount !== 1) throw new Error('Invalid indexer state cardinality');
  return Object.freeze(indexerState.parse(selected.rows[0]));
}

/**
 * Closed durable projection: identity/scope/revision are in the enclosing state
 * preimage. Timestamps do not establish a business change. This primitive alone
 * does not admit a profile, authorize a command, or attest to its completion.
 */
export function bindIndexerBusinessState(
  context: TransitionStateContext,
  state: IndexerBusinessState | undefined,
  profileVersion = 1,
): { readonly reference: StateRef; readonly preimage: Buffer } {
  if (context.aggregateType !== 'indexer-profile') throw new Error('Invalid indexer aggregate');
  const actual = state === undefined ? undefined : indexerState.parse(state);
  if (
    ![1, 2].includes(profileVersion) ||
    (profileVersion === 1 && actual?.policyGenerationDigest === null)
  )
    throw new Error('Invalid indexer provenance profile');
  const projection =
    actual === undefined
      ? new Map<number, CborValue>()
      : new Map<number, CborValue>([
          [0, actual.engine],
          [1, actual.engineVersion],
          [2, Buffer.from(actual.methodProfileDigest.slice(7), 'hex')],
          [3, actual.state],
        ]);
  if (actual !== undefined) {
    if (profileVersion === 1) {
      projection.set(4, Buffer.from(actual.policyGenerationDigest!.slice(7), 'hex'));
    } else {
      projection.set(4, actual.policyGenerationDigest === null ? 0n : 1n);
      if (actual.policyGenerationDigest !== null)
        projection.set(5, Buffer.from(actual.policyGenerationDigest.slice(7), 'hex'));
    }
  }
  const existence = actual === undefined ? 0 : 1;
  const revision = actual === undefined ? 0n : BigInt(actual.revision);
  const preimage = transitionStatePreimage(context, existence, revision, projection);
  return {
    preimage,
    reference: { existence, revision, stateDigest: createHash('sha256').update(preimage).digest() },
  };
}

export type IndexerStateCommand =
  | {
      readonly kind: 'CREATE';
      readonly engine: IndexerBusinessState['engine'];
      readonly engineVersion: string;
      readonly methodProfileDigest: string;
    }
  | {
      readonly kind: 'UPDATE';
      readonly expectedRevision: string;
      readonly replacementDigest: string;
    };

/** Validate effects against the command and actual pre/post rows, not a returned API DTO. */
export function assertIndexerBusinessTransition(
  command: IndexerStateCommand,
  before: IndexerBusinessState | undefined,
  after: IndexerBusinessState | undefined,
): void {
  const prior = before === undefined ? undefined : indexerState.parse(before);
  const next = after === undefined ? undefined : indexerState.parse(after);
  if (next === undefined)
    throw new IndexerBusinessTransitionError('Indexer transition has no durable result');
  if (command.kind === 'CREATE') {
    if (
      prior !== undefined ||
      next.revision !== '1' ||
      next.state !== 'REGISTERED' ||
      next.engine !== command.engine ||
      next.engineVersion !== command.engineVersion ||
      next.methodProfileDigest !== command.methodProfileDigest
    )
      throw new IndexerBusinessTransitionError('Invalid indexer creation transition');
    return;
  }
  if (
    command.kind !== 'UPDATE' ||
    prior === undefined ||
    command.expectedRevision !== prior.revision ||
    BigInt(next.revision) !== BigInt(prior.revision) + 1n ||
    next.engine !== prior.engine ||
    next.engineVersion !== prior.engineVersion ||
    next.state !== prior.state ||
    next.methodProfileDigest !== command.replacementDigest ||
    (next.methodProfileDigest === prior.methodProfileDigest &&
      next.policyGenerationDigest === prior.policyGenerationDigest)
  )
    throw new IndexerBusinessTransitionError('Invalid or unchanged indexer update transition');
}
