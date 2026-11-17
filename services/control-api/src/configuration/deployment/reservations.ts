import type { PoolClient } from 'pg';
import { z } from 'zod';

import { canonicalJson } from '../digest.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const hash = z.string().regex(/^0x[0-9a-f]{64}$/u);
const address = z.string().regex(/^0x[0-9a-f]{40}$/u);
const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);

/** Internal binding, resolved by the deployment owner, never public request authority.
 * Factory CREATE normally retains a null symbolic address. A concrete address
 * does not itself establish certified pre-mine serialization.
 */
const bindingSchema = z
  .strictObject({
    attemptId: uuid,
    commandId: uuid,
    participantId: uuid,
    privacyDomainId: uuid,
    targetRuntimeId: z.string().regex(/^[A-Za-z][A-Za-z0-9_.:@/-]{1,191}$/u),
    chainId: z
      .string()
      .refine((value) => /^[1-9][0-9]{0,77}$/u.test(value) && BigInt(value) < 2n ** 256n),
    genesisDigest: digest,
    contractAddress: address.nullable(),
    helperAddress: address.optional(),
    senderAddress: address,
    creatorAddress: address,
    mechanism: z.enum(['TRANSACTION_CREATE', 'CREATE', 'CREATE2', 'CREATE3']),
    saltNamespaceDigest: digest.nullable(),
    effectiveSalt: hash.nullable(),
    artifactDigest: digest,
    initCodeHash: hash,
    intentDigest: digest,
    profileDigest: digest,
    generationDigest: digest,
    transactionHash: hash,
    preparedRecordDigest: digest,
    nativeValueAuthorizationId: uuid.optional(),
    nativeValueAuthorizationDigest: digest.optional(),
    expiresAt: z.iso.datetime({ precision: 3 }),
  })
  .refine(
    (value) =>
      (value.nativeValueAuthorizationId === undefined) ===
      (value.nativeValueAuthorizationDigest === undefined),
  )
  .refine((value) => value.contractAddress !== null || value.mechanism === 'CREATE')
  .refine((value) =>
    value.mechanism === 'CREATE2' || value.mechanism === 'CREATE3'
      ? value.saltNamespaceDigest !== null && value.effectiveSalt !== null
      : value.saltNamespaceDigest === null &&
        value.effectiveSalt === null &&
        (value.mechanism !== 'TRANSACTION_CREATE' || value.senderAddress === value.creatorAddress),
  )
  .refine((value) =>
    value.mechanism === 'CREATE3'
      ? value.helperAddress !== undefined && value.helperAddress !== value.contractAddress
      : value.helperAddress === undefined,
  );

export type DeploymentReservationBinding = z.infer<typeof bindingSchema>;
export type DeploymentReservationState = 'RESERVED' | 'HANDOFF' | 'EXPIRED';
export interface DeploymentReservation {
  readonly binding: DeploymentReservationBinding;
  readonly state: DeploymentReservationState;
  readonly createdAt: string;
  readonly handoffAt: string | null;
  readonly expiredAt: string | null;
}

export class DeploymentReservationError extends Error {
  constructor(readonly code: 'INVALID_BINDING' | 'UNAVAILABLE') {
    super(code);
  }
}

const columns = {
  attemptId: 'attempt_id',
  commandId: 'command_id',
  participantId: 'participant_id',
  privacyDomainId: 'privacy_domain_id',
  targetRuntimeId: 'target_runtime_id',
  chainId: 'chain_id',
  genesisDigest: 'genesis_digest',
  contractAddress: 'contract_address',
  helperAddress: 'helper_address',
  senderAddress: 'sender_address',
  creatorAddress: 'creator_address',
  mechanism: 'mechanism',
  saltNamespaceDigest: 'salt_namespace_digest',
  effectiveSalt: 'effective_salt',
  artifactDigest: 'artifact_digest',
  initCodeHash: 'init_code_hash',
  intentDigest: 'intent_digest',
  profileDigest: 'profile_digest',
  generationDigest: 'generation_digest',
  transactionHash: 'transaction_hash',
  preparedRecordDigest: 'prepared_record_digest',
  nativeValueAuthorizationId: 'native_value_authorization_id',
  nativeValueAuthorizationDigest: 'native_value_authorization_digest',
  expiresAt: 'expires_at',
} as const satisfies Record<keyof DeploymentReservationBinding, string>;
const entries = Object.entries(columns) as [keyof DeploymentReservationBinding, string][];
const projection =
  entries.map(([key, column]) => `${column} as "${key}"`).join(',') +
  ',state,created_at as "createdAt",handoff_at as "handoffAt",expired_at as "expiredAt"';
type Row = Omit<
  DeploymentReservationBinding,
  'expiresAt' | 'helperAddress' | 'nativeValueAuthorizationId' | 'nativeValueAuthorizationDigest'
> & {
  helperAddress: string | null;
  nativeValueAuthorizationId: string | null;
  nativeValueAuthorizationDigest: string | null;
  expiresAt: Date;
  state: DeploymentReservationState;
  createdAt: Date;
  handoffAt: Date | null;
  expiredAt: Date | null;
};

export function parseDeploymentReservationBinding(input: unknown): DeploymentReservationBinding {
  const result = bindingSchema.safeParse(input);
  if (!result.success) throw new DeploymentReservationError('INVALID_BINDING');
  return result.data;
}

function record(row: Row): DeploymentReservation {
  const {
    state,
    createdAt,
    handoffAt,
    expiredAt,
    helperAddress,
    nativeValueAuthorizationId,
    nativeValueAuthorizationDigest,
    ...binding
  } = row;
  return {
    binding: parseDeploymentReservationBinding({
      ...binding,
      ...(helperAddress === null || helperAddress === undefined ? {} : { helperAddress }),
      ...(nativeValueAuthorizationId === null || nativeValueAuthorizationId === undefined
        ? {}
        : { nativeValueAuthorizationId }),
      ...(nativeValueAuthorizationDigest === null || nativeValueAuthorizationDigest === undefined
        ? {}
        : { nativeValueAuthorizationDigest }),
      expiresAt: binding.expiresAt.toISOString(),
    }),
    state,
    createdAt: createdAt.toISOString(),
    handoffAt: handoffAt?.toISOString() ?? null,
    expiredAt: expiredAt?.toISOString() ?? null,
  };
}

async function readExact(
  client: PoolClient,
  binding: DeploymentReservationBinding,
  lock: boolean,
  senderNonce?: string,
): Promise<DeploymentReservation | undefined> {
  const result = await client.query<Row>(
    `select ${projection} from control.deployment_address_reservation
    where attempt_id=$1 and participant_id=$2 and privacy_domain_id=$3
      and ($4::text is null or sender_nonce=$4) ${lock ? 'for update' : ''}`,
    [binding.attemptId, binding.participantId, binding.privacyDomainId, senderNonce ?? null],
  );
  const row = result.rows[0];
  if (!row) return undefined;
  const found = record(row);
  if (canonicalJson(found.binding) !== canonicalJson(binding))
    throw new DeploymentReservationError('UNAVAILABLE');
  return found;
}

/** Runs inside the owning worker's scoped transaction. No authorization, networking,
 * automatic replacement, or cross-tenant discovery occurs here. The caller must
 * commit before any downstream handoff and preserve an uncertain commit as unknown.
 */
export async function reserveDeploymentAddress(
  client: PoolClient,
  input: DeploymentReservationBinding,
  senderNonce: string,
): Promise<DeploymentReservation> {
  const binding = parseDeploymentReservationBinding(input);
  if (!/^(0|[1-9][0-9]{0,19})$/u.test(senderNonce) || BigInt(senderNonce) >= 2n ** 64n)
    throw new DeploymentReservationError('INVALID_BINDING');
  const existing = await readExact(client, binding, false, senderNonce);
  if (existing) return existing;
  // A cross-scope unique conflict deliberately returns the same unavailable result
  // as any conflicting command/transaction. Do not surface constraint or row details.
  const inserted = await client
    .query<Row>(
      `insert into control.deployment_address_reservation
    (${entries.map(([, column]) => column).join(',')},sender_nonce) values (${entries.map((_, index) => `$${index + 1}`).join(',')},$${entries.length + 1})
    on conflict do nothing returning ${projection}`,
      [...entries.map(([key]) => binding[key]), senderNonce],
    )
    .catch((error: unknown) => {
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === '23505')
        throw new DeploymentReservationError('UNAVAILABLE');
      throw error;
    });
  if (inserted.rows[0]) return record(inserted.rows[0]);
  const replay = await readExact(client, binding, false, senderNonce);
  if (replay) return replay;
  throw new DeploymentReservationError('UNAVAILABLE');
}

/** One durable handoff transition. A replay is readback only: transitioned=false
 * must never be interpreted as permission to send. The target's real journal and
 * fresh authorization fence remain mandatory, including when a commit reply is lost.
 */
export async function handoffDeploymentAddress(
  client: PoolClient,
  input: DeploymentReservationBinding,
): Promise<{ reservation: DeploymentReservation; transitioned: boolean }> {
  const binding = parseDeploymentReservationBinding(input);
  const existing = await readExact(client, binding, true);
  if (!existing) throw new DeploymentReservationError('UNAVAILABLE');
  if (existing.state !== 'RESERVED') return { reservation: existing, transitioned: false };
  const updated = await client.query<Row>(
    `update control.deployment_address_reservation set state='HANDOFF'
    where attempt_id=$1 and participant_id=$2 and privacy_domain_id=$3 and state='RESERVED' and expires_at>clock_timestamp()
    returning ${projection}`,
    [binding.attemptId, binding.participantId, binding.privacyDomainId],
  );
  if (!updated.rows[0]) throw new DeploymentReservationError('UNAVAILABLE');
  return { reservation: record(updated.rows[0]), transitioned: true };
}

/** Only reservations never handed off may time out. Unknown send outcomes,
 * acknowledgements, absence from a provider, finality and reorg cannot call this
 * transition to release custody. Post-handoff release has no implementation here.
 */
export async function expireUnhandedDeploymentAddress(
  client: PoolClient,
  input: DeploymentReservationBinding,
): Promise<DeploymentReservation> {
  const binding = parseDeploymentReservationBinding(input);
  const existing = await readExact(client, binding, true);
  if (!existing) throw new DeploymentReservationError('UNAVAILABLE');
  if (existing.state === 'EXPIRED') return existing;
  if (existing.state !== 'RESERVED') throw new DeploymentReservationError('UNAVAILABLE');
  const updated = await client.query<Row>(
    `update control.deployment_address_reservation set state='EXPIRED'
    where attempt_id=$1 and participant_id=$2 and privacy_domain_id=$3 and state='RESERVED' and expires_at<=clock_timestamp()
    returning ${projection}`,
    [binding.attemptId, binding.participantId, binding.privacyDomainId],
  );
  if (!updated.rows[0]) throw new DeploymentReservationError('UNAVAILABLE');
  return record(updated.rows[0]);
}
