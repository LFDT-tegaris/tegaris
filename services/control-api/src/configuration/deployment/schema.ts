import { sql } from 'drizzle-orm';
import {
  check,
  boolean,
  foreignKey,
  pgPolicy,
  pgRole,
  pgSchema,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { nativeValueAuthorizations } from '../native-value/schema.js';

const control = pgSchema('control');
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
const instant = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 3, mode: 'string' });

/** Coordination only: neither a grant nor an assertion that public chain state is reserved.
 * HANDOFF is deliberately irreversible here. Reconciliation/governed release must be
 * connected to their actual evidence owners before a post-handoff release is supported.
 */
export const deploymentAddressReservations = control.table(
  'deployment_address_reservation',
  {
    attemptId: uuid('attempt_id').primaryKey(),
    commandId: uuid('command_id').notNull(),
    predecessorCommandId: uuid('predecessor_command_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    targetRuntimeId: text('target_runtime_id').notNull(),
    chainId: text('chain_id').notNull(),
    genesisDigest: text('genesis_digest').notNull(),
    contractAddress: text('contract_address'),
    helperAddress: text('helper_address'),
    senderAddress: text('sender_address').notNull(),
    // Nullable only for pre-upgrade custody whose immutable intent is unavailable.
    // Such retained rows block this sender until their existing owner resolves them.
    senderNonce: text('sender_nonce'),
    creatorAddress: text('creator_address').notNull(),
    mechanism: text('mechanism').notNull(),
    saltNamespaceDigest: text('salt_namespace_digest'),
    effectiveSalt: text('effective_salt'),
    artifactDigest: text('artifact_digest').notNull(),
    initCodeHash: text('init_code_hash').notNull(),
    intentDigest: text('intent_digest').notNull(),
    profileDigest: text('profile_digest').notNull(),
    generationDigest: text('generation_digest').notNull(),
    transactionHash: text('transaction_hash').notNull(),
    preparedRecordDigest: text('prepared_record_digest').notNull(),
    nativeValueAuthorizationId: uuid('native_value_authorization_id'),
    nativeValueAuthorizationDigest: text('native_value_authorization_digest'),
    expiresAt: instant('expires_at').notNull(),
    state: text('state').notNull().default('RESERVED'),
    createdAt: instant('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
    handoffAt: instant('handoff_at'),
    expiredAt: instant('expired_at'),
  },
  (t) => [
    pgPolicy('participant_isolation', {
      as: 'permissive',
      for: 'all',
      to: roles,
      using: sql`openpc.matches_participant(${t.participantId})`,
      withCheck: sql`openpc.matches_participant(${t.participantId})`,
    }),
    pgPolicy('privacy_domain_isolation', {
      as: 'restrictive',
      for: 'all',
      to: roles,
      using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
    }),
    // Physical collision domain, deliberately independent of tenant, target, factory,
    // salt namespace and mechanism. Configured network aliases cannot split custody.
    uniqueIndex('deployment_address_held_uq')
      .on(t.chainId, t.genesisDigest, t.contractAddress)
      .where(sql`${t.state}<>'EXPIRED' and ${t.predecessorCommandId} is null`),
    uniqueIndex('deployment_sender_nonce_held_uq')
      .on(t.chainId, t.genesisDigest, t.senderAddress, t.senderNonce)
      .where(sql`${t.state}<>'EXPIRED' and ${t.predecessorCommandId} is null`),
    uniqueIndex('deployment_native_value_held_uq')
      .on(t.nativeValueAuthorizationId)
      .where(
        sql`${t.state}<>'EXPIRED' and ${t.nativeValueAuthorizationId} is not null and ${t.predecessorCommandId} is null`,
      ),
    // A successor shares the predecessor's retained physical custody. Neither
    // failure nor expiry permits a second successor or releases the root.
    unique('deployment_replacement_predecessor_uq').on(t.predecessorCommandId),
    foreignKey({
      name: 'deployment_replacement_predecessor_fk',
      columns: [t.predecessorCommandId],
      foreignColumns: [t.commandId],
    }).onDelete('restrict'),
    check(
      'deployment_replacement_predecessor_ck',
      sql`${t.predecessorCommandId} is null or (${t.predecessorCommandId}<>${t.commandId} and substring(${t.predecessorCommandId}::text,15,1)='7')`,
    ),
    foreignKey({
      name: 'deployment_native_value_authorization_fk',
      columns: [t.nativeValueAuthorizationId],
      foreignColumns: [nativeValueAuthorizations.nativeValueAuthorizationId],
    }).onDelete('restrict'),
    check(
      'deployment_native_value_reference_ck',
      sql`
      (${t.nativeValueAuthorizationId} is null and ${t.nativeValueAuthorizationDigest} is null)
      or (${t.nativeValueAuthorizationId} is not null and ${t.nativeValueAuthorizationDigest} is not null
        and ${t.nativeValueAuthorizationDigest} ~ '^sha256:[0-9a-f]{64}$')`,
    ),
    check(
      'deployment_sender_nonce_ck',
      sql`${t.senderNonce} is null or (${t.senderNonce} ~ '^(0|[1-9][0-9]{0,19})$' and ${t.senderNonce}::numeric<2::numeric^64)`,
    ),
    unique('deployment_address_command_uq').on(t.commandId),
    // Expiration does not authorize a second attempt of the same signed bytes.
    unique('deployment_address_transaction_uq').on(t.chainId, t.genesisDigest, t.transactionHash),
    check(
      'deployment_address_chain_ck',
      sql`${t.chainId} ~ '^[1-9][0-9]{0,77}$' and ${t.chainId}::numeric<2::numeric^256`,
    ),
    check(
      'deployment_address_target_ck',
      sql`${t.targetRuntimeId} ~ '^[A-Za-z][A-Za-z0-9_.:@/-]{1,191}$'`,
    ),
    check(
      'deployment_address_ids_ck',
      sql`substring(${t.attemptId}::text,15,1)='7' and substring(${t.commandId}::text,15,1)='7'`,
    ),
    check(
      'deployment_address_addresses_ck',
      sql`((${t.contractAddress} is not null and ${t.contractAddress} ~ '^0x[0-9a-f]{40}$') or (${t.contractAddress} is null and ${t.mechanism}='CREATE')) and ${t.senderAddress} ~ '^0x[0-9a-f]{40}$' and ${t.creatorAddress} ~ '^0x[0-9a-f]{40}$'`,
    ),
    check(
      'deployment_address_hashes_ck',
      sql`${t.initCodeHash} ~ '^0x[0-9a-f]{64}$' and ${t.transactionHash} ~ '^0x[0-9a-f]{64}$'`,
    ),
    check(
      'deployment_address_digests_ck',
      sql`${t.genesisDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.artifactDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.intentDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.profileDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.generationDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.preparedRecordDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'deployment_helper_address_ck',
      sql`(${t.mechanism}='CREATE3' and ${t.helperAddress} is not null and ${t.helperAddress} ~ '^0x[0-9a-f]{40}$' and ${t.helperAddress}<>${t.contractAddress}) or (${t.mechanism}<>'CREATE3' and ${t.helperAddress} is null)`,
    ),
    check(
      'deployment_address_mechanism_ck',
      sql`(
    ${t.mechanism} in ('CREATE2','CREATE3') and ${t.saltNamespaceDigest} is not null and ${t.saltNamespaceDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.effectiveSalt} is not null and ${t.effectiveSalt} ~ '^0x[0-9a-f]{64}$'
  ) or (${t.mechanism} in ('TRANSACTION_CREATE','CREATE') and ${t.saltNamespaceDigest} is null and ${t.effectiveSalt} is null and (${t.mechanism}<>'TRANSACTION_CREATE' or ${t.senderAddress}=${t.creatorAddress}))`,
    ),
    check(
      'deployment_address_state_ck',
      sql`(
    ${t.state}='RESERVED' and ${t.handoffAt} is null and ${t.expiredAt} is null
  ) or (${t.state}='HANDOFF' and ${t.handoffAt} is not null and ${t.handoffAt}>=${t.createdAt} and ${t.handoffAt}<${t.expiresAt} and ${t.expiredAt} is null
  ) or (${t.state}='EXPIRED' and ${t.handoffAt} is null and ${t.expiredAt} is not null and ${t.expiredAt}>=${t.expiresAt})`,
    ),
    check(
      'deployment_address_expiry_ck',
      sql`${t.expiresAt}>${t.createdAt} and isfinite(${t.expiresAt})`,
    ),
  ],
);

/** Physical uniqueness index for every address in the same reservation.
 * The reservation trigger alone maintains it; this is not another grant or lease.
 */
export const deploymentAddressClaims = control.table(
  'deployment_address_claim',
  {
    attemptId: uuid('attempt_id').notNull(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    chainId: text('chain_id').notNull(),
    genesisDigest: text('genesis_digest').notNull(),
    address: text('address').notNull(),
    active: boolean('active').notNull(),
  },
  (t) => [
    primaryKey({ name: 'deployment_address_claim_pk', columns: [t.attemptId, t.address] }),
    foreignKey({
      name: 'deployment_address_claim_parent_fk',
      columns: [t.attemptId],
      foreignColumns: [deploymentAddressReservations.attemptId],
    }),
    uniqueIndex('deployment_address_claim_active_uq')
      .on(t.chainId, t.genesisDigest, t.address)
      .where(sql`${t.active}`),
    pgPolicy('deployment_address_claim_scope', {
      for: 'all',
      to: [...roles, pgRole('openpc_control_owner', { inherit: false })],
      using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
    }),
  ],
);
