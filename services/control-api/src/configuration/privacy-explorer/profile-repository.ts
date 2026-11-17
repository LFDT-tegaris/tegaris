import type { Pool, PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { PrivacyExplorerExportProfileV1 } from '../../contracts/privacy-explorer-adapter.js';
import { validateExplorerProfile } from '../../privacy-explorer/profile-registration.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import { explorerProfileResponseSchema } from './profile-contract.js';

export async function lockExplorerProfile(
  client: PoolClient,
  registrationId: string,
  write = false,
) {
  await client.query(
    `select pg_advisory_xact_lock${write ? '' : '_shared'}(hashtextextended($1,0))`,
    [`privacy-explorer-profile:${registrationId}`],
  );
}

/** Policy and delivery consume this same source under its revocation fence. */
export async function loadRegisteredExplorerProfile(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  registrationId: string,
) {
  await lockExplorerProfile(client, registrationId);
  const result = await client.query<{ profile: unknown; profileDigest: string }>(
    `select profile,profile_digest as "profileDigest" from control.privacy_explorer_profile
     where participant_id=$1 and privacy_domain_id=$2 and registration_id=$3 and state='REGISTERED'
       and (profile->>'maximumDeadlineAt')::timestamptz>clock_timestamp()`,
    [participantId, privacyDomainId, registrationId],
  );
  const row = result.rows[0];
  if (result.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-AUTH-0005');
  const profile = validateExplorerProfile(row.profile);
  if (profile.digest !== row.profileDigest) throw new ConfigurationRepositoryError('PC-DATA-6004');
  return { registrationId, ...profile };
}

export class ExplorerProfileRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(pool: Pool, verifier?: IdentityRuntimeVerifier) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }
  create(context: MutationContext, input: PrivacyExplorerExportProfileV1) {
    const profile = validateExplorerProfile(input);
    return this.mutations.execute(context, async (client, registrationId, operationId) => {
      await client.query(
        `insert into control.privacy_explorer_profile
        (registration_id,participant_id,privacy_domain_id,profile,profile_digest,publication_operation_id,publication_authority_digest)
        values($1,$2,$3,$4::jsonb,$5,$6,$7)`,
        [
          registrationId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          JSON.stringify(profile),
          profile.digest,
          operationId,
          `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
        ],
      );
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'openpc.privacy-explorer.profile.registered.v1',
      };
    });
  }
  revoke(context: MutationContext, expectedRevision: string) {
    return this.mutations.execute(context, async (client, registrationId, operationId) => {
      await lockExplorerProfile(client, registrationId, true);
      const changed = await client.query(
        `update control.privacy_explorer_profile set state='REVOKED',revision=revision+1,revocation_operation_id=$4
        where registration_id=$1 and participant_id=$2 and privacy_domain_id=$3 and revision=$5::bigint and state='REGISTERED' returning registration_id`,
        [
          registrationId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          operationId,
          expectedRevision,
        ],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      return {
        result: undefined,
        revision: '2',
        outboxEventType: 'openpc.privacy-explorer.profile.revoked.v1',
      };
    });
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<Record<string, unknown>>(
        `select registration_id::text as "registrationId",profile,profile_digest as "profileDigest",
        state,revision::text,publication_operation_id::text as "publicationOperationId",publication_authority_digest as "publicationAuthorityDigest",
        revocation_operation_id::text as "revocationOperationId",created_at as "createdAt" from control.privacy_explorer_profile
        where registration_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
        [
          context.resourceId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
        ],
      );
      const row = selected.rows[0];
      if (selected.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      return explorerProfileResponseSchema.parse({
        ...row,
        registrationId: `urn:openpc:resource:${row.registrationId}`,
        runtimePermission: 'NONE_WITHOUT_ACTIVE_POLICY',
        createdAt: new Date(row.createdAt as string).toISOString(),
      });
    });
  }
}
