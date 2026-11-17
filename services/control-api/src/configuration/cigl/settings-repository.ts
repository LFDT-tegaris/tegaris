import { validateCiglSettings, encodeCiglSettingsSource } from './settings-core.js';
import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import {
  ciglSettingsDefinitionSchema,
  ciglSettingsResponseSchema,
  type CiglSettingsDefinition,
} from './settings-contract.js';

export class CiglSettingsRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(pool: Pool, verifier?: IdentityRuntimeVerifier) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }
  create(context: MutationContext, definition: CiglSettingsDefinition) {
    const validated = validateCiglSettings(ciglSettingsDefinitionSchema.parse(definition));
    return this.mutations.execute(context, async (client, settingsId, operationId) => {
      await client.query(
        `insert into control.cigl_settings(cigl_settings_id,participant_id,privacy_domain_id,
        definition,definition_digest,publication_operation_id,publication_authority_digest)
        values ($1,$2,$3,$4::jsonb,$5,$6,$7)`,
        [
          settingsId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          JSON.stringify(validated.definition),
          validated.definitionDigest,
          operationId,
          `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
        ],
      );
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'openpc.cigl.settings.staged.v1',
      };
    });
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<{
        definition: unknown;
        definitionDigest: string;
        publicationOperationId: string;
        publicationAuthorityDigest: string;
        createdAt: Date;
      }>(
        `select definition,definition_digest as "definitionDigest",publication_operation_id::text as "publicationOperationId",
          publication_authority_digest as "publicationAuthorityDigest",created_at as "createdAt"
         from control.cigl_settings where cigl_settings_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
        [
          context.resourceId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
        ],
      );
      const row = result.rows[0];
      if (result.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const validated = validateCiglSettings(ciglSettingsDefinitionSchema.parse(row.definition));
      if (validated.definitionDigest !== row.definitionDigest)
        throw new ConfigurationRepositoryError('PC-DATA-6004');
      return ciglSettingsResponseSchema.parse({
        ...encodeCiglSettingsSource({
          settingsId: context.resourceId,
          participantId: context.authorization.participantId,
          privacyDomainId: context.authorization.privacyDomainId,
          publicationOperationId: row.publicationOperationId,
          publicationAuthorityDigest: row.publicationAuthorityDigest,
          definitionDigest: validated.definitionDigest,
          definition: validated.definition,
        }),
        ciglSettingsId: `urn:openpc:resource:${context.resourceId}`,
        definition: validated.definition,
        definitionDigest: validated.definitionDigest,
        publicationOperationId: row.publicationOperationId,
        publicationAuthorityDigest: row.publicationAuthorityDigest,
        revision: '1',
        state: 'STAGED',
        runtimePermission: 'NONE',
        createdAt: new Date(row.createdAt).toISOString(),
      });
    });
  }
}
