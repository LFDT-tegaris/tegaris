import { readFileSync, statSync } from 'node:fs';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import { configurationCoreCommand } from '../core-command.js';
import { sha256 } from '../digest.js';
import { digestSchema } from '../resource-contracts.js';
import { enqueueCiglProfile } from './profile-queue.js';
import { readCiglProfile } from './profile-readback.js';
import {
  ciglAnalysisDefinitionSchema,
  ciglAnalysisResponseSchema,
  verifiedCiglAnalysisSchema,
  type CiglAnalysisDefinition,
  type CiglActionReview,
  ciglActionReviewSchema,
} from './analysis-contract.js';

const resourceId = (urn: string) => urn.slice('urn:openpc:resource:'.length);
interface AnalysisRow {
  analysis_id: string;
  participant_id: string;
  privacy_domain_id: string;
  runtime_target_id: string;
  runtime_binding_id: string;
  contract_method_policy_id: string;
  definition: CiglAnalysisDefinition;
  capsule_digest: string;
  policy_generation_digest: string;
  state: 'OPEN' | 'OBSERVED' | 'REVIEWED';
  review_definition: CiglActionReview | null;
  review_digest: string | null;
  revision: string;
  signed_receipt: Buffer | null;
  receipt_digest: string | null;
  analysis_digest: string | null;
  created_at: Date;
  expires_at: Date;
  now_ms: string;
}

/** Target IDs are pinned to deployment-owned keys. No public request supplies
 * trust. Reload on use so removing a key immediately withholds its evidence. */
function targetKey(targetId: string): string {
  try {
    const path = process.env.OPENPC_CIGL_ANALYSIS_TARGET_KEYS_FILE;
    if (!path || statSync(path).size > 65_536) throw new Error('missing target trust');
    const keys = z
      .record(z.uuidv7(), z.string().regex(/^(02|03)[0-9a-f]{64}$/u))
      .parse(JSON.parse(readFileSync(path, 'utf8')));
    const key = keys[targetId];
    if (!key) throw new Error('missing target trust');
    return `0x${key}`;
  } catch {
    throw new ConfigurationRepositoryError('PC-FACT-4001');
  }
}

function receiptInput(row: AnalysisRow, bytes: Buffer) {
  const definition = ciglAnalysisDefinitionSchema.parse(row.definition);
  return {
    signedBytes: `0x${bytes.toString('hex')}`,
    verificationKey: targetKey(row.runtime_target_id),
    expected: {
      analysisId: row.analysis_id,
      targetRuntimeId: row.runtime_target_id,
      capsuleDigest: row.capsule_digest.slice(7),
      transactionHash: [...Buffer.from(definition.transactionHash.slice(2), 'hex')],
      participantId: row.participant_id,
      privacyDomainId: row.privacy_domain_id,
      workloadId: definition.workloadId,
      rootRuntimeBindingId: row.runtime_binding_id,
      rootContractMethodPolicyId: row.contract_method_policy_id,
      policyGenerationDigest: row.policy_generation_digest.slice(7),
      createdAtMs: new Date(row.created_at).getTime(),
      expiresAtMs: new Date(row.expires_at).getTime(),
    },
    nowMs: Number(row.now_ms),
  };
}
function verify(row: AnalysisRow, bytes: Buffer) {
  return verifiedCiglAnalysisSchema.parse(
    configurationCoreCommand('READ_CIGL_ANALYSIS', receiptInput(row, bytes)),
  );
}
function verifyReview(row: AnalysisRow, review: CiglActionReview) {
  if (row.signed_receipt === null) throw new ConfigurationRepositoryError('PC-DATA-6007');
  try {
    const result = z
      .strictObject({
        identity: z.literal('PC-CIGL-ANALYSIS-REVIEW-1'),
        authority: z.literal('NONE'),
        receiptDigest: digestSchema,
        analysisDigest: digestSchema,
      })
      .parse(
        configurationCoreCommand('REVIEW_CIGL_ANALYSIS', {
          receipt: receiptInput(row, row.signed_receipt),
          review: {
            analysisDigest: review.analysisDigest.slice(7),
            actions: review.actions.map((action) => ({
              ...action,
              actionDigest: action.actionDigest.slice(7),
            })),
            program: review.program,
          },
        }),
      );
    if (
      result.receiptDigest !== row.receipt_digest ||
      result.analysisDigest !== row.analysis_digest
    )
      throw new ConfigurationRepositoryError('PC-FACT-4001');
  } catch (error) {
    if (error instanceof ConfigurationRepositoryError) throw error;
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
}

async function load(
  client: PoolClient,
  id: string,
  participant: string,
  privacy: string,
  lock = false,
) {
  const result = await client.query<AnalysisRow>(
    `select analysis.*,revision::text,
    floor(extract(epoch from clock_timestamp())*1000)::text now_ms
    from control.cigl_analysis analysis where analysis_id=$1 and participant_id=$2 and privacy_domain_id=$3${lock ? ' for update' : ''}`,
    [id, participant, privacy],
  );
  if (result.rowCount !== 1 || !result.rows[0])
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  return result.rows[0];
}

function referenceFailure(error: unknown): never {
  if (
    error instanceof Error &&
    'code' in error &&
    error.code === 'P0001' &&
    error.message === 'PC-AUTH-0005-CIGL-ANALYSIS-REFERENCE'
  )
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  throw error;
}

export class CiglAnalysisRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(pool: Pool, verifier?: IdentityRuntimeVerifier) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }
  create(context: MutationContext, input: CiglAnalysisDefinition) {
    const definition = ciglAnalysisDefinitionSchema.parse(input);
    // Fail before creating a job when its configured trust cannot verify any
    // result. The SQL owner independently resolves the current admitted capsule.
    return this.mutations
      .execute(context, async (client, analysisId, operationId) => {
        targetKey(resourceId(definition.targetRuntimeId));
        await client.query(
          `insert into control.cigl_analysis(analysis_id,participant_id,privacy_domain_id,
        runtime_target_id,runtime_binding_id,contract_method_policy_id,definition,
        creation_operation_id,publication_operation_id,publication_authority_digest,expires_at)
        values($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$8,$9,clock_timestamp())`,
          [
            analysisId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            resourceId(definition.targetRuntimeId),
            resourceId(definition.runtimeBindingId),
            resourceId(definition.contractMethodPolicyId),
            JSON.stringify(definition),
            operationId,
            `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
          ],
        );
        return {
          result: undefined,
          revision: '1',
          outboxEventType: 'openpc.cigl.analysis.created.v1',
        };
      })
      .catch(referenceFailure);
  }
  complete(context: MutationContext, input: { signedReceipt: string }) {
    return this.mutations
      .execute(context, async (client, analysisId, operationId) => {
        const row = await load(
          client,
          analysisId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          true,
        );
        if (
          row.state !== 'OPEN' ||
          row.revision !== '1' ||
          new Date(row.expires_at).getTime() <= Number(row.now_ms)
        )
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        const bytes = Buffer.from(input.signedReceipt.slice(2), 'hex');
        let verified;
        try {
          verified = verify(row, bytes);
        } catch (error) {
          if (error instanceof ConfigurationRepositoryError) throw error;
          throw new ConfigurationRepositoryError('PC-DATA-6004');
        }
        await client.query(
          `update control.cigl_analysis set state='OBSERVED',revision=2,signed_receipt=$2,
        receipt_digest=$3,analysis_digest=$4,publication_operation_id=$5,publication_authority_digest=$6 where analysis_id=$1`,
          [
            analysisId,
            bytes,
            verified.receiptDigest,
            verified.analysisDigest,
            operationId,
            `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
          ],
        );
        return {
          result: undefined,
          revision: '2',
          outboxEventType: 'openpc.cigl.analysis.observed.v1',
        };
      })
      .catch(referenceFailure);
  }
  review(context: MutationContext, input: CiglActionReview) {
    const review = ciglActionReviewSchema.parse(input);
    return this.mutations
      .execute(context, async (client, analysisId, operationId) => {
        const row = await load(
          client,
          analysisId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          true,
        );
        if (
          row.state !== 'OBSERVED' ||
          row.revision !== '2' ||
          new Date(row.expires_at).getTime() <= Number(row.now_ms)
        )
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        verifyReview(row, review);
        await client.query(
          `update control.cigl_analysis set state='REVIEWED',revision=3,review_definition=$2::jsonb,review_digest=$3,
        publication_operation_id=$4,publication_authority_digest=$5 where analysis_id=$1`,
          [
            analysisId,
            JSON.stringify(review),
            sha256(review),
            operationId,
            `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
          ],
        );
        await enqueueCiglProfile(client, context, analysisId, operationId);
        return {
          result: undefined,
          revision: '3',
          outboxEventType: 'openpc.cigl.analysis.reviewed.v1',
          asynchronous: true,
        };
      })
      .catch(referenceFailure);
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const row = await load(
        client,
        context.resourceId,
        context.authorization.participantId,
        context.authorization.privacyDomainId,
      );
      let observation = null;
      if (row.signed_receipt !== null) {
        try {
          observation = verify(row, row.signed_receipt);
          if (
            observation.receiptDigest !== row.receipt_digest ||
            observation.analysisDigest !== row.analysis_digest
          )
            throw new Error('unverifiable retained evidence');
        } catch {
          throw new ConfigurationRepositoryError('PC-FACT-4001');
        }
      }
      let review = null;
      if (row.review_definition !== null) {
        try {
          const definition = ciglActionReviewSchema.parse(row.review_definition);
          if (sha256(definition) !== row.review_digest) throw new Error('review digest mismatch');
          verifyReview(row, definition);
          const profile = await readCiglProfile(
            client,
            row.analysis_id,
            row.participant_id,
            row.privacy_domain_id,
            true,
          );
          review = {
            definition,
            digest: row.review_digest,
            profileCompilation: profile?.state ?? 'REQUIRED',
            profile: profile ?? null,
          };
        } catch {
          throw new ConfigurationRepositoryError('PC-FACT-4001');
        }
      }
      return ciglAnalysisResponseSchema.parse({
        analysisId: `urn:openpc:resource:${row.analysis_id}`,
        definition: row.definition,
        capsuleDigest: row.capsule_digest,
        policyGenerationDigest: row.policy_generation_digest,
        state:
          row.state === 'OPEN' && new Date(row.expires_at).getTime() <= Number(row.now_ms)
            ? 'EXPIRED'
            : row.state,
        revision: row.revision,
        runtimePermission: 'NONE',
        createdAt: new Date(row.created_at).toISOString(),
        expiresAt: new Date(row.expires_at).toISOString(),
        observation,
        review,
      });
    });
  }
}
