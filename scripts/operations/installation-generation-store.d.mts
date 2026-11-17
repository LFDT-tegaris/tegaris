import type { OperationsSourceCustody } from './installation-source-authentication.mjs';
import type { Pool, PoolClient } from 'pg';
export interface OperationsInstallationScope {
  participantId: string;
  privacyDomainId: string;
}
export function withInstallationTransaction<T>(
  pool: Pool,
  scope: OperationsInstallationScope,
  action: (client: PoolClient, scope: OperationsInstallationScope) => Promise<T>,
): Promise<T>;
export function lockInstallationEnvironment(client: PoolClient, environment: string): Promise<void>;
export interface OperationsGenerationSources {
  schema: unknown;
  schemaBytes: Buffer;
  namedProfile: unknown;
  profileBytes: Buffer;
  site: Record<string, unknown>;
  siteBytes: Buffer;
  environment: Record<string, unknown>;
  profile: string;
}
export interface OperationsGenerationReadback {
  generation_id: string;
  base_generation_id: string;
  candidate_digest: string;
  state: 'STAGED' | 'FENCED';
  effective_digest: string | null;
  missing: string[];
}
export function installInitialOperationsEnvironment(
  pool: Pool,
  scope: OperationsInstallationScope,
  input: {
    pins: unknown;
    initialBaseGenerationId: string;
    schemaBytes: Buffer;
    profileBytes: Buffer;
    sourceAuthentication?: OperationsSourceCustody;
  },
): Promise<string>;
export function stageInitialOperationsGeneration(
  pool: Pool,
  scope: OperationsInstallationScope,
  sources: OperationsGenerationSources,
  signed: { payload: Buffer; cose: Buffer },
): Promise<{
  environmentId: string;
  generationId: string;
  candidateDigest: string;
  state: 'STAGED';
  effective: false;
  missingBindings: string[];
}>;
export function commitOperationsGeneration(
  pool: Pool,
  scope: OperationsInstallationScope,
  environment: string,
  generationId: string,
): Promise<{ generation_id: string; effective_digest: string }>;
/** Uses the actual request context and native provider-retry ES256/evidence
 * checks on this same control-owner READ COMMITTED client. No pool or caller
 * readiness evidence is accepted. Caller must roll back on any failure and
 * retain the transaction through all other required live-source rechecks. */
export function commitOperationsGenerationInTransaction(
  client: PoolClient,
  scope: OperationsInstallationScope,
  environment: string,
  generationId: string,
): Promise<{ generation_id: string; effective_digest: string }>;
export function readOperationsGeneration(
  pool: Pool,
  scope: OperationsInstallationScope,
  environment: string,
  generationId: string,
): Promise<OperationsGenerationReadback>;
