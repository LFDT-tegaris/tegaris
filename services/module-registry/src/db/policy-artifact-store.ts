import { createHash } from 'node:crypto';

import type { Pool, PoolClient } from 'pg';

import {
  compilePolicySemantics,
  validatePolicySemantics,
  type PolicySemanticDocument,
} from '../domain/policy-semantics.js';
import { ContractError } from '../domain/errors.js';
import { assertPolicyModuleBindings, loadPolicyContractInputs } from './policy-inputs.js';
import { loadPolicyDeploymentInputs } from './deployment-policy-inputs.js';
import { loadPolicyIndexerInputs } from './indexer-policy-inputs.js';
import { loadPolicyVisibilityInputs } from './visibility-policy-inputs.js';
import {
  decodePolicyArtifactPayload,
  type TrustedPolicyArtifactSigner,
  verifyPolicyArtifactCose,
} from '../domain/policy-artifact.js';

const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const semanticVersion = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;

export interface AdmitPolicyArtifactInput {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly policyId: string;
  readonly admittedByPrincipalId: string;
  readonly operationId: string;
  readonly actionIntentId: string;
  readonly semanticVersion: string;
  readonly semanticDocument: unknown;
  readonly semanticCbor: Buffer;
  readonly policySchemaDigest: Buffer;
  readonly dependencyClosureDigest: Buffer;
  readonly payloadCbor: Buffer;
  readonly coseSign1: Buffer;
  readonly trustedSigners: readonly TrustedPolicyArtifactSigner[];
}

export interface AdmittedPolicyArtifact {
  readonly policyArtifactId: string;
  readonly semanticDigest: Buffer;
  readonly semanticBytesDigest: Buffer;
  readonly admittedAt: string;
}

export interface CreatePolicyVersionFromArtifactInput {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly policyId: string;
  readonly createdByPrincipalId: string;
  readonly operationId: string;
  readonly actionIntentId: string;
  readonly semanticVersion: string;
  readonly normalizedPolicyDigest: Buffer;
  readonly dependencyClosureDigest: Buffer;
}

export interface StoredPolicyVersion {
  readonly policyVersionId: string;
  readonly semanticVersion: string;
  readonly semanticDigest: Buffer;
  readonly semanticBytesDigest: Buffer;
  readonly dependencyClosureDigest: Buffer;
  readonly createdAt: string;
}

interface PreparedArtifact {
  readonly document: PolicySemanticDocument;
  readonly semanticCbor: Buffer;
  readonly semanticDigest: Buffer;
  readonly signerKeyDigest: Buffer;
}

function urn(kind: 'participant' | 'privacy-domain' | 'policy-set', id: string): string {
  return `urn:openpc:${kind}:${id}`;
}

function exactDigest(value: Buffer): boolean {
  return value.length === 32;
}

function validateIdentifiers(input: {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly policyId: string;
  readonly operationId: string;
  readonly principalId: string;
  readonly actionIntentId: string;
  readonly semanticVersion: string;
}): void {
  if (
    !uuidV7.test(input.participantId) ||
    !uuidV7.test(input.privacyDomainId) ||
    !uuidV7.test(input.policyId) ||
    !uuidV7.test(input.operationId) ||
    !uuidV7.test(input.principalId) ||
    !/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u.test(input.actionIntentId) ||
    !semanticVersion.test(input.semanticVersion)
  ) {
    throw new ContractError('PC-POLICY-2000', 'invalid policy artifact identity');
  }
}

function prepareArtifact(input: AdmitPolicyArtifactInput): PreparedArtifact {
  validateIdentifiers({
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    policyId: input.policyId,
    operationId: input.operationId,
    principalId: input.admittedByPrincipalId,
    actionIntentId: input.actionIntentId,
    semanticVersion: input.semanticVersion,
  });
  if (
    !exactDigest(input.policySchemaDigest) ||
    !exactDigest(input.dependencyClosureDigest) ||
    input.semanticCbor.length === 0 ||
    input.payloadCbor.length === 0 ||
    input.coseSign1.length === 0 ||
    input.trustedSigners.length === 0
  ) {
    throw new ContractError('PC-POLICY-2000', 'incomplete policy artifact');
  }
  try {
    const canonical = validatePolicySemantics(input.semanticDocument);
    const semanticBytesDigest = createHash('sha256').update(canonical.bytes).digest();
    const payload = decodePolicyArtifactPayload(input.payloadCbor);
    if (
      !canonical.bytes.equals(input.semanticCbor) ||
      canonical.document.participantId !== input.participantId ||
      canonical.document.privacyDomainId !== input.privacyDomainId ||
      !canonical.digest.equals(semanticBytesDigest) ||
      payload.participantId !== urn('participant', input.participantId) ||
      payload.privacyDomainId !== urn('privacy-domain', input.privacyDomainId) ||
      payload.policySetId !== urn('policy-set', input.policyId) ||
      payload.semanticVersion !== input.semanticVersion ||
      !payload.policySchemaDigest.equals(input.policySchemaDigest) ||
      !payload.semanticDigest.equals(canonical.digest) ||
      !payload.semanticBytesDigest.equals(semanticBytesDigest) ||
      !payload.dependencyClosureDigest.equals(input.dependencyClosureDigest)
    ) {
      throw new Error('artifact binding mismatch');
    }
    const signerKeyDigest = verifyPolicyArtifactCose(
      input.trustedSigners,
      input.payloadCbor,
      input.coseSign1,
    );
    if (signerKeyDigest === undefined) throw new Error('untrusted policy artifact signature');
    return {
      document: canonical.document,
      semanticCbor: canonical.bytes,
      semanticDigest: canonical.digest,
      signerKeyDigest,
    };
  } catch (error) {
    if (error instanceof ContractError) throw error;
    throw new ContractError('PC-POLICY-2003', 'policy artifact verification failed');
  }
}

async function setContext(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly operationId: string;
    readonly actionIntentId: string;
  },
): Promise<void> {
  await client.query('set local row_security=on');
  await client.query('select openpc.set_request_context($1,$2,$3,$4,$5,true)', [
    'PARTICIPANT',
    input.participantId,
    input.privacyDomainId,
    input.operationId,
    input.actionIntentId,
  ]);
}

async function serializable<T>(
  pool: Pool,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const client = await pool.connect();
    try {
      await client.query('begin isolation level serializable');
      const result = await operation(client);
      await client.query('commit');
      return result;
    } catch (error) {
      await client.query('rollback').catch(() => undefined);
      if (
        attempt < 3 &&
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === '40001'
      ) {
        continue;
      }
      throw error;
    } finally {
      client.release();
    }
  }
  throw new Error('SERIALIZABLE_RETRY_EXHAUSTED');
}

function artifactMatches(
  row: Record<string, unknown>,
  input: AdmitPolicyArtifactInput,
  prepared: PreparedArtifact,
): boolean {
  return (
    String(row.participant_id) === input.participantId &&
    String(row.privacy_domain_id) === input.privacyDomainId &&
    String(row.policy_id) === input.policyId &&
    String(row.semantic_version) === input.semanticVersion &&
    String(row.admitted_by_principal_id) === input.admittedByPrincipalId &&
    Buffer.isBuffer(row.policy_schema_digest) &&
    row.policy_schema_digest.equals(input.policySchemaDigest) &&
    Buffer.isBuffer(row.semantic_cbor) &&
    row.semantic_cbor.equals(prepared.semanticCbor) &&
    Buffer.isBuffer(row.semantic_digest) &&
    row.semantic_digest.equals(prepared.semanticDigest) &&
    Buffer.isBuffer(row.semantic_bytes_digest) &&
    row.semantic_bytes_digest.equals(prepared.semanticDigest) &&
    Buffer.isBuffer(row.dependency_closure_digest) &&
    row.dependency_closure_digest.equals(input.dependencyClosureDigest) &&
    Buffer.isBuffer(row.payload_cbor) &&
    row.payload_cbor.equals(input.payloadCbor) &&
    Buffer.isBuffer(row.payload_digest) &&
    row.payload_digest.equals(createHash('sha256').update(input.payloadCbor).digest()) &&
    // ES256 signatures may differ for an identical authenticated payload. Keep
    // the original stored signature; replay requires the same verified signer.
    Buffer.isBuffer(row.signer_key_digest) &&
    row.signer_key_digest.equals(prepared.signerKeyDigest)
  );
}

export async function admitPolicyArtifact(
  pool: Pool,
  input: AdmitPolicyArtifactInput,
): Promise<AdmittedPolicyArtifact> {
  return serializable(pool, (client) => admitPolicyArtifactInTransaction(client, input));
}

export async function admitPolicyArtifactInTransaction(
  client: PoolClient,
  input: AdmitPolicyArtifactInput,
): Promise<AdmittedPolicyArtifact> {
  const prepared = prepareArtifact(input);
  await setContext(client, input);
  await assertPolicyModuleBindings(client, prepared.document, input.dependencyClosureDigest);
  const admittedContracts = await loadPolicyContractInputs(client, prepared.document);
  const admittedDeployments = await loadPolicyDeploymentInputs(client, prepared.document);
  const indexerInputs = await loadPolicyIndexerInputs(client, prepared.document);
  const visibilityInputs = await loadPolicyVisibilityInputs(client, prepared.document);
  compilePolicySemantics(
    prepared.document,
    admittedContracts,
    prepared.document.indexerPolicies?.[0]?.workloadId ?? input.admittedByPrincipalId,
    admittedDeployments,
    indexerInputs,
    visibilityInputs,
  );
  const owner = await client.query(
    `select policy.policy_id
       from control.policy policy
       join control.principal principal
         on (principal.participant_id,principal.principal_id)=($1,$4)
      where policy.participant_id=$1 and policy.privacy_domain_id=$2 and policy.policy_id=$3
        and principal.state='ACTIVE'`,
    [input.participantId, input.privacyDomainId, input.policyId, input.admittedByPrincipalId],
  );
  if (owner.rowCount !== 1) throw new ContractError('PC-POLICY-2001');
  const inserted = await client.query(
    `insert into control.policy_artifact
     (participant_id,privacy_domain_id,policy_id,semantic_version,policy_schema_digest,
      semantic_cbor,semantic_digest,semantic_bytes_digest,dependency_closure_digest,
      payload_cbor,payload_digest,cose_sign1,signer_key_digest,admitted_by_principal_id)
     values ($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10,$11,$12,$13)
     on conflict do nothing
     returning policy_artifact_id,semantic_digest,semantic_bytes_digest,admitted_at`,
    [
      input.participantId,
      input.privacyDomainId,
      input.policyId,
      input.semanticVersion,
      input.policySchemaDigest,
      prepared.semanticCbor,
      prepared.semanticDigest,
      input.dependencyClosureDigest,
      input.payloadCbor,
      createHash('sha256').update(input.payloadCbor).digest(),
      input.coseSign1,
      prepared.signerKeyDigest,
      input.admittedByPrincipalId,
    ],
  );
  let row = inserted.rows[0] as Record<string, unknown> | undefined;
  if (inserted.rowCount !== 1) {
    const replay = await client.query(
      `select * from control.policy_artifact
        where participant_id=$1 and privacy_domain_id=$2
          and (semantic_digest=$3 or
               (policy_id=$4 and semantic_version=$5 and policy_schema_digest=$6))`,
      [
        input.participantId,
        input.privacyDomainId,
        prepared.semanticDigest,
        input.policyId,
        input.semanticVersion,
        input.policySchemaDigest,
      ],
    );
    if (replay.rowCount !== 1 || !artifactMatches(replay.rows[0]!, input, prepared)) {
      throw new ContractError('PC-POLICY-2002', 'policy artifact replay conflict');
    }
    row = replay.rows[0] as Record<string, unknown>;
  }
  return {
    policyArtifactId: String(row?.policy_artifact_id),
    semanticDigest: Buffer.from(row?.semantic_digest as Buffer),
    semanticBytesDigest: Buffer.from(row?.semantic_bytes_digest as Buffer),
    admittedAt: new Date(String(row?.admitted_at)).toISOString(),
  };
}

export async function createPolicyVersionFromArtifact(
  pool: Pool,
  input: CreatePolicyVersionFromArtifactInput,
): Promise<StoredPolicyVersion> {
  return serializable(pool, (client) => createPolicyVersionInTransaction(client, input));
}

export async function createPolicyVersionInTransaction(
  client: PoolClient,
  input: CreatePolicyVersionFromArtifactInput,
): Promise<StoredPolicyVersion> {
  validateIdentifiers({
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    policyId: input.policyId,
    operationId: input.operationId,
    principalId: input.createdByPrincipalId,
    actionIntentId: input.actionIntentId,
    semanticVersion: input.semanticVersion,
  });
  if (!exactDigest(input.normalizedPolicyDigest) || !exactDigest(input.dependencyClosureDigest)) {
    throw new ContractError('PC-POLICY-2000', 'invalid policy version digest');
  }
  await setContext(client, input);
  const artifact = await client.query(
    `select artifact.*
       from control.policy_artifact artifact
       join control.principal principal
         on (principal.participant_id,principal.principal_id)=($1,$7)
      where artifact.participant_id=$1 and artifact.privacy_domain_id=$2
        and artifact.policy_id=$3 and artifact.semantic_version=$4
        and artifact.semantic_digest=$5 and artifact.dependency_closure_digest=$6
        and principal.state='ACTIVE'`,
    [
      input.participantId,
      input.privacyDomainId,
      input.policyId,
      input.semanticVersion,
      input.normalizedPolicyDigest,
      input.dependencyClosureDigest,
      input.createdByPrincipalId,
    ],
  );
  if (artifact.rowCount !== 1) {
    throw new ContractError('PC-POLICY-2001', 'admitted policy artifact not found');
  }
  const artifactRow = artifact.rows[0] as Record<string, unknown>;
  const inserted = await client.query(
    `insert into control.policy_version
     (policy_id,participant_id,privacy_domain_id,version,schema_digest,semantic_cbor,
      semantic_digest,cose_sign1,created_by_principal_id)
     select policy_id,participant_id,privacy_domain_id,semantic_version,policy_schema_digest,
            semantic_cbor,semantic_digest,cose_sign1,$7
       from control.policy_artifact
      where participant_id=$1 and privacy_domain_id=$2 and policy_id=$3
        and semantic_version=$4 and semantic_digest=$5 and dependency_closure_digest=$6
     on conflict do nothing
     returning policy_version_id,version,semantic_digest,created_at`,
    [
      input.participantId,
      input.privacyDomainId,
      input.policyId,
      input.semanticVersion,
      input.normalizedPolicyDigest,
      input.dependencyClosureDigest,
      input.createdByPrincipalId,
    ],
  );
  let row = inserted.rows[0] as Record<string, unknown> | undefined;
  if (inserted.rowCount !== 1) {
    const replay = await client.query(
      `select version.policy_version_id,version.version,version.semantic_digest,
              version.created_by_principal_id,version.created_at,
              artifact.semantic_bytes_digest,artifact.dependency_closure_digest
         from control.policy_version version
         join control.policy_artifact artifact
           on (artifact.participant_id,artifact.privacy_domain_id,artifact.policy_id,
               artifact.semantic_version,artifact.semantic_digest)=
              (version.participant_id,version.privacy_domain_id,version.policy_id,
               version.version,version.semantic_digest)
        where version.participant_id=$1 and version.privacy_domain_id=$2
          and version.policy_id=$3 and (version.semantic_digest=$4 or version.version=$5)`,
      [
        input.participantId,
        input.privacyDomainId,
        input.policyId,
        input.normalizedPolicyDigest,
        input.semanticVersion,
      ],
    );
    const candidate = replay.rows[0] as Record<string, unknown> | undefined;
    if (
      replay.rowCount !== 1 ||
      candidate === undefined ||
      candidate.version !== input.semanticVersion ||
      candidate.created_by_principal_id !== input.createdByPrincipalId ||
      !Buffer.isBuffer(candidate.semantic_digest) ||
      !candidate.semantic_digest.equals(input.normalizedPolicyDigest) ||
      !Buffer.isBuffer(candidate.semantic_bytes_digest) ||
      !candidate.semantic_bytes_digest.equals(input.normalizedPolicyDigest) ||
      !Buffer.isBuffer(candidate.dependency_closure_digest) ||
      !candidate.dependency_closure_digest.equals(input.dependencyClosureDigest)
    ) {
      throw new ContractError('PC-POLICY-2002', 'policy version replay conflict');
    }
    row = candidate;
  }
  return {
    policyVersionId: String(row?.policy_version_id),
    semanticVersion: String(row?.version),
    semanticDigest: Buffer.from(row?.semantic_digest as Buffer),
    semanticBytesDigest: Buffer.from(artifactRow.semantic_bytes_digest as Buffer),
    dependencyClosureDigest: Buffer.from(artifactRow.dependency_closure_digest as Buffer),
    createdAt: new Date(String(row?.created_at)).toISOString(),
  };
}
