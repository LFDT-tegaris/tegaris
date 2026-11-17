import {
  readModuleAdmissionState,
  bindModuleAdmissionTransition,
} from './module-admission-state.js';
import type { ConfigurationBusinessEvidence } from '../../../control-api/src/configuration/persistence/business-receipt-writer.js';
import { AtomicConfigurationMutation } from '../../../control-api/src/configuration/persistence/atomic-mutation.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import type { MutationContext } from '../../../control-api/src/configuration/persistence/types.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { Pool, PoolClient } from 'pg';

import {
  resolveDependencies,
  type ModuleNode,
  type ExactDependency,
} from '../domain/dependency-resolver.js';
import { ContractError } from '../domain/errors.js';
import { uuidV7 } from '../domain/operation-id.js';
import type { ModuleReleaseBundle, VerifiedModuleRelease } from '../domain/module-release.js';
import { assertActionIntent, inScope, type PublicApprovalScope } from './public-approval-store.js';

export type ModuleReleaseVerifier = (
  bundle: ModuleReleaseBundle,
  nowMs: number,
) => VerifiedModuleRelease;
const hash = (value: unknown) => Buffer.from(sha256(value).slice(7), 'hex');
const hex = (value: Buffer) => `sha256:${value.toString('hex')}`;
const urn = (value: string) => `urn:openpc:resource:${value}`;
const releaseKey = (moduleId: string, version: string, manifestDigest: string) =>
  `${moduleId}@${version}:${manifestDigest}`;

export interface StoredRelease extends ModuleReleaseBundle {
  readonly moduleVersionId: string;
  readonly admissionDependencyDigest: Buffer | null;
  readonly moduleInstallationId: string;
  readonly state: string;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly lifecycleOperationId?: string | null;
}

export const selectRelease = `select version.module_version_id::text as "moduleVersionId",
 installation.module_installation_id::text as "moduleInstallationId",installation.state,
 installation.admission_dependency_digest as "admissionDependencyDigest",
 installation.lifecycle_operation_id::text as "lifecycleOperationId",
 installation.aggregate_version::text as revision,installation.created_at::text as "createdAt",
 installation.updated_at::text as "updatedAt",version.release_manifest_json as "manifestBytes",
 version.release_artifact as "artifactBytes",version.release_sbom as "sbomBytes",
 version.release_provenance as "provenanceBytes",version.release_build_receipt as "buildReceiptBytes",
 version.release_configuration_json as "configurationBytes",version.release_payload_cbor as "payloadCbor",
 version.cose_sign1 as "coseSign1"
 from control.module_installation installation join control.module_version version
 on version.module_version_id=installation.module_version_id`;

/** Resolve each dependency from this tenant's retained release and current signing trust. */
export async function dependencyClosure(
  client: PoolClient,
  scope: Pick<PublicApprovalScope, 'participantId' | 'privacyDomainId'>,
  root: VerifiedModuleRelease,
  verify: ModuleReleaseVerifier,
  nowMs: number,
  retained: ReadonlyMap<string, VerifiedModuleRelease> = new Map(),
) {
  // Reuse only bytes verified in this transaction, never another request's trust or scope.
  const verified = new Map(retained);
  verified.set(
    releaseKey(root.manifest.metadata.id, root.manifest.metadata.version, hex(root.manifestDigest)),
    root,
  );
  const nodes = new Map<string, ModuleNode>();
  const edges: ExactDependency[] = [];
  const queue = [root];
  const releases: VerifiedModuleRelease[] = [];
  while (queue.length) {
    if (nodes.size > 33) throw new ContractError('PC-MODULE-7001');
    const release = queue.shift()!;
    const manifest = release.manifest;
    const prior = nodes.get(manifest.metadata.id);
    if (prior) {
      if (prior.manifestDigest !== hex(release.manifestDigest))
        throw new ContractError('PC-MODULE-7003');
      continue;
    }
    nodes.set(manifest.metadata.id, {
      moduleId: manifest.metadata.id,
      semanticVersion: manifest.metadata.version,
      manifestDigest: hex(release.manifestDigest),
      capabilities: manifest.capabilities.provided.map((item) => item.capabilityId),
    });
    releases.push(release);
    for (const dependency of manifest.dependencies) {
      edges.push({
        edgeId: dependency.edgeId,
        consumerModuleId: manifest.metadata.id,
        providerModuleId: dependency.providerModuleId,
        capabilityId: dependency.capabilityId,
        semanticVersion: dependency.version,
        providerManifestDigest: dependency.manifestDigest,
      });
      const key = releaseKey(
        dependency.providerModuleId,
        dependency.version,
        dependency.manifestDigest,
      );
      const cached = verified.get(key);
      if (cached !== undefined) {
        queue.push(cached);
        continue;
      }
      const selected = await client.query<StoredRelease>(
        `${selectRelease}
       where installation.participant_id=$1 and installation.privacy_domain_id=$2
         and version.module_id=$3 and version.semantic_version=$4 and version.manifest_digest=$5
         and installation.state in ('ADMITTED','INSTALLED_DISABLED','ENABLED')
         and version.release_payload_cbor is not null`,
        [
          scope.participantId,
          scope.privacyDomainId,
          dependency.providerModuleId,
          dependency.version,
          Buffer.from(dependency.manifestDigest.slice(7), 'hex'),
        ],
      );
      if (selected.rowCount !== 1 || selected.rows[0] === undefined)
        throw new ContractError('PC-MODULE-7001');
      const provider = verify(selected.rows[0], nowMs);
      verified.set(key, provider);
      queue.push(provider);
    }
  }
  if (
    releases.some((release) => release.manifest.conflicts.moduleIds.some((id) => nodes.has(id)))
  ) {
    throw new ContractError('PC-MODULE-7004');
  }
  return resolveDependencies([...nodes.values()], edges);
}

export async function registerModuleRelease(
  pool: Pool,
  context: MutationContext,
  request: {
    readonly name: string;
    readonly semanticVersion: string;
    readonly manifestDigest: string;
    readonly supportProfile: string;
    readonly actionIntentId: string;
    readonly actionIntentDigest: string;
    readonly reason: string;
  },
  bundle: ModuleReleaseBundle,
  verify: ModuleReleaseVerifier,
  identityRuntimeVerifier?: IdentityRuntimeVerifier,
  businessEvidence?: ConfigurationBusinessEvidence,
) {
  if (businessEvidence === undefined || identityRuntimeVerifier === undefined)
    throw new ContractError('PC-MODULE-7008');
  return new AtomicConfigurationMutation(pool, identityRuntimeVerifier, businessEvidence).execute(
    context,
    async (client, moduleId) => {
      const scope = context.authorization;
      const before = await readModuleAdmissionState(client, context);
      const release = verify(bundle, Date.now());
      const manifest = release.manifest;
      if (
        request.name !== manifest.metadata.id ||
        request.semanticVersion !== manifest.metadata.version ||
        request.manifestDigest !== hex(release.manifestDigest) ||
        request.supportProfile !== 'R1'
      ) {
        throw new ContractError('PC-MODULE-7003');
      }
      await client.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
        `module-admission:${scope.participantId}:${scope.privacyDomainId}`,
      ]);
      const installed = await client.query<StoredRelease>(
        `${selectRelease}
        where installation.participant_id=$1 and installation.privacy_domain_id=$2
          and installation.state in ('ADMITTED','INSTALLED_DISABLED','ENABLED')`,
        [scope.participantId, scope.privacyDomainId],
      );
      const nowMs = Date.now();
      const retained = new Map<string, VerifiedModuleRelease>();
      for (const row of installed.rows) {
        const admitted = verify(row, nowMs);
        const key = releaseKey(
          admitted.manifest.metadata.id,
          admitted.manifest.metadata.version,
          hex(admitted.manifestDigest),
        );
        if (retained.has(key)) throw new ContractError('PC-MODULE-7009');
        retained.set(key, admitted);
        if (
          manifest.conflicts.moduleIds.includes(admitted.manifest.metadata.id) ||
          admitted.manifest.conflicts.moduleIds.includes(manifest.metadata.id)
        )
          throw new ContractError('PC-MODULE-7004');
      }
      const closure = await dependencyClosure(client, scope, release, verify, nowMs, retained);
      // One semantic version is immutable even when a second release uses another digest.
      await client.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
        `module-release:${request.name}`,
      ]);
      const prior = await client.query<{
        moduleVersionId: string;
        manifestDigest: Buffer;
        payloadCbor: Buffer | null;
      }>(
        `select module_version_id::text as "moduleVersionId",manifest_digest as "manifestDigest",release_payload_cbor as "payloadCbor"
       from control.module_version where module_id=$1 and semantic_version=$2`,
        [request.name, request.semanticVersion],
      );
      if (
        prior.rowCount !== 0 &&
        (prior.rowCount !== 1 ||
          !prior.rows[0]!.manifestDigest.equals(release.manifestDigest) ||
          !prior.rows[0]!.payloadCbor?.equals(release.payloadCbor))
      ) {
        throw new ContractError('PC-MODULE-7009');
      }
      let versionId = prior.rows[0]?.moduleVersionId;
      if (versionId === undefined) {
        await client.query(
          `insert into control.module_registration(module_id,display_name,owner,state)
        values($1,$2,'LS-MODULE-REGISTRY','ADMITTED') on conflict(module_id) do nothing`,
          [request.name, manifest.metadata.displayName],
        );
        versionId = uuidV7();
        await client.query(
          `insert into control.module_version
       (module_version_id,module_id,semantic_version,manifest_cbor,manifest_digest,cose_sign1,
        sbom_digest,provenance_digest,build_receipt_digest,release_manifest_json,release_artifact,
        release_sbom,release_provenance,release_build_receipt,release_configuration_json,
        release_payload_cbor,release_signer_key_digest)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
          [
            versionId,
            request.name,
            request.semanticVersion,
            release.manifestCbor,
            release.manifestDigest,
            release.coseSign1,
            release.sbomDigest,
            release.provenanceDigest,
            release.buildReceiptDigest,
            bundle.manifestBytes,
            bundle.artifactBytes,
            bundle.sbomBytes,
            bundle.provenanceBytes,
            bundle.buildReceiptBytes,
            bundle.configurationBytes,
            release.payloadCbor,
            release.signerKeyDigest,
          ],
        );
        for (const capability of manifest.capabilities.provided) {
          await client.query(
            `insert into control.module_capability(module_version_id,capability_id,contract_digest)
          values($1,$2,$3)`,
            [versionId, capability.capabilityId, hash(capability)],
          );
        }
        for (const dependency of manifest.dependencies) {
          await client.query(
            `insert into control.module_dependency(consumer_module_version_id,edge_id,
          provider_module_id,capability_id,semantic_version,provider_manifest_digest) values($1,$2,$3,$4,$5,$6)`,
            [
              versionId,
              dependency.edgeId,
              dependency.providerModuleId,
              dependency.capabilityId,
              dependency.version,
              Buffer.from(dependency.manifestDigest.slice(7), 'hex'),
            ],
          );
        }
      }
      const installation = await client.query(
        `insert into control.module_installation
      (module_installation_id,participant_id,privacy_domain_id,module_version_id,state,authority_epoch,
       delegation_epoch,desired_manifest_digest,idempotency_key,admission_dependency_digest)
      values($1,$2,$3,$4,'ADMITTED',$5,$6,$7,$8,$9) on conflict do nothing returning module_installation_id`,
        [
          moduleId,
          scope.participantId,
          scope.privacyDomainId,
          versionId,
          scope.authorityEpoch,
          scope.delegationEpoch,
          release.manifestDigest,
          context.idempotencyKey,
          Buffer.from(closure.closureDigest, 'hex'),
        ],
      );
      if (installation.rowCount !== 1) throw new ContractError('PC-MODULE-7009');
      await client.query(
        `insert into control.module_configuration_generation
      (participant_id,privacy_domain_id,module_installation_id,generation,configuration_cbor,configuration_digest,active)
      values($1,$2,$3,1,$4,$5,false)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          moduleId,
          release.configurationCbor,
          release.configurationDigest,
        ],
      );
      const after = await readModuleAdmissionState(client, context);
      return {
        businessState: bindModuleAdmissionTransition(context, before, after, {
          moduleId: request.name,
          semanticVersion: request.semanticVersion,
          manifestDigest: release.manifestDigest,
          dependencyDigest: Buffer.from(closure.closureDigest, 'hex'),
          configurationDigest: release.configurationDigest,
        }),
        result: undefined,
        revision: '1',
        outboxEventType: 'io.openpc.control.command.committed.v1',
      };
    },
  );
}

export async function readModuleRelease(
  pool: Pool,
  scope: PublicApprovalScope,
  moduleId: string,
  verify: ModuleReleaseVerifier,
) {
  return inScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['modules']);
    const selected = await client.query<StoredRelease>(
      `${selectRelease}
      where installation.participant_id=$1 and installation.privacy_domain_id=$2
        and installation.module_installation_id=$3 and version.release_payload_cbor is not null`,
      [scope.participantId, scope.privacyDomainId, moduleId],
    );
    const row = selected.rows[0];
    if (selected.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2001');
    const release = verify(row, Date.now());
    const closure = await dependencyClosure(client, scope, release, verify, Date.now());
    if (row.admissionDependencyDigest?.toString('hex') !== closure.closureDigest)
      throw new ContractError('PC-MODULE-7003');
    return {
      moduleId: urn(moduleId),
      name: release.manifest.metadata.id,
      semanticVersion: release.manifest.metadata.version,
      manifestDigest: hex(release.manifestDigest),
      supportProfile: 'R1' as const,
      state: await publicState(client, scope, row),
      revision: row.revision,
      createdAt: new Date(row.createdAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
      updatedAt: new Date(row.updatedAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
    };
  });
}

async function publicState(client: PoolClient, scope: PublicApprovalScope, row: StoredRelease) {
  if (row.state === 'INSTALLED_DISABLED') {
    // Initial installation and governed disable have distinct public readback;
    // derive the distinction from the exact retained signed effect, not a label.
    const result = await client.query<{ operation: string }>(
      `
      select a.catalog_operation_id operation from control.audit_occurrence a
      join control.evidence_record e using(participant_id,privacy_domain_id,receipt_id)
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.aggregate_id=$3
        and a.aggregate_type='module-registration' and a.operation_id=$4 and a.after_revision=$5
        and a.after_existence=1 and a.receipt_digest=sha256(a.receipt_cbor) and e.receipt_digest=a.receipt_digest
        and a.catalog_operation_id in ('MOD-OP-INSTALL','MOD-OP-DISABLE')`,
      [
        scope.participantId,
        scope.privacyDomainId,
        row.moduleInstallationId,
        row.lifecycleOperationId,
        row.revision,
      ],
    );
    if (result.rowCount !== 1) throw new ContractError('PC-MODULE-7003');
    return result.rows[0]!.operation === 'MOD-OP-DISABLE'
      ? ('DISABLED' as const)
      : ('INSTALLED' as const);
  }
  switch (row.state) {
    case 'ADMITTED':
      return 'REGISTERED' as const;
    case 'ENABLED':
      return 'ACTIVE' as const;
    default:
      throw new ContractError('PC-MODULE-7000');
  }
}
