import type { Pool } from 'pg';
import { requireDeploymentModules } from '../../../../module-registry/src/db/module-lifecycle-store.js';
import type { ModuleReleaseVerifier } from '../../../../module-registry/src/db/module-release-store.js';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { loadPolicyDeploymentInputs } from '../../../../module-registry/src/db/deployment-policy-inputs.js';
import { authorizeRuntimeArtifactRead } from '../../../../module-registry/src/db/runtime-artifact-materialization.js';
import { assertPolicyModuleBindings } from '../../../../module-registry/src/db/policy-inputs.js';
import { validatePolicySemantics } from '../../../../module-registry/src/domain/policy-semantics.js';
import { canonicalJson, sha256 } from '../digest.js';
import { resolveExecutionPrincipal } from '../execution-principal.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import { deploymentIntentCore } from './intent-core.js';
import type { CreateDeploymentIntent } from './intent-contract.js';
import { readStoredDeploymentIntent } from './intent-readback.js';

const id = (value: string) => value.slice(value.lastIndexOf(':') + 1);
const hex = (value: Buffer) => `0x${value.toString('hex')}`;
const decoded = (value: string) => Buffer.from(value.slice(2), 'hex');

export class DeploymentIntentRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(
    pool: Pool,
    verifier?: IdentityRuntimeVerifier,
    private readonly moduleVerifier?: ModuleReleaseVerifier,
  ) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  create(context: MutationContext, input: CreateDeploymentIntent) {
    return this.mutations.execute(context, async (client, intentId, operationId) => {
      const authority = context.authorization;
      const moduleGenerationDigest = await requireDeploymentModules(
        client,
        authority.participantId,
        authority.privacyDomainId,
        this.moduleVerifier,
      );
      // Preparation is a management action by the maker, not workload
      // authentication. Resolve the optional executor from current credential
      // ownership; its runtime grant and TLS proof are checked at submission.
      const executionPrincipalId = await resolveExecutionPrincipal(
        client,
        authority.participantId,
        input.executionWorkloadId,
      );
      // Wallet revocation is an authority denial, independently of runtime
      // source availability. Hold the current wallet through preparation so a
      // concurrent revoke cannot turn that decision into an unknown context.
      const walletAuthority = await client.query(
        `select 1 from control.wallet_binding
         where wallet_binding_id=$1 and participant_id=$2 and privacy_domain_id=$3
          and subject_id=$4 and state='ACTIVE' for share`,
        [
          id(input.walletBindingId),
          authority.participantId,
          authority.privacyDomainId,
          executionPrincipalId ?? authority.principalId,
        ],
      );
      if (walletAuthority.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const scoped = await client.query<{
        semanticCbor: Buffer;
        semanticDigest: Buffer;
        dependencyClosureDigest: Buffer;
        generationDigest: string;
        routingDigest: string;
        routeValidUntil: Date;
        walletAddress: string;
        walletEpoch: string;
        envelopeDigest: string;
        roleId: string;
        nowMs: string;
        inputId: string;
        configurationDigest: string;
      }>(
        `select version.semantic_cbor as "semanticCbor",version.semantic_digest as "semanticDigest",
        generation.dependency_closure_digest as "dependencyClosureDigest",target.policy_generation_digest as "generationDigest",
        route.routing_source_digest as "routingDigest",route.valid_until as "routeValidUntil",
        wallet.wallet_address as "walletAddress",wallet.binding_epoch::text as "walletEpoch",
        encode(envelope.semantic_digest,'hex') as "envelopeDigest",assignment.role_id as "roleId",
        floor(extract(epoch from clock_timestamp())*1000)::text as "nowMs",
        module_configuration.runtime_configuration_input_id::text as "inputId",
        encode(module_configuration.configuration_digest,'hex') as "configurationDigest"
       from control.runtime_target target
       join control.runtime_configuration_generation configuration on configuration.participant_id=target.participant_id
        and configuration.privacy_domain_id=target.privacy_domain_id and configuration.runtime_target_id=target.runtime_target_id
        and configuration.state='ACTIVE'
        and configuration.policy_generation_digest=target.policy_generation_digest
       join control.runtime_route_publication route on route.runtime_configuration_generation_id=configuration.runtime_configuration_generation_id
        and route.participant_id=target.participant_id and route.privacy_domain_id=target.privacy_domain_id
        and route.runtime_target_id=target.runtime_target_id and route.generation_digest=configuration.generation_digest
        and route.policy_generation_digest=target.policy_generation_digest and route.valid_until>clock_timestamp()
       join control.runtime_activation_observation activation on activation.configuration_work_id=route.configuration_work_id
        and activation.runtime_configuration_generation_id=configuration.runtime_configuration_generation_id
        and activation.runtime_target_id=target.runtime_target_id and activation.generation_digest=configuration.generation_digest
        and activation.capsule_digest=target.active_generation_digest
       join control.configuration_work work on work.configuration_work_id=activation.configuration_work_id
        and work.participant_id=target.participant_id and work.privacy_domain_id=target.privacy_domain_id
        and work.runtime_target_id=target.runtime_target_id and work.state='COMPLETED'
       join control.runtime_configuration_input_current_metadata module_configuration
        on 'sha256:'||encode(module_configuration.configuration_digest,'hex')=work.configuration_digest
        and module_configuration.active
       join control.module_installation installation on installation.module_installation_id=module_configuration.module_installation_id
        and installation.participant_id=target.participant_id and installation.privacy_domain_id=target.privacy_domain_id
        and installation.state='ENABLED'
       join control.module_version module_version on module_version.module_version_id=installation.module_version_id
        and module_version.module_id='pc.config.assets'
       join control.policy_generation generation on generation.participant_id=target.participant_id and generation.privacy_domain_id=target.privacy_domain_id
        and generation.generation_digest=decode(replace(target.policy_generation_digest,'sha256:',''),'hex') and generation.active
       join control.policy_version version on version.participant_id=generation.participant_id and version.privacy_domain_id=generation.privacy_domain_id
        and version.policy_version_id=generation.policy_version_id
       join control.wallet_binding wallet on wallet.participant_id=target.participant_id and wallet.privacy_domain_id=target.privacy_domain_id
        and wallet.wallet_binding_id=$4 and wallet.subject_id=coalesce($10::uuid,$5::uuid) and wallet.state='ACTIVE'
       join control.authority_envelope envelope on envelope.participant_id=target.participant_id and envelope.authority_envelope_id=$6
        and envelope.state='ACTIVE' and envelope.authority_epoch=$7 and envelope.delegation_epoch=$8
       join control.assignment assignment on assignment.participant_id=target.participant_id and assignment.assignment_id=$9
        and assignment.principal_id=$5 and assignment.state='ACTIVE'
       where target.participant_id=$1 and target.privacy_domain_id=$2 and target.runtime_target_id=$3
        and target.state='ACTIVE_MATCHED' and target.desired_generation_digest=target.active_generation_digest
       for share of target,configuration,generation,wallet,envelope,assignment`,
        [
          authority.participantId,
          authority.privacyDomainId,
          id(input.runtimeTargetId),
          id(input.walletBindingId),
          authority.principalId,
          authority.authorityEnvelopeId,
          authority.authorityEpoch,
          authority.delegationEpoch,
          authority.assignmentId,
          executionPrincipalId ?? null,
        ],
      );
      const owner = scoped.rows[0];
      if (scoped.rowCount !== 1 || !owner) throw new ConfigurationRepositoryError('PC-FACT-4001');
      await authorizeRuntimeArtifactRead(client, owner.inputId);
      const materialized = await client.query<{ payload: Buffer }>(
        'select openpc.runtime_artifact_input_payload($1::uuid) payload',
        [owner.inputId],
      );
      if (materialized.rowCount !== 1 || !Buffer.isBuffer(materialized.rows[0]?.payload))
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      const semantic = validatePolicySemantics(Array.from(owner.semanticCbor), 'DECODE_SEMANTICS');
      const document = semantic.document;
      if (
        !semantic.digest.equals(owner.semanticDigest) ||
        document.participantId !== authority.participantId ||
        document.privacyDomainId !== authority.privacyDomainId
      )
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      // Draft preparation retains exact admitted inputs, like administrative
      // simulation. It does not assert runtime enablement or grant submission.
      await assertPolicyModuleBindings(client, document, owner.dependencyClosureDigest);
      const publications = await loadPolicyDeploymentInputs(client, document);
      const publication = publications.find(
        (value) => value.deploymentPolicyId === id(input.deploymentPolicyId),
      );
      if (
        !publication ||
        !publication.definition.requiredRoles.every((role) => role === owner.roleId)
      )
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const walletChain = await client.query(
        'select 1 from control.wallet_binding where wallet_binding_id=$1 and chain_id=$2',
        [id(input.walletBindingId), publication.definition.chainId],
      );
      if (walletChain.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      let nativeValue: { documentBytes: Buffer; validUntil: Date } | undefined;
      if (input.nativeValueAuthorizationId !== undefined) {
        const issued = await client.query<{ documentBytes: Buffer; validUntil: Date }>(
          `select issued_grant.document_bytes as "documentBytes",issued_grant.valid_until as "validUntil"
           from control.native_value_authorization issued_grant
           where issued_grant.native_value_authorization_id=$1 and issued_grant.participant_id=$2
            and issued_grant.privacy_domain_id=$3 and issued_grant.wallet_binding_id=$4
            and issued_grant.wallet_binding_epoch=$5 and issued_grant.actor_principal_id=$6
            and issued_grant.execution_workload_id is not distinct from $7
            and issued_grant.valid_until>clock_timestamp()
            and not exists(select 1 from control.deployment_address_reservation reservation
              where reservation.native_value_authorization_id=issued_grant.native_value_authorization_id
               and reservation.state='HANDOFF')`,
          [
            id(input.nativeValueAuthorizationId),
            authority.participantId,
            authority.privacyDomainId,
            id(input.walletBindingId),
            owner.walletEpoch,
            executionPrincipalId ?? authority.principalId,
            input.executionWorkloadId ?? null,
          ],
        );
        if (issued.rowCount !== 1 || !issued.rows[0])
          throw new ConfigurationRepositoryError('PC-AUTH-0005');
        nativeValue = issued.rows[0];
      }
      const nowMs = Number(owner.nowMs);
      const expiresAtMs = Math.min(
        nowMs + 300_000,
        Date.parse(publication.definition.expiresAt),
        owner.routeValidUntil.getTime(),
        nativeValue?.validUntil.getTime() ?? Number.POSITIVE_INFINITY,
      );
      const authorityDigest = authority.evidenceDigest.toString('hex');
      const prepared = deploymentIntentCore('PREPARE_DEPLOYMENT_INTENT', {
        publication,
        signingPayload: input.signingPayload,
        nowMs,
        ...(input.executionWorkloadId === undefined
          ? {}
          : {
              runtimeConfiguration: {
                bytes: hex(materialized.rows[0]!.payload),
                digest: owner.configurationDigest,
              },
            }),
        context: {
          intentId,
          participantId: authority.participantId,
          privacyDomainId: authority.privacyDomainId,
          participantEpoch: authority.participantEpoch,
          actorSubjectId: executionPrincipalId ?? authority.principalId,
          workloadBindingId: input.executionWorkloadId ?? null,
          walletBindingId: id(input.walletBindingId),
          walletBindingEpoch: owner.walletEpoch,
          sender: Array.from(Buffer.from(owner.walletAddress.slice(2), 'hex')),
          chainEnvironmentId: `${publication.definition.chainId}:${publication.definition.networkId}:${publication.definition.genesisDigest}`,
          targetRuntimeId: id(input.runtimeTargetId),
          policyGenerationDigest: owner.generationDigest.slice(7),
          authorityDigest,
          policyDecisionDigest: sha256({
            authorityDigest,
            publicationDigest: publication.definitionDigest,
            semanticDigest: semantic.digest.toString('hex'),
            signingPayloadDigest: sha256(decoded(input.signingPayload)),
            roleId: owner.roleId,
          }).slice(7),
          entitlementEnvelopeDigest: owner.envelopeDigest,
          routingConstraintDigest: owner.routingDigest.slice(7),
          // Approval of creating a draft is not deployment execution approval.
          approvalSetDigest: sha256([]).slice(7),
          ...(nativeValue === undefined
            ? {}
            : { nativeValueAuthorizationBytes: hex(nativeValue.documentBytes) }),
          issuedAtMs: nowMs,
          expiresAtMs,
        },
      });
      const record = decoded(prepared.recordBytes);
      if (
        sha256(record) !== `sha256:${prepared.recordDigest}` ||
        prepared.signingPayload !== input.signingPayload
      )
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      await client.query(
        `insert into control.deployment_intent(deployment_intent_id,participant_id,privacy_domain_id,actor_principal_id,
        deployment_policy_id,runtime_target_id,wallet_binding_id,preparation_bytes,publication_bytes,preparation_digest,intent_digest,
        creation_operation_id,creation_authority_digest,expires_at,execution_principal_id,execution_workload_id,module_generation_digest)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
        [
          intentId,
          authority.participantId,
          authority.privacyDomainId,
          authority.principalId,
          id(input.deploymentPolicyId),
          id(input.runtimeTargetId),
          id(input.walletBindingId),
          record,
          Buffer.from(canonicalJson(publication)),
          `sha256:${prepared.recordDigest}`,
          `sha256:${prepared.intentDigest}`,
          operationId,
          `sha256:${authorityDigest}`,
          new Date(prepared.expiresAtMs),
          executionPrincipalId ?? null,
          input.executionWorkloadId ?? null,
          moduleGenerationDigest,
        ],
      );
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'openpc.deployment.intent.prepared.v1',
      };
    });
  }

  get(context: ReadContext) {
    return this.reads.execute(context, (client) =>
      readStoredDeploymentIntent(client, {
        deploymentIntentId: context.resourceId,
        participantId: context.authorization.participantId,
        privacyDomainId: context.authorization.privacyDomainId,
        makerPrincipalId: context.authorization.principalId,
      }),
    );
  }
}
