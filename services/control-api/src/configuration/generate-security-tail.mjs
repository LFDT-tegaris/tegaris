import {
  expiredCredentialDenialProvenanceSql,
  expiredCredentialDenialAdmissionSql,
  expiredCredentialDenialIssuanceSql,
} from './expired-credential-denial-guards.mjs';
import { expiredDenialHandoverGuardsSql } from './expired-denial-handover-guards.mjs';
import { expiredActivationGuardsSql } from './expired-activation-guards.mjs';
import { activationMaintenanceGuardsSql } from './activation-maintenance-guards.mjs';
import { runtimeArtifactRetirementAdmissionSql } from '../evidence/runtime-artifact-retirement-admission.mjs';
import { runtimeArtifactDispositionGuardsSql } from '../evidence/runtime-artifact-disposition-guards.mjs';
import { notificationCompletionWorkerRegistrationSql } from '../notifications/completion-worker-registration.mjs';
import { notificationAsyncWorkerGuardsSql } from '../notifications/async-worker-guards.mjs';
import { notificationCompletionDispositionRegistrationSql } from '../notifications/completion-disposition-registration.mjs';
import { workItemLifecycleGuardsSql } from '../../../identity-service/src/db/work-item-receipt-guards.mjs';
import { targetDispositionRegistrationSql } from './target-disposition/registration.mjs';
import { runtimeArtifactRetirementGuardsSql } from '../evidence/runtime-artifact-retirement-guards.mjs';
import { runtimeArtifactUseGuardsSql } from '../evidence/runtime-artifact-use-guards.mjs';
import { runtimeArtifactSourceGuardsSql } from '../evidence/runtime-artifact-source-guards.mjs';
import {
  runtimeArtifactMaterializationGuardsSql,
  runtimeArtifactPayloadGrantsSql,
} from '../evidence/runtime-artifact-materialization-guards.mjs';
import { runtimeGenerationRetryGuardsSql } from './runtime-generation-retry-guards.mjs';
import { runtimeArtifactArchiveGuardsSql } from '../evidence/runtime-artifact-archive-guards.mjs';
import { notificationOutcomePublicationGuardsSql } from '../notifications/delivery-outcome-publication-guards.mjs';
import { notificationOutcomePublicationSharedSql } from '../notifications/delivery-outcome-publication-shared.mjs';
import { providerRetryQualificationGuardsSql } from './operations/provider-retry-qualification-guards.mjs';
import { providerRetryQualificationRolesSql } from './operations/provider-retry-registration.mjs';
import { providerRetryProbeSourceSql } from './operations/provider-retry-probe-source.mjs';
import {
  qualificationKeyCustodyGuardsSql,
  qualificationKeyPeerGrantsSql,
} from './operations/qualification-key-custody-guards.mjs';
import { qualificationDeploymentObservationGuardsSql } from './operations/qualification-deployment-observation-guards.mjs';
import { notificationDeliveryDispatchGuardsSql } from '../notifications/delivery-dispatch-guards.mjs';
import { notificationDeliveryCancellationGuardsSql } from '../notifications/delivery-cancellation-guards.mjs';
import {
  notificationDeliveryOutcomeObservationGuardsSql,
  notificationDeliveryOutcomeImmutabilityGuardsSql,
  notificationDeliveryOutcomeSigningGuardsSql,
} from '../notifications/delivery-outcome-guards.mjs';
import { notificationDeliverySigningGuardsSql } from '../notifications/delivery-signing-guards.mjs';
import { notificationDeliveryStartAtomicGuardsSql } from '../notifications/delivery-start-atomic-guards.mjs';
import { operationsSourceAuthenticationGuardsSql } from './operations/source-authentication-guards.mjs';
import { notificationReceiptSignerGuardsSql } from '../notifications/receipt-signer-guards.mjs';
import { buildOperationsSecretResolutionGuardsSql } from './operations/secret-resolution-guards.mjs';
import { notificationDeliveryPreparationGuardsSql } from '../notifications/delivery-start-preparation-guards.mjs';
import { evidenceExportPublicationGuardsSql } from '../evidence/export-completion-publication-guards.mjs';
import { operationsGenerationGuardsSql } from './operations/guards.mjs';
import { notificationDeliveryBudgetGuardsSql } from '../notifications/delivery-start-guards.mjs';
import {
  notificationOccurrenceGuardsSql,
  notificationOccurrencePublicationGuardsSql,
} from '../notifications/occurrence-guards.mjs';
import { notificationKeyCustodyGuardsSql } from '../evidence/notification-key-guards.mjs';
import { notificationWorkerInstallationGuardsSql } from '../notifications/worker-installation-guards.mjs';
import {
  evidenceKmsInstallationGuardsSql,
  evidenceKmsReceiptGuardsSql,
  evidenceKmsPreparationGuardsSql,
} from '../evidence/kms-guards.mjs';
import { notificationRoutingInstallationGuardsSql } from '../notifications/routing-installation-guards.mjs';
import { evidenceExportCompletionGuardsSql } from '../evidence/export-completion-guards.mjs';
import { evidenceExportProducerGuardsSql } from '../evidence/export-producer-guards.mjs';
import { moduleControlReferenceWriteFenceSql } from '../../../module-registry/src/db/module-lifecycle-guards.mjs';
import { factConsumerFailureGuardsSql } from '../fact-consumers/failure-guards.mjs';
import { notificationReceiptGuardsSql } from '../notifications/receipt-guards.mjs';
import {
  notificationEndpointAdmissionGuardsSql,
  notificationEndpointAdmissionGrantsSql,
  notificationEndpointPersistenceAdmissionSql,
} from '../notifications/endpoint-admission-guards.mjs';
import { factConsumerProfileGuardsSql } from '../fact-consumers/profile-guards.mjs';
import { fleetDeliveryGuardsSql } from '../fact-consumers/fleet-delivery-guards.mjs';
import { factDeliveryGuardsSql } from '../evidence/fact-delivery-guards.mjs';
import { candidateArchiveGuardsSql } from '../evidence/candidate-archive/guards.mjs';
import {
  projectionDeletionGuardsSql,
  projectionRetirementCoreSql,
} from '../evidence/projection-deletion-guards.mjs';
import { rawProofDeletionGuardsSql } from '../evidence/raw-deletion-guards.mjs';
import { deploymentLineageGuardsSql } from '../evidence/deployment-lineage-guards.mjs';
import { deploymentProjectionGuardsSql } from '../evidence/deployment-projection-guards.mjs';
import { remoteArchiveGuardsSql } from '../evidence/remote-archive-guards.mjs';
import { remoteArchiveCustodyGuardsSql } from '../evidence/remote-archive-custody-guards.mjs';
import { factProvenanceGuardsSql } from '../evidence/fact-provenance-guards.mjs';
import { rpcProvenanceGuardsSql } from '../evidence/rpc-provenance-guards.mjs';
import { protectedProofGuardsSql } from '../evidence/protected-guards.mjs';
import { protectedProofCustodyGuardsSql } from '../evidence/protected-custody-guards.mjs';
import { protectedRemoteCustodyGuardsSql } from '../evidence/protected-remote-custody-guards.mjs';
import { protectedRemoteArchiveSourceSql } from '../evidence/protected-remote-archive-guards.mjs';
import { evidenceDeletionGuardsSql } from '../evidence/deletion-guards.mjs';
import { runtimeInputGuardsSql } from './runtime-input-guards.mjs';
import { runtimeArtifactFenceSql } from '../evidence/runtime-artifact-fence.mjs';
import { runtimeArtifactReferenceGuardsSql } from '../evidence/runtime-artifact-reference-guards.mjs';
import { preparationGuardsSql, contractRegistrationGuardsSql } from './preparation-guards.mjs';
import { discoveryGuardsSql } from './discovery-guards.mjs';
import { explorerProfileGuardsSql } from './privacy-explorer/profile-guards.mjs';
import { explorerCustodyGuardsSql } from '../privacy-explorer/custody-guards.mjs';
import { evidenceCustodyGuardsSql } from '../evidence/guards.mjs';
import { evidencePayloadGuardsSql } from '../evidence/payload-guards.mjs';
import { evidenceHoldGuardsSql } from '../evidence/hold-guards.mjs';
import { retentionPolicyGuardsSql } from '../evidence/retention-guards.mjs';
import { storeRetirementGuardsSql } from '../evidence/store-retirement-guards.mjs';
import { storeRetirementSourceGuardsSql } from '../evidence/store-retirement-source-guards.mjs';
import { storeRetirementAdmissionGuardsSql } from '../evidence/store-retirement-admission-guards.mjs';
import { storeRetirementAuthorityGuardsSql } from '../evidence/store-retirement-authority-guards.mjs';
import { storeRetirementDeliveryGuardsSql } from '../evidence/store-retirement-delivery-guards.mjs';
import { sourceDispatchGuardsSql } from './source-dispatch-guards.mjs';
import { contractAdministrationGuardsSql } from './contract-administration-guards.mjs';
import { deploymentReservationGuardsSql } from './deployment/reservation-guards.mjs';
import { deploymentRejectionGuardsSql } from './deployment/rejection-guards.mjs';
import { deploymentPolicyGuardsSql } from './deployment/policy-guards.mjs';
import { deploymentIntentGuardsSql } from './deployment/intent-guards.mjs';
import { nativeValueGuardsSql } from './native-value/guards.mjs';
import { ciglSettingsGuardsSql } from './cigl/settings-guards.mjs';
import { ciglGrantGuardsSql } from './cigl/grant-guards.mjs';
import { ciglAnalysisGuardsSql } from './cigl/analysis-guards.mjs';
import { ciglProfileGuardsSql } from './cigl/profile-guards.mjs';
import { ciglDependencyGuardsSql } from './cigl/dependency-guards.mjs';
import { ciglActivationGuardsSql } from './cigl/activation-guards.mjs';
import { runtimeTargetProfileBindingGuardsSql } from './runtime-profile/guards.mjs';
import { deploymentAssociationGuardsSql } from '../../../participant-service/src/domain/deployment-association-guards.mjs';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.ts';

const marker = '-- OPENPC CONTROL-API SECURITY TAIL';
const preludeBegin = '-- OPENPC CONTROL-API REFERENCE PRELUDE';
const preludeEnd = '-- END OPENPC CONTROL-API REFERENCE PRELUDE';
const generationArguments = process.argv.slice(2);
if (
  generationArguments.length > 1 ||
  (generationArguments.length === 1 && generationArguments[0] !== '--operations-source-only')
)
  throw new Error('Unsupported security-tail generation arguments');
const directory = new URL('../../../../migrations/postgres/control-api/', import.meta.url);
const migrations = (await readdir(directory))
  .filter((name) => /^[0-9]{4}_.*\.sql$/u.test(name))
  .sort();
const latest = migrations.at(-1);
if (latest === undefined) throw new Error('control-api migration missing');
const path = new URL(latest, directory);
const source = await readFile(path, 'utf8');
if (generationArguments[0] === '--operations-source-only') {
  // Drizzle creates the journal entry and empty custom migration first. This
  // lane emits only the changed source owner, leaving applied bytes untouched.
  const journal = JSON.parse(await readFile(new URL('meta/_journal.json', directory), 'utf8'));
  if (
    !/^[0-9]{4}_public_operations_source_v1\.sql$/u.test(latest) ||
    journal.entries?.at(-1)?.tag !== latest.slice(0, -4)
  )
    throw new Error('A new latest Drizzle public-source custom migration is required');
  const generated = `-- Generated from configuration/operations/source-authentication-guards.mjs.\n${operationsSourceAuthenticationGuardsSql.trim()}\n`;
  if (source !== generated) {
    const empty = source.replace(/^\s*--[^\n]*(?:\n|$)/gmu, '').trim() === '';
    if (!empty) throw new Error('Existing migration bytes are immutable; create a new migration');
    await writeFile(path, generated, 'utf8');
  }
  process.exit(0);
}

const withoutPrelude = source.startsWith(preludeBegin)
  ? source.slice(source.indexOf(preludeEnd) + preludeEnd.length).trimStart()
  : source;
const base = withoutPrelude.includes(marker)
  ? withoutPrelude.slice(0, withoutPrelude.indexOf(marker)).trimEnd()
  : withoutPrelude.trimEnd();
// Drizzle's new FKs run before the security tail. Restore only the referenced
// columns for DDL; each owning tail revokes the temporary privilege again.
const referenceGrants = [
  /REFERENCES "control"\."operations_installation"\(/u.test(base)
    ? 'GRANT REFERENCES(participant_id,privacy_domain_id,environment_id) ON control.operations_installation TO openpc_control_owner;'
    : '',
  /REFERENCES "control"\."evidence_wrapped_key"\(/u.test(base)
    ? 'GRANT REFERENCES(participant_id,privacy_domain_id,key_id) ON control.evidence_wrapped_key TO openpc_control_owner;'
    : '',
  /REFERENCES "control"\."operations_generation"\(/u.test(base)
    ? 'GRANT REFERENCES(participant_id,privacy_domain_id,environment_id,generation_id) ON control.operations_generation TO openpc_control_owner;'
    : '',
].filter(Boolean);
// FK validation runs as the referenced table's real schema owner. Leave RLS
// enabled and every runtime policy intact; the owning tail restores FORCE in
// the same atomic migration before any catalogue change becomes visible.
const referenceOwnerValidation =
  /REFERENCES "control"\."runtime_expired_activation_denial"\(/u.test(base)
    ? ['ALTER TABLE control.runtime_expired_activation_denial NO FORCE ROW LEVEL SECURITY;']
    : [];
const referencePreludeStatements = [...referenceGrants, ...referenceOwnerValidation];
const referencePrelude = referencePreludeStatements.length
  ? `${preludeBegin}\n${referencePreludeStatements.join('\n')}\n${preludeEnd}\n`
  : '';
const tables = [
  'privacy_explorer_profile',
  'privacy_explorer_execution',
  'privacy_explorer_continuation',
  'privacy_explorer_route_audit',
  'abi_artifact',
  'logical_contract_asset',
  'contract_administration_transfer',
  'contract_runtime_binding',
  'typed_argument_rule_version',
  'argument_rule_named_set_binding',
  'typed_argument_rule',
  'contract_method_policy',
  'provider_profile',
  'provider_probe_observation',
  'indexer_profile',
  'runtime_target',
  'runtime_target_profile_binding',
  'runtime_target_connection',
  'projection_plan',
  'runtime_configuration_generation',
  'configuration_work',
  'runtime_configuration_input',
  'runtime_activation_observation',
  'runtime_route_publication',
  'deployment_address_reservation',
  'deployment_address_claim',
  'deployment_policy',
  'deployment_intent',
  'native_value_authorization',
  'cigl_settings',
  'cigl_method_access_grants',
  'cigl_grant_history',
  'cigl_analysis',
  'cigl_method_profile',
  'cigl_profile_version',
  'cigl_profile_grant_source',
  'cigl_profile_method_source',
  'cigl_profile_dependency_path',
  'cigl_method_grant_dependency_claims',
  'deployment_result',
  'contract_governance_association',
];
const qualified = tables.map((table) => `"control"."${table}"`).join(', ');
const mutable = tables
  .filter(
    (table) =>
      ![
        'runtime_activation_observation',
        'runtime_target_connection',
        'runtime_target_profile_binding',
        'runtime_configuration_input',
        'provider_probe_observation',
        'runtime_route_publication',
        'deployment_address_reservation',
        'deployment_address_claim',
        'deployment_result',
        'native_value_authorization',
        'cigl_settings',
        'cigl_method_access_grants',
        'cigl_grant_history',
        'cigl_analysis',
        'cigl_method_profile',
        'cigl_profile_version',
        'cigl_profile_grant_source',
        'cigl_profile_method_source',
        'cigl_profile_dependency_path',
        'cigl_method_grant_dependency_claims',
        'contract_governance_association',
      ].includes(table),
  )
  .map((table) => `"control"."${table}"`)
  .join(', ');
const tail = `${marker}
${preparationGuardsSql}
${contractRegistrationGuardsSql}
${discoveryGuardsSql}
${explorerProfileGuardsSql}
${explorerCustodyGuardsSql}
${contractAdministrationGuardsSql}
${deploymentRejectionGuardsSql}
${deploymentReservationGuardsSql}
${deploymentPolicyGuardsSql}
${deploymentIntentGuardsSql}
${nativeValueGuardsSql}
${ciglSettingsGuardsSql}
${ciglGrantGuardsSql}
${ciglAnalysisGuardsSql}
${ciglProfileGuardsSql}
${ciglDependencyGuardsSql}
${ciglActivationGuardsSql}
${runtimeTargetProfileBindingGuardsSql}
${deploymentAssociationGuardsSql}
${runtimeArtifactRetirementGuardsSql}
-- Native callers may observe denial and verify historical source proof only.
-- Physical capture/grants are installed below after the current source,
-- eligibility and signed effect owners have been defined.
GRANT SELECT ON control.runtime_artifact_retirement TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT EXECUTE ON FUNCTION openpc.assert_runtime_artifact_retirement_context(),
 openpc.runtime_artifact_digest_retired(text) TO openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_retirement_digest(control.runtime_artifact_retirement),
 openpc.runtime_artifact_retirement_after_digest(control.runtime_artifact_retirement),
 openpc.assert_runtime_artifact_retirement_owner(text),
 openpc.assert_runtime_artifact_retirement_committed(control.runtime_artifact_retirement) TO openpc_control_runtime;
${runtimeArtifactUseGuardsSql}
${runtimeArtifactSourceGuardsSql}
${runtimeArtifactMaterializationGuardsSql}
${runtimeInputGuardsSql}
${runtimeArtifactFenceSql}
${runtimeGenerationRetryGuardsSql}
${runtimeArtifactReferenceGuardsSql}
GRANT EXECUTE ON FUNCTION openpc.observe_runtime_artifact_references(uuid,text) TO openpc_control_runtime;
${moduleControlReferenceWriteFenceSql}
${sourceDispatchGuardsSql}
REVOKE ALL ON ${qualified} FROM PUBLIC;
REVOKE ALL ON ${qualified} FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON ${mutable} TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_target_connection" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON control.runtime_target_profile_binding TO openpc_control_runtime;
-- Identity's installed login inherits openpc_control_runtime. Its login is
-- created after Control DDL, so refer to the existing runtime group here.
GRANT SELECT ON control.runtime_target_profile_binding TO openpc_control_reader,openpc_control_worker;
GRANT SELECT ON "control"."provider_probe_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_route_publication" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_address_reservation" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."native_value_authorization" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_settings" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_access_grants" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_grant_history" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_analysis" TO "openpc_control_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_profile" TO "openpc_control_runtime";
GRANT SELECT, INSERT ON "control"."cigl_profile_version" TO "openpc_control_runtime";
GRANT SELECT ON "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source" TO "openpc_control_runtime";
GRANT UPDATE ON "control"."cigl_profile_version" TO "openpc_control_worker";
GRANT INSERT ON "control"."cigl_profile_grant_source", "control"."cigl_profile_method_source" TO "openpc_control_worker";
GRANT SELECT ON "control"."cigl_profile_dependency_path" TO "openpc_control_runtime";
GRANT INSERT ON "control"."cigl_profile_dependency_path" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE ON "control"."cigl_method_grant_dependency_claims" TO "openpc_control_runtime";
GRANT SELECT ON "control"."deployment_result", "control"."contract_governance_association" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_configuration_input" TO "openpc_control_runtime";
GRANT INSERT ON "control"."runtime_configuration_input" TO "openpc_control_worker";
GRANT UPDATE (selected) ON "control"."runtime_configuration_input" TO "openpc_control_worker";
GRANT SELECT ON ${qualified} TO "openpc_control_worker";
GRANT UPDATE ON ${mutable} TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."runtime_target_connection" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."provider_probe_observation" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."deployment_address_reservation" TO "openpc_control_worker";
GRANT INSERT ON "control"."deployment_result" TO "openpc_control_worker";
GRANT SELECT ON ${qualified} TO "openpc_control_reader";
${runtimeArtifactPayloadGrantsSql}
CREATE OR REPLACE FUNCTION openpc.reject_runtime_activation_observation_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
DROP TRIGGER IF EXISTS runtime_activation_observation_immutable ON "control"."runtime_activation_observation";
CREATE TRIGGER runtime_activation_observation_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_activation_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
DROP TRIGGER IF EXISTS runtime_route_publication_immutable ON "control"."runtime_route_publication";
CREATE TRIGGER runtime_route_publication_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_route_publication"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_provider_probe_observation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP='DELETE' OR OLD.state<>'RUNNING' OR
    ROW(NEW.observation_id,NEW.participant_id,NEW.privacy_domain_id,NEW.provider_profile_id,
        NEW.source_revision,NEW.input_digest,NEW.configuration_digest,NEW.created_at)
    IS DISTINCT FROM
    ROW(OLD.observation_id,OLD.participant_id,OLD.privacy_domain_id,OLD.provider_profile_id,
        OLD.source_revision,OLD.input_digest,OLD.configuration_digest,OLD.created_at) THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6020-IMMUTABLE-ROW';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS provider_probe_observation_guard ON "control"."provider_probe_observation";
CREATE TRIGGER provider_probe_observation_guard BEFORE UPDATE OR DELETE ON "control"."provider_probe_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.guard_provider_probe_observation();
${projectionRetirementCoreSql}
${evidenceCustodyGuardsSql}
${evidenceExportProducerGuardsSql}
${evidenceExportCompletionGuardsSql}
${evidenceExportPublicationGuardsSql}
${evidenceKmsInstallationGuardsSql}
${evidenceKmsPreparationGuardsSql}
${evidenceKmsReceiptGuardsSql}
${evidencePayloadGuardsSql}
${deploymentLineageGuardsSql}
${deploymentProjectionGuardsSql}
${remoteArchiveGuardsSql}
${evidenceHoldGuardsSql}
${remoteArchiveCustodyGuardsSql}
${factProvenanceGuardsSql}
${factDeliveryGuardsSql}
${candidateArchiveGuardsSql}
${runtimeArtifactArchiveGuardsSql}
${fleetFactGuardsSql}
${factConsumerProfileGuardsSql}
${fleetDeliveryGuardsSql}
${factConsumerFailureGuardsSql}
${notificationReceiptGuardsSql}
${notificationEndpointAdmissionGuardsSql}
${notificationEndpointAdmissionGrantsSql}
${notificationEndpointPersistenceAdmissionSql}
${notificationRoutingInstallationGuardsSql}
${notificationKeyCustodyGuardsSql}
${notificationWorkerInstallationGuardsSql}
${notificationCompletionWorkerRegistrationSql}
${targetDispositionRegistrationSql}
${notificationReceiptSignerGuardsSql}
${notificationOccurrenceGuardsSql}
${notificationOccurrencePublicationGuardsSql}
${retentionPolicyGuardsSql}
${evidenceDeletionGuardsSql}
${protectedProofGuardsSql}
${protectedProofCustodyGuardsSql}
${protectedRemoteArchiveSourceSql}
${protectedRemoteCustodyGuardsSql}
${rawProofDeletionGuardsSql}
${rpcProvenanceGuardsSql}
${projectionDeletionGuardsSql}
${storeRetirementGuardsSql}
${storeRetirementSourceGuardsSql}
${runtimeArtifactDispositionGuardsSql}
${runtimeArtifactRetirementAdmissionSql}
${storeRetirementAdmissionGuardsSql}
${storeRetirementAuthorityGuardsSql}
${storeRetirementDeliveryGuardsSql}
${operationsSourceAuthenticationGuardsSql}
${providerRetryQualificationRolesSql}
${providerRetryQualificationGuardsSql}
${providerRetryProbeSourceSql.trim()}
${qualificationKeyCustodyGuardsSql.trim()}
${qualificationKeyPeerGrantsSql.trim()}
${qualificationDeploymentObservationGuardsSql.trim()}
${operationsGenerationGuardsSql}
${buildOperationsSecretResolutionGuardsSql()}
ALTER TABLE control.notification_delivery ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.notification_delivery FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.notification_delivery FROM PUBLIC,openpc_control_runtime,openpc_control_worker;
GRANT SELECT,INSERT,UPDATE ON control.notification_delivery TO openpc_control_runtime;
${notificationDeliveryBudgetGuardsSql}
GRANT EXECUTE ON FUNCTION openpc.assert_notification_delivery_budget_owner() TO openpc_control_runtime;
ALTER TABLE control.notification_delivery_preparation ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.notification_delivery_preparation FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.notification_delivery_preparation FROM PUBLIC,openpc_control_runtime,openpc_control_worker;
GRANT SELECT,INSERT ON control.notification_delivery_preparation TO openpc_control_runtime;
${notificationDeliveryPreparationGuardsSql}
GRANT EXECUTE ON FUNCTION openpc.assert_notification_delivery_preparation_owner() TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.read_notification_delivery_payload_size(uuid,text) TO openpc_control_runtime;
-- Native admission and protected publication are not installed yet. Register
-- the durable shape and denial guards without granting scheduling DML or
-- activating the prepared outbox family. Every future grant needs its real owner.
${notificationAsyncWorkerGuardsSql}
${['notification_async_work', 'notification_async_work_transition']
  .map(
    (name) => `
ALTER TABLE control.${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${name} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;`,
  )
  .join('\n')}
GRANT EXECUTE ON FUNCTION openpc.assert_notification_async_worker_owner(),openpc.notification_async_pre_effect_phase(uuid),openpc.notification_async_initial_disposition(uuid,text,numeric) TO openpc_control_runtime;
${[
  'notification_delivery_signing',
  'notification_delivery_start',
  'notification_delivery_attempt',
  'notification_delivery_dispatch_intent',
]
  .map(
    (name) => `
ALTER TABLE control.${name} ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${name} FROM PUBLIC,openpc_control_runtime,openpc_control_worker;
GRANT SELECT,INSERT ON control.${name} TO openpc_control_runtime;`,
  )
  .join('\n')}
GRANT UPDATE ON control.notification_delivery_signing TO openpc_control_runtime;
${notificationDeliverySigningGuardsSql}
${notificationDeliveryStartAtomicGuardsSql}
${notificationDeliveryDispatchGuardsSql}
GRANT UPDATE ON control.notification_delivery_dispatch_intent TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.assert_notification_delivery_dispatch_owner(),openpc.check_notification_delivery_dispatch_current(uuid),openpc.check_notification_delivery_dispatch_intent_original(control.notification_delivery_dispatch_intent) TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.assert_notification_delivery_signing_owner(),openpc.check_notification_delivery_signing_original(control.notification_delivery_signing),openpc.check_notification_delivery_signing_current(control.notification_delivery_signing),openpc.assert_notification_delivery_start_atomic_guards(),openpc.assert_notification_delivery_start_atomic_owner(),openpc.check_notification_delivery_start_original(control.notification_delivery_start),openpc.check_notification_delivery_start_projection(control.notification_delivery,control.notification_delivery),openpc.check_notification_delivery_start_complete(uuid) TO openpc_control_runtime;
-- Replace the closed attempt barrier only after every coherent atomic guard is installed.
SELECT openpc.assert_notification_delivery_start_atomic_guards();
DROP TRIGGER IF EXISTS notification_delivery_attempt_closed ON control.notification_delivery_attempt;

${['notification_cancellation_signing', 'notification_delivery_cancellation']
  .map(
    (name) => `
ALTER TABLE control.${name} ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${name} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,INSERT ON control.${name} TO openpc_control_runtime;`,
  )
  .join('\n')}
GRANT UPDATE ON control.notification_cancellation_signing TO openpc_control_runtime;
-- The cause's source outbox is historical proof. Final cancellation still needs
-- its own atomic native publication/custody record before this write is released.
REVOKE INSERT ON control.notification_delivery_cancellation FROM openpc_control_runtime;
${notificationDeliveryCancellationGuardsSql}
GRANT EXECUTE ON FUNCTION openpc.assert_notification_delivery_cancellation_owner(),
 openpc.check_notification_delivery_cancellation_original(control.notification_delivery_cancellation),
 openpc.check_notification_delivery_cancellation_projection(control.notification_delivery,control.notification_delivery),
 openpc.check_notification_delivery_cancellation_complete(uuid),
 openpc.check_notification_cancellation_signing_original(control.notification_cancellation_signing),
 openpc.check_notification_cancellation_signing_current(control.notification_cancellation_signing),
 openpc.check_notification_delivery_cancellation_signer(uuid,text) TO openpc_control_runtime;

-- Start closed; only install the final grants after all shared/native guards below.
${[
  'notification_delivery_outcome_signing',
  'notification_delivery_outcome',
  'notification_delivery_observation',
]
  .map(
    (name) => `
ALTER TABLE control.${name} ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${name} FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.${name} TO openpc_control_runtime;
DROP TRIGGER IF EXISTS notification_outcome_closed ON control.${name};
CREATE TRIGGER notification_outcome_closed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON control.${name}
 FOR EACH STATEMENT EXECUTE FUNCTION openpc.deny_notification_delivery_effect();`,
  )
  .join('\n')}
${notificationDeliveryOutcomeObservationGuardsSql}
${notificationDeliveryOutcomeImmutabilityGuardsSql}
${notificationDeliveryOutcomeSigningGuardsSql}
GRANT EXECUTE ON FUNCTION openpc.check_notification_delivery_observation_original(control.notification_delivery_observation),
 openpc.assert_notification_outcome_signing_owner(),
 openpc.check_notification_outcome_signing_original(control.notification_delivery_outcome_signing),
 openpc.check_notification_outcome_signing_current(control.notification_delivery_outcome_signing) TO openpc_control_runtime;
-- Durable signing and final publication have distinct checked owners.
GRANT INSERT,UPDATE ON control.notification_delivery_outcome_signing TO openpc_control_runtime;
DROP TRIGGER IF EXISTS notification_outcome_closed ON control.notification_delivery_outcome_signing;
${workItemLifecycleGuardsSql}
${notificationOutcomePublicationGuardsSql}
${notificationOutcomePublicationSharedSql}
GRANT EXECUTE ON FUNCTION openpc.assert_notification_outcome_publication_owner(),
 openpc.check_notification_outcome_publication_receipt(control.notification_delivery_outcome),
 openpc.check_notification_delivery_completed_event(control.outbox_event),
 openpc.notification_failure_initial_projection(control.notification_delivery_outcome),
 openpc.check_notification_delivery_failure_work(control.work_item),
 openpc.check_notification_outcome_publication_original(uuid),
 openpc.check_notification_delivery_outcome_projection(control.notification_delivery,control.notification_delivery),
 openpc.check_notification_outcome_publication_complete(uuid) TO openpc_control_runtime;
-- Only immutable historical dependencies are readable by the existing custody
-- worker. No current signing, publication, claim or result write grant escapes.
GRANT SELECT ON control.notification_delivery_signing,control.notification_delivery_start,
 control.notification_delivery_attempt,control.notification_delivery_dispatch_intent,
 control.notification_delivery_outcome_signing,control.notification_delivery_outcome,
 control.notification_delivery_observation,control.notification_receipt_signer_installation,
 control.installed_notification_worker TO openpc_control_worker;
GRANT EXECUTE ON FUNCTION openpc.check_notification_outcome_publication_original(uuid),
 openpc.check_notification_outcome_publication_receipt(control.notification_delivery_outcome),
 openpc.check_notification_delivery_completed_event(control.outbox_event),
 openpc.notification_failure_initial_projection(control.notification_delivery_outcome),
 openpc.check_notification_outcome_signing_original(control.notification_delivery_outcome_signing),
 openpc.check_notification_delivery_observation_original(control.notification_delivery_observation),
 openpc.check_notification_delivery_start_original(control.notification_delivery_start),
 openpc.check_notification_delivery_dispatch_intent_original(control.notification_delivery_dispatch_intent),
 openpc.work_item_business_projection(control.work_item) TO openpc_control_worker;
SELECT openpc.assert_notification_outcome_publication_shared_owners();
GRANT INSERT ON control.notification_delivery_outcome,control.notification_delivery_observation TO openpc_control_runtime;
DROP TRIGGER IF EXISTS notification_outcome_closed ON control.notification_delivery_outcome;
DROP TRIGGER IF EXISTS notification_outcome_closed ON control.notification_delivery_observation;
${notificationCompletionDispositionRegistrationSql}
${activationMaintenanceGuardsSql}
${expiredActivationGuardsSql}
${expiredDenialHandoverGuardsSql}
${expiredCredentialDenialProvenanceSql}
${expiredCredentialDenialAdmissionSql}
${expiredCredentialDenialIssuanceSql}

`;
const migrationSql = `${referencePrelude}${base}\n${tail.trimEnd()}\n`;
verifyConditionCases(migrationSql);
await writeFile(path, migrationSql, 'utf8');
import { fleetFactGuardsSql } from './fleet-fact-guards.mjs';
