import { currentPlatformEnvelopeSql } from '../../../identity-service/src/db/current-platform-envelope.js';
import { PlatformScopeOwnerFailure } from '../../../identity-service/src/db/platform-scope-owner-failure.js';
import {
  commitPlatformScopeReplacement,
  readPlatformScopeReadiness,
} from '../../../identity-service/src/db/platform-scope-commit-store.js';
import { platformAssignmentAdmission } from '../../../identity-service/src/db/platform-assignment-admission.js';
import {
  preparePlatformScopeReplacement,
  readPlatformScopeReplacementCatalog,
  readPlatformScopeReplacementSource,
} from '../../../identity-service/src/db/platform-scope-replacement-store.js';
import type {
  PlatformScopeReplacementPreparation,
  PlatformScopeReplacementCommit,
} from '../contracts/platform-scope-replacement.js';
import {
  currentMutationCandidateSql,
  fenceMutationIntent,
} from '../../../identity-service/src/db/mutation-candidate-fence.js';
import {
  readContractAdministration,
  type ContractAdministrationSource,
} from '../../../control-api/src/configuration/repositories/contract-administration.js';
import { ConfigurationRepositoryError } from '../../../control-api/src/configuration/persistence/types.js';
import {
  participantLifecycleChange,
  type ParticipantLifecycleProposal,
} from '../contracts/participant-lifecycle.js';
import { changeParticipantLifecycle, readParticipantLifecycle } from './participant-lifecycle.js';
import type {
  ParticipantLifecycleChange,
  ParticipantLifecycleReadback,
} from '../contracts/participant-lifecycle.js';
import { createHash, randomBytes } from 'node:crypto';
import {
  firstAdministratorProposal,
  participantBootstrapChangeOperations,
  participantBootstrapChange,
  type ParticipantBootstrapChange,
  type ParticipantBootstrapReadback,
  participantBootstrapCreate,
  type ParticipantBootstrapProposalReadback,
} from '../contracts/first-administrator.js';
import { createParticipantBootstrap } from './participant-bootstrap.js';
import {
  fenceEnvelopePlatformContext,
  type EnvelopePlatformContext,
} from '../../../identity-service/src/db/platform-context.js';
import {
  sourceBootstrapReadback,
  changeBootstrapCustody,
} from './participant-bootstrap-lifecycle.js';
import {
  captureBootstrapAuthority,
  assertPlatformBootstrapActor,
  type BootstrapIssuanceAuthority,
} from '../../../identity-service/src/domain/bootstrap-authority.js';
import {
  captureInitialRootEnvelopeProposal,
  fenceEnvelopeProposalParticipants,
  inEnvelopeParticipantScope,
  insertInitialEnvelopeProposal,
} from '../../../identity-service/src/db/identity-envelope-proposal.js';
import {
  readEnvelopeCreation,
  readEnvelopeEffectReadback,
} from '../../../identity-service/src/db/identity-envelope-readback.js';
import { prepareInitialEnvelopeActivation } from '../../../identity-service/src/db/identity-envelope-activation-prepare.js';
import {
  claimInitialEnvelopeActivationDispatch,
  commitInitialEnvelopeActivation,
  readInitialEnvelopeActivation,
  recordInitialEnvelopeActivationObservation,
} from '../../../identity-service/src/db/identity-envelope-activation-store.js';
import type { IdentityEnvelopeSigningProvider } from '../../../identity-service/src/domain/identity-envelope-signing-provider.js';
import {
  typedEnvelopeCreateCandidate,
  type TypedEnvelopeCreateCandidate,
} from '../contracts/envelope.js';

import { verifyStoredStepUpEvidence } from '../../../identity-service/src/db/verified-step-up-evidence.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { Pool, PoolClient } from 'pg';
import { approvalAuthorityDependencies } from '../../../identity-service/src/db/approval-authority-fence.js';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
  type AuthorityFence,
  type BoundAuthority,
} from '../../../identity-service/src/db/authority-fence.js';

import {
  type Assignment,
  type AuthorizationRequest,
  type AuthorityEnvelope,
  type Delegation,
  type PermissionSet,
  validateDelegation,
} from './authority-kernel.js';
import {
  grantOperations,
  readGrant,
  readGrantProposal,
  grantDescendants,
  revokeGrant,
  type GrantReadback,
  type GrantProposal,
} from './grant-lifecycle.js';
import { assertGrantAdmission } from './grant-admission.js';
import {
  readAdministrativeAccess,
  type AccessReviewQuery,
  type AccessReviewPage,
} from './access-review.js';
import { authorityReadPaths } from '../../../identity-service/src/db/authority-read-paths.js';
import {
  roleCatalogueCandidates,
  type RoleCatalogueQuery,
  type RoleCatalogueCandidates,
} from './role-catalogue.js';
import {
  groupCatalogueCandidates,
  type GroupCatalogueQuery,
  type GroupCatalogueCandidates,
} from './group-catalogue.js';
import {
  assignmentFromRow,
  delegationFromRow,
  envelopeFromRow,
  envelopeFromGovernedCreation,
  type AssignmentRow,
  type DelegationRow,
  type EnvelopeRow,
} from './authority-records.js';
import { groupOperationIds, type GroupChange } from '../contracts/group-operations.js';
import {
  directoryGroupOperation,
  type DirectoryGroupCandidate,
  type DirectoryGroupChange,
} from '../contracts/directory-group-operations.js';
import type { DirectoryGroupObservation } from '../../../identity-service/src/contracts/directory-group-observation.js';
import {
  prepareDirectoryGroup,
  projectDirectoryGroup,
  readDirectoryGroup,
} from './directory-groups.js';
import {
  mutateGroup,
  readGroup,
  readGroupProposal,
  resolveGroupProposal,
  type GroupReadback,
  type GroupProposal,
  type GroupProposalBinding,
  type GroupMutationResult,
} from './group-lifecycle.js';
import { participantGovernanceOperations } from '../contracts/role-operations.js';
import { ParticipantKernelError } from './participant-errors.js';
import { readRoleBindingPreview, type RoleBindingPreview } from './role-binding-preview.js';
export { ParticipantKernelError } from './participant-errors.js';
import {
  createRole,
  archiveRole,
  readRole,
  readRoleProposal,
  type RoleProposal,
  type RoleDefinition,
  type RoleRecord,
  type RoleReadback,
  type RoleArchiveResult,
} from './role-lifecycle.js';
import {
  envelopeCatalogueCandidates,
  participantCatalogueCandidates,
  type EnvelopeCatalogueCandidates,
  type EnvelopeCatalogueQuery,
  type ParticipantCatalogueCandidates,
  type ParticipantCatalogueQuery,
} from './rpc-access-catalogue.js';

export type AuthorityEvaluationTarget = Pick<
  AuthorizationRequest,
  'privacyDomainId' | 'actionIntentId' | 'resourceId' | 'riskClass'
>;

export interface ParticipantRecord {
  readonly participantId: string;
  readonly displayName: string;
  readonly state:
    'PROVISIONING' | 'ACTIVE' | 'SUSPENDED' | 'TRANSFER_PENDING' | 'REVOKED' | 'OFFBOARDED';
  readonly authorityEpoch: string;
  readonly rowVersion: string;
}

export interface AuthorityEnvelopeReadback {
  readonly effect: AuthorityEnvelope;
  readonly operationId: string | null;
}

export interface AssignmentReadback {
  readonly effect: Assignment;
  readonly revision: string;
  readonly operationId: string | null;
}

export interface AuthenticatedActor {
  readonly principalId: string;
  readonly participantId: string;
  readonly boundParticipantEpoch: string;
  readonly boundPrincipalEpoch: string;
  readonly boundEnvelopeEpoch: string;
  readonly sessionId?: string;
  readonly sessionToken?: string;
  readonly privacyDomainId?: string;
  readonly mutationAuthorization?: MutationAuthorization;
  readonly readAuthorization?: BoundAuthority;
  readonly platform: boolean;
}

export interface InitialEnvelopeActivationRuntime {
  readonly environmentId: string;
  readonly callerWorkloadCredentialId: string;
  readonly provider: IdentityEnvelopeSigningProvider;
}

export interface MutationAuthorization {
  readonly authorized: true;
  readonly catalogOperationId: string;
  readonly actionIntentId: string;
  readonly idempotencyKey: string;
  readonly candidateDigest: string;
  readonly privacyDomainId: string;
  readonly approvalRequestId: string;
  readonly checkerPrincipalId: string;
  readonly aggregateVersion: string;
  readonly signerCredentialId: string;
  readonly mfaChallengeId?: string;
  readonly webauthnSessionId?: string;
  readonly webauthnSignerCredentialId?: string;
  readonly webauthnAssertionBindingDigest?: Buffer;
  readonly webauthnEvidenceCbor?: Buffer;
  readonly webauthnEvidenceDigest?: Buffer;
  readonly webauthnCoseSign1?: Buffer;
  readonly evidenceCbor: Buffer;
  readonly evidenceDigest: Buffer;
  readonly coseSign1: Buffer;
}

export interface IdempotencyOutcome<T> {
  readonly operationId: string;
  readonly result: T;
}

interface MutationIdempotency<T> {
  readonly expectedAggregateVersion: string;
  readonly operationId: string;
  readonly replay: boolean;
  readonly result: T | undefined;
  readonly resultAggregateVersion: string | undefined;
}

export interface EffectiveAuthority {
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly envelopeEpoch: string;
  readonly currentParticipantEpoch: string;
  readonly currentPrincipalEpoch: string;
  readonly currentEnvelopeEpoch: string;
  readonly envelope: AuthorityEnvelope;
  readonly assignment: Assignment;
  readonly delegations: readonly Delegation[];
}

export interface ParticipantRepository {
  platformScopeSource(
    actor: AuthenticatedActor,
    privacy: string,
    root: string,
  ): Promise<Awaited<ReturnType<typeof readPlatformScopeReplacementSource>>>;
  preparePlatformScope(
    actor: AuthenticatedActor,
    candidate: PlatformScopeReplacementPreparation,
  ): Promise<Awaited<ReturnType<typeof preparePlatformScopeReplacement>>>;
  platformScopeReadiness(
    actor: AuthenticatedActor,
    privacy: string,
    replacement: string,
  ): Promise<Awaited<ReturnType<typeof readPlatformScopeReadiness>>>;
  commitPlatformScope(
    actor: AuthenticatedActor,
    candidate: PlatformScopeReplacementCommit,
  ): Promise<Awaited<ReturnType<typeof commitPlatformScopeReplacement>>>;
  participantCatalogueCandidates(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    query: ParticipantCatalogueQuery,
  ): Promise<ParticipantCatalogueCandidates>;
  fenceParticipantCatalogue(actor: AuthenticatedActor, privacyDomainId: string): Promise<void>;
  getParticipant(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    participantId: string,
  ): Promise<ParticipantRecord>;
  envelopeCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: EnvelopeCatalogueQuery,
  ): Promise<EnvelopeCatalogueCandidates>;
  fenceEnvelopeCatalogue(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
  ): Promise<void>;
  contractAdministration(
    actor: AuthenticatedActor,
    target: string,
    targetPrivacy: string,
    sourcePrivacy: string,
    contract: string,
  ): Promise<ContractAdministrationSource>;

  lifecycleProposal(
    actor: AuthenticatedActor,
    privacy: string,
    resource: string,
    digest: string,
  ): Promise<ParticipantLifecycleProposal>;

  lifecycleReadback(
    actor: AuthenticatedActor,
    target: string,
    targetPrivacy: string,
    sourcePrivacy: string,
  ): Promise<ParticipantLifecycleReadback>;
  changeLifecycle(
    actor: AuthenticatedActor,
    candidate: ParticipantLifecycleChange,
  ): Promise<{ operationId: string; result: ParticipantLifecycleReadback }>;

  bootstrapReadback(
    actor: AuthenticatedActor,
    target: string,
    privacy: string,
  ): Promise<ParticipantBootstrapReadback>;
  changeBootstrap(
    actor: AuthenticatedActor,
    candidate: ParticipantBootstrapChange,
  ): Promise<{ operationId: string; result: ParticipantBootstrapReadback }>;
  bootstrapMetadata(actor: AuthenticatedActor): Promise<{
    participantId: string;
    privacyDomainId: string;
    actionIntentDigest: string;
    stepUpActionIntentDigest: string;
  }>;
  getBootstrapProposal(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    resourceId: string,
    digest: string,
  ): Promise<ParticipantBootstrapProposalReadback>;
  accessReviewResources(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    subjectId: string,
    query: AccessReviewQuery,
  ): Promise<readonly string[]>;
  getAccessReview(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    subjectId: string,
    query: AccessReviewQuery,
    admissions: readonly AuthenticatedActor[],
  ): Promise<AccessReviewPage>;
  prepareDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    change: DirectoryGroupChange,
    revision: string,
    observation: DirectoryGroupObservation,
  ): Promise<DirectoryGroupCandidate>;
  projectDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    candidate: DirectoryGroupCandidate,
  ): ReturnType<typeof projectDirectoryGroup>;
  getDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    groupId: string,
    cursor?: string,
  ): ReturnType<typeof readDirectoryGroup>;
  mutateGroup(
    actor: AuthenticatedActor,
    participantId: string,
    change: GroupChange,
  ): Promise<GroupMutationResult>;
  getGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    groupId: string,
    cursor?: string,
  ): Promise<GroupReadback>;
  groupCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: GroupCatalogueQuery,
  ): Promise<GroupCatalogueCandidates>;
  fenceGroupCatalogue(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
  ): Promise<void>;
  resolveGroupProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
    binding: GroupProposalBinding,
  ): Promise<string>;
  getGroupProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
    binding: GroupProposalBinding,
  ): Promise<GroupProposal>;
  roleCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: RoleCatalogueQuery,
  ): Promise<RoleCatalogueCandidates>;
  fenceRoleCatalogue(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
  ): Promise<void>;
  resolveGrantProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ): Promise<string>;
  getGrantProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ): Promise<GrantProposal>;
  getDelegation(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    delegationId: string,
  ): Promise<GrantReadback>;
  resolveRoleProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ): Promise<string>;
  getRoleProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ): Promise<RoleProposal>;
  createRole(actor: AuthenticatedActor, value: RoleDefinition): Promise<RoleRecord>;
  archiveRole(
    actor: AuthenticatedActor,
    participantId: string,
    roleId: string,
  ): Promise<RoleArchiveResult>;
  getRole(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    roleId: string,
  ): Promise<RoleReadback>;
  getRoleBindingPreview(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    roleId: string,
  ): Promise<RoleBindingPreview>;
  getAssignment(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    assignmentId: string,
  ): Promise<AssignmentReadback>;
  getEnvelope(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    envelopeId: string,
  ): Promise<AuthorityEnvelopeReadback>;
  createParticipant(
    actor: AuthenticatedActor,
    participant: ParticipantRecord,
    key: string,
    request: unknown,
  ): Promise<IdempotencyOutcome<ParticipantRecord>>;
  activateParticipant(
    actor: AuthenticatedActor,
    participantId: string,
    key: string,
    request: unknown,
  ): Promise<IdempotencyOutcome<ParticipantRecord>>;
  createEnvelope(
    actor: AuthenticatedActor,
    value: AuthorityEnvelope | TypedEnvelopeCreateCandidate,
  ): Promise<AuthorityEnvelope>;
  activateEnvelope(
    actor: AuthenticatedActor,
    participantId: string,
    envelopeId: string,
  ): Promise<AuthorityEnvelope>;
  revokeEnvelope(
    actor: AuthenticatedActor,
    participantId: string,
    envelopeId: string,
    reason: string,
  ): Promise<AuthorityEnvelope>;
  createAssignment(actor: AuthenticatedActor, value: Assignment): Promise<Assignment>;
  issueDelegation(actor: AuthenticatedActor, value: Delegation): Promise<Delegation>;
  revokeAuthority(
    actor: AuthenticatedActor,
    participantId: string,
    kind: 'assignment' | 'delegation',
    targetId: string,
  ): Promise<{ readonly newEpoch: string }>;
  effectiveAuthority(
    actor: AuthenticatedActor,
    participantId: string,
    target: AuthorityEvaluationTarget,
  ): Promise<EffectiveAuthority | undefined>;
}

const unavailableRepository: ParticipantRepository = new Proxy({} as ParticipantRepository, {
  get: () => async () => {
    throw new ParticipantKernelError('PC-IDENTITY-1004');
  },
});

/** Domain coordinator. Runtime state is owned exclusively by its repository. */
export class ParticipantKernel {
  participantCatalogueCandidates(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    query: ParticipantCatalogueQuery,
  ) {
    return this.repository.participantCatalogueCandidates(actor, privacyDomainId, query);
  }
  fenceParticipantCatalogue(actor: AuthenticatedActor, privacyDomainId: string) {
    return this.repository.fenceParticipantCatalogue(actor, privacyDomainId);
  }
  getParticipant(actor: AuthenticatedActor, privacyDomainId: string, participantId: string) {
    return this.repository.getParticipant(actor, privacyDomainId, participantId);
  }
  envelopeCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: EnvelopeCatalogueQuery,
  ) {
    return this.repository.envelopeCatalogueCandidates(
      actor,
      participantId,
      privacyDomainId,
      query,
    );
  }
  fenceEnvelopeCatalogue(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
  ) {
    return this.repository.fenceEnvelopeCatalogue(actor, participantId, privacyDomainId);
  }
  contractAdministration(
    actor: AuthenticatedActor,
    target: string,
    targetPrivacy: string,
    sourcePrivacy: string,
    contract: string,
  ) {
    return this.repository.contractAdministration(
      actor,
      target,
      targetPrivacy,
      sourcePrivacy,
      contract,
    );
  }

  lifecycleProposal(actor: AuthenticatedActor, privacy: string, resource: string, digest: string) {
    return this.repository.lifecycleProposal(actor, privacy, resource, digest);
  }

  lifecycleReadback(
    actor: AuthenticatedActor,
    target: string,
    targetPrivacy: string,
    sourcePrivacy: string,
  ) {
    return this.repository.lifecycleReadback(actor, target, targetPrivacy, sourcePrivacy);
  }
  changeLifecycle(actor: AuthenticatedActor, candidate: ParticipantLifecycleChange) {
    return this.repository.changeLifecycle(actor, candidate);
  }

  platformScopeReadiness(actor: AuthenticatedActor, privacy: string, replacement: string) {
    return this.repository.platformScopeReadiness(actor, privacy, replacement);
  }
  commitPlatformScope(actor: AuthenticatedActor, candidate: PlatformScopeReplacementCommit) {
    return this.repository.commitPlatformScope(actor, candidate);
  }
  platformScopeSource(actor: AuthenticatedActor, privacy: string, root: string) {
    return this.repository.platformScopeSource(actor, privacy, root);
  }
  preparePlatformScope(actor: AuthenticatedActor, candidate: PlatformScopeReplacementPreparation) {
    return this.repository.preparePlatformScope(actor, candidate);
  }
  constructor(private readonly repository: ParticipantRepository = unavailableRepository) {}
  bootstrapReadback(actor: AuthenticatedActor, target: string, privacy: string) {
    return this.repository.bootstrapReadback(actor, target, privacy);
  }
  changeBootstrap(actor: AuthenticatedActor, candidate: ParticipantBootstrapChange) {
    return this.repository.changeBootstrap(actor, candidate);
  }
  bootstrapMetadata(actor: AuthenticatedActor) {
    return this.repository.bootstrapMetadata(actor);
  }
  getBootstrapProposal(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    resourceId: string,
    digest: string,
  ) {
    return this.repository.getBootstrapProposal(actor, privacyDomainId, resourceId, digest);
  }
  accessReviewResources(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    subjectId: string,
    query: AccessReviewQuery,
  ) {
    return this.repository.accessReviewResources(
      actor,
      participantId,
      privacyDomainId,
      subjectId,
      query,
    );
  }
  getAccessReview(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    subjectId: string,
    query: AccessReviewQuery,
    admissions: readonly AuthenticatedActor[],
  ) {
    return this.repository.getAccessReview(
      actor,
      participantId,
      privacyDomainId,
      subjectId,
      query,
      admissions,
    );
  }
  prepareDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    change: DirectoryGroupChange,
    revision: string,
    observation: DirectoryGroupObservation,
  ) {
    return this.repository.prepareDirectoryGroup(
      actor,
      participantId,
      privacyDomainId,
      change,
      revision,
      observation,
    );
  }
  projectDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    candidate: DirectoryGroupCandidate,
  ) {
    return this.repository.projectDirectoryGroup(actor, participantId, candidate);
  }
  getDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    groupId: string,
    cursor?: string,
  ) {
    return this.repository.getDirectoryGroup(
      actor,
      participantId,
      privacyDomainId,
      groupId,
      cursor,
    );
  }
  roleCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: RoleCatalogueQuery,
  ) {
    return this.repository.roleCatalogueCandidates(actor, participantId, privacyDomainId, query);
  }
  fenceRoleCatalogue(actor: AuthenticatedActor, participantId: string, privacyDomainId: string) {
    return this.repository.fenceRoleCatalogue(actor, participantId, privacyDomainId);
  }

  resolveGrantProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ) {
    return this.repository.resolveGrantProposalResource(
      actor,
      participantId,
      privacyDomainId,
      candidateDigest,
    );
  }
  getGrantProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ) {
    return this.repository.getGrantProposal(actor, participantId, privacyDomainId, candidateDigest);
  }
  getDelegation(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    delegationId: string,
  ) {
    return this.repository.getDelegation(actor, participantId, privacyDomainId, delegationId);
  }
  resolveRoleProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ) {
    return this.repository.resolveRoleProposalResource(
      actor,
      participantId,
      privacyDomainId,
      candidateDigest,
    );
  }
  getRoleProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ) {
    return this.repository.getRoleProposal(actor, participantId, privacyDomainId, candidateDigest);
  }

  mutateGroup(actor: AuthenticatedActor, participantId: string, change: GroupChange) {
    return this.repository.mutateGroup(actor, participantId, change);
  }
  getGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    groupId: string,
    cursor?: string,
  ) {
    return this.repository.getGroup(actor, participantId, privacyDomainId, groupId, cursor);
  }
  groupCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: GroupCatalogueQuery,
  ) {
    return this.repository.groupCatalogueCandidates(actor, participantId, privacyDomainId, query);
  }
  fenceGroupCatalogue(actor: AuthenticatedActor, participantId: string, privacyDomainId: string) {
    return this.repository.fenceGroupCatalogue(actor, participantId, privacyDomainId);
  }
  resolveGroupProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
    binding: GroupProposalBinding,
  ) {
    return this.repository.resolveGroupProposalResource(
      actor,
      participantId,
      privacyDomainId,
      candidateDigest,
      binding,
    );
  }
  getGroupProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
    binding: GroupProposalBinding,
  ) {
    return this.repository.getGroupProposal(
      actor,
      participantId,
      privacyDomainId,
      candidateDigest,
      binding,
    );
  }

  createRole(actor: AuthenticatedActor, value: RoleDefinition) {
    return this.repository.createRole(actor, value);
  }
  archiveRole(actor: AuthenticatedActor, participantId: string, roleId: string) {
    return this.repository.archiveRole(actor, participantId, roleId);
  }
  getRole(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    roleId: string,
  ) {
    return this.repository.getRole(actor, participantId, privacyDomainId, roleId);
  }
  getRoleBindingPreview(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    roleId: string,
  ) {
    return this.repository.getRoleBindingPreview(actor, participantId, privacyDomainId, roleId);
  }

  createParticipant(
    actor: AuthenticatedActor,
    value: ParticipantRecord,
    key: string,
    request: unknown,
  ) {
    return this.repository.createParticipant(actor, value, key, request);
  }
  activateParticipant(
    actor: AuthenticatedActor,
    participantId: string,
    key: string,
    request: unknown,
  ) {
    return this.repository.activateParticipant(actor, participantId, key, request);
  }
  createEnvelope(
    actor: AuthenticatedActor,
    value: AuthorityEnvelope | TypedEnvelopeCreateCandidate,
  ) {
    return this.repository.createEnvelope(actor, value);
  }
  getEnvelope(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    envelopeId: string,
  ) {
    return this.repository.getEnvelope(actor, participantId, privacyDomainId, envelopeId);
  }
  activateEnvelope(actor: AuthenticatedActor, participantId: string, envelopeId: string) {
    return this.repository.activateEnvelope(actor, participantId, envelopeId);
  }
  revokeEnvelope(
    actor: AuthenticatedActor,
    participantId: string,
    envelopeId: string,
    reason: string,
  ) {
    return this.repository.revokeEnvelope(actor, participantId, envelopeId, reason);
  }
  createAssignment(actor: AuthenticatedActor, value: Assignment) {
    return this.repository.createAssignment(actor, value);
  }
  getAssignment(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    assignmentId: string,
  ) {
    return this.repository.getAssignment(actor, participantId, privacyDomainId, assignmentId);
  }
  issueDelegation(actor: AuthenticatedActor, value: Delegation) {
    return this.repository.issueDelegation(actor, value);
  }
  revokeAuthority(
    actor: AuthenticatedActor,
    participantId: string,
    kind: 'assignment' | 'delegation',
    targetId: string,
  ) {
    return this.repository.revokeAuthority(actor, participantId, kind, targetId);
  }
  effectiveAuthority(
    actor: AuthenticatedActor,
    participantId: string,
    target: AuthorityEvaluationTarget,
  ) {
    return this.repository.effectiveAuthority(actor, participantId, target);
  }
}

type TxOperation<T> = (client: PoolClient, operationId: string) => Promise<T>;
const CATALOG_OPERATION_PATTERN = /^ID-OP-[A-Z0-9-]+$/u;

function uuidV7(): string {
  const bytes = randomBytes(16);
  const timestamp = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number((timestamp >> BigInt((5 - index) * 8)) & 0xffn);
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export class PostgresParticipantRepository implements ParticipantRepository {
  platformScopeReadiness(actor: AuthenticatedActor, privacy: string, replacement: string) {
    if (!actor.sessionId) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacy,
          replacement,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          actor.platform,
        );
        const readiness = await readPlatformScopeReadiness(client, replacement);
        // Participant assignment handoff can inspect only its explicitly declared
        // live pending replacement. The ordinary resource/tenant/epoch fence
        // above still owns READ authority; this grants no transition permission.
        if (
          !actor.platform &&
          (readiness.state !== 'WITHDRAWING' ||
            BigInt(readiness.sourceExpiresAtNs) <= BigInt(readiness.nowNs) ||
            !readiness.administrators.some((admin) => admin.principalId === actor.principalId))
        )
          throw new ParticipantKernelError('PC-IDENTITY-1008');
        return readiness;
      },
      privacy,
    );
  }
  commitPlatformScope(actor: AuthenticatedActor, candidate: PlatformScopeReplacementCommit) {
    const proof = actor.mutationAuthorization;
    if (!actor.platform || !proof?.webauthnSignerCredentialId)
      throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.mutationTx(
      actor,
      actor.participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-PLATFORM-SCOPE-COMMIT',
      'platform-scope-replacement',
      candidate.replacementId,
      candidate,
      async (client, operationId) =>
        commitPlatformScopeReplacement(
          client,
          {
            participantId: actor.participantId,
            privacyDomainId: proof.privacyDomainId,
            operationId,
            approvalRequestId: proof.approvalRequestId,
            makerPrincipalId: actor.principalId,
            checkerPrincipalId: proof.checkerPrincipalId,
            makerCredentialId: proof.webauthnSignerCredentialId!,
            checkerCredentialId: proof.signerCredentialId,
          },
          candidate,
        ),
      async (client) => {
        const held = await client.query<{ held: boolean }>(
          `select pg_try_advisory_xact_lock(hashtextextended('platform-scope-replacement:'||$1::text,0)) held`,
          [candidate.platformContextId],
        );
        if (held.rows[0]?.held !== true) throw new AuthorityFenceError();
        const plans = await client.query<{ candidate: PlatformScopeReplacementPreparation }>(
          `select candidate from control.platform_scope_replacement
          where participant_id=$1 and privacy_domain_id=$2 and replacement_id=$3 and state='WITHDRAWING'`,
          [actor.participantId, proof.privacyDomainId, candidate.replacementId],
        );
        const admins = one(plans.rows, 'PC-IDENTITY-1001').candidate.administrators;
        return {
          participant: [{ id: actor.participantId, write: true }],
          principal: admins.map((a) => ({ id: a.principalId })),
          authority_envelope: admins.map((a) => ({ id: a.envelopeId })),
          assignment: admins.map((a) => ({ id: a.assignmentId })),
          authority_role: admins.map((a) => ({ id: a.roleId })),
        };
      },
    );
  }
  platformScopeSource(actor: AuthenticatedActor, privacy: string, root: string) {
    if (!actor.platform || !actor.sessionId) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacy,
          root,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          true,
        );
        return readPlatformScopeReplacementSource(client, actor.participantId, privacy, root);
      },
      privacy,
    );
  }
  preparePlatformScope(actor: AuthenticatedActor, candidate: PlatformScopeReplacementPreparation) {
    if (!actor.platform) throw new ParticipantKernelError('PC-IDENTITY-1008');
    const proof = actor.mutationAuthorization;
    if (!proof?.webauthnSignerCredentialId) throw new ParticipantKernelError('PC-IDENTITY-1004');
    return this.mutationTx(
      actor,
      actor.participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-PLATFORM-SCOPE-PREPARE',
      'platform-scope-replacement',
      candidate.replacementId,
      candidate,
      async (client, operationId) =>
        preparePlatformScopeReplacement(
          client,
          {
            participantId: actor.participantId,
            privacyDomainId: proof.privacyDomainId,
            operationId,
            approvalRequestId: proof.approvalRequestId,
            makerPrincipalId: actor.principalId,
            checkerPrincipalId: proof.checkerPrincipalId,
            makerCredentialId: proof.webauthnSignerCredentialId!,
            checkerCredentialId: proof.signerCredentialId,
          },
          candidate,
        ),
      async (client) => {
        const lock = await client.query<{ held: boolean }>(
          `select pg_try_advisory_xact_lock(hashtextextended('platform-scope-replacement:'||$1::text,0)) as held`,
          [candidate.platformContextId],
        );
        if (lock.rows[0]?.held !== true) throw new AuthorityFenceError();
        return {
          principal: candidate.administrators.map((admin) => ({ id: admin.principalId })),
          authority_role: candidate.administrators.map((admin) => ({ id: admin.roleId })),
        };
      },
    );
  }
  participantCatalogueCandidates(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    query: ParticipantCatalogueQuery,
  ) {
    if (!actor.platform || !actor.sessionId) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      async (client, operationId) => {
        await this.fenceRead(
          client,
          actor,
          privacyDomainId,
          actor.participantId,
          'ACT-PARTICIPANTS_READ_COLLECTION-V1',
          true,
        );
        return participantCatalogueCandidates(client, actor, privacyDomainId, operationId, query);
      },
      privacyDomainId,
    );
  }
  fenceParticipantCatalogue(actor: AuthenticatedActor, privacyDomainId: string) {
    return this.participantCatalogueCandidates(actor, privacyDomainId, {
      search: '',
      state: 'ALL',
    }).then(() => undefined);
  }
  getParticipant(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    participantId: string,
  ): Promise<ParticipantRecord> {
    if (!actor.platform || !actor.sessionId) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client, operationId) => {
        await this.fenceRead(
          client,
          actor,
          privacyDomainId,
          participantId,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          true,
        );
        const owner = {
          participantId: actor.participantId,
          privacyDomainId,
          operationId,
          actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        };
        const selected = await inEnvelopeParticipantScope(client, owner, participantId, () =>
          client.query<{
            participant_id: string;
            display_name: string;
            state: ParticipantRecord['state'];
            authority_epoch: string;
            row_version: string;
          }>(
            `select participant_id::text,display_name,state,
                    authority_epoch::text,row_version::text
               from control.participant where participant_id=$1`,
            [participantId],
          ),
        );
        const row = one(selected.rows, 'PC-IDENTITY-1008');
        return {
          participantId: row.participant_id,
          displayName: row.display_name,
          state: row.state,
          authorityEpoch: row.authority_epoch,
          rowVersion: row.row_version,
        };
      },
      privacyDomainId,
    );
  }
  envelopeCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: EnvelopeCatalogueQuery,
  ) {
    this.owner(actor, participantId);
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacyDomainId,
          participantId,
          'ACT-PARTICIPANTS_READ_COLLECTION-V1',
          actor.platform,
        );
        return envelopeCatalogueCandidates(client, actor, participantId, privacyDomainId, query);
      },
      privacyDomainId,
    );
  }
  fenceEnvelopeCatalogue(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
  ) {
    return this.envelopeCatalogueCandidates(actor, participantId, privacyDomainId, {
      state: 'ALL',
    }).then(() => undefined);
  }
  contractAdministration(
    actor: AuthenticatedActor,
    target: string,
    targetPrivacy: string,
    sourcePrivacy: string,
    contract: string,
  ) {
    if (!actor.platform || !actor.sessionId || actor.participantId === target)
      throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client, operationId) => {
        await this.fenceRead(
          client,
          actor,
          sourcePrivacy,
          target,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          true,
        );
        await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
          target,
          targetPrivacy,
          operationId,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        ]);
        await readParticipantLifecycle(client, target, targetPrivacy);
        try {
          return await readContractAdministration(client, target, targetPrivacy, contract);
        } catch (error) {
          if (error instanceof ConfigurationRepositoryError)
            throw new ParticipantKernelError('PC-IDENTITY-1008');
          throw error;
        }
      },
      sourcePrivacy,
    );
  }

  lifecycleProposal(
    actor: AuthenticatedActor,
    privacy: string,
    resource: string,
    digest: string,
  ): Promise<ParticipantLifecycleProposal> {
    if (!actor.platform || !actor.sessionId) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacy,
          resource,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          true,
        );
        const rows = await client.query<{
          candidate_document: unknown;
          state: string;
          expires_at: Date;
          consumed_operation_id: string | null;
          result_payload: unknown;
        }>(
          `select c.candidate_document,c.state,c.expires_at,c.consumed_operation_id,r.result_payload
         from control.mutation_candidate c left join control.idempotency_record r on r.participant_id=c.participant_id
          and r.operation_id=c.consumed_operation_id and r.terminal_state='COMMITTED'
         where c.participant_id=$1 and c.privacy_domain_id=$2 and c.resource_id=$3 and c.candidate_digest=$4
          and c.catalog_operation_id in ('ID-OP-PARTICIPANT-TRANSFER', 'ID-OP-PARTICIPANT-SHRINK', 'ID-OP-PARTICIPANT-ARCHIVE','ID-OP-PARTICIPANT-RESTORE')`,
          [actor.participantId, privacy, resource, Buffer.from(digest.slice(7), 'hex')],
        );
        if (rows.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
        const row = rows.rows[0]!;
        return {
          candidate: participantLifecycleChange.parse(row.candidate_document),
          candidateDigest: digest,
          state: row.state,
          expiresAt: row.expires_at.toISOString(),
          operationId: row.consumed_operation_id,
          result: row.result_payload ?? null,
        };
      },
      privacy,
    );
  }

  lifecycleReadback(
    actor: AuthenticatedActor,
    target: string,
    targetPrivacy: string,
    sourcePrivacy: string,
  ) {
    if (!actor.platform || !actor.sessionId || actor.participantId === target)
      throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client, operationId) => {
        await this.fenceRead(
          client,
          actor,
          sourcePrivacy,
          target,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          true,
        );
        await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
          target,
          targetPrivacy,
          operationId,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        ]);
        return readParticipantLifecycle(client, target, targetPrivacy);
      },
      sourcePrivacy,
    );
  }
  changeLifecycle(actor: AuthenticatedActor, candidate: ParticipantLifecycleChange) {
    if (
      !actor.platform ||
      actor.participantId === candidate.participantId ||
      actor.mutationAuthorization?.idempotencyKey !== candidate.idempotencyKey
    )
      throw new ParticipantKernelError('PC-IDENTITY-1005');
    return this.mutationTx(
      actor,
      candidate.participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      `ID-OP-PARTICIPANT-${candidate.mutation}`,
      'participant',
      candidate.participantId,
      candidate,
      async (client, operationId) => {
        try {
          return await changeParticipantLifecycle(client, actor, candidate, operationId);
        } catch (error) {
          if (error instanceof ConfigurationRepositoryError)
            throw new ParticipantKernelError('PC-IDENTITY-1009');
          throw error;
        }
      },
    );
  }

  constructor(
    private readonly pool: Pool,
    private readonly identityRuntimeVerifier?: IdentityRuntimeVerifier,
    private readonly initialEnvelopeActivation?: InitialEnvelopeActivationRuntime,
  ) {}
  bootstrapReadback(actor: AuthenticatedActor, target: string, privacy: string) {
    if (!actor.platform || !actor.sessionId) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacy,
          target,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          true,
        );
        return sourceBootstrapReadback(client, actor, target, privacy);
      },
      privacy,
    );
  }
  changeBootstrap(actor: AuthenticatedActor, candidate: ParticipantBootstrapChange) {
    if (!actor.platform || actor.mutationAuthorization?.idempotencyKey !== candidate.idempotencyKey)
      throw new ParticipantKernelError('PC-IDENTITY-1005');
    return this.mutationTx(
      actor,
      candidate.participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      participantBootstrapChangeOperations[candidate.change.mutation],
      'participant',
      candidate.participantId,
      candidate,
      (client, operationId) => changeBootstrapCustody(client, actor, candidate, operationId),
      async () => ({ participant: [{ id: actor.participantId, write: true }] }),
    );
  }
  bootstrapMetadata(actor: AuthenticatedActor) {
    if (!actor.platform || !actor.sessionId) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(actor.participantId, 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1', async (client) => {
      await assertPlatformBootstrapActor(
        client,
        actor.participantId,
        actor.principalId,
        actor.sessionId!,
      );
      const row = (
        await client.query<{ privacy_domain_id: string; digest: string; step_up_digest: string }>(
          `select participant.root_privacy_domain_id privacy_domain_id,'sha256:'||encode(action.semantic_digest,'hex') digest,
          (select 'sha256:'||encode(semantic_digest,'hex') from control.action_intent where action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1') step_up_digest
        from control.participant participant cross join control.action_intent action
        where participant.participant_id=$1 and participant.root_privacy_domain_id is not null and action.action_intent_id='ACT-PARTICIPANTS_CREATE_RESOURCE-V1'`,
          [actor.participantId],
        )
      ).rows[0];
      if (!row) throw new ParticipantKernelError('PC-IDENTITY-1008');
      return {
        participantId: actor.participantId,
        privacyDomainId: row.privacy_domain_id,
        actionIntentDigest: row.digest,
        stepUpActionIntentDigest: row.step_up_digest,
      };
    });
  }
  getBootstrapProposal(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    resourceId: string,
    digest: string,
  ): Promise<ParticipantBootstrapProposalReadback> {
    if (!actor.platform || !actor.sessionId) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return this.tx(
      actor.participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacyDomainId,
          resourceId,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          true,
        );
        const row = (
          await client.query<{
            candidate_document: unknown;
            state: string;
            expires_at: Date;
            consumed_operation_id: string | null;
            result_payload: unknown;
          }>(
            `select candidate.candidate_document,candidate.state,candidate.expires_at,candidate.consumed_operation_id,receipt.result_payload
        from control.mutation_candidate candidate left join control.idempotency_record receipt on receipt.participant_id=candidate.participant_id
          and receipt.operation_id=candidate.consumed_operation_id and receipt.terminal_state='COMMITTED'
        where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.resource_id=$3 and candidate.candidate_digest=$4
          and candidate.catalog_operation_id in ('ID-OP-PARTICIPANT-CREATE','ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE','ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE')`,
            [actor.participantId, privacyDomainId, resourceId, Buffer.from(digest.slice(7), 'hex')],
          )
        ).rows;
        if (row.length !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
        const value = row[0]!;
        return {
          candidate: participantBootstrapCreate
            .or(participantBootstrapChange)
            .parse(value.candidate_document),
          candidateDigest: digest,
          state: value.state,
          expiresAt: value.expires_at.toISOString(),
          operationId: value.consumed_operation_id,
          result: value.result_payload ?? null,
        };
      },
      privacyDomainId,
    );
  }
  accessReviewResources(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    subjectId: string,
    query: AccessReviewQuery,
  ) {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacyDomainId,
          subjectId,
          'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        );
        const ids = new Set<string>();
        await readAdministrativeAccess(
          client,
          participantId,
          privacyDomainId,
          subjectId,
          query,
          async (id) => {
            ids.add(id);
          },
        );
        return [...ids];
      },
      privacyDomainId,
    );
  }
  getAccessReview(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    subjectId: string,
    query: AccessReviewQuery,
    admissions: readonly AuthenticatedActor[],
  ) {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      async (client) => {
        const fence = async (admitted: AuthenticatedActor, resourceId: string) => {
          if (admitted.principalId !== actor.principalId || admitted.sessionId !== actor.sessionId)
            throw new ParticipantKernelError('PC-IDENTITY-1008');
          await this.fenceRead(
            client,
            admitted,
            privacyDomainId,
            resourceId,
            'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
          );
        };
        await fence(actor, subjectId);
        const byId = new Map<string, AuthenticatedActor>();
        for (const admitted of admissions) {
          const id = admitted.readAuthorization?.resourceId;
          if (!id) throw new ParticipantKernelError('PC-IDENTITY-1008');
          await fence(admitted, id);
          byId.set(id, admitted);
        }
        const page = await readAdministrativeAccess(
          client,
          participantId,
          privacyDomainId,
          subjectId,
          query,
          async (id) => {
            if (!byId.has(id)) throw new ParticipantKernelError('PC-IDENTITY-1008');
          },
        );
        // Recheck time-sensitive authority after reading. All HTTP authorization
        // happened before this transaction; no remote session writer waits on it.
        await fence(actor, subjectId);
        for (const [id, admitted] of byId) await fence(admitted, id);
        return page;
      },
      privacyDomainId,
    );
  }
  roleCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: RoleCatalogueQuery,
  ) {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacyDomainId,
          participantId,
          'ACT-PARTICIPANTS_READ_COLLECTION-V1',
        );
        return roleCatalogueCandidates(
          client,
          participantId,
          actor.principalId,
          privacyDomainId,
          query,
        );
      },
      privacyDomainId,
    );
  }
  fenceRoleCatalogue(actor: AuthenticatedActor, participantId: string, privacyDomainId: string) {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      (client) =>
        this.fenceRead(
          client,
          actor,
          privacyDomainId,
          participantId,
          'ACT-PARTICIPANTS_READ_COLLECTION-V1',
        ),
      privacyDomainId,
    );
  }

  resolveGrantProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ): Promise<string> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        const found = await client.query<{ resource_id: string }>(
          `select resource_id from control.mutation_candidate
        where participant_id=$1 and privacy_domain_id=$2 and candidate_digest=$3
          and catalog_operation_id=any($4::text[]) limit 2`,
          [
            participantId,
            privacyDomainId,
            Buffer.from(candidateDigest.slice(7), 'hex'),
            grantOperations,
          ],
        );
        if (found.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
        return found.rows[0]!.resource_id;
      },
      privacyDomainId,
    );
  }
  getGrantProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ): Promise<GrantProposal> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        const resourceId = actor.readAuthorization?.resourceId;
        if (resourceId === undefined) throw new ParticipantKernelError('PC-IDENTITY-1008');
        await this.fenceRead(client, actor, privacyDomainId, resourceId);
        return readGrantProposal(
          client,
          participantId,
          privacyDomainId,
          candidateDigest,
          resourceId,
        );
      },
      privacyDomainId,
    );
  }
  getDelegation(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    delegationId: string,
  ): Promise<GrantReadback> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(client, actor, privacyDomainId, delegationId);
        return readGrant(client, participantId, privacyDomainId, delegationId, 'delegation');
      },
      privacyDomainId,
    );
  }
  resolveRoleProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ): Promise<string> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        const found = await client.query<{ resource_id: string }>(
          `select resource_id from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2
          and candidate_digest=$3 and catalog_operation_id in ('ID-OP-ROLE-CREATE','ID-OP-ROLE-ARCHIVE') limit 2`,
          [participantId, privacyDomainId, Buffer.from(candidateDigest.slice(7), 'hex')],
        );
        if (found.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
        return found.rows[0]!.resource_id;
      },
      privacyDomainId,
    );
  }

  getRoleProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
  ): Promise<RoleProposal> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        const resourceId = actor.readAuthorization?.resourceId;
        if (resourceId === undefined) throw new ParticipantKernelError('PC-IDENTITY-1008');
        await this.fenceRead(client, actor, privacyDomainId, resourceId);
        return readRoleProposal(
          client,
          participantId,
          privacyDomainId,
          candidateDigest,
          resourceId,
          this.identityRuntimeVerifier,
        );
      },
      privacyDomainId,
    );
  }

  prepareDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    change: DirectoryGroupChange,
    revision: string,
    observation: DirectoryGroupObservation,
  ) {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(client, actor, privacyDomainId, change.groupId);
        return prepareDirectoryGroup(client, participantId, change, revision, observation);
      },
      privacyDomainId,
    );
  }
  getDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    groupId: string,
    cursor?: string,
  ) {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(client, actor, privacyDomainId, groupId);
        return readDirectoryGroup(client, participantId, groupId, cursor);
      },
      privacyDomainId,
    );
  }
  projectDirectoryGroup(
    actor: AuthenticatedActor,
    participantId: string,
    candidate: DirectoryGroupCandidate,
  ) {
    this.owner(actor, participantId);
    return this.mutationTx(
      actor,
      participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      directoryGroupOperation(candidate),
      'group',
      candidate.groupId,
      candidate,
      (client, operationId) =>
        projectDirectoryGroup(client, participantId, actor.principalId, candidate, operationId),
      async () => ({ participant: [{ id: participantId, write: true }] }),
    );
  }
  mutateGroup(
    actor: AuthenticatedActor,
    participantId: string,
    change: GroupChange,
  ): Promise<GroupMutationResult> {
    this.owner(actor, participantId);
    return this.mutationTx(
      actor,
      participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      groupOperationIds[change.mutation],
      'group',
      change.groupId,
      { ...change, expectedRevision: actor.mutationAuthorization?.aggregateVersion },
      (client, operationId) =>
        mutateGroup(client, participantId, actor.principalId, change, operationId),
      async () => ({ participant: [{ id: participantId, write: true }] }),
    );
  }
  getGroup(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    groupId: string,
    cursor?: string,
  ): Promise<GroupReadback> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(client, actor, privacyDomainId, groupId);
        return readGroup(client, participantId, groupId, cursor);
      },
      privacyDomainId,
    );
  }
  groupCatalogueCandidates(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    query: GroupCatalogueQuery,
  ) {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacyDomainId,
          participantId,
          'ACT-PARTICIPANTS_READ_COLLECTION-V1',
        );
        return groupCatalogueCandidates(
          client,
          participantId,
          actor.principalId,
          privacyDomainId,
          query,
        );
      },
      privacyDomainId,
    );
  }
  fenceGroupCatalogue(actor: AuthenticatedActor, participantId: string, privacyDomainId: string) {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      (client) =>
        this.fenceRead(
          client,
          actor,
          privacyDomainId,
          participantId,
          'ACT-PARTICIPANTS_READ_COLLECTION-V1',
        ),
      privacyDomainId,
    );
  }
  resolveGroupProposalResource(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
    binding: GroupProposalBinding,
  ): Promise<string> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) =>
        resolveGroupProposal(client, participantId, privacyDomainId, candidateDigest, binding),
      privacyDomainId,
    );
  }
  getGroupProposal(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    candidateDigest: string,
    binding: GroupProposalBinding,
  ): Promise<GroupProposal> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        const resourceId = actor.readAuthorization?.resourceId;
        if (resourceId === undefined) throw new ParticipantKernelError('PC-IDENTITY-1008');
        await this.fenceRead(client, actor, privacyDomainId, resourceId);
        return readGroupProposal(
          client,
          participantId,
          privacyDomainId,
          resourceId,
          candidateDigest,
          binding,
        );
      },
      privacyDomainId,
    );
  }

  createRole(actor: AuthenticatedActor, value: RoleDefinition): Promise<RoleRecord> {
    this.owner(actor, value.participantId);
    return this.mutationTx(
      actor,
      value.participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-ROLE-CREATE',
      'role',
      value.id,
      value,
      (client, _operationId, envelopeId) =>
        createRole(client, actor.principalId, envelopeId, value),
      async () => ({ participant: [{ id: value.participantId, write: true }] }),
    );
  }

  archiveRole(
    actor: AuthenticatedActor,
    participantId: string,
    roleId: string,
  ): Promise<RoleArchiveResult> {
    this.owner(actor, participantId);
    return this.mutationTx(
      actor,
      participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-ROLE-ARCHIVE',
      'role',
      roleId,
      { roleId, state: 'ARCHIVED' },
      (client, operationId) =>
        archiveRole(client, participantId, actor.principalId, roleId, operationId),
      async () => ({ participant: [{ id: participantId, write: true }] }),
    );
  }

  getRole(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    roleId: string,
  ): Promise<RoleReadback> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(client, actor, privacyDomainId, roleId);
        return readRole(client, participantId, privacyDomainId, roleId);
      },
      privacyDomainId,
    );
  }

  getRoleBindingPreview(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    roleId: string,
  ): Promise<RoleBindingPreview> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(
          client,
          actor,
          privacyDomainId,
          roleId,
          'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          actor.platform,
        );
        return readRoleBindingPreview(client, participantId, roleId);
      },
      privacyDomainId,
    );
  }

  async getAssignment(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    assignmentId: string,
  ): Promise<AssignmentReadback> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(client, actor, privacyDomainId, assignmentId);
        const result = await client.query<
          AssignmentRow & { row_version: string; consumed_operation_id: string | null }
        >(
          `select assignment.*,lower(assignment.valid_during) valid_from,
                  upper(assignment.valid_during) valid_until,candidate.consumed_operation_id::text
             from control.assignment assignment
             left join lateral (
               select consumed_operation_id from control.mutation_candidate
                where participant_id=assignment.participant_id and privacy_domain_id=$3::uuid and state='CONSUMED'
                  and ((assignment.last_mutation_operation_id is not null and consumed_operation_id=assignment.last_mutation_operation_id)
                    or (assignment.last_mutation_operation_id is null and resource_id=assignment.assignment_id
                      and catalog_operation_id in ('ID-OP-ASSIGNMENT-CREATE','ID-OP-ASSIGNMENT-REVOKE')
                      and expected_revision=assignment.row_version-1))
               union all
               select role_candidate.consumed_operation_id from control.mutation_candidate role_candidate
                where assignment.last_mutation_operation_id is null and role_candidate.participant_id=assignment.participant_id
                  and role_candidate.resource_id=right(assignment.role_id,36)::uuid
                  and role_candidate.privacy_domain_id=$3::uuid and role_candidate.state='CONSUMED'
                  and role_candidate.catalog_operation_id='ID-OP-ROLE-ARCHIVE'
                  and assignment.state='REVOKED' and exists (
                    select 1 from control.revocation revocation
                     where revocation.participant_id=assignment.participant_id
                       and revocation.target_type='assignment' and revocation.target_id=assignment.assignment_id
                       and revocation.reason_code='ROLE_ARCHIVED')
                limit 1
             ) candidate on true
            where assignment.participant_id=$1 and assignment.assignment_id=$2
              and $3::text=any(assignment.privacy_domain_ids)`,
          [participantId, assignmentId, privacyDomainId],
        );
        const row = one(result.rows, 'PC-IDENTITY-1008');
        return {
          effect: { ...assignmentFromRow(row), privacyDomainIds: [privacyDomainId] },
          revision: String(row.row_version),
          operationId: row.consumed_operation_id,
        };
      },
      privacyDomainId,
    );
  }

  async getEnvelope(
    actor: AuthenticatedActor,
    participantId: string,
    privacyDomainId: string,
    envelopeId: string,
  ) {
    this.owner(actor, participantId);
    if (actor.platform) {
      return this.tx(
        actor.participantId,
        'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        async (client, operationId) => {
          try {
            const scope = {
              participantId: actor.participantId,
              privacyDomainId,
              operationId,
              actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
            };
            const resolved = await readEnvelopeCreation(client, scope, envelopeId);
            if (resolved.stored.targetParticipantId !== participantId)
              throw new AuthorityFenceError();
            // Resolve before entering the target. Lock Participant roots before
            // actor dependencies and the proposal/target business rows.
            for (const root of [...new Set([actor.participantId, participantId])].sort()) {
              await inEnvelopeParticipantScope(client, scope, root, async () => {
                const locked = await client.query(
                  'select participant_id from control.participant where participant_id=$1 for share',
                  [root],
                );
                if (locked.rowCount !== 1) throw new AuthorityFenceError();
              });
            }
            await this.fenceRead(
              client,
              actor,
              privacyDomainId,
              envelopeId,
              scope.actionIntentId,
              true,
            );
            const direct = await client.query(
              'select 1 from control.assignment where participant_id=$1 and assignment_id=$2 and principal_id=$3',
              [actor.participantId, actor.readAuthorization?.assignmentId, actor.principalId],
            );
            if (direct.rowCount !== 1) throw new AuthorityFenceError();
            const creation = await readEnvelopeCreation(client, scope, envelopeId, 'share');
            const readback = await readEnvelopeEffectReadback(client, scope, creation);
            return await inEnvelopeParticipantScope(client, scope, participantId, async () => {
              const selected = await client.query<EnvelopeRow>(
                `select * from control.authority_envelope
                  where participant_id=$1 and authority_envelope_id=$2 and representation='TYPED_V1'
                    and issuer_participant_id=$3 and issuer_privacy_domain_id=$4
                    and semantic_cbor=$5 and semantic_digest=$6 and state=$7 and row_version=$8
                    and last_mutation_operation_id=$9 for share`,
                [
                  participantId,
                  envelopeId,
                  actor.participantId,
                  privacyDomainId,
                  creation.stored.bytes,
                  creation.stored.digest,
                  readback.state,
                  readback.version,
                  readback.operationId,
                ],
              );
              const row = one(selected.rows, 'PC-IDENTITY-1008');
              return {
                effect: {
                  ...envelopeFromGovernedCreation(
                    row,
                    typedEnvelopeCreateCandidate.parse(creation.original.document),
                  ),
                  // This is the selected disclosure slice, never the complete
                  // proposal scope. Empty is truthful and grants nothing.
                  privacyDomainIds: row.privacy_domain_ids.filter(
                    (value) => value === privacyDomainId,
                  ),
                },
                operationId: readback.operationId,
              };
            });
          } catch (error) {
            if (error instanceof AuthorityFenceError)
              throw new ParticipantKernelError('PC-IDENTITY-1008');
            throw error;
          }
        },
        privacyDomainId,
      );
    }
    return this.tx(
      participantId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      async (client) => {
        await this.fenceRead(client, actor, privacyDomainId, envelopeId);
        const result = await client.query<EnvelopeRow & { consumed_operation_id: string | null }>(
          `select envelope.*,candidate.consumed_operation_id::text
           from control.authority_envelope envelope
           left join control.mutation_candidate candidate
             on candidate.participant_id=envelope.participant_id
            and ((envelope.last_mutation_operation_id is not null and candidate.consumed_operation_id=envelope.last_mutation_operation_id)
              or (envelope.last_mutation_operation_id is null and candidate.resource_id=envelope.authority_envelope_id))
            and (envelope.last_mutation_operation_id is not null or candidate.catalog_operation_id='ID-OP-ENVELOPE-CREATE')
            and candidate.state='CONSUMED'
            and candidate.privacy_domain_id=$3::uuid
          where envelope.participant_id=$1 and envelope.authority_envelope_id=$2
            and $3::text=any(envelope.privacy_domain_ids)`,
          [participantId, envelopeId, privacyDomainId],
        );
        const row = one(result.rows, 'PC-IDENTITY-1008');
        return {
          effect: { ...envelopeFromRow(row), privacyDomainIds: [privacyDomainId] },
          operationId: row.consumed_operation_id,
        };
      },
      privacyDomainId,
    );
  }

  async createParticipant(
    actor: AuthenticatedActor,
    participant: ParticipantRecord,
    key: string,
    request: unknown,
  ) {
    if (!actor.platform) throw new ParticipantKernelError('PC-IDENTITY-1000');
    if (actor.mutationAuthorization?.idempotencyKey !== key)
      throw new ParticipantKernelError('PC-IDENTITY-1009');
    return this.mutationTx(
      actor,
      participant.participantId,
      'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
      'ID-OP-PARTICIPANT-CREATE',
      'participant',
      participant.participantId,
      request,
      async (client, operationId, _envelopeId, bootstrapAuthority) => {
        const query = await client.query<ParticipantRow>(
          `insert into control.participant (participant_id,display_name,state,authority_epoch,row_version)
         values ($1,$2,'PROVISIONING',0,1)
         returning participant_id,display_name,state,authority_epoch::text,row_version::text`,
          [participant.participantId, participant.displayName],
        );
        const result = participantFromRow(one(query.rows));
        if (
          !bootstrapAuthority ||
          typeof request !== 'object' ||
          request === null ||
          !('firstAdministrator' in request)
        )
          throw new ParticipantKernelError('PC-IDENTITY-1005');
        const bootstrap = await createParticipantBootstrap(
          client,
          participant.participantId,
          firstAdministratorProposal.parse(request.firstAdministrator),
          bootstrapAuthority,
        );
        return { operationId, result: { ...result, bootstrap } };
      },
    );
  }

  async activateParticipant(
    actor: AuthenticatedActor,
    participantId: string,
    key: string,
    request: unknown,
  ) {
    this.owner(actor, participantId);
    if (actor.mutationAuthorization?.idempotencyKey !== key)
      throw new ParticipantKernelError('PC-IDENTITY-1009');
    return this.mutationTx(
      actor,
      participantId,
      'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
      'ID-OP-PARTICIPANT-ACTIVATE',
      'participant',
      participantId,
      request,
      async (client, operationId) => {
        const custody = await client.query(
          'select 1 from control.participant_bootstrap_custody where participant_id=$1',
          [participantId],
        );
        if (custody.rowCount !== 0) throw new ParticipantKernelError('PC-IDENTITY-1005');
        const query = await client.query<ParticipantRow>(
          `update control.participant set state='ACTIVE',row_version=row_version+1,updated_at=clock_timestamp()
         where participant_id=$1 and state='PROVISIONING'
         returning participant_id,display_name,state,authority_epoch::text,row_version::text`,
          [participantId],
        );
        const result = participantFromRow(one(query.rows, 'PC-IDENTITY-1002'));
        return { operationId, result };
      },
      async () =>
        participantId === actor.participantId
          ? { participant: [{ id: participantId, write: true }] }
          : {},
    );
  }

  async createEnvelope(
    actor: AuthenticatedActor,
    value: AuthorityEnvelope | TypedEnvelopeCreateCandidate,
  ) {
    this.owner(actor, value.participantId);
    return this.mutationTx(
      actor,
      value.participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-ENVELOPE-CREATE',
      'authority-envelope',
      value.id,
      value,
      async (
        client,
        operationId,
        _issuerEnvelopeId,
        _bootstrapAuthority,
        platform,
        typedProposal,
      ) => {
        if ('schema' in value) {
          if (!typedProposal || !actor.mutationAuthorization)
            throw new ParticipantKernelError('PC-IDENTITY-1005');
          const scope = {
            participantId: actor.participantId,
            privacyDomainId: actor.mutationAuthorization.privacyDomainId,
            operationId,
            actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          };
          // The generic owner enters the target for its effect callback. The
          // governance record belongs to the already-fenced original issuer.
          await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
            scope.participantId,
            scope.privacyDomainId,
            operationId,
            scope.actionIntentId,
          ]);
          await insertInitialEnvelopeProposal(
            client,
            scope,
            typedProposal,
            actor.mutationAuthorization.approvalRequestId,
          );
          await client.query(
            `select openpc.set_request_context('PARTICIPANT',$1,NULL,$2,$3,false)`,
            [value.participantId, operationId, scope.actionIntentId],
          );
          const row = await client.query<EnvelopeRow>(
            `select * from control.authority_envelope
            where participant_id=$1 and authority_envelope_id=$2`,
            [value.participantId, value.id],
          );
          // Restore the callback's entry context. Same-Participant CREATE must
          // retain issuer privacy for the candidate/evidence/outbox commit.
          const sameParticipant = value.participantId === scope.participantId;
          await client.query(`select openpc.set_request_context($1,$2,$3,$4,$5,$6)`, [
            sameParticipant ? 'PARTICIPANT' : 'PLATFORM',
            value.participantId,
            sameParticipant ? scope.privacyDomainId : null,
            operationId,
            scope.actionIntentId,
            sameParticipant,
          ]);
          return envelopeFromGovernedCreation(one(row.rows), value);
        }
        const epoch = await this.participantEpoch(client, value.participantId);
        if (value.state !== 'DRAFT') throw new ParticipantKernelError('PC-IDENTITY-1001');
        await this.principal(client, value.participantId, actor.principalId);
        if (platform === undefined) throw new ParticipantKernelError('PC-IDENTITY-1005');
        const result = await client.query<EnvelopeRow>(
          `insert into control.authority_envelope
         (authority_envelope_id,participant_id,principal_id,maker_principal_id,authority_epoch,delegation_epoch,state,
          valid_from,valid_until,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,
          resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,runtime_capability_ids,
          platform_context_id,platform_authority_epoch)
         values ($1,$2,$3,$3,$4,0,'DRAFT',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) returning *`,
          [
            value.id,
            value.participantId,
            actor.principalId,
            epoch,
            value.validFrom,
            value.validUntil,
            Buffer.from(value.semanticDigest),
            digest(value.semanticDigest),
            Buffer.alloc(0),
            value.privacyDomainIds,
            value.actionIntentIds,
            value.resourceIds,
            value.riskClasses,
            value.makerCheckerRequired,
            value.stepUpRequired,
            value.onwardDelegationDepth,
            value.capabilityIds ?? [],
            platform?.platformContextId ?? null,
            platform?.platformAuthorityEpoch ?? null,
          ],
        );
        return envelopeFromRow(one(result.rows));
      },
    );
  }

  async activateEnvelope(actor: AuthenticatedActor, participantId: string, envelopeId: string) {
    this.owner(actor, participantId);
    const proof = actor.mutationAuthorization;
    if (proof !== undefined) {
      const representation = await this.tx(
        actor.participantId,
        'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        async (client) => {
          const selected = await client.query<{ representation: string }>(
            `select representation from control.authority_envelope
             where participant_id=$1 and authority_envelope_id=$2`,
            [participantId, envelopeId],
          );
          return one(selected.rows, 'PC-IDENTITY-1005').representation;
        },
        proof.privacyDomainId,
      );
      if (representation === 'TYPED_V1')
        return this.activateInitialTypedEnvelope(actor, participantId, envelopeId);
    }
    return this.mutationTx(
      actor,
      participantId,
      'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
      'ID-OP-ENVELOPE-ACTIVATE',
      'authority-envelope',
      envelopeId,
      { envelopeId },
      async (client) => {
        const epoch = await this.participantEpoch(client, participantId);
        const result = await client.query<EnvelopeRow>(
          `update control.authority_envelope set state='ACTIVE',row_version=row_version+1,
           updated_at=clock_timestamp()
         where participant_id=$1 and authority_envelope_id=$2 and state='APPROVED'
           and checker_principal_id is not null and authority_epoch=$3 returning *`,
          [participantId, envelopeId, epoch],
        );
        return envelopeFromRow(one(result.rows, 'PC-IDENTITY-1005'));
      },
      async () => ({ authority_envelope: [{ id: envelopeId, write: true }] }),
    );
  }

  async revokeEnvelope(
    actor: AuthenticatedActor,
    participantId: string,
    envelopeId: string,
    reason: string,
  ) {
    this.owner(actor, participantId);
    const candidate = { envelopeId, reason };
    return this.mutationTx(
      actor,
      participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-ENVELOPE-REVOKE',
      'authority-envelope',
      envelopeId,
      candidate,
      async (client, operationId) => {
        const result = await client.query<EnvelopeRow>(
          `update control.authority_envelope
              set state='REVOKED',row_version=row_version+1,
                  last_mutation_operation_id=$3,updated_at=clock_timestamp()
            where participant_id=$1 and authority_envelope_id=$2 and state='ACTIVE'
            returning *`,
          [participantId, envelopeId, operationId],
        );
        return envelopeFromRow(one(result.rows, 'PC-IDENTITY-1005'));
      },
      async () => ({ authority_envelope: [{ id: envelopeId, write: true }] }),
    );
  }

  private async activateInitialTypedEnvelope(
    actor: AuthenticatedActor,
    participantId: string,
    envelopeId: string,
  ) {
    const proof = actor.mutationAuthorization;
    const runtime = this.initialEnvelopeActivation;
    if (
      !runtime ||
      !actor.platform ||
      actor.participantId !== participantId ||
      actor.sessionId === undefined ||
      proof === undefined ||
      !proof.authorized ||
      proof.actionIntentId !== 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' ||
      proof.catalogOperationId !== 'ID-OP-ENVELOPE-ACTIVATE' ||
      proof.aggregateVersion !== '3' ||
      proof.candidateDigest !== `sha256:${stableDigest({ envelopeId }).toString('hex')}`
    )
      throw new ParticipantKernelError('PC-IDENTITY-1005');
    const scopeBase = {
      participantId,
      privacyDomainId: proof.privacyDomainId,
      actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' as const,
    };
    const identity = {
      principalId: actor.principalId,
      idempotencyKey: proof.idempotencyKey,
      envelopeId,
    };
    let original = await this.tx(
      participantId,
      scopeBase.actionIntentId,
      (client) => readInitialEnvelopeActivation(client, scopeBase, identity),
      proof.privacyDomainId,
    );
    if (!original) {
      original = await this.tx(
        participantId,
        scopeBase.actionIntentId,
        (client, operationId) =>
          prepareInitialEnvelopeActivation(
            client,
            { ...scopeBase, operationId },
            {
              principalId: actor.principalId,
              sessionId: actor.sessionId!,
              envelopeId,
              approvalRequestId: proof.approvalRequestId,
              idempotencyKey: proof.idempotencyKey,
              environmentId: runtime.environmentId,
              callerWorkloadCredentialId: runtime.callerWorkloadCredentialId,
            },
            this.identityRuntimeVerifier,
          ).then(() => readInitialEnvelopeActivation(client, scopeBase, identity)),
        proof.privacyDomainId,
      );
    }
    if (!original) throw new ParticipantKernelError('PC-IDENTITY-1005');
    const scope = { ...scopeBase, operationId: original.operationId };
    let mayPerform = false;
    if (original.state === 'PREPARED') {
      const makerAuthority = await this.tx(
        participantId,
        scope.actionIntentId,
        async (client) => {
          const selected = await client.query<{ authority: BoundAuthority }>(
            `select maker_authority#>'{durable,grant}' || jsonb_build_object(
              'sessionId',maker_authority#>'{binding,sessionId}',
              'sessionEpoch',maker_authority#>'{binding,sessionEpoch}') as authority
             from control.identity_envelope_activation where operation_id=$1`,
            [scope.operationId],
          );
          return one(selected.rows, 'PC-IDENTITY-1005').authority;
        },
        proof.privacyDomainId,
        scope.operationId,
      );
      mayPerform = await this.tx(
        participantId,
        scope.actionIntentId,
        (client) =>
          claimInitialEnvelopeActivationDispatch(
            client,
            scope,
            original!.attemptId,
            makerAuthority,
          ),
        proof.privacyDomainId,
        scope.operationId,
      );
      original = await this.tx(
        participantId,
        scope.actionIntentId,
        (client) => readInitialEnvelopeActivation(client, scope, identity),
        proof.privacyDomainId,
        scope.operationId,
      );
    }
    if (!original) throw new ParticipantKernelError('PC-IDENTITY-1005');
    if (original.state === 'DISPATCHED') {
      let observation;
      try {
        if (!mayPerform) throw new Error('lookup-only');
        observation = await runtime.provider.perform(original.request);
      } catch {
        const reconciled = await runtime.provider.lookup(original.request);
        if (reconciled.state !== 'OBSERVED') throw new ParticipantKernelError('PC-IDENTITY-1004');
        observation = reconciled.observation;
      }
      await this.tx(
        participantId,
        scope.actionIntentId,
        (client) =>
          recordInitialEnvelopeActivationObservation(client, scope, original!, observation),
        proof.privacyDomainId,
        scope.operationId,
      );
      original = await this.tx(
        participantId,
        scope.actionIntentId,
        (client) => readInitialEnvelopeActivation(client, scope, identity),
        proof.privacyDomainId,
        scope.operationId,
      );
    }
    if (!original) throw new ParticipantKernelError('PC-IDENTITY-1005');
    if (original.state === 'COMMITTED') {
      return this.tx(
        participantId,
        scope.actionIntentId,
        async (client) => {
          const selected = await client.query<EnvelopeRow>(
            `select * from control.authority_envelope
             where participant_id=$1 and authority_envelope_id=$2 and state='ACTIVE'`,
            [participantId, envelopeId],
          );
          return envelopeFromRow(one(selected.rows, 'PC-IDENTITY-1005'));
        },
        proof.privacyDomainId,
      );
    }
    if (original.state !== 'OBSERVED') throw new ParticipantKernelError('PC-IDENTITY-1004');
    return this.tx(
      participantId,
      scope.actionIntentId,
      async (client) => {
        await commitInitialEnvelopeActivation(client, scope, original!);
        const activation = one(
          (
            await client.query<{
              candidate_id: string;
              approval_request_id: string;
              maker_challenge_id: string;
              maker_participant_epoch: string;
              maker_principal_epoch: string;
              maker_authority_envelope_id: string;
              maker_authority_epoch: string;
              maker_assignment_id: string;
            }>(
              `select activation.candidate_id,activation.approval_request_id,
                activation.maker_challenge_id,
                activation.maker_authority#>>'{binding,participantEpoch}' as maker_participant_epoch,
                activation.maker_authority#>>'{binding,principalEpoch}' as maker_principal_epoch,
                activation.maker_authority#>>'{binding,authorityEnvelopeId}' as maker_authority_envelope_id,
                activation.maker_authority#>>'{binding,authorityEpoch}' as maker_authority_epoch,
                activation.maker_authority#>>'{binding,assignmentId}' as maker_assignment_id
               from control.identity_envelope_activation activation
               where activation.operation_id=$1 and activation.state='COMMITTED'`,
              [scope.operationId],
            )
          ).rows,
          'PC-IDENTITY-1005',
        );
        const consumed = await client.query(
          `update control.mutation_candidate set state='CONSUMED',consumed_operation_id=$2,
             updated_at=clock_timestamp()
           where mutation_candidate_id=$1 and state='APPROVED'`,
          [activation.candidate_id, scope.operationId],
        );
        if (consumed.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1005');
        const selected = await client.query<EnvelopeRow>(
          `select * from control.authority_envelope
           where participant_id=$1 and authority_envelope_id=$2 and state='ACTIVE'`,
          [participantId, envelopeId],
        );
        const result = envelopeFromRow(one(selected.rows, 'PC-IDENTITY-1005'));
        const sequence = one(
          (
            await client.query<{ last_sequence: string }>(
              `insert into control.outbox_aggregate_head
                (participant_id,aggregate_type,aggregate_id,last_sequence)
               values($1,'authority-envelope',$2,1)
               on conflict (participant_id,aggregate_type,aggregate_id) do update
                set last_sequence=control.outbox_aggregate_head.last_sequence+1,
                    updated_at=clock_timestamp()
               returning last_sequence::text`,
              [participantId, envelopeId],
            )
          ).rows,
        ).last_sequence;
        await client.query(
          `insert into control.mutation_evidence
            (participant_id,privacy_domain_id,operation_id,principal_id,checker_principal_id,
             action_intent_id,catalog_operation_id,aggregate_type,aggregate_id,aggregate_version,
             candidate_digest,approval_request_id,mfa_challenge_id,bound_participant_epoch,
             bound_principal_epoch,bound_authority_envelope_id,bound_envelope_epoch,
             bound_assignment_id,signer_credential_id,webauthn_assertion_binding_digest,
             evidence_cbor,evidence_digest,cose_sign1)
           values($1,$2,$3,$4,$5,$6,'ID-OP-ENVELOPE-ACTIVATE','authority-envelope',$7,3,
             $8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
          [
            participantId,
            proof.privacyDomainId,
            scope.operationId,
            actor.principalId,
            proof.checkerPrincipalId,
            scope.actionIntentId,
            envelopeId,
            Buffer.from(proof.candidateDigest.slice(7), 'hex'),
            activation.approval_request_id,
            activation.maker_challenge_id,
            activation.maker_participant_epoch,
            activation.maker_principal_epoch,
            activation.maker_authority_envelope_id,
            activation.maker_authority_epoch,
            activation.maker_assignment_id,
            proof.signerCredentialId,
            proof.webauthnAssertionBindingDigest,
            proof.evidenceCbor,
            proof.evidenceDigest,
            proof.coseSign1,
          ],
        );
        await client.query(
          `insert into control.outbox_event
            (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
             aggregate_sequence,payload_cbor,payload_digest,cose_sign1,
             webauthn_assertion_binding_digest,occurred_at)
           values($1,$2,$3,'openpc.authority-envelope.mutation.committed.v1',
             'authority-envelope',$4,$5,$6,$7,$8,$9,clock_timestamp())`,
          [
            participantId,
            proof.privacyDomainId,
            uuidV7(),
            envelopeId,
            sequence,
            proof.evidenceCbor,
            proof.evidenceDigest,
            proof.coseSign1,
            proof.webauthnAssertionBindingDigest,
          ],
        );
        await client.query(
          `update control.idempotency_record set result_digest=$2,result_payload=$3,
             result_aggregate_version=4,terminal_state='COMMITTED'
           where operation_id=$1 and terminal_state is null`,
          [scope.operationId, stableDigest(result), result],
        );
        return result;
      },
      proof.privacyDomainId,
      scope.operationId,
    );
  }

  async createAssignment(actor: AuthenticatedActor, value: Assignment) {
    this.owner(actor, value.participantId);
    return this.mutationTx(
      actor,
      value.participantId,
      'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      'ID-OP-ASSIGNMENT-CREATE',
      'assignment',
      value.id,
      value,
      async (client, operationId) => {
        const stored = await client.query<EnvelopeRow>(
          `select * from control.authority_envelope where participant_id=$1 and authority_envelope_id=$2 and state='ACTIVE' for share`,
          [value.participantId, value.authorityEnvelopeId],
        );
        const envelope = envelopeFromRow(one(stored.rows, 'PC-IDENTITY-1002'));
        if (value.state !== 'ACTIVE' || !subsetOf(value, envelope))
          throw new ParticipantKernelError('PC-IDENTITY-1002');
        if (value.roleId !== undefined) {
          const role = await client.query<{ action_intent_ids: string[] }>(
            `select action_intent_ids from control.authority_role
              where participant_id=$1 and role_id=$2 and state='ACTIVE' for share`,
            [value.participantId, value.roleId],
          );
          if (
            role.rowCount !== 1 ||
            !value.actionIntentIds.every((action) =>
              role.rows[0]!.action_intent_ids.includes(action),
            )
          )
            throw new ParticipantKernelError('PC-IDENTITY-1002');
        }
        await this.participantEpoch(client, value.participantId);
        // Root revocation invalidates sessions without changing every envelope's
        // delegation lineage. Bind the grant to its actual source epoch.
        const delegationEpoch = String(stored.rows[0]!.delegation_epoch);
        await this.principal(client, value.participantId, value.principalId);
        if (value.groupId !== undefined) {
          const membership = await client.query<{ allowed: boolean }>(
            `select openpc.assignment_group_permits($1,$2,$3,tstzrange($4,$5,'[)')) allowed`,
            [
              value.participantId,
              value.groupId,
              value.principalId,
              value.validFrom,
              value.validUntil,
            ],
          );
          if (membership.rows[0]?.allowed !== true)
            throw new ParticipantKernelError('PC-IDENTITY-1002');
        }
        const futureRoot = await platformAssignmentAdmission(client, value);
        await assertGrantAdmission(client, value, futureRoot);
        const result = await client.query<AssignmentRow>(
          `insert into control.assignment
         (assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,valid_during,
          state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
          maker_checker_required,step_up_required,onward_delegation_depth,role_id,runtime_capability_ids,last_mutation_operation_id,authority_group_id)
         values ($1,$2,$3,$4,$5,$6,tstzrange($7,$8,'[)'),'ACTIVE',$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
         returning *,lower(valid_during) valid_from,upper(valid_during) valid_until`,
          [
            value.id,
            value.participantId,
            value.principalId,
            value.authorityEnvelopeId,
            delegationEpoch,
            digest(value.scopeDigest),
            value.validFrom,
            value.validUntil,
            actor.principalId,
            value.privacyDomainIds,
            value.actionIntentIds,
            value.resourceIds,
            value.riskClasses,
            value.makerCheckerRequired,
            value.stepUpRequired,
            value.onwardDelegationDepth,
            value.roleId ?? null,
            value.capabilityIds ?? [],
            operationId,
            value.groupId ?? null,
          ],
        );
        return assignmentFromRow(one(result.rows));
      },
      async () => ({
        participant: [{ id: value.participantId, write: true }],
        principal: [{ id: value.principalId }],
        authority_envelope: [{ id: value.authorityEnvelopeId }],
      }),
    );
  }

  async issueDelegation(actor: AuthenticatedActor, value: Delegation) {
    this.owner(actor, value.participantId);
    if (actor.principalId !== value.grantorId) throw new ParticipantKernelError('PC-IDENTITY-1003');
    return this.mutationTx(
      actor,
      value.participantId,
      'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      'ID-OP-DELEGATION-ISSUE',
      'delegation',
      value.id,
      value,
      async (client, operationId) => {
        const parent = await this.parent(client, value.participantId, value.parentId);
        if (parent === undefined || validateDelegation(value, parent) !== undefined)
          throw new ParticipantKernelError('PC-IDENTITY-1003');
        await this.principal(client, value.participantId, value.granteeId);
        await assertGrantAdmission(client, value);
        const parentDelegation = 'parentId' in parent;
        const result = await client.query<DelegationRow>(
          `insert into control.delegation
         (delegation_id,participant_id,parent_assignment_id,parent_delegation_id,grantor_principal_id,delegate_principal_id,
          delegation_epoch,scope_digest,valid_during,state,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
          maker_checker_required,step_up_required,onward_delegation_depth,runtime_capability_ids,last_mutation_operation_id)
         values ($1,$2,$3,$4,$5,$6,$7,$8,tstzrange($9,$10,'[)'),'ACTIVE',$11,$12,$13,$14,$15,$16,$17,$18,$19)
         returning *,lower(valid_during) valid_from,upper(valid_during) valid_until`,
          [
            value.id,
            value.participantId,
            parentDelegation ? null : value.parentId,
            parentDelegation ? value.parentId : null,
            value.grantorId,
            value.granteeId,
            parent.delegationEpoch,
            digest(value.scopeDigest),
            value.validFrom,
            value.validUntil,
            value.privacyDomainIds,
            value.actionIntentIds,
            value.resourceIds,
            value.riskClasses,
            value.makerCheckerRequired,
            value.stepUpRequired,
            value.onwardDelegationDepth,
            value.capabilityIds ?? [],
            operationId,
          ],
        );
        return delegationFromRow(one(result.rows));
      },
      async (client) => {
        const parent = await this.parent(client, value.participantId, value.parentId);
        if (parent === undefined) throw new ParticipantKernelError('PC-IDENTITY-1003');
        return {
          participant: [{ id: value.participantId, write: true }],
          principal: [{ id: value.granteeId }],
          ...('parentId' in parent
            ? { delegation: [{ id: value.parentId }] }
            : { assignment: [{ id: value.parentId }] }),
        };
      },
    );
  }

  async revokeAuthority(
    actor: AuthenticatedActor,
    participantId: string,
    kind: 'assignment' | 'delegation',
    targetId: string,
  ) {
    this.owner(actor, participantId);
    return this.mutationTx(
      actor,
      participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      kind === 'assignment' ? 'ID-OP-ASSIGNMENT-REVOKE' : 'ID-OP-DELEGATION-REVOKE',
      kind,
      targetId,
      { kind, targetId },
      (client, operationId) =>
        revokeGrant(client, participantId, actor.principalId, kind, targetId, operationId),
      async (client) => {
        const descendants = await grantDescendants(client, participantId, kind, targetId);
        return {
          participant: [{ id: participantId, write: true }],
          assignment: kind === 'assignment' ? [{ id: targetId, write: true }] : [],
          delegation: [
            ...(kind === 'delegation' ? [{ id: targetId, write: true }] : []),
            ...descendants.map((id) => ({ id, write: true })),
          ],
        };
      },
    );
  }

  async effectiveAuthority(
    actor: AuthenticatedActor,
    participantId: string,
    target: AuthorityEvaluationTarget,
  ): Promise<EffectiveAuthority | undefined> {
    this.owner(actor, participantId);
    return this.tx(
      participantId,
      'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      async (client) => {
        const participant = await client.query<{ authority_epoch: string }>(
          `select authority_epoch::text from control.participant where participant_id=$1 and state='ACTIVE'`,
          [participantId],
        );
        if (participant.rowCount !== 1) return undefined;
        const resolved = await authorityReadPaths(
          client,
          participantId,
          actor.principalId,
          target.privacyDomainId,
          target.actionIntentId,
          [target.resourceId],
          target.riskClass,
        );
        if (resolved.rowCount !== 1) return undefined;
        const chain = one(resolved.rows);
        const assignment = await client.query<AssignmentRow>(
          `select *,lower(valid_during) valid_from,upper(valid_during) valid_until
           from control.assignment where participant_id=$1 and assignment_id=$2 and state='ACTIVE'`,
          [participantId, chain.assignment_id],
        );
        const assignmentValue = assignmentFromRow(one(assignment.rows, 'PC-IDENTITY-1002'));
        const envelope = await client.query<EnvelopeRow>(
          `select e.* from control.authority_envelope e where e.participant_id=$1 and e.authority_envelope_id=$2 and e.state='ACTIVE'
         and ${currentPlatformEnvelopeSql('e', false, true)}
         and e.valid_from<=clock_timestamp() and (e.valid_until is null or e.valid_until>clock_timestamp())`,
          [participantId, assignmentValue.authorityEnvelopeId],
        );
        if (envelope.rowCount !== 1) return undefined;
        const delegationRows =
          chain.delegation_path.length === 0
            ? []
            : (
                await client.query<DelegationRow>(
                  `select *,lower(valid_during) valid_from,upper(valid_during) valid_until
                   from control.delegation where participant_id=$1 and delegation_id=any($2::uuid[])
                  order by array_position($2::uuid[],delegation_id)`,
                  [participantId, chain.delegation_path],
                )
              ).rows;
        if (delegationRows.length !== chain.delegation_path.length) return undefined;
        const envelopeValue = envelopeFromRow(one(envelope.rows));
        const principal = one(
          (
            await client.query<{ authority_epoch: string }>(
              `select authority_epoch::text from control.principal
              where participant_id=$1 and principal_id=$2 and state='ACTIVE'`,
              [participantId, actor.principalId],
            )
          ).rows,
          'PC-IDENTITY-1002',
        );
        return {
          participantEpoch: actor.boundParticipantEpoch,
          principalEpoch: actor.boundPrincipalEpoch,
          envelopeEpoch: actor.boundEnvelopeEpoch,
          currentParticipantEpoch: one(participant.rows).authority_epoch,
          currentPrincipalEpoch: principal.authority_epoch,
          currentEnvelopeEpoch: envelopeValue.authorityEpoch,
          envelope: envelopeValue,
          assignment: assignmentValue,
          delegations: delegationRows.map(delegationFromRow),
        };
      },
      target.privacyDomainId,
    );
  }

  /** Keep the live authority fenced until the read transaction commits. */
  private async fenceRead(
    client: PoolClient,
    actor: AuthenticatedActor,
    privacyDomainId: string,
    resourceId: string,
    actionIntentId = 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    bootstrapRead = false,
  ): Promise<void> {
    const authority = actor.readAuthorization;
    if (
      authority === undefined ||
      authority.principalId !== actor.principalId ||
      authority.sessionId !== actor.sessionId ||
      authority.participantEpoch !== actor.boundParticipantEpoch ||
      authority.principalEpoch !== actor.boundPrincipalEpoch ||
      authority.authorityEpoch !== actor.boundEnvelopeEpoch ||
      authority.privacyDomainId !== privacyDomainId ||
      authority.resourceId !== resourceId ||
      authority.actionIntentId !== actionIntentId
    ) {
      throw new ParticipantKernelError('PC-IDENTITY-1008');
    }
    try {
      const fence = await fenceBoundAuthorities(client, actor.participantId, [authority]);
      if (bootstrapRead)
        await assertPlatformBootstrapActor(
          client,
          actor.participantId,
          actor.principalId,
          authority.sessionId,
        );
      const assurance = await client.query(
        `with permissions as (
           select risk_classes,step_up_required from control.authority_envelope
            where participant_id=$1 and authority_envelope_id=$3
           union all
           select risk_classes,step_up_required from control.assignment
            where participant_id=$1 and assignment_id=$4
           union all
           select risk_classes,step_up_required from control.delegation
            where participant_id=$1 and delegation_id=any($5::uuid[])
         )
         select session.session_id from control.session session
          where session.participant_id=$1 and session.session_id=$2
            and ((session.context_mode='PARTICIPANT' and session.privacy_domain_id=$6) or ($7 and session.context_mode='PLATFORM' and session.privacy_domain_id is null))
            and not exists (select 1 from permissions where not 'LOW'=any(risk_classes))
            and (not exists (select 1 from permissions where step_up_required)
              or openpc.session_step_up_valid_until(session.participant_id,session.session_id,session.principal_id)>clock_timestamp())`,
        [
          actor.participantId,
          authority.sessionId,
          authority.authorityEnvelopeId,
          authority.assignmentId,
          fence.delegation?.map((delegation) => delegation.id) ?? [],
          privacyDomainId,
          bootstrapRead,
        ],
      );
      if (assurance.rowCount !== 1) throw new ParticipantKernelError('PC-IDENTITY-1008');
    } catch (error) {
      if (error instanceof AuthorityFenceError)
        throw new ParticipantKernelError('PC-IDENTITY-1008');
      throw error;
    }
  }

  private async tx<T>(
    participantId: string,
    actionIntentId: string,
    operation: TxOperation<T>,
    privacyDomainId?: string,
    fixedOperationId?: string,
  ): Promise<T> {
    const client = await this.pool.connect();
    const operationId = fixedOperationId ?? uuidV7();
    try {
      await client.query('discard all');
      const checkout = await client.query<{ clean: boolean }>(
        `select nullif(current_setting('openpc.context_mode',true),'') is null
                and nullif(current_setting('openpc.participant_id',true),'') is null
                and nullif(current_setting('openpc.privacy_domain_id',true),'') is null
                and nullif(current_setting('openpc.operation_id',true),'') is null
                and nullif(current_setting('openpc.action_intent_id',true),'') is null as clean`,
      );
      if (checkout.rows[0]?.clean !== true) throw new ParticipantKernelError('PC-IDENTITY-1004');
      await client.query('begin');
      await client.query('set local row_security=on');
      await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,$5)`, [
        participantId,
        privacyDomainId ?? null,
        operationId,
        actionIntentId,
        privacyDomainId !== undefined,
      ]);
      await client.query('select openpc.assert_request_context($1)', [
        privacyDomainId !== undefined,
      ]);
      const guard = await client.query<{
        participant_id: string;
        privacy_domain_id: string | null;
        operation_id: string;
        action_intent_id: string;
        bypass: boolean;
        superuser: boolean;
      }>(
        `select current_setting('openpc.participant_id',true) participant_id,
                nullif(current_setting('openpc.privacy_domain_id',true),'') privacy_domain_id,
                current_setting('openpc.operation_id',true) operation_id,
                current_setting('openpc.action_intent_id',true) action_intent_id,r.rolbypassrls bypass,r.rolsuper superuser
         from pg_roles r where r.rolname=current_user`,
      );
      const context = one(guard.rows, 'PC-IDENTITY-1004');
      if (
        context.participant_id !== participantId ||
        context.privacy_domain_id !== (privacyDomainId ?? null) ||
        context.operation_id !== operationId ||
        context.action_intent_id !== actionIntentId ||
        context.bypass ||
        context.superuser
      ) {
        throw new ParticipantKernelError('PC-IDENTITY-1004');
      }
      const result = await operation(client, operationId);
      await client.query('commit');
      await client.query('discard all');
      return result;
    } catch (error) {
      await client.query('rollback').catch(() => undefined);
      await client.query('discard all').catch(() => undefined);
      if (error instanceof PlatformScopeOwnerFailure) throw error;
      if (
        error instanceof AuthorityFenceError ||
        (error instanceof ParticipantKernelError && error.code === 'PC-IDENTITY-1001')
      ) {
        process.stderr.write(
          JSON.stringify({
            event: 'participant_mutation_authority_rejected',
            participantId,
            actionIntentId,
            classification: error instanceof AuthorityFenceError ? 'AUTHORITY_FENCE' : 'STALE',
            frames: error.stack
              ?.split('\n')
              .slice(1, 4)
              .map((frame) => frame.trim()),
            disposition: 'TRANSACTION_ROLLED_BACK',
          }) + '\n',
        );
      }
      if (error instanceof AuthorityFenceError)
        throw new ParticipantKernelError('PC-IDENTITY-1001');
      throw error;
    } finally {
      client.release();
    }
  }

  private async mutationTx<T>(
    actor: AuthenticatedActor,
    targetParticipantId: string,
    actionIntentId: string,
    catalogOperationId: string,
    aggregateType: string,
    aggregateId: string,
    request: unknown,
    operation: (
      client: PoolClient,
      operationId: string,
      authorityEnvelopeId: string,
      bootstrapAuthority?: BootstrapIssuanceAuthority,
      platformContext?: EnvelopePlatformContext | null,
      typedProposal?: Awaited<ReturnType<typeof captureInitialRootEnvelopeProposal>>,
    ) => Promise<T>,
    writeDependencies?: (client: PoolClient) => Promise<AuthorityFence>,
  ): Promise<T> {
    const proof = actor.mutationAuthorization;
    if (proof === undefined || actor.sessionId === undefined || !proof.authorized) {
      throw new ParticipantKernelError('PC-IDENTITY-1004');
    }
    const candidateDigest = stableDigest(request);
    const typedRequest =
      catalogOperationId === 'ID-OP-ENVELOPE-CREATE'
        ? typedEnvelopeCreateCandidate.safeParse(request)
        : undefined;
    if (
      proof.catalogOperationId !== catalogOperationId ||
      proof.actionIntentId !== actionIntentId ||
      !proof.candidateDigest.startsWith('sha256:') ||
      !candidateDigest.equals(Buffer.from(proof.candidateDigest.slice(7), 'hex')) ||
      !createHash('sha256').update(proof.evidenceCbor).digest().equals(proof.evidenceDigest) ||
      proof.coseSign1.length === 0 ||
      proof.checkerPrincipalId === actor.principalId ||
      proof.mfaChallengeId === undefined ||
      proof.webauthnSessionId === undefined ||
      proof.webauthnSignerCredentialId === undefined ||
      proof.webauthnAssertionBindingDigest === undefined ||
      proof.webauthnEvidenceCbor === undefined ||
      proof.webauthnEvidenceDigest === undefined ||
      proof.webauthnCoseSign1 === undefined ||
      !createHash('sha256')
        .update(proof.webauthnEvidenceCbor)
        .digest()
        .equals(proof.webauthnEvidenceDigest) ||
      BigInt(proof.aggregateVersion) < 0n ||
      !CATALOG_OPERATION_PATTERN.test(catalogOperationId)
    ) {
      throw new ParticipantKernelError(
        proof.catalogOperationId !== catalogOperationId || proof.actionIntentId !== actionIntentId
          ? 'PC-IDENTITY-1009'
          : 'PC-IDENTITY-1005',
      );
    }
    const webauthnAssertionBindingDigest = proof.webauthnAssertionBindingDigest;
    const operationContract = participantGovernanceOperations.find(
      (candidate) => candidate.id === catalogOperationId,
    );
    const stateMachineByAggregate: Readonly<Record<string, string>> = {
      'participant': 'PARTICIPANT',
      'authority-envelope': 'AUTHORITY_ENVELOPE',
      'assignment': 'ASSIGNMENT',
      'delegation': 'DELEGATION',
      'role': 'ROLE',
      'group': 'GROUP',
      'platform-scope-replacement': 'PLATFORM_SCOPE_REPLACEMENT',
    };
    if (
      operationContract === undefined ||
      operationContract.actionIntentId !== actionIntentId ||
      operationContract.stateMachine !== stateMachineByAggregate[aggregateType] ||
      !operationContract.makerCheckerRequired ||
      !operationContract.webauthnStepUpRequired
    ) {
      throw new ParticipantKernelError('PC-IDENTITY-1009');
    }
    return this.tx(actor.participantId, actionIntentId, async (client, operationId) => {
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
        [actor.participantId, proof.privacyDomainId, operationId, actionIntentId],
      );
      const current = await client.query<{ sessionEpoch: string; delegationEpoch: string }>(
        `select s.session_epoch::text as "sessionEpoch",s.delegation_epoch::text as "delegationEpoch"
          from control.participant p join control.principal pr on pr.participant_id=p.participant_id
          join control.session s on s.participant_id=p.participant_id and s.principal_id=pr.principal_id
          where p.participant_id=$1 and p.state='ACTIVE' and p.authority_epoch=$2
            and pr.principal_id=$3 and pr.state='ACTIVE' and pr.authority_epoch=$4
            and s.session_id=$5 and s.state='ACTIVE' and s.participant_epoch=p.authority_epoch
            and s.authority_epoch=pr.authority_epoch and s.idle_expires_at>clock_timestamp()
            and s.absolute_expires_at>clock_timestamp()`,
        [
          actor.participantId,
          actor.boundParticipantEpoch,
          actor.principalId,
          actor.boundPrincipalEpoch,
          actor.sessionId,
        ],
      );
      const session = one(current.rows, 'PC-IDENTITY-1001');
      const authority = one(
        (
          await client.query<{
            assignment_id: string;
            assignment_row_version: string;
            authority_envelope_id: string;
            authority_epoch: string;
          }>(
            `with recursive authority_chain as (
               select a.assignment_id,null::uuid current_delegation_id,a.principal_id terminal_principal_id,0 depth
                 from control.assignment a where a.participant_id=$1 and a.state='ACTIVE'
                  and a.valid_during @> clock_timestamp() and $4=any(a.action_intent_ids)
                  and $5::text=any(a.privacy_domain_ids)
                  and openpc.administration_resource_permits(a.resource_ids,$6::text,$4,$1,$2,$7,a.authority_envelope_id)
               union all
               select c.assignment_id,d.delegation_id,d.delegate_principal_id,c.depth+1
                 from authority_chain c join control.delegation d on d.participant_id=$1
                  and ((c.current_delegation_id is null and d.parent_assignment_id=c.assignment_id)
                    or d.parent_delegation_id=c.current_delegation_id)
                  and d.grantor_principal_id=c.terminal_principal_id and d.state='ACTIVE'
                  and d.valid_during @> clock_timestamp() and $4=any(d.action_intent_ids)
                  and $5::text=any(d.privacy_domain_ids)
                  and ($6::text=any(d.resource_ids) or '*'=any(d.resource_ids))
                where c.depth<32
             )
             select a.assignment_id,a.row_version::text as assignment_row_version,
                    ae.authority_envelope_id,ae.authority_epoch::text
               from authority_chain c join control.assignment a
                 on a.participant_id=$1 and a.assignment_id=c.assignment_id
               join control.authority_envelope ae on ae.participant_id=a.participant_id
                 and ae.authority_envelope_id=a.authority_envelope_id
              where c.terminal_principal_id=$2 and ae.state='ACTIVE' and ae.authority_epoch=$3
                and ${currentPlatformEnvelopeSql('ae', false, true)}
                and ae.valid_from<=clock_timestamp()
                and (ae.valid_until is null or ae.valid_until>clock_timestamp())
                and $4=any(ae.action_intent_ids) and $5::text=any(ae.privacy_domain_ids)
                and openpc.administration_resource_permits(ae.resource_ids,$6::text,$4,$1,$2,$7,ae.authority_envelope_id)`,
            [
              actor.participantId,
              actor.principalId,
              actor.boundEnvelopeEpoch,
              actionIntentId,
              proof.privacyDomainId,
              aggregateId,
              actor.sessionId,
            ],
          )
        ).rows,
        'PC-IDENTITY-1002',
      );
      const dependencies = await approvalAuthorityDependencies(
        client,
        { participantId: actor.participantId, privacyDomainId: proof.privacyDomainId },
        proof.approvalRequestId,
        true,
      );
      const writes = await writeDependencies?.(client);
      const issuerScope = {
        participantId: actor.participantId,
        privacyDomainId: proof.privacyDomainId,
        operationId,
        actionIntentId,
      };
      let typedTargetEpoch: string | undefined;
      const checkerBusiness =
        typedRequest?.success && dependencies.authorities[1]
          ? {
              ...dependencies.authorities[1],
              actionIntentId,
              resourceId: aggregateId,
              catalogOperationId: undefined,
            }
          : undefined;
      if (typedRequest?.success) {
        if (!actor.platform || !checkerBusiness)
          throw new ParticipantKernelError('PC-IDENTITY-1005');
        await assertPlatformBootstrapActor(
          client,
          actor.participantId,
          actor.principalId,
          actor.sessionId!,
        );
        typedTargetEpoch = await fenceEnvelopeProposalParticipants(
          client,
          issuerScope,
          targetParticipantId,
        );
      }
      const makerAuthority: BoundAuthority = {
        principalId: actor.principalId,
        sessionId: actor.sessionId!,
        sessionEpoch: session.sessionEpoch,
        participantEpoch: actor.boundParticipantEpoch,
        principalEpoch: actor.boundPrincipalEpoch,
        assignmentId: authority.assignment_id,
        assignmentRowVersion: authority.assignment_row_version,
        authorityEnvelopeId: authority.authority_envelope_id,
        authorityEpoch: authority.authority_epoch,
        delegationEpoch: session.delegationEpoch,
        privacyDomainId: proof.privacyDomainId,
        actionIntentId,
        resourceId: aggregateId,
      };
      await fenceBoundAuthorities(
        client,
        actor.participantId,
        [
          makerAuthority,
          ...dependencies.authorities,
          ...(checkerBusiness ? [checkerBusiness] : []),
        ],
        {
          ...writes,
          credential: [
            { id: proof.signerCredentialId },
            ...(proof.webauthnSignerCredentialId === undefined
              ? []
              : [{ id: proof.webauthnSignerCredentialId }]),
            ...(dependencies.rows.credential ?? []),
            ...(writes?.credential ?? []),
          ],
        },
      );
      await approvalAuthorityDependencies(
        client,
        { participantId: actor.participantId, privacyDomainId: proof.privacyDomainId },
        proof.approvalRequestId,
        true,
      );
      await fenceMutationIntent(client, {
        participantId: actor.participantId,
        privacyDomainId: proof.privacyDomainId,
        principalId: actor.principalId,
        actionIntentId,
        catalogOperationId,
        idempotencyKey: proof.idempotencyKey,
      });
      const idempotency = await this.beginIdempotency<T>(
        client,
        actor,
        actor.participantId,
        actionIntentId,
        catalogOperationId,
        proof.idempotencyKey,
        request,
        webauthnAssertionBindingDigest,
        proof.aggregateVersion,
        operationId,
      );
      // Capture the issuing envelope while its source context and authority
      // fences are still selected, before a Platform command enters its target.
      const typedProposal =
        typedRequest?.success &&
        !idempotency.replay &&
        typedTargetEpoch !== undefined &&
        checkerBusiness
          ? await captureInitialRootEnvelopeProposal(
              client,
              issuerScope,
              typedRequest.data,
              typedTargetEpoch,
              makerAuthority,
              checkerBusiness,
            )
          : undefined;
      const envelopePlatform =
        catalogOperationId === 'ID-OP-ENVELOPE-CREATE' && !idempotency.replay
          ? await fenceEnvelopePlatformContext(
              client,
              actor.participantId,
              authority.authority_envelope_id,
            )
          : undefined;
      if (envelopePlatform !== undefined) {
        for (const envelopeId of new Set(
          dependencies.authorities.map((entry) => entry.authorityEnvelopeId),
        )) {
          const currentPlatform = await fenceEnvelopePlatformContext(
            client,
            actor.participantId,
            envelopeId,
          );
          if (
            currentPlatform?.platformContextId !== envelopePlatform?.platformContextId ||
            currentPlatform?.platformAuthorityEpoch !== envelopePlatform?.platformAuthorityEpoch
          )
            throw new ParticipantKernelError('PC-IDENTITY-1005');
        }
      }
      if (targetParticipantId !== actor.participantId) {
        if (!actor.platform) throw new ParticipantKernelError('PC-IDENTITY-1000');
        await client.query(
          `select openpc.set_request_context('PLATFORM',$1,null,$2,$3,false),openpc.assert_request_context(false)`,
          [targetParticipantId, operationId, actionIntentId],
        );
      }
      const beforeState = await this.currentCatalogState(
        client,
        targetParticipantId,
        aggregateType,
        aggregateId,
      );
      const admittedCurrentStates = idempotency.replay
        ? operationContract.successStates
        : operationContract.allowedFromStates;
      if (
        (admittedCurrentStates.length === 0 && beforeState !== undefined) ||
        (admittedCurrentStates.length > 0 &&
          (beforeState === undefined ||
            !(admittedCurrentStates as readonly string[]).includes(beforeState)))
      ) {
        throw new ParticipantKernelError('PC-IDENTITY-1009');
      }
      const aggregateVersion = await this.currentAggregateVersion(
        client,
        targetParticipantId,
        aggregateType,
        aggregateId,
      );
      if (targetParticipantId !== actor.participantId) {
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
          [actor.participantId, proof.privacyDomainId, operationId, actionIntentId],
        );
      }
      const authorizedAggregateVersion = idempotency.replay
        ? idempotency.resultAggregateVersion
        : proof.aggregateVersion;
      if (
        idempotency.expectedAggregateVersion !== proof.aggregateVersion ||
        authorizedAggregateVersion === undefined ||
        aggregateVersion !== authorizedAggregateVersion
      ) {
        throw new ParticipantKernelError('PC-IDENTITY-1001');
      }
      const approval = await client.query<{
        approval_request_id: string;
        cose_sign1: Buffer;
        evidence_cbor: Buffer;
        public_key_digest: Buffer;
        public_key_spki_der: Buffer;
      }>(
        `select ar.approval_request_id,ad.cose_sign1,ad.evidence_cbor,
                credential.public_key_digest,credential.public_key_spki_der
           from control.approval_request ar
          join control.mutation_candidate candidate
            on candidate.participant_id=ar.participant_id
           and candidate.privacy_domain_id=ar.privacy_domain_id
           and candidate.mutation_candidate_id=ar.subject_id
           and candidate.action_intent_id=ar.action_intent_id
           and candidate.candidate_digest=ar.subject_digest
           and candidate.expected_revision=ar.subject_version
           and candidate.resource_id=$8::uuid
           and candidate.catalog_operation_id=$11
           and candidate.idempotency_key=$12
           and candidate.maker_principal_id=$6::uuid
           and candidate.state in ('APPROVED','CONSUMED')
           and ${currentMutationCandidateSql('candidate')}
           and candidate.expires_at>clock_timestamp()
          join control.approval_decision_record ad
            on ad.participant_id=ar.participant_id and ad.approval_request_id=ar.approval_request_id
          join control.principal checker on checker.participant_id=ar.participant_id
            and checker.principal_id=ad.approver_principal_id and checker.state='ACTIVE'
            and checker.authority_epoch=ad.approver_principal_epoch
          join control.credential credential on credential.participant_id=ar.participant_id
            and credential.credential_id=ad.signer_credential_id
            and credential.principal_id=checker.principal_id and credential.kind='WEBAUTHN'
            and credential.state='ACTIVE' and credential.valid_from<=clock_timestamp()
            and (credential.valid_until is null or credential.valid_until>clock_timestamp())
          join control.assignment checker_assignment on checker_assignment.participant_id=ar.participant_id
            and checker_assignment.assignment_id=ad.approver_assignment_id
            and checker_assignment.principal_id=checker.principal_id and checker_assignment.state='ACTIVE'
            and checker_assignment.valid_during @> clock_timestamp()
          join control.authority_envelope checker_envelope on checker_envelope.participant_id=ar.participant_id
            and checker_envelope.authority_envelope_id=ad.approver_authority_envelope_id
            and checker_envelope.authority_envelope_id=checker_assignment.authority_envelope_id
            and checker_envelope.authority_epoch=ad.approver_envelope_epoch
            and checker_envelope.state='ACTIVE'
         where ar.participant_id=$1::uuid and ar.privacy_domain_id=$2::uuid
           and ar.approval_request_id=$3::uuid
           and ar.action_intent_id=$4 and ar.subject_digest=$5 and ar.maker_principal_id=$6::uuid
           and ar.subject_version=$9 and ar.subject_type='CONFIGURATION_CANDIDATE'
           and ar.state='APPROVED' and ar.expires_at>clock_timestamp()
           and ad.decision='APPROVE' and ad.approver_principal_id=$7::uuid
           and ad.approver_principal_id<>ar.maker_principal_id
           and ad.aggregate_version=$9 and ad.candidate_digest=$5
           and ad.signer_credential_id=$10::uuid for update of ar,candidate`,
        [
          actor.participantId,
          proof.privacyDomainId,
          proof.approvalRequestId,
          actionIntentId,
          candidateDigest,
          actor.principalId,
          proof.checkerPrincipalId,
          aggregateId,
          proof.aggregateVersion,
          proof.signerCredentialId,
          catalogOperationId,
          proof.idempotencyKey,
        ],
      );
      const checked = one(approval.rows, 'PC-IDENTITY-1005');
      if (
        !checked.evidence_cbor.equals(proof.evidenceCbor) ||
        !checked.cose_sign1.equals(proof.coseSign1) ||
        !createHash('sha256')
          .update(checked.public_key_spki_der)
          .digest()
          .equals(checked.public_key_digest) ||
        !(await verifyStoredStepUpEvidence(
          client,
          {
            participantId: actor.participantId,
            privacyDomainId: proof.privacyDomainId,
            principalId: proof.checkerPrincipalId,
            credentialId: proof.signerCredentialId,
            approvalRequestId: proof.approvalRequestId,
            credentialPublicKey: checked.public_key_spki_der,
            evidenceCbor: proof.evidenceCbor,
            coseSign1: proof.coseSign1,
          },
          this.identityRuntimeVerifier,
        ))
      ) {
        throw new ParticipantKernelError('PC-IDENTITY-1005');
      }
      if (
        proof.mfaChallengeId === undefined ||
        proof.webauthnSessionId === undefined ||
        proof.webauthnSignerCredentialId === undefined ||
        proof.webauthnAssertionBindingDigest === undefined ||
        proof.webauthnEvidenceCbor === undefined ||
        proof.webauthnEvidenceDigest === undefined ||
        proof.webauthnCoseSign1 === undefined ||
        !createHash('sha256')
          .update(proof.webauthnEvidenceCbor)
          .digest()
          .equals(proof.webauthnEvidenceDigest)
      ) {
        throw new ParticipantKernelError('PC-IDENTITY-1005');
      }
      const challenge = await client.query<{
        mfa_challenge_id: string;
        public_key_digest: Buffer;
        public_key_spki_der: Buffer;
      }>(
        `select challenge.mfa_challenge_id,step_up_credential.public_key_digest,
                step_up_credential.public_key_spki_der
           from control.mfa_challenge challenge
           join control.mutation_evidence verification
             on verification.participant_id=challenge.participant_id
            and verification.privacy_domain_id=$12
            and verification.principal_id=challenge.principal_id
            and verification.mfa_challenge_id=challenge.mfa_challenge_id
            and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
            and verification.aggregate_type='webauthn-verification'
            and verification.aggregate_id=challenge.session_id
            and verification.webauthn_assertion_binding_digest=$8
            and verification.evidence_cbor=$9 and verification.evidence_digest=$10
            and verification.cose_sign1=$11
           join control.idempotency_record verification_idempotency
             on verification_idempotency.participant_id=verification.participant_id
            and verification_idempotency.privacy_domain_id=verification.privacy_domain_id
            and verification_idempotency.principal_id=verification.principal_id
            and verification_idempotency.operation_id=verification.operation_id
            and verification_idempotency.catalog_operation_id=verification.catalog_operation_id
            and verification_idempotency.input_digest=verification.candidate_digest
            and verification_idempotency.webauthn_assertion_binding_digest=$8
            and verification_idempotency.terminal_state='COMMITTED'
           join control.outbox_event verification_event
             on verification_event.participant_id=verification.participant_id
            and verification_event.privacy_domain_id=verification.privacy_domain_id
            and verification_event.aggregate_type=verification.aggregate_type
            and verification_event.aggregate_id=verification.aggregate_id
            and verification_event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
            and verification_event.webauthn_assertion_binding_digest=$8
            and verification_event.payload_cbor=verification.evidence_cbor
            and verification_event.payload_digest=verification.evidence_digest
            and verification_event.cose_sign1=verification.cose_sign1
           join control.credential step_up_credential
             on step_up_credential.participant_id=challenge.participant_id
            and step_up_credential.credential_id=$13
            and step_up_credential.principal_id=challenge.principal_id
            and step_up_credential.kind='WEBAUTHN' and step_up_credential.state='ACTIVE'
            and step_up_credential.valid_from<=clock_timestamp()
            and (step_up_credential.valid_until is null
                 or step_up_credential.valid_until>clock_timestamp())
          where challenge.participant_id=$1 and challenge.mfa_challenge_id=$2
            and challenge.session_id=$3 and challenge.principal_id=$4
            and challenge.action_intent_id=$5 and challenge.resource_digest=$6
            and challenge.consumed_at>clock_timestamp()-interval '5 minutes'
            and challenge.expires_at>clock_timestamp()
            and (challenge.used_at is null or challenge.used_operation_id=$7)
            and not exists (
              select 1 from control.mutation_evidence consumed
               where consumed.participant_id=challenge.participant_id
                 and consumed.mfa_challenge_id=challenge.mfa_challenge_id
                 and consumed.catalog_operation_id<>'ID-OP-WEBAUTHN-VERIFY'
                 and consumed.operation_id<>$7
            ) for update of challenge`,
        [
          actor.participantId,
          proof.mfaChallengeId,
          proof.webauthnSessionId,
          actor.principalId,
          actionIntentId,
          candidateDigest,
          idempotency.operationId,
          proof.webauthnAssertionBindingDigest,
          proof.webauthnEvidenceCbor,
          proof.webauthnEvidenceDigest,
          proof.webauthnCoseSign1,
          proof.privacyDomainId,
          proof.webauthnSignerCredentialId,
        ],
      );
      const stepUp = one(challenge.rows, 'PC-IDENTITY-1004');
      if (
        !createHash('sha256')
          .update(stepUp.public_key_spki_der)
          .digest()
          .equals(stepUp.public_key_digest) ||
        !(await verifyStoredStepUpEvidence(
          client,
          {
            participantId: actor.participantId,
            privacyDomainId: proof.privacyDomainId,
            principalId: actor.principalId,
            credentialId: proof.webauthnSignerCredentialId,
            mfaChallengeId: proof.mfaChallengeId,
            actionIntentId,
            candidateDigest,
            credentialPublicKey: stepUp.public_key_spki_der,
            evidenceCbor: proof.webauthnEvidenceCbor,
            coseSign1: proof.webauthnCoseSign1,
          },
          this.identityRuntimeVerifier,
        ))
      ) {
        throw new ParticipantKernelError('PC-IDENTITY-1005');
      }
      const challengeId = stepUp.mfa_challenge_id;
      if (idempotency.replay) return idempotency.result as T;
      let bootstrapAuthority: BootstrapIssuanceAuthority | undefined;
      if (catalogOperationId === 'ID-OP-PARTICIPANT-CREATE') {
        if (
          !actor.platform ||
          typeof request !== 'object' ||
          request === null ||
          !('firstAdministrator' in request)
        )
          throw new ParticipantKernelError('PC-IDENTITY-1005');
        const proposal = firstAdministratorProposal.parse(request.firstAdministrator);
        bootstrapAuthority = await captureBootstrapAuthority(client, actor.participantId, {
          operationId,
          approvalRequestId: proof.approvalRequestId,
          candidateDigest: proof.candidateDigest,
          adminActions: proposal.actionIntentIds,
          makerSignerCredentialId: proof.webauthnSignerCredentialId,
          checkerSignerCredentialId: proof.signerCredentialId,
          approvalAuthorities: dependencies.authorities,
          makerAuthority: {
            principalId: actor.principalId,
            sessionId: actor.sessionId!,
            sessionEpoch: session.sessionEpoch,
            participantEpoch: actor.boundParticipantEpoch,
            principalEpoch: actor.boundPrincipalEpoch,
            assignmentId: authority.assignment_id,
            assignmentRowVersion: authority.assignment_row_version,
            authorityEnvelopeId: authority.authority_envelope_id,
            authorityEpoch: authority.authority_epoch,
            delegationEpoch: session.delegationEpoch,
            privacyDomainId: proof.privacyDomainId,
            actionIntentId,
            resourceId: aggregateId,
          },
        });
      }
      if (targetParticipantId !== actor.participantId) {
        if (!actor.platform) throw new ParticipantKernelError('PC-IDENTITY-1000');
        await client.query(
          `select openpc.set_request_context('PLATFORM',$1,null,$2,$3,false),openpc.assert_request_context(false)`,
          [targetParticipantId, operationId, actionIntentId],
        );
      }
      const result = await operation(
        client,
        operationId,
        authority.authority_envelope_id,
        bootstrapAuthority,
        envelopePlatform,
        typedProposal,
      );
      const successState = await this.currentCatalogState(
        client,
        targetParticipantId,
        aggregateType,
        aggregateId,
      );
      if (
        successState === undefined ||
        !(operationContract.successStates as readonly string[]).includes(successState)
      ) {
        throw new ParticipantKernelError('PC-IDENTITY-1009');
      }
      const resultAggregateVersion = await this.currentAggregateVersion(
        client,
        targetParticipantId,
        aggregateType,
        aggregateId,
      );
      if (targetParticipantId !== actor.participantId) {
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
          [actor.participantId, proof.privacyDomainId, operationId, actionIntentId],
        );
      }
      await client.query(
        `update control.mfa_challenge set used_at=clock_timestamp(),used_operation_id=$2
          where mfa_challenge_id=$1 and used_at is null`,
        [challengeId, operationId],
      );
      const consumedCandidate = await client.query(
        `update control.mutation_candidate candidate
            set state='CONSUMED',consumed_operation_id=$4,updated_at=clock_timestamp()
           from control.approval_request approval
          where approval.participant_id=$1 and approval.privacy_domain_id=$2
            and approval.approval_request_id=$3 and approval.state='APPROVED'
            and approval.subject_type='CONFIGURATION_CANDIDATE'
            and candidate.participant_id=approval.participant_id
            and candidate.privacy_domain_id=approval.privacy_domain_id
            and candidate.mutation_candidate_id=approval.subject_id
            and candidate.state='APPROVED'
            and ${currentMutationCandidateSql('candidate')}`,
        [actor.participantId, proof.privacyDomainId, proof.approvalRequestId, operationId],
      );
      if (consumedCandidate.rowCount !== 1) {
        throw new ParticipantKernelError('PC-IDENTITY-1005');
      }
      const sequence = await client.query<{ last_sequence: string }>(
        `insert into control.outbox_aggregate_head
          (participant_id,aggregate_type,aggregate_id,last_sequence)
          values ($1,$2,$3,1)
          on conflict (participant_id,aggregate_type,aggregate_id) do update
            set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp()
          returning last_sequence::text`,
        [actor.participantId, aggregateType, aggregateId],
      );
      await client.query(
        `insert into control.mutation_evidence
          (participant_id,privacy_domain_id,operation_id,principal_id,checker_principal_id,action_intent_id,catalog_operation_id,
           aggregate_type,aggregate_id,aggregate_version,candidate_digest,approval_request_id,mfa_challenge_id,
           bound_participant_epoch,bound_principal_epoch,bound_authority_envelope_id,bound_envelope_epoch,
           bound_assignment_id,signer_credential_id,webauthn_assertion_binding_digest,
           evidence_cbor,evidence_digest,cose_sign1)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
        [
          actor.participantId,
          proof.privacyDomainId,
          operationId,
          actor.principalId,
          proof.checkerPrincipalId,
          actionIntentId,
          catalogOperationId,
          aggregateType,
          aggregateId,
          aggregateVersion,
          candidateDigest,
          proof.approvalRequestId,
          challengeId,
          actor.boundParticipantEpoch,
          actor.boundPrincipalEpoch,
          authority.authority_envelope_id,
          authority.authority_epoch,
          authority.assignment_id,
          proof.signerCredentialId,
          proof.webauthnAssertionBindingDigest,
          proof.evidenceCbor,
          proof.evidenceDigest,
          proof.coseSign1,
        ],
      );
      await client.query(
        `insert into control.outbox_event
          (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
           aggregate_sequence,payload_cbor,payload_digest,cose_sign1,
           webauthn_assertion_binding_digest,occurred_at)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())`,
        [
          actor.participantId,
          proof.privacyDomainId,
          uuidV7(),
          `openpc.${aggregateType}.mutation.committed.v1`,
          aggregateType,
          aggregateId,
          one(sequence.rows).last_sequence,
          proof.evidenceCbor,
          proof.evidenceDigest,
          proof.coseSign1,
          proof.webauthnAssertionBindingDigest,
        ],
      );
      await this.finishIdempotency(client, operationId, result, resultAggregateVersion);
      return result;
    });
  }

  private async currentAggregateVersion(
    client: PoolClient,
    participantId: string,
    aggregateType: string,
    aggregateId: string,
  ): Promise<string> {
    if (aggregateType === 'platform-scope-replacement')
      return (
        (await readPlatformScopeReplacementCatalog(client, participantId, aggregateId))?.revision ??
        '0'
      );
    if (aggregateType === 'participant') {
      const row = await client.query<{ row_version: string }>(
        `select row_version::text from control.participant where participant_id=$1 for update`,
        [aggregateId],
      );
      return row.rows[0]?.row_version ?? '0';
    }
    const lookup: Readonly<Record<string, { readonly table: string; readonly id: string }>> = {
      'authority-envelope': { table: 'authority_envelope', id: 'authority_envelope_id' },
      'assignment': { table: 'assignment', id: 'assignment_id' },
      'delegation': { table: 'delegation', id: 'delegation_id' },
      'role': { table: 'authority_role', id: 'authority_role_id' },
      'group': { table: 'authority_group', id: 'authority_group_id' },
    };
    const target = lookup[aggregateType];
    if (target === undefined) throw new ParticipantKernelError('PC-IDENTITY-1004');
    const existing = await client.query<{ row_version: string }>(
      `select row_version::text from control.${target.table}
        where participant_id=$1 and ${target.id}=$2 for update`,
      [participantId, aggregateId],
    );
    return existing.rows[0]?.row_version ?? '0';
  }

  private async currentCatalogState(
    client: PoolClient,
    participantId: string,
    aggregateType: string,
    aggregateId: string,
  ): Promise<string | undefined> {
    if (aggregateType === 'platform-scope-replacement')
      return (await readPlatformScopeReplacementCatalog(client, participantId, aggregateId))?.state;
    if (aggregateType === 'participant') {
      const row = await client.query<{ state: string }>(
        `select state::text from control.participant where participant_id=$1 for update`,
        [aggregateId],
      );
      return row.rows[0]?.state;
    }
    const lookup: Readonly<Record<string, { readonly table: string; readonly id: string }>> = {
      'authority-envelope': { table: 'authority_envelope', id: 'authority_envelope_id' },
      'assignment': { table: 'assignment', id: 'assignment_id' },
      'delegation': { table: 'delegation', id: 'delegation_id' },
      'role': { table: 'authority_role', id: 'authority_role_id' },
      'group': { table: 'authority_group', id: 'authority_group_id' },
    };
    const target = lookup[aggregateType];
    if (target === undefined) throw new ParticipantKernelError('PC-IDENTITY-1009');
    const row = await client.query<{ state: string }>(
      `select state::text from control.${target.table}
        where participant_id=$1 and ${target.id}=$2 for update`,
      [participantId, aggregateId],
    );
    return row.rows[0]?.state;
  }

  private owner(actor: AuthenticatedActor, participantId: string) {
    if (!actor.platform && actor.participantId !== participantId)
      throw new ParticipantKernelError('PC-IDENTITY-1000');
  }

  private async principal(client: PoolClient, participantId: string, principalId: string) {
    const result = await client.query(
      `select 1 from control.principal where participant_id=$1 and principal_id=$2 and state='ACTIVE'`,
      [participantId, principalId],
    );
    one(result.rows, 'PC-IDENTITY-1000');
  }

  private async participantEpoch(client: PoolClient, participantId: string) {
    const result = await client.query<{ authority_epoch: string }>(
      `select authority_epoch::text from control.participant where participant_id=$1 and state='ACTIVE' for update`,
      [participantId],
    );
    return one(result.rows, 'PC-IDENTITY-1001').authority_epoch;
  }

  private async beginIdempotency<T>(
    client: PoolClient,
    actor: AuthenticatedActor,
    participantId: string,
    action: string,
    catalogOperationId: string,
    key: string,
    request: unknown,
    webauthnAssertionBindingDigest: Buffer,
    expectedAggregateVersion: string,
    operationId: string,
  ): Promise<MutationIdempotency<T>> {
    const input = stableDigest(request);
    const inserted = await client.query<{ operation_id: string }>(
      `insert into control.idempotency_record
       (participant_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,operation_id,
        input_digest,webauthn_assertion_binding_digest,expected_aggregate_version,created_at,
        expires_at,privacy_domain_id)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp(),clock_timestamp()+interval '24 hours',$10)
       on conflict (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key)
       do update set operation_id=excluded.operation_id,input_digest=excluded.input_digest,
         webauthn_assertion_binding_digest=excluded.webauthn_assertion_binding_digest,
         expected_aggregate_version=excluded.expected_aggregate_version,result_digest=null,
         result_payload=null,result_aggregate_version=null,terminal_state=null,
         created_at=clock_timestamp(),expires_at=excluded.expires_at
       where control.idempotency_record.expires_at<=clock_timestamp()
       returning operation_id`,
      [
        participantId,
        actor.principalId,
        action,
        catalogOperationId,
        key,
        operationId,
        input,
        webauthnAssertionBindingDigest,
        expectedAggregateVersion,
        actor.mutationAuthorization!.privacyDomainId,
      ],
    );
    if (inserted.rows[0]?.operation_id === operationId) {
      return {
        expectedAggregateVersion,
        operationId,
        replay: false,
        result: undefined,
        resultAggregateVersion: undefined,
      };
    }
    const result = await client.query<{
      expected_aggregate_version: string;
      operation_id: string;
      input_digest: Buffer;
      result_aggregate_version: string | null;
      result_payload: T | null;
      terminal_state: string | null;
      webauthn_assertion_binding_digest: Buffer | null;
    }>(
      `select operation_id,input_digest,expected_aggregate_version::text,
              result_aggregate_version::text,result_payload,terminal_state,
              webauthn_assertion_binding_digest
         from control.idempotency_record
       where participant_id=$1 and principal_id=$2 and action_intent_id=$3
         and catalog_operation_id=$4 and idempotency_key=$5 and privacy_domain_id=$6 for update`,
      [
        participantId,
        actor.principalId,
        action,
        catalogOperationId,
        key,
        actor.mutationAuthorization!.privacyDomainId,
      ],
    );
    const row = one(result.rows, 'PC-IDENTITY-1009');
    if (
      !row.input_digest.equals(input) ||
      row.webauthn_assertion_binding_digest === null ||
      !row.webauthn_assertion_binding_digest.equals(webauthnAssertionBindingDigest) ||
      row.expected_aggregate_version !== expectedAggregateVersion ||
      row.terminal_state !== 'COMMITTED' ||
      row.result_aggregate_version === null
    )
      throw new ParticipantKernelError('PC-IDENTITY-1009');
    return {
      expectedAggregateVersion: row.expected_aggregate_version,
      operationId: row.operation_id,
      replay: true,
      result: row.result_payload ?? undefined,
      resultAggregateVersion: row.result_aggregate_version,
    };
  }

  private async finishIdempotency(
    client: PoolClient,
    operationId: string,
    result: unknown,
    resultAggregateVersion: string,
  ) {
    await client.query(
      `update control.idempotency_record set result_digest=$2,result_payload=$3,
       result_aggregate_version=$4,terminal_state='COMMITTED' where operation_id=$1`,
      [operationId, stableDigest(result), result, resultAggregateVersion],
    );
  }

  private async parent(
    client: PoolClient,
    participantId: string,
    parentId: string,
  ): Promise<Assignment | Delegation | undefined> {
    const assignment = await client.query<AssignmentRow>(
      `select *,lower(valid_during) valid_from,upper(valid_during) valid_until from control.assignment where participant_id=$1 and assignment_id=$2 and state='ACTIVE'`,
      [participantId, parentId],
    );
    if (assignment.rowCount === 1) return assignmentFromRow(one(assignment.rows));
    const delegation = await client.query<DelegationRow>(
      `select *,lower(valid_during) valid_from,upper(valid_during) valid_until from control.delegation where participant_id=$1 and delegation_id=$2 and state='ACTIVE'`,
      [participantId, parentId],
    );
    return delegation.rowCount === 1 ? delegationFromRow(one(delegation.rows)) : undefined;
  }
}

interface ParticipantRow {
  participant_id: string;
  display_name: string;
  state: ParticipantRecord['state'];
  authority_epoch: string;
  row_version: string;
}
function one<T>(rows: readonly T[], code = 'PC-IDENTITY-1000'): T {
  const row = rows[0];
  if (rows.length !== 1 || row === undefined) throw new ParticipantKernelError(code);
  return row;
}
function participantFromRow(row: ParticipantRow): ParticipantRecord {
  return {
    participantId: row.participant_id,
    displayName: row.display_name,
    state: row.state,
    authorityEpoch: row.authority_epoch,
    rowVersion: row.row_version,
  };
}
function digest(value: string): Buffer {
  return Buffer.from(
    value.startsWith('sha256:') ? value.slice(7) : createHash('sha256').update(value).digest('hex'),
    'hex',
  );
}
function stableDigest(value: unknown): Buffer {
  return createHash('sha256').update(stableJson(value)).digest();
}
function stableJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(',')}}`;
}
function subsetOf(child: PermissionSet, parent: PermissionSet): boolean {
  const subset = (a: readonly string[], b: readonly string[]) =>
    a.every((value) => b.includes(value));
  const resourceSubset =
    parent.resourceIds.includes('*') ||
    (!child.resourceIds.includes('*') && subset(child.resourceIds, parent.resourceIds));
  return (
    child.participantId === parent.participantId &&
    subset(child.privacyDomainIds, parent.privacyDomainIds) &&
    subset(child.actionIntentIds, parent.actionIntentIds) &&
    subset(child.capabilityIds ?? [], parent.capabilityIds ?? []) &&
    resourceSubset &&
    subset(child.riskClasses, parent.riskClasses) &&
    child.validFrom >= parent.validFrom &&
    (parent.validUntil === null ||
      (child.validUntil !== null && child.validUntil <= parent.validUntil)) &&
    (!parent.makerCheckerRequired || child.makerCheckerRequired) &&
    (!parent.stepUpRequired || child.stepUpRequired) &&
    child.onwardDelegationDepth <= parent.onwardDelegationDepth
  );
}
