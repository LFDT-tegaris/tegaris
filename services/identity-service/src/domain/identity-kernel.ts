import { localQaDurationMultiplier } from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';
import {
  prepareDiscoveryCertificateIssuance,
  finishDiscoveryCertificateIssuerAttempt,
  readDiscoveryCertificateObservation,
  completeDiscoveryCertificateRecoveryMutation,
  type DiscoveryCertificatePreparation,
} from '../db/discovery-certificate-issuance-store.js';
import {
  defaultDiscoveryCertificateIssuancePolicy,
  type DiscoveryCertificateIssuancePolicy,
} from './discovery-certificate-issuance-policy.js';
import {
  applyObservedWorkloadCredentialEffect,
  type WorkloadRotationEffectInput,
  rotateWorkloadCredentialEffect,
} from './workload-rotation-effect.js';
import {
  discoveryCertificateRecoveryContextEligible,
  assertPlatformRecoveryCommitPurpose,
} from '../db/platform-recovery-commit-purpose.js';
import { currentPlatformEnvelopeSql } from '../db/current-platform-envelope.js';
import {
  postReviewIdentityEnvelopeRecovery,
  lockIdentityEnvelopeRecoveryReviewVersion,
} from '../db/identity-envelope-recovery-post-review.js';
import { resolveIdentityEnvelopeRecoveryRotationOperation } from '../db/identity-envelope-recovery-rotation.js';
import { resolveIdentityEnvelopeRecoveryRotationStep } from '../db/identity-envelope-recovery-rotation-queue.js';
import {
  executePlatformRecoveryCommand,
  executeDiscoveryCertificateRecoveryCommand,
  type DiscoveryCertificateRecoveryCommand,
  type PlatformRecoveryCommand,
} from '../db/platform-recovery-command.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';
import { readDiscoveryCertificateRecoveryReceipt } from '../db/platform-recovery-readback.js';
import { consumeWorkloadTransportProof, type PresentedCertificate } from './workload-transport.js';
import {
  runBootstrapCommand,
  type BootstrapCommand,
  type BootstrapSessionScope,
} from './bootstrap-acceptance.js';
import type { WebAuthnRegistrationAdapter } from './webauthn-registration.js';
import {
  appendAuthenticationOccurrence,
  appendWorkloadAuthenticationOccurrence,
  oidcAuthenticationProofDigest,
} from '../db/authentication-occurrence-store.js';
import {
  persistOidcAuthorization,
  matchesOidcCustody,
  oidcExchangeFromRow,
  type OidcClientConfiguration,
  type OidcAuthorizationStart,
  type OidcTransactionCustody,
  type OidcExchangeContext,
  type OidcRow,
} from './oidc-authorization.js';
export type {
  OidcClientConfiguration,
  OidcAuthorization,
  OidcAuthorizationStart,
  OidcTransactionCustody,
  OidcExchangeContext,
} from './oidc-authorization.js';
import {
  readWorkloadCertificate,
  resolveWorkloadProposal,
  readWorkloadProposal,
} from './workload-lifecycle-readback.js';
import {
  createWalletBinding,
  revokeWalletBinding,
  readWalletBinding,
  type WalletBindingCreation,
} from './wallet-binding.js';
import {
  readWebAuthnCredentials,
  resolveWebAuthnProposal,
  readWebAuthnProposal,
} from './webauthn-lifecycle-readback.js';
import {
  verifyStoredStepUpEvidence,
  authenticateHistoricalRuntimeStepUpEvidence,
} from '../db/verified-step-up-evidence.js';
import { readWebAuthnEnrollment } from './webauthn-enrollment-readback.js';
import {
  resolveRecoveryProposal,
  readRecoveryProposal,
  type RecoveryProposalBinding,
} from './recovery-proposal.js';
import {
  assertRecoveryOidcFreshness,
  fenceInitialEnrollment,
  initialEnrollmentRecovery,
  completeRecoveryEnrollment,
} from './recovery-reenrollment.js';
import {
  identityStepUpSigner,
  selectCommittedIdentityStepUp,
  type CommittedIdentityStepUpInput,
} from '../db/identity-step-up-signer.js';
import {
  qualifyRecoveryPrincipal,
  revokeRecoveryPrincipal,
  readRecoveryPrincipal,
  assertQualifiedRecoveryPrincipal,
  type RecoveryQualification,
} from './recovery-principal.js';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import {
  identityCredentialCoseContext,
  verifyCoseSign1Es256,
  verifyEs256P1363,
} from '@openpc/security-kernel';
import type { Pool, PoolClient } from 'pg';
import {
  createInitialHumanMembership,
  resolveSubjectMembership,
  readIdentitySubject,
} from './human-identity.js';

import { identityGovernanceOperations } from '../contracts/principal-operations.js';
import { resolveInvitationProposal, readInvitationProposal } from './invitation-proposals.js';
import {
  invitationAction,
  invitationOperationIds,
  type InvitationCandidate,
} from '../contracts/invitation-operations.js';
import {
  readParticipantInvitation,
  mutateParticipantInvitation,
} from './participant-invitations.js';
import { captureInvitationAuthority } from './invitation-authority.js';
import {
  beginInvitationProof,
  invitationProofContext,
  completeInvitationProof,
  type InvitationScope,
  type InvitationProofRequest,
} from './invitation-redemption.js';
import type { VerifiedOidcIdentity } from './trust-adapter.js';
import {
  directoryConnectorOperationIds,
  type DirectoryConnectorCandidate,
} from '../contracts/directory-operations.js';
import {
  readDirectoryConnector,
  mutateDirectoryConnector,
  resolveDirectoryMember,
  readDirectoryMember,
} from './directory-connectors.js';
import { resolveDirectoryProposal, readDirectoryProposal } from './directory-proposals.js';
import {
  directoryReconciliationContext,
  directoryReconciliationFence,
  reconcileDirectoryMembers,
} from './directory-reconciliation.js';
import {
  directoryCandidateOperation,
  directoryCandidateAction,
  type DirectoryReconciliationCandidate,
} from '../contracts/directory-operations.js';
import type { RegisteredDirectoryProfile } from './directory-profiles.js';
import { IdentityKernelError } from './identity-errors.js';
export { IdentityKernelError } from './identity-errors.js';
import {
  activatePrincipal,
  readPrincipal,
  readPrincipalProposal,
  resolvePrincipalProposal,
  type PrincipalRecord,
  type PrincipalReadback,
} from './principal-lifecycle.js';
export type { PrincipalRecord } from './principal-lifecycle.js';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import {
  createGovernedInitialEnrollmentAssertion,
  selectGovernedInitialEnrollmentAccount,
  type GovernedInitialEnrollmentProfile,
  type GovernedInitialEnrollmentEvidence,
} from './governed-initial-enrollment.js';
import {
  readGovernedInitialEnrollmentResult,
  saveGovernedInitialEnrollmentResult,
} from '../db/governed-initial-enrollment-result.js';
import { readGovernedInitialEnrollmentSource } from '../db/governed-initial-enrollment-source.js';
import { runScopedTransaction, ScopedTransactionSecurityError } from '../db/scoped-transaction.js';
import { approvalAuthorityDependencies } from '../db/approval-authority-fence.js';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
  lockAuthorityFence,
  type AuthorityFence,
  type BoundAuthority,
  type MutationAuthorityContext,
} from '../db/authority-fence.js';
import { principalInvalidationFence } from '../db/principal-invalidation-fence.js';
import { saveHardwareAuthenticator } from '../db/hardware-authenticator-store.js';
import type { HardwareAttestation } from './hardware-attestation.js';
import { membershipRemovalFence, removeMembership } from './membership-removal.js';
import { readRecovery } from './recovery-readback.js';
import {
  currentRecoveryEpochs,
  captureCustodianAuthority,
  recoveryPrincipalIds,
  recoveryAuthorityFence,
  assertRecoveryAuthority,
  type RecoveryAuthorityRow,
} from './recovery-authority.js';
import {
  principalCatalogueCandidates,
  type PrincipalCatalogueQuery,
} from './principal-catalogue.js';
import { problemFor } from '../errors.js';
import {
  createIdentityRuntimeAuthorizationAssertion,
  verifyIdentityRuntimeAuthorizationAssertion,
  type IdentityRuntimeAuthorizationContext,
} from './identity-runtime-authorization.js';
import {
  verifiedWebAuthnAssertionDigest,
  type VerifiedWebAuthnAssertion,
} from './trust-adapter.js';
import {
  stepUpAuthorizationCandidate,
  type StepUpAuthorizationCandidate,
} from './step-up-authorization.js';
import type { VerifiedWebAuthnRegistration } from './webauthn-registration.js';
import {
  WORKLOAD_CERTIFICATE_MAX_LIFETIME_MS as WORKLOAD_MAX_LIFETIME_MS,
  type WorkloadCertificateRequest,
  type WorkloadCredentialIssuer,
  type IssuedWorkloadCertificate,
} from './workload-credential-issuer.js';
import type {
  RuntimeSnapshotPublisher,
  RuntimePublicationContext,
  PublishedWorkloadRuntime,
} from './runtime-snapshot-publisher.js';

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const ABSOLUTE_TIMEOUT_MS = 12 * 60 * 60 * 1000;
const OIDC_TRANSACTION_MS = 5 * 60 * 1000;
const STEP_UP_MAX_AGE_MS = 5 * 60 * 1000;
const RECOVERY_LEASE_MS = 15 * 60 * 1000;
const WORKLOAD_ROTATION_MS = 12 * 60 * 60 * 1000;
const SESSION_MUTATION_REPLAY_GRACE_MS = 60 * 1000;
const ACTION_PATTERN = /^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u;
const CATALOG_OPERATION_PATTERN = /^ID-OP-[A-Z0-9-]+$/u;
const UUID_V7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export interface OidcCallback {
  readonly state: string;
  readonly nonce: string;
  readonly issuer: string;
  readonly subject: string;
  readonly audience: string;
  readonly authorizedParty: string;
  readonly principalId?: string;
  readonly participantId: string;
  readonly issuedAt: Date;
  readonly authenticatedAt?: Date;
  readonly expiresAt: Date;
}

export interface SessionSnapshot {
  readonly sessionId: string;
  readonly sessionToken: string;
  readonly principalId: string;
  readonly participantId: string;
  readonly contextMode: 'PLATFORM' | 'PARTICIPANT';
  readonly privacyDomainId?: string;
  readonly contextEpoch: string;
  readonly participantEpoch: string;
  readonly authorityEpoch: string;
  readonly sessionEpoch: string;
  readonly refreshFamilyId: string;
  readonly state:
    'AUTHENTICATING' | 'ACTIVE' | 'STEP_UP_REQUIRED' | 'REVOKED' | 'EXPIRED' | 'COMPROMISED';
  readonly issuedAt: Date;
  readonly lastSeenAt: Date;
  readonly idleExpiresAt: Date;
  readonly absoluteExpiresAt: Date;
  readonly stepUpVerifiedAt?: Date;
}

export interface StepUpProof {
  readonly sessionToken: string;
  readonly actionIntentId: string;
  readonly resourceDigest: string;
  readonly resourceId?: string;
  readonly challenge: string;
  readonly rpIdHash: string;
  readonly verifiedAssertion: VerifiedWebAuthnAssertion;
}

export interface StepUpChallenge {
  readonly durationProfile?: 'LOCAL_QA_10X';
  readonly expiresAt?: string;
  readonly challenge: string;
  readonly credentialIds: readonly string[];
}

export interface AuthenticatedIdentityActor {
  readonly principalId: string;
  readonly participantId: string;
  readonly sessionToken: string;
  readonly mutationAuthorization?: IdentityMutationAuthorization;
  readonly platform: boolean;
}

interface IdentityMutationAuthorizationCommon {
  readonly authorized: true;
  readonly idempotencyKey: string;
  readonly candidateDigest: string;
  readonly privacyDomainId: string;
  readonly approvalRequestId?: string;
  readonly checkerPrincipalId?: string;
  readonly aggregateVersion: string;
  readonly evidenceCbor: Buffer;
  readonly evidenceDigest: Buffer;
  readonly coseSign1: Buffer;
  readonly webauthnAssertionBindingDigest?: Buffer;
}

export type IdentityMutationAuthorization = IdentityMutationAuthorizationCommon &
  (
    | {
        readonly evidenceKind: 'IDENTITY_RUNTIME';
        readonly signerKeyDigest: Buffer;
      }
    | {
        readonly evidenceKind: 'USER_WEBAUTHN';
        readonly signerCredentialId: string;
      }
  );

export interface IdentityRuntimeAssertionVerifier {
  verifyCanonicalAssertion(
    evidenceCbor: Buffer,
    coseSign1: Buffer,
  ): Promise<{ readonly signerKeyDigest: Buffer } | undefined>;
}

export interface IdentityRuntimeEvidenceSigner extends IdentityRuntimeAssertionVerifier {
  signCanonicalAssertion(evidenceCbor: Buffer): Promise<{
    readonly coseSign1: Buffer;
    readonly evidenceCbor: Buffer;
    readonly evidenceDigest: Buffer;
    readonly signerKeyDigest: Buffer;
  }>;
}

export interface InitialWebAuthnEnrollment {
  readonly enrollmentId: string;
  readonly challenge: string;
  readonly rpId: string;
  readonly origin: string;
  readonly principalId: string;
  readonly displayLabel: string;
  readonly excludedCredentialIds: readonly string[];
  readonly expiresAt: Date;
}

export interface InitialWebAuthnEnrollmentContext {
  readonly expectedChallengeDigest: Buffer;
  readonly expectedOrigin: string;
  readonly expectedRpId: string;
}

export interface ReplacementWebAuthnEnrollment extends InitialWebAuthnEnrollment {
  readonly replacedCredentialId: string;
}

export interface ReplacementWebAuthnEnrollmentContext extends InitialWebAuthnEnrollmentContext {
  readonly replacedCredentialId: string;
}

export interface WebAuthnReplacementCandidate {
  readonly enrollmentId: string;
  readonly replacedCredentialId: string;
  readonly externalCredentialId: string;
  readonly publicKeyDigest: string;
  readonly publicKeySpkiDer: string;
  readonly signCount: string;
  readonly attestationDigest: string;
  readonly hardwareAttestation?: HardwareAttestation;
}

export interface RegisteredWebAuthnCredential {
  readonly credentialId: string;
  readonly externalCredentialId: string;
  readonly credentialEpoch: string;
  readonly state: 'ACTIVE';
}

export interface SessionContextSelection {
  readonly participantId: string;
  readonly privacyDomainId: string;
}

export interface WorkloadRecord {
  readonly credentialId: string;
  readonly principalId: string;
  readonly participantId: string;
  readonly workloadId: string;
  readonly state: 'ISSUED' | 'ACTIVE' | 'ROTATING' | 'REVOKED' | 'EXPIRED';
  readonly workloadEpoch: string;
  readonly keyId: string;
  readonly uriSan: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly issuer?: string;
  readonly certificateFingerprint?: Buffer;
  readonly publicKeySpkiDer?: Buffer;
}

export interface WorkloadCredentialInput {
  readonly participantId: string;
  readonly workloadId: string;
  readonly participantEpoch: string;
  readonly workloadEpoch: string;
  readonly keyId: string;
  readonly certificateFingerprint: Buffer;
  readonly uriSan: string;
  readonly tlsVersion: 'TLS1.2' | 'TLS1.3';
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly issuerTrusted: boolean;
  readonly keyTrusted: boolean;
  readonly revoked: boolean;
}

export interface AuthenticatedWorkloadIdentity {
  readonly credentialId: string;
  readonly principalId: string;
  readonly participantId: string;
  readonly workloadId: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly workloadEpoch: string;
  readonly keyId: string;
  readonly uriSan: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly runtime?: PublishedWorkloadRuntime;
}

export interface RecoveryRequest {
  readonly recoveryId: string;
  readonly subjectId: string;
  readonly recoveryPrincipalId: string;
  readonly participantId: string;
  readonly custodianPrincipalIds: readonly [string, string];
  readonly purposeDigest: string;
  readonly actionIntentId: string;
}

interface SessionRow {
  duration_profile?: 'C17' | 'LOCAL_QA' | 'LOCAL_QA_10X';
  idle_timeout_ms?: number | string;
  absolute_timeout_ms?: number | string;
  session_id: string;
  participant_id: string;
  principal_id: string;
  context_mode: SessionSnapshot['contextMode'];
  privacy_domain_id: string | null;
  context_epoch: string;
  state: SessionSnapshot['state'];
  opaque_token_digest: Buffer;
  authority_epoch: string;
  participant_epoch: string;
  delegation_epoch: string;
  session_epoch: string;
  refresh_family_id: string;
  refresh_used: boolean;
  row_version: string;
  csrf_secret: Buffer;
  issued_at: Date;
  last_seen_at: Date;
  idle_expires_at: Date;
  absolute_expires_at: Date;
  step_up_verified_at: Date | null;
  step_up_mfa_challenge_id?: string | null;
}

interface SessionMutationReplayRow {
  action_intent_digest: Buffer;
  created_at: Date;
  csrf_secret: Buffer;
  expected_aggregate_version: string;
  operation_id: string;
  principal_id: string;
  refresh_family_id: string;
  revoked_at: Date;
  result_digest: Buffer;
  result_payload: unknown | null;
  session_epoch: string;
  updated_at: Date;
}

interface MutationIdempotency<T> {
  readonly expectedAggregateVersion: string;
  readonly operationId: string;
  readonly replay: boolean;
  readonly result: T | undefined;
  readonly resultAggregateVersion: string | undefined;
}

export interface IdentityOperationRecord {
  readonly operationId: string;
  readonly resourceRef: string;
  readonly actionIntentId: string;
  readonly intentDigest: string;
  readonly idempotencyKey: string;
  readonly state: 'SUCCEEDED';
  readonly truthState: 'SUCCESS';
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly revision: string;
}

export interface IdentityMutationCommit<T> {
  readonly result: T;
  readonly operation: IdentityOperationRecord;
}

export interface SessionMutationContext {
  readonly participantId: string;
  readonly principalId: string;
  readonly privacyDomainId: string;
  readonly expectedRevision: string;
  readonly actionIntentDigest: string;
  readonly replay: boolean;
  readonly replayCsrfToken?: string;
}

export interface SessionMutationContextInput {
  readonly sessionToken: string;
  readonly privacyDomainId?: string;
  readonly actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' | 'ACT-IDENTITY_DELETE_SESSION-V1';
  readonly catalogOperationId: 'ID-OP-SESSION-REFRESH' | 'ID-OP-SESSION-REVOKE';
  readonly idempotencyKey: string;
  readonly candidateDigest: string;
  readonly origin: string;
  readonly host: string;
}

export interface SessionMutationReplay {
  readonly operation: IdentityOperationRecord;
  readonly nextSessionToken?: string;
}

export interface SessionMutationReplayInput {
  readonly sessionToken: string;
  readonly privacyDomainId: string;
  readonly actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' | 'ACT-IDENTITY_DELETE_SESSION-V1';
  readonly actionIntentDigest: string;
  readonly catalogOperationId: 'ID-OP-SESSION-REFRESH' | 'ID-OP-SESSION-REVOKE';
  readonly idempotencyKey: string;
  readonly candidateDigest: string;
  readonly expectedRevision: string;
  readonly csrfToken: string;
  readonly origin: string;
  readonly host: string;
}

function digest(value: string | Buffer): Buffer {
  return createHash('sha256').update(value).digest();
}

function sessionCsrfToken(
  secret: Buffer,
  sessionEpoch: string,
  actionIntentId: string,
  origin: string,
  host: string,
): string {
  return createHmac('sha256', secret)
    .update(`${sessionEpoch}\u0000${actionIntentId}\u0000${origin}\u0000${host}`)
    .digest('base64url');
}

function timestamp(value: Date | string): string {
  return new Date(value).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
}

function stableDigest(value: unknown): Buffer {
  return canonicalAuthorizationDigestBytes(value);
}

export function webAuthnReplacementCandidate(
  enrollmentId: string,
  replacedCredentialId: string,
  registration: VerifiedWebAuthnRegistration,
): WebAuthnReplacementCandidate {
  return {
    enrollmentId,
    replacedCredentialId,
    externalCredentialId: registration.externalCredentialId,
    publicKeyDigest: `sha256:${registration.publicKeyDigest.toString('hex')}`,
    publicKeySpkiDer: registration.publicKeySpkiDer.toString('base64'),
    signCount: registration.signCount,
    attestationDigest: `sha256:${registration.attestationDigest.toString('hex')}`,
    ...(registration.hardwareAttestation === undefined
      ? {}
      : { hardwareAttestation: registration.hardwareAttestation }),
  };
}

function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

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

function sameBuffer(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function one<T>(rows: T[], code: Parameters<typeof problemFor>[0] = 'PC-IDENTITY-1004'): T {
  const value = rows[0];
  if (value === undefined) throw new IdentityKernelError(code);
  return value;
}

function nextEpoch(epoch: string): string {
  return (BigInt(epoch) + 1n).toString();
}

function parseSessionToken(token: string): { participantId: string; sessionId: string } {
  const [participantId, sessionId, extra] = token.split('.');
  if (
    participantId === undefined ||
    sessionId === undefined ||
    extra !== undefined ||
    !UUID_V7_PATTERN.test(participantId) ||
    !UUID_V7_PATTERN.test(sessionId)
  ) {
    throw new IdentityKernelError('PC-AUTH-0003');
  }
  return { participantId, sessionId };
}

function sessionFromRow(row: SessionRow): SessionSnapshot {
  return {
    sessionId: row.session_id,
    sessionToken: `${row.participant_id}.${row.session_id}`,
    principalId: row.principal_id,
    participantId: row.participant_id,
    contextMode: row.context_mode,
    ...(row.privacy_domain_id === null ? {} : { privacyDomainId: row.privacy_domain_id }),
    contextEpoch: row.context_epoch,
    participantEpoch: row.participant_epoch,
    authorityEpoch: row.authority_epoch,
    sessionEpoch: row.session_epoch,
    refreshFamilyId: row.refresh_family_id,
    state: row.state,
    issuedAt: row.issued_at,
    lastSeenAt: row.last_seen_at,
    idleExpiresAt: row.idle_expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    ...(row.step_up_verified_at === null ? {} : { stepUpVerifiedAt: row.step_up_verified_at }),
  };
}

type ScopedOperation<T> = (client: PoolClient, operationId: string) => Promise<T>;
type MutationOperation<T> = (
  client: PoolClient,
  operationId: string,
  context: MutationAuthorityContext,
) => Promise<T>;

export interface SessionTimeouts {
  readonly durationProfile?: 'C17' | 'LOCAL_QA' | 'LOCAL_QA_10X';
  readonly idleMs: number;
  readonly absoluteMs: number;
}

import {
  defaultRecoveryLifetimes,
  type RecoveryLifetimeSettings,
} from './platform-recovery-lifetimes.js';

const defaultSessionTimeouts: SessionTimeouts = {
  idleMs: IDLE_TIMEOUT_MS,
  absoluteMs: ABSOLUTE_TIMEOUT_MS,
};

/** Authoritative identity repository. Every runtime mutation is PostgreSQL-backed. */
export class PostgresIdentityRepository {
  constructor(
    private readonly pool: Pool,
    private readonly clock: Clock = systemClock,
    private readonly identityRuntimeVerifier?: IdentityRuntimeAssertionVerifier,
    private readonly runtimeSnapshotPublisher?: RuntimeSnapshotPublisher,
    private readonly sessionTimeouts: SessionTimeouts = defaultSessionTimeouts,
    private readonly platformRecoveryLocalQaEnabled = false,
    private readonly platformRecoveryLifetimes: RecoveryLifetimeSettings = defaultRecoveryLifetimes,
    private readonly discoveryIssuancePolicy: DiscoveryCertificateIssuancePolicy = defaultDiscoveryCertificateIssuancePolicy,
    private readonly governedInitialEnrollmentProfile?: GovernedInitialEnrollmentProfile,
  ) {}

  private selectGovernedEnrollmentAccount(
    participantId: string,
    principalId: string,
    origin: string,
  ) {
    const profile = this.governedInitialEnrollmentProfile;
    if (!profile || !profile.accounts.some((account) => account.principalId === principalId))
      return undefined;
    const account = selectGovernedInitialEnrollmentAccount({
      profile,
      localQaEnabled: this.platformRecoveryLocalQaEnabled,
      participantId,
      principalId,
      origin,
      now: this.clock.now(),
    });
    if (!account) throw new IdentityKernelError('PC-IDENTITY-1002');
    return account;
  }

  async platformRecoveryCommand(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    enrollmentId: string,
    command: PlatformRecoveryCommand,
    origin: string,
  ) {
    const signer = this.identityRuntimeVerifier;
    if (!signer || !('signCanonicalAssertion' in signer))
      throw new IdentityKernelError('PC-IDENTITY-1004');
    const reservedOperationId =
      command.kind === 'ROTATION_CREATE'
        ? await this.scopedPrivacyTx(
            actor.participantId,
            privacyDomainId,
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            (client) =>
              resolveIdentityEnvelopeRecoveryRotationOperation(
                client,
                actor,
                enrollmentId,
                command.recoveryId,
                this.platformRecoveryLocalQaEnabled,
                signer as IdentityRuntimeEvidenceSigner,
              ),
          ).catch((error: unknown) => {
            if (error instanceof PlatformRecoveryError)
              throw new IdentityKernelError('PC-AUTH-0005');
            throw error;
          })
        : command.kind === 'ROTATION_ADVANCE'
          ? await this.scopedPrivacyTx(
              actor.participantId,
              privacyDomainId,
              'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
              (client) =>
                resolveIdentityEnvelopeRecoveryRotationStep(
                  client,
                  actor,
                  enrollmentId,
                  command,
                  this.platformRecoveryLocalQaEnabled,
                  signer as IdentityRuntimeEvidenceSigner,
                ),
            ).catch((error: unknown) => {
              if (error instanceof PlatformRecoveryError)
                throw new IdentityKernelError('PC-AUTH-0005');
              throw error;
            })
          : undefined;
    return this.transaction(
      actor.participantId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      async (client, operationId) => {
        try {
          return await executePlatformRecoveryCommand(
            client,
            actor,
            enrollmentId,
            command,
            origin,
            operationId,
            this.platformRecoveryLocalQaEnabled,
            signer as IdentityRuntimeEvidenceSigner,
            this.platformRecoveryLifetimes,
          );
        } catch (error) {
          if (error instanceof PlatformRecoveryError) throw new IdentityKernelError('PC-AUTH-0005');
          throw error;
        }
      },
      privacyDomainId,
      reservedOperationId,
    );
  }

  discoveryCertificateRecoveryCommand(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    enrollmentId: string,
    command: DiscoveryCertificateRecoveryCommand,
    origin: string,
  ) {
    const signer = this.identityRuntimeVerifier;
    if (!signer || !('signCanonicalAssertion' in signer))
      throw new IdentityKernelError('PC-IDENTITY-1004');
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      async (client, operationId) => {
        try {
          return await executeDiscoveryCertificateRecoveryCommand(
            client,
            actor,
            enrollmentId,
            command,
            origin,
            operationId,
            this.platformRecoveryLocalQaEnabled,
            signer as IdentityRuntimeEvidenceSigner,
            this.platformRecoveryLifetimes,
          );
        } catch (error) {
          if (error instanceof PlatformRecoveryError) throw new IdentityKernelError('PC-AUTH-0005');
          throw error;
        }
      },
    );
  }

  discoveryRecoveryCertificate(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    enrollmentId: string,
    recoveryId: string,
    credentialId: string,
  ) {
    const verifier = this.identityRuntimeVerifier;
    if (!actor.platform || !verifier) throw new IdentityKernelError('PC-AUTH-0005');
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      async (client) => {
        const read = await readDiscoveryCertificateRecoveryReceipt(
          client,
          actor,
          enrollmentId,
          recoveryId,
          verifier,
        );
        const completion = read.receipt.completion;
        if (
          read.enrollment.privacyDomainId !== privacyDomainId ||
          !completion ||
          read.receipt.authority !== 'NONE' ||
          completion.successorCredentialId !== credentialId
        )
          throw new IdentityKernelError('PC-AUTH-0005');
        const certificate = await readWorkloadCertificate(
          client,
          actor.participantId,
          credentialId,
        );
        if (certificate.certificateFingerprint !== completion.certificateFingerprint)
          throw new IdentityKernelError('PC-AUTH-0005');
        return certificate;
      },
    );
  }

  bootstrapAcceptance(
    scope: BootstrapSessionScope,
    command: BootstrapCommand,
    origin: string,
    registration: WebAuthnRegistrationAdapter,
  ) {
    const signer = this.identityRuntimeVerifier;
    if (!signer || !('signCanonicalAssertion' in signer))
      throw new IdentityKernelError('PC-AUTH-0002');
    return this.scopedPrivacyTx(
      scope.participantId,
      scope.privacyDomainId,
      'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
      (client, operationId) =>
        runBootstrapCommand(
          client,
          operationId,
          scope,
          command,
          origin,
          registration,
          signer as IdentityRuntimeEvidenceSigner,
        ),
    );
  }

  async directoryProfileReadback(
    actor: AuthenticatedIdentityActor,
    authority: BoundAuthority,
    profiles: readonly { profileId: string; label: string }[],
  ) {
    return this.identityScopedRead(actor, actor.participantId, authority, async () => ({
      profiles,
    }));
  }

  async resolveDirectoryMemberResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    connectorId: string,
    externalId: string,
  ) {
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) => resolveDirectoryMember(client, actor.participantId, connectorId, externalId),
    );
  }
  async directoryMemberReadback(
    actor: AuthenticatedIdentityActor,
    connectorId: string,
    externalId: string,
    connectorAuthority: BoundAuthority,
    memberAuthority: BoundAuthority,
  ) {
    return this.identityScopedRead(actor, connectorId, connectorAuthority, async (client) => {
      if (
        memberAuthority.actionIntentId !== 'ACT-PARTICIPANTS_READ_RESOURCE-V1' ||
        memberAuthority.privacyDomainId !== connectorAuthority.privacyDomainId ||
        memberAuthority.principalId !== actor.principalId ||
        memberAuthority.sessionId !== connectorAuthority.sessionId
      )
        throw new IdentityKernelError('PC-IDENTITY-1008');
      await fenceBoundAuthorities(client, actor.participantId, [memberAuthority]);
      return readDirectoryMember(
        client,
        actor.participantId,
        connectorAuthority.privacyDomainId,
        connectorId,
        externalId,
        memberAuthority.resourceId,
      );
    });
  }

  async directoryReconciliationContext(
    actor: AuthenticatedIdentityActor,
    connectorId: string,
    authority: BoundAuthority,
    externalIds: readonly string[],
  ) {
    return this.identityScopedRead(actor, connectorId, authority, (client) =>
      directoryReconciliationContext(client, actor.participantId, connectorId, externalIds),
    );
  }
  async reconcileDirectoryMembers(
    actor: AuthenticatedIdentityActor,
    candidate: DirectoryReconciliationCandidate,
    profile: RegisteredDirectoryProfile,
  ) {
    return this.mutationTx(
      actor,
      directoryCandidateAction(candidate),
      directoryCandidateOperation(candidate),
      'directory-connector',
      candidate.connectorId,
      candidate,
      (client, operationId) =>
        reconcileDirectoryMembers(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          actor.principalId,
          candidate,
          profile,
          operationId,
        ),
      (client) => directoryReconciliationFence(client, actor.participantId, candidate),
    );
  }

  async directoryConnectorReadback(
    actor: AuthenticatedIdentityActor,
    connectorId: string,
    authority: BoundAuthority,
  ) {
    return this.identityScopedRead(actor, connectorId, authority, (client) =>
      readDirectoryConnector(client, actor.participantId, connectorId),
    );
  }

  async resolveDirectoryProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    digest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) =>
        resolveDirectoryProposal(client, actor.participantId, privacyDomainId, digest, binding),
    );
  }
  async directoryProposal(
    actor: AuthenticatedIdentityActor,
    connectorId: string,
    authority: BoundAuthority,
    digest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.identityScopedRead(actor, connectorId, authority, (client) =>
      readDirectoryProposal(
        client,
        actor.participantId,
        authority.privacyDomainId,
        connectorId,
        digest,
        binding,
      ),
    );
  }

  async mutateDirectoryConnector(
    actor: AuthenticatedIdentityActor,
    candidate: DirectoryConnectorCandidate,
  ) {
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      directoryConnectorOperationIds[candidate.change.mutation],
      'directory-connector',
      candidate.change.connectorId,
      candidate,
      (client, operationId) =>
        mutateDirectoryConnector(client, actor.participantId, candidate, operationId),
      async () => ({ participant: [{ id: actor.participantId, write: true }] }),
    );
  }

  async resolveInvitationProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    digest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) =>
        resolveInvitationProposal(client, actor.participantId, privacyDomainId, digest, binding),
    );
  }
  async invitationProposal(
    actor: AuthenticatedIdentityActor,
    invitationId: string,
    authority: BoundAuthority,
    digest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.identityScopedRead(actor, invitationId, authority, (client) =>
      readInvitationProposal(
        client,
        actor.participantId,
        authority.privacyDomainId,
        invitationId,
        digest,
        binding,
      ),
    );
  }

  async invitationReadback(
    actor: AuthenticatedIdentityActor,
    invitationId: string,
    authority: BoundAuthority,
  ) {
    return this.identityScopedRead(actor, invitationId, authority, (client) =>
      readParticipantInvitation(
        client,
        actor.participantId,
        authority.privacyDomainId,
        invitationId,
      ),
    );
  }

  async mutateInvitation(
    actor: AuthenticatedIdentityActor,
    candidate: InvitationCandidate,
    roleAuthority?: BoundAuthority,
  ) {
    const change = candidate.change;
    if (
      change.mutation !== 'REVOKE' &&
      (!roleAuthority || roleAuthority.principalId !== actor.principalId)
    )
      throw new IdentityKernelError('PC-IDENTITY-1005');
    return this.mutationTx(
      actor,
      invitationAction(candidate),
      invitationOperationIds[change.mutation],
      'participant-invitation',
      change.invitationId,
      candidate,
      async (client, operationId, issuanceContext) => {
        const privacyDomainId = actor.mutationAuthorization!.privacyDomainId;
        const roleId =
          change.mutation === 'CREATE'
            ? change.intendedRoleId
            : (
                await readParticipantInvitation(
                  client,
                  actor.participantId,
                  privacyDomainId,
                  change.invitationId,
                )
              ).roleIntent.roleId;
        if (
          roleAuthority &&
          (roleAuthority.resourceId !== roleId ||
            roleAuthority.privacyDomainId !== privacyDomainId ||
            roleAuthority.sessionId !== parseSessionToken(actor.sessionToken).sessionId)
        )
          throw new IdentityKernelError('PC-IDENTITY-1005');
        return mutateParticipantInvitation(
          client,
          actor.participantId,
          privacyDomainId,
          actor.principalId,
          candidate,
          operationId,
          change.mutation === 'REVOKE'
            ? undefined
            : await captureInvitationAuthority(client, actor.participantId, {
                ...issuanceContext,
                roleAuthority: roleAuthority!,
                approvalRequestId: actor.mutationAuthorization!.approvalRequestId!,
                candidateDigest: actor.mutationAuthorization!.candidateDigest,
                operationId,
              }),
        );
      },
      async () => ({
        participant: [{ id: actor.participantId, write: true }],
        authorities: roleAuthority ? [roleAuthority] : [],
      }),
    );
  }

  async beginOidc(
    configuration: OidcClientConfiguration,
    selectedParticipantId?: string,
  ): Promise<OidcAuthorizationStart> {
    return this.systemTx('ACT-IDENTITY_CREATE_OIDC_AUTHORIZATION-V1', (client) =>
      persistOidcAuthorization(
        client,
        configuration,
        this.clock.now(),
        'SESSION',
        selectedParticipantId,
      ),
    );
  }

  beginInvitationProof(
    scope: InvitationScope & { readonly tokenVersion: string; readonly token: string },
    configuration: OidcClientConfiguration,
  ) {
    return this.scopedPrivacyTx(
      scope.participantId,
      scope.privacyDomainId,
      'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      (client) => beginInvitationProof(client, scope, configuration, this.clock.now()),
    );
  }

  invitationProofContext(
    request: InvitationProofRequest,
    custody: OidcTransactionCustody,
    configuration: OidcClientConfiguration,
  ) {
    return this.scopedPrivacyTx(
      request.participantId,
      request.privacyDomainId,
      'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      (client) => invitationProofContext(client, request, custody, configuration),
    );
  }

  completeInvitationProof(
    request: InvitationProofRequest,
    custody: OidcTransactionCustody,
    identity: VerifiedOidcIdentity,
  ) {
    const signer = this.identityRuntimeVerifier;
    if (!signer || !('signCanonicalAssertion' in signer))
      throw new IdentityKernelError('PC-AUTH-0002');
    return this.scopedPrivacyTx(
      request.participantId,
      request.privacyDomainId,
      'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      async (client, operationId) => {
        const completed = await completeInvitationProof(
          client,
          operationId,
          request,
          custody,
          identity,
          signer as IdentityRuntimeEvidenceSigner,
        );
        if (completed.signed)
          await this.appendDirectSignedOutbox(
            client,
            request.participantId,
            request.privacyDomainId,
            'invitation-redemption',
            request.invitationId,
            'openpc.identity.invitation.accepted.v1',
            completed.signed,
          );
        return completed.result;
      },
    );
  }

  /** Local-development-only adapter hook; PostgreSQL retains session authority. */
  async issueLocalDevelopmentSession(
    participantId: string,
    principalId: string,
    freshStepUp: boolean,
  ): Promise<SessionSnapshot> {
    return this.scopedTx(participantId, 'ACT-IDENTITY_CREATE_SESSION-V1', async (client) => {
      await lockAuthorityFence(client, participantId, {
        participant: [{ id: participantId }],
        principal: [{ id: principalId }],
      });
      const authority = await client.query<{
        authority_epoch: string;
        principal_epoch: string;
        delegation_epoch: string;
        root_privacy_domain_id: string;
      }>(
        `select p.authority_epoch::text,pr.authority_epoch::text principal_epoch,
          p.root_privacy_domain_id::text,
          coalesce((select max(a.delegation_epoch) from control.assignment a
            where a.participant_id=p.participant_id and a.principal_id=pr.principal_id
              and a.state='ACTIVE' and a.valid_during @> clock_timestamp()),0)::text delegation_epoch
         from control.participant p join control.principal pr on pr.participant_id=p.participant_id
         join control.privacy_domain privacy on privacy.participant_id=p.participant_id
          and privacy.privacy_domain_id=p.root_privacy_domain_id and privacy.state='ACTIVE'
         where p.participant_id=$1 and p.state='ACTIVE' and pr.principal_id=$2 and pr.state='ACTIVE'
           and p.root_privacy_domain_id is not null`,
        [participantId, principalId],
      );
      const epochs = one(authority.rows, 'PC-AUTH-0002');
      const now = this.clock.now();
      const sessionId = uuidV7();
      const familyId = uuidV7();
      const absoluteExpiresAt = new Date(now.getTime() + this.sessionTimeouts.absoluteMs);
      const idleExpiresAt = new Date(now.getTime() + this.sessionTimeouts.idleMs);
      const inserted = await client.query<SessionRow>(
        `insert into control.session
         (session_id,participant_id,principal_id,context_mode,privacy_domain_id,
          opaque_token_digest,state,authority_epoch,participant_epoch,
          delegation_epoch,session_epoch,refresh_family_id,refresh_token_digest,refresh_used,csrf_secret,
          issued_at,last_seen_at,idle_expires_at,absolute_expires_at,client_fingerprint_digest,step_up_verified_at,duration_profile,idle_timeout_ms,absolute_timeout_ms)
         values ($1,$2,$3,'PARTICIPANT',$4,$5,'ACTIVE',$6,$7,$8,1,$9,$10,false,$11,
                 $12,$12,$13,$14,$15,$16,'${this.sessionTimeouts.durationProfile ?? 'C17'}',${this.sessionTimeouts.idleMs},${this.sessionTimeouts.absoluteMs})
         returning *,authority_epoch::text,participant_epoch::text,session_epoch::text`,
        [
          sessionId,
          participantId,
          principalId,
          epochs.root_privacy_domain_id,
          digest(`${participantId}.${sessionId}`),
          epochs.principal_epoch,
          epochs.authority_epoch,
          epochs.delegation_epoch,
          familyId,
          digest(randomToken()),
          randomBytes(32),
          now,
          idleExpiresAt,
          absoluteExpiresAt,
          digest('local-development-adapter'),
          freshStepUp ? now : null,
        ],
      );
      return sessionFromRow(one(inserted.rows));
    });
  }

  async oidcExchangeContext(
    transactionId: string,
    custody: OidcTransactionCustody,
  ): Promise<OidcExchangeContext | undefined> {
    return this.systemTx('ACT-IDENTITY_CREATE_SESSION-V1', async (client) => {
      const result = await client.query<OidcRow>(
        `select * from control.oidc_transaction
         where transaction_id=$1 and purpose='SESSION' and consumed_at is null and expires_at>clock_timestamp()`,
        [transactionId],
      );
      const row = result.rows[0];
      return row === undefined || !matchesOidcCustody(row, custody)
        ? undefined
        : oidcExchangeFromRow(row, custody);
    });
  }

  async completeOidc(
    transactionId: string,
    custody: OidcTransactionCustody,
    callback: OidcCallback,
  ): Promise<SessionSnapshot> {
    return this.scopedTx(
      callback.participantId,
      'ACT-IDENTITY_CREATE_SESSION-V1',
      async (client, operationId) => {
        // Resolve only an exact scoped external account. Recheck after the principal fence;
        // the preliminary lookup takes no row lock ahead of the established lock order.
        const resolved = await client.query<{ principal_id: string }>(
          `select principal_id from control.credential
           where participant_id=$1 and kind='OIDC_SUBJECT' and issuer=$2 and subject=$3
             and audience=$4 and state='ACTIVE' and credential_epoch>0
             and valid_from<=clock_timestamp()
             and (valid_until is null or valid_until>clock_timestamp()) limit 2`,
          [callback.participantId, callback.issuer, callback.subject, callback.audience],
        );
        if (resolved.rows.length !== 1) throw new IdentityKernelError('PC-AUTH-0002');
        const principalId = resolved.rows[0]!.principal_id;
        if (callback.principalId !== undefined && callback.principalId !== principalId)
          throw new IdentityKernelError('PC-AUTH-0002');
        await lockAuthorityFence(client, callback.participantId, {
          participant: [{ id: callback.participantId }],
          principal: [{ id: principalId }],
        });
        const transaction = await client.query<OidcRow>(
          `select * from control.oidc_transaction where transaction_id=$1 for update`,
          [transactionId],
        );
        const oidc = one(transaction.rows, 'PC-AUTH-0002');
        const now = this.clock.now();
        if (
          oidc.purpose !== 'SESSION' ||
          oidc.consumed_at !== null ||
          (oidc.selected_participant_id === null
            ? callback.principalId === undefined
            : oidc.selected_participant_id !== callback.participantId) ||
          oidc.expires_at <= now ||
          !sameBuffer(oidc.browser_session_digest, digest(custody.browserSession)) ||
          !sameBuffer(oidc.code_verifier_digest, digest(custody.codeVerifier)) ||
          !sameBuffer(oidc.state_digest, digest(callback.state)) ||
          !sameBuffer(oidc.nonce_digest, digest(callback.nonce)) ||
          oidc.issuer !== callback.issuer ||
          oidc.client_id !== callback.audience ||
          oidc.client_id !== callback.authorizedParty ||
          callback.issuedAt > now ||
          callback.expiresAt <= now
        ) {
          throw new IdentityKernelError('PC-AUTH-0002');
        }
        // Provider claims identify an external account. Internal IDs are only
        // context hints and must match the durable Identity-owned binding.
        const bindings = await client.query<{ principal_id: string; credential_id: string }>(
          `select principal_id,credential_id from control.credential
            where participant_id=$1 and kind='OIDC_SUBJECT' and issuer=$2 and subject=$3
              and audience=$4 and state='ACTIVE' and credential_epoch>0
              and valid_from<=clock_timestamp()
              and (valid_until is null or valid_until>clock_timestamp())
            order by credential_id limit 2 for share`,
          [callback.participantId, callback.issuer, callback.subject, callback.audience],
        );
        if (bindings.rows.length !== 1 || bindings.rows[0]!.principal_id !== principalId)
          throw new IdentityKernelError('PC-AUTH-0002');
        await assertRecoveryOidcFreshness(
          client,
          callback.participantId,
          principalId,
          callback.authenticatedAt,
          now,
        );
        const authority = await client.query<{
          authority_epoch: string;
          delegation_epoch: string;
          principal_epoch: string;
        }>(
          `select p.authority_epoch::text,pr.authority_epoch::text principal_epoch,
             coalesce((select max(a.delegation_epoch) from control.assignment a
               where a.participant_id=p.participant_id and a.principal_id=pr.principal_id
                 and a.state='ACTIVE' and a.valid_during @> clock_timestamp()),0)::text delegation_epoch
           from control.participant p join control.principal pr on pr.participant_id=p.participant_id
           where p.participant_id=$1 and p.state='ACTIVE' and pr.principal_id=$2 and pr.state='ACTIVE'`,
          [callback.participantId, principalId],
        );
        const epochs = one(authority.rows, 'PC-AUTH-0002');
        await client.query(
          `update control.oidc_transaction set consumed_at=clock_timestamp()
           where transaction_id=$1 and consumed_at is null`,
          [transactionId],
        );
        const sessionId = uuidV7();
        const familyId = uuidV7();
        const absoluteExpiresAt = new Date(now.getTime() + this.sessionTimeouts.absoluteMs);
        const idleExpiresAt = new Date(
          Math.min(now.getTime() + this.sessionTimeouts.idleMs, absoluteExpiresAt.getTime()),
        );
        const inserted = await client.query<SessionRow>(
          `insert into control.session
           (session_id,participant_id,principal_id,opaque_token_digest,state,authority_epoch,participant_epoch,
            delegation_epoch,session_epoch,refresh_family_id,refresh_token_digest,refresh_used,csrf_secret,
            issued_at,last_seen_at,idle_expires_at,absolute_expires_at,client_fingerprint_digest,duration_profile,idle_timeout_ms,absolute_timeout_ms)
           values ($1,$2,$3,$4,'ACTIVE',$5,$6,$7,1,$8,$9,false,$10,$11,$11,$12,$13,$14,'${this.sessionTimeouts.durationProfile ?? 'C17'}',${this.sessionTimeouts.idleMs},${this.sessionTimeouts.absoluteMs})
           returning *,authority_epoch::text,participant_epoch::text,session_epoch::text`,
          [
            sessionId,
            callback.participantId,
            principalId,
            digest(`${callback.participantId}.${sessionId}`),
            epochs.principal_epoch,
            epochs.authority_epoch,
            epochs.delegation_epoch,
            familyId,
            digest(randomToken()),
            randomBytes(32),
            now,
            idleExpiresAt,
            absoluteExpiresAt,
            digest('server-controlled'),
          ],
        );
        await appendAuthenticationOccurrence(client, {
          sessionId,
          operationId,
          method: 'OIDC_CODE_PKCE_S256',
          sourceId: transactionId,
          credentialId: bindings.rows[0]!.credential_id,
          proofDigest: await oidcAuthenticationProofDigest(
            client,
            transactionId,
            bindings.rows[0]!.credential_id,
          ),
          occurredAt: now,
        });
        return sessionFromRow(one(inserted.rows));
      },
    );
  }

  async beginInitialWebAuthnEnrollment(
    sessionToken: string,
    rpId: string,
    origin: string,
    hardwareAttestation = false,
  ): Promise<InitialWebAuthnEnrollment> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(
      participantId,
      'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      async (client, operationId) => {
        let session = await this.activeSession(client, participantId, sessionId, false);
        await fenceInitialEnrollment(
          client,
          participantId,
          session.principal_id,
          sessionId,
          session.authority_epoch,
          this.governedInitialEnrollmentProfile?.accounts.find(
            (account) =>
              account.participantId === participantId &&
              account.principalId === session.principal_id,
          )?.privacyDomainId,
        );
        session = await this.activeSession(client, participantId, sessionId, true);
        if (session.context_mode !== 'PLATFORM' || session.step_up_verified_at !== null) {
          throw new IdentityKernelError('PC-AUTH-0006');
        }
        const principal = one(
          (
            await client.query<{ display_label: string }>(
              `select display_label from control.principal
              where participant_id=$1 and principal_id=$2 and state='ACTIVE' for share`,
              [participantId, session.principal_id],
            )
          ).rows,
          'PC-AUTH-0006',
        );
        const governedAccount = this.selectGovernedEnrollmentAccount(
          participantId,
          session.principal_id,
          origin,
        );
        if (governedAccount?.kind === 'EXECUTOR' && !hardwareAttestation)
          throw new IdentityKernelError('PC-IDENTITY-1002');
        if (governedAccount) {
          await client.query(
            `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,
              'ACT-IDENTITY_UPDATE_STEP_UP-V1',true),openpc.assert_request_context(true)`,
            [participantId, governedAccount.privacyDomainId, operationId],
          );
        }
        await initialEnrollmentRecovery(
          client,
          participantId,
          session.principal_id,
          session.authority_epoch,
        );

        await client.query(
          `update control.webauthn_enrollment
            set expires_at=clock_timestamp(),row_version=row_version+1
          where participant_id=$1 and principal_id=$2 and session_id=$3
            and replaced_credential_id is null
            and consumed_at is null and expires_at>clock_timestamp()`,
          [participantId, session.principal_id, sessionId],
        );
        const enrollmentId = uuidV7();
        const challenge = randomToken();
        const expiresAt = new Date(this.clock.now().getTime() + OIDC_TRANSACTION_MS);
        await client.query(
          `insert into control.webauthn_enrollment
          (enrollment_id,participant_id,principal_id,session_id,challenge_digest,rp_id,origin,expires_at,governed_initial_profile_digest)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            enrollmentId,
            participantId,
            session.principal_id,
            sessionId,
            digest(challenge),
            rpId,
            origin,
            expiresAt,
            governedAccount
              ? canonicalAuthorizationDigestBytes(this.governedInitialEnrollmentProfile)
              : null,
          ],
        );
        if (governedAccount) {
          if (!this.identityRuntimeVerifier) throw new IdentityKernelError('PC-IDENTITY-1004');
          await client.query(
            `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,
            'ACT-IDENTITY_UPDATE_STEP_UP-V1',true),openpc.assert_request_context(true)`,
            [participantId, governedAccount.privacyDomainId, operationId],
          );
          await readGovernedInitialEnrollmentSource(
            client,
            {
              account: governedAccount,
              sessionId,
              enrollmentId,
              profileDigest: `sha256:${canonicalAuthorizationDigestBytes(this.governedInitialEnrollmentProfile).toString('hex')}`,
              origin,
              rpId,
            },
            this.identityRuntimeVerifier,
          );
        }
        return {
          enrollmentId,
          challenge,
          rpId,
          origin,
          principalId: session.principal_id,
          displayLabel: principal.display_label,
          excludedCredentialIds: [],
          expiresAt,
        };
      },
    );
  }

  async webAuthnEnrollmentReadback(sessionToken: string, enrollmentId: string) {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(
      participantId,
      'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      async (client, operationId) => {
        let session = await this.activeSession(client, participantId, sessionId, false);
        await lockAuthorityFence(client, participantId, {
          participant: [{ id: participantId }],
          privacy_domain: session.privacy_domain_id ? [{ id: session.privacy_domain_id }] : [],
          principal: [{ id: session.principal_id }],
          session: [{ id: sessionId }],
        });
        session = await this.activeSession(client, participantId, sessionId, false);
        const readback = await readWebAuthnEnrollment(
          client,
          participantId,
          session.principal_id,
          session.authority_epoch,
          enrollmentId,
        );
        if (readback.state === 'COMPLETED') {
          const bound = await client.query<{ privacy_domain_id: string }>(
            `select participant.root_privacy_domain_id::text privacy_domain_id
           from control.webauthn_enrollment enrollment
           join control.participant participant using(participant_id)
           where enrollment.participant_id=$1 and enrollment.principal_id=$2 and enrollment.enrollment_id=$3
             and enrollment.governed_initial_profile_digest is not null`,
            [participantId, session.principal_id, enrollmentId],
          );
          if (bound.rowCount !== 0) {
            if (bound.rowCount !== 1 || !this.identityRuntimeVerifier)
              throw new IdentityKernelError('PC-IDENTITY-1004');
            await client.query(
              `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,
              'ACT-IDENTITY_UPDATE_STEP_UP-V1',true),openpc.assert_request_context(true)`,
              [participantId, bound.rows[0]!.privacy_domain_id, operationId],
            );
            await readGovernedInitialEnrollmentResult(
              client,
              participantId,
              session.principal_id,
              enrollmentId,
              this.identityRuntimeVerifier,
            );
          }
        }
        return readback;
      },
    );
  }

  async initialWebAuthnEnrollmentContext(
    sessionToken: string,
    enrollmentId: string,
  ): Promise<InitialWebAuthnEnrollmentContext> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, 'ACT-IDENTITY_UPDATE_STEP_UP-V1', async (client) => {
      const session = await this.activeSession(client, participantId, sessionId, false);
      if (session.context_mode !== 'PLATFORM') throw new IdentityKernelError('PC-AUTH-0006');
      const enrollment = one(
        (
          await client.query<{
            challenge_digest: Buffer;
            origin: string;
            rp_id: string;
          }>(
            `select challenge_digest,origin,rp_id from control.webauthn_enrollment
              where participant_id=$1 and principal_id=$2 and session_id=$3 and enrollment_id=$4
                and replaced_credential_id is null
                and consumed_at is null and expires_at>clock_timestamp()`,
            [participantId, session.principal_id, sessionId, enrollmentId],
          )
        ).rows,
        'PC-AUTH-0006',
      );
      return {
        expectedChallengeDigest: enrollment.challenge_digest,
        expectedOrigin: enrollment.origin,
        expectedRpId: enrollment.rp_id,
      };
    });
  }

  async completeInitialWebAuthnEnrollment(
    sessionToken: string,
    enrollmentId: string,
    registration: VerifiedWebAuthnRegistration,
  ): Promise<RegisteredWebAuthnCredential> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    const signer = this.identityRuntimeVerifier;
    if (signer === undefined || !('signCanonicalAssertion' in signer)) {
      throw new IdentityKernelError('PC-IDENTITY-1004');
    }
    return this.scopedTx(
      participantId,
      'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      async (client, operationId) => {
        let session = await this.activeSession(client, participantId, sessionId, false);
        await fenceInitialEnrollment(
          client,
          participantId,
          session.principal_id,
          sessionId,
          session.authority_epoch,
          this.governedInitialEnrollmentProfile?.accounts.find(
            (account) =>
              account.participantId === participantId &&
              account.principalId === session.principal_id,
          )?.privacyDomainId,
        );
        session = await this.activeSession(client, participantId, sessionId, true);
        if (session.context_mode !== 'PLATFORM' || session.step_up_verified_at !== null) {
          throw new IdentityKernelError('PC-AUTH-0006');
        }
        const enrollment = one(
          (
            await client.query<{ challenge_digest: Buffer; origin: string; rp_id: string }>(
              `select challenge_digest,origin,rp_id from control.webauthn_enrollment
              where participant_id=$1 and principal_id=$2 and session_id=$3 and enrollment_id=$4
                and replaced_credential_id is null
                and consumed_at is null and expires_at>clock_timestamp() for update`,
              [participantId, session.principal_id, sessionId, enrollmentId],
            )
          ).rows,
          'PC-AUTH-0006',
        );
        const recovery = await initialEnrollmentRecovery(
          client,
          participantId,
          session.principal_id,
          session.authority_epoch,
        );
        if (!digest(registration.publicKeySpkiDer).equals(registration.publicKeyDigest)) {
          throw new IdentityKernelError('PC-AUTH-0006');
        }
        const root = one(
          (
            await client.query<{ root_privacy_domain_id: string }>(
              `select root_privacy_domain_id from control.participant
              where participant_id=$1 and root_privacy_domain_id is not null`,
              [participantId],
            )
          ).rows,
          'PC-IDENTITY-1004',
        );
        const enrollmentPrivacyDomainId = recovery?.privacyDomainId ?? root.root_privacy_domain_id;
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,
                  'ACT-IDENTITY_UPDATE_STEP_UP-V1',true),openpc.assert_request_context(true)`,
          [participantId, enrollmentPrivacyDomainId, operationId],
        );

        const governedAccount =
          recovery === undefined
            ? this.selectGovernedEnrollmentAccount(
                participantId,
                session.principal_id,
                enrollment.origin,
              )
            : undefined;
        if (
          governedAccount &&
          (governedAccount.privacyDomainId !== enrollmentPrivacyDomainId ||
            (governedAccount.kind === 'EXECUTOR' && registration.hardwareAttestation === undefined))
        )
          throw new IdentityKernelError('PC-IDENTITY-1002');
        const governedProfile = governedAccount
          ? this.governedInitialEnrollmentProfile!
          : undefined;
        const governedSource = governedAccount
          ? await readGovernedInitialEnrollmentSource(
              client,
              {
                account: governedAccount,
                sessionId,
                enrollmentId,
                profileDigest: `sha256:${canonicalAuthorizationDigestBytes(governedProfile).toString('hex')}`,
                origin: enrollment.origin,
                rpId: enrollment.rp_id,
              },
              signer,
            )
          : undefined;

        const credentialId = uuidV7();
        await client.query(
          `insert into control.credential
          (credential_id,participant_id,principal_id,kind,issuer,subject,audience,
           public_key_digest,public_key_spki_der,authenticator_sign_count,state,credential_epoch,valid_from)
         select $1,$2,$3,'WEBAUTHN','webauthn://' || enrollment.rp_id,$4,enrollment.origin,
                $5,$6,$7,'ACTIVE',1,clock_timestamp()
           from control.webauthn_enrollment enrollment
          where enrollment.participant_id=$2 and enrollment.enrollment_id=$8`,
          [
            credentialId,
            participantId,
            session.principal_id,
            registration.externalCredentialId,
            registration.publicKeyDigest,
            registration.publicKeySpkiDer,
            registration.signCount,
            enrollmentId,
          ],
        );
        if (recovery !== undefined)
          await completeRecoveryEnrollment(
            client,
            participantId,
            session.principal_id,
            recovery.recoveryId,
            recovery.privacyDomainId,
            credentialId,
            session.authority_epoch,
          );
        await saveHardwareAuthenticator(
          client,
          participantId,
          session.principal_id,
          credentialId,
          registration,
        );
        await client.query(
          `update control.webauthn_enrollment
            set consumed_at=clock_timestamp(),credential_id=$3,attestation_digest=$4,
                row_version=row_version+1
          where participant_id=$1 and enrollment_id=$2 and consumed_at is null`,
          [participantId, enrollmentId, credentialId, registration.attestationDigest],
        );
        await client.query(
          `update control.session set step_up_verified_at=clock_timestamp(),step_up_mfa_challenge_id=null,row_version=row_version+1,
                updated_at=clock_timestamp()
          where participant_id=$1 and session_id=$2`,
          [participantId, sessionId],
        );

        let evidenceCbor: Buffer;
        let governedResult: GovernedInitialEnrollmentEvidence | undefined;
        if (governedSource && governedAccount && governedProfile) {
          const committedAt = this.clock.now();
          // Recheck the finite operator selection after source/signature reads.
          if (
            !selectGovernedInitialEnrollmentAccount({
              profile: governedProfile,
              localQaEnabled: this.platformRecoveryLocalQaEnabled,
              participantId,
              principalId: session.principal_id,
              origin: enrollment.origin,
              now: committedAt,
            })
          )
            throw new IdentityKernelError('PC-IDENTITY-1002');
          governedResult = {
            schema: 'pc.identity.governed-initial-enrollment-result',
            schemaVersion: 1,
            purpose: 'FIRST_AUTHENTICATOR_ONLY',
            permissionEffect: 'NONE',
            operationId,
            account: governedAccount,
            profileDigest: `sha256:${canonicalAuthorizationDigestBytes(governedProfile).toString('hex')}`,
            sessionId,
            sessionEpoch: session.session_epoch,
            sessionIssuedAt: session.issued_at.toISOString(),
            sessionValidUntil: new Date(
              Math.min(session.idle_expires_at.getTime(), session.absolute_expires_at.getTime()),
            ).toISOString(),
            authenticationOccurrenceId: governedSource.authenticationOccurrenceId,
            authenticationReceiptDigest: governedSource.authenticationReceiptDigest,
            oidcCredentialId: governedSource.oidcCredentialId,
            oidcCredentialEpoch: governedSource.oidcCredentialEpoch,
            activationEvidenceDigest: governedSource.activationEvidenceDigest,
            acceptanceEvidenceDigest: governedSource.acceptanceEvidenceDigest,
            makerVerificationEvidenceDigest: governedSource.makerVerificationEvidenceDigest,
            enrollmentId,
            enrollmentCreatedAt: governedSource.enrollmentCreatedAt.toISOString(),
            enrollmentValidUntil: governedSource.enrollmentValidUntil.toISOString(),
            rpId: enrollment.rp_id,
            origin: enrollment.origin,
            authenticatorCredentialId: credentialId,
            authenticatorPublicKeyDigest: `sha256:${registration.publicKeyDigest.toString('hex')}`,
            attestationDigest: `sha256:${registration.attestationDigest.toString('hex')}`,
            hardwareAttestation: registration.hardwareAttestation ? 'VERIFIED' : 'NOT_REQUIRED',
            committedAt: committedAt.toISOString(),
            validUntil: new Date(
              Math.min(
                committedAt.getTime() + 60_000,
                governedSource.enrollmentValidUntil.getTime(),
                session.idle_expires_at.getTime(),
                session.absolute_expires_at.getTime(),
                Date.parse(governedProfile.validUntil),
              ),
            ).toISOString(),
          };
          evidenceCbor = createGovernedInitialEnrollmentAssertion(governedResult);
        } else {
          const authority = one(
            (
              await client.query<{
                assignment_id: string;
                assignment_row_version: string;
                authority_envelope_id: string;
                envelope_epoch: string;
                participant_epoch: string;
                principal_epoch: string;
              }>(
                `select a.assignment_id,a.row_version::text assignment_row_version,
                    ae.authority_envelope_id,ae.authority_epoch::text envelope_epoch,
                    p.authority_epoch::text participant_epoch,pr.authority_epoch::text principal_epoch
               from control.assignment a
               join control.authority_envelope ae on ae.participant_id=a.participant_id
                and ae.authority_envelope_id=a.authority_envelope_id and ae.state='ACTIVE'
                and ${currentPlatformEnvelopeSql('ae')}
                and ae.valid_from<=clock_timestamp()
                and (ae.valid_until is null or ae.valid_until>clock_timestamp())
                and 'ACT-IDENTITY_UPDATE_STEP_UP-V1'=any(ae.action_intent_ids) and $3::text=any(ae.privacy_domain_ids)
               join control.participant p on p.participant_id=a.participant_id and p.state='ACTIVE'
               join control.principal pr on pr.participant_id=a.participant_id
                and pr.principal_id=a.principal_id and pr.state='ACTIVE'
              where a.participant_id=$1 and a.principal_id=$2 and a.state='ACTIVE'
                and a.valid_during @> clock_timestamp()
                and 'ACT-IDENTITY_UPDATE_STEP_UP-V1'=any(a.action_intent_ids)
                and $3::text=any(a.privacy_domain_ids)
              order by a.assignment_id limit 1`,
                [participantId, session.principal_id, enrollmentPrivacyDomainId],
              )
            ).rows,
            'PC-IDENTITY-1002',
          );
          const candidateDigest = `sha256:${stableDigest({
            enrollmentId,
            credentialId,
            principalId: session.principal_id,
            participantId,
            externalCredentialId: registration.externalCredentialId,
            publicKeyDigest: `sha256:${registration.publicKeyDigest.toString('hex')}`,
            attestationDigest: `sha256:${registration.attestationDigest.toString('hex')}`,
            ...(recovery === undefined ? {} : { recoveryId: recovery.recoveryId }),
          }).toString('hex')}`;
          evidenceCbor = createIdentityRuntimeAuthorizationAssertion(
            operationId,
            {
              participantId,
              principalId: session.principal_id,
              sessionId,
              sessionEpoch: session.session_epoch,
              sessionIssuedAt: session.issued_at,
              sessionIdleExpiresAt: session.idle_expires_at,
              sessionAbsoluteExpiresAt: session.absolute_expires_at,
              participantEpoch: authority.participant_epoch,
              principalEpoch: authority.principal_epoch,
              assignmentId: authority.assignment_id,
              assignmentRowVersion: authority.assignment_row_version,
              authorityEnvelopeId: authority.authority_envelope_id,
              authorityEpoch: authority.envelope_epoch,
              delegationEpoch: session.delegation_epoch,
              actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
              catalogOperationId: 'ID-OP-WEBAUTHN-REGISTER',
              resourceId: credentialId,
              candidateDigest,
              sessionToken,
            },
            this.clock.now(),
          );
        }
        const signed = await (signer as IdentityRuntimeEvidenceSigner).signCanonicalAssertion(
          evidenceCbor,
        );
        const sequence = one(
          (
            await client.query<{ last_sequence: string }>(
              `insert into control.outbox_aggregate_head
              (participant_id,aggregate_type,aggregate_id,last_sequence)
             values ($1,'credential',$2,1)
             on conflict (participant_id,aggregate_type,aggregate_id) do update
               set last_sequence=control.outbox_aggregate_head.last_sequence+1,
                   updated_at=clock_timestamp()
             returning last_sequence::text`,
              [participantId, credentialId],
            )
          ).rows,
        ).last_sequence;
        const eventId = uuidV7();
        await client.query(
          `insert into control.outbox_event
          (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
           aggregate_sequence,payload_cbor,payload_digest,cose_sign1,occurred_at)
         values ($1,$2,$3,$9,
                 'credential',$4,$5,$6,$7,$8,clock_timestamp())`,
          [
            participantId,
            enrollmentPrivacyDomainId,
            eventId,
            credentialId,
            sequence,
            signed.evidenceCbor,
            signed.evidenceDigest,
            signed.coseSign1,
            governedSource
              ? 'openpc.identity.webauthn.governed-initial-enrollment.completed.v1'
              : 'openpc.identity.webauthn.initial-enrollment.completed.v1',
          ],
        );
        if (governedResult) {
          await saveGovernedInitialEnrollmentResult(
            client,
            governedResult,
            eventId,
            signed,
            signer,
          );
        }
        return {
          credentialId,
          externalCredentialId: registration.externalCredentialId,
          credentialEpoch: '1',
          state: 'ACTIVE',
        };
      },
    );
  }

  async beginReplacementWebAuthnEnrollment(
    sessionToken: string,
    replacedCredentialId: string,
    rpId: string,
    origin: string,
  ): Promise<ReplacementWebAuthnEnrollment> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, 'ACT-IDENTITY_UPDATE_STEP_UP-V1', async (client) => {
      const session = await this.activeSession(client, participantId, sessionId, true);
      if (session.context_mode !== 'PARTICIPANT') throw new IdentityKernelError('PC-AUTH-0006');
      const principal = one(
        (
          await client.query<{ display_label: string }>(
            `select display_label from control.principal
              where participant_id=$1 and principal_id=$2 and state='ACTIVE' for share`,
            [participantId, session.principal_id],
          )
        ).rows,
        'PC-AUTH-0006',
      );
      one(
        (
          await client.query(
            `select 1 from control.credential
              where participant_id=$1 and principal_id=$2 and credential_id=$3
                and kind='WEBAUTHN' and state='ACTIVE'
                and valid_from<=clock_timestamp()
                and (valid_until is null or valid_until>clock_timestamp()) for share`,
            [participantId, session.principal_id, replacedCredentialId],
          )
        ).rows,
        'PC-AUTH-0006',
      );
      const credentials = await client.query<{ subject: string }>(
        `select subject from control.credential
          where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN' and state='ACTIVE'
            and subject is not null order by credential_id for share`,
        [participantId, session.principal_id],
      );
      await client.query(
        `update control.webauthn_enrollment
            set expires_at=clock_timestamp(),row_version=row_version+1
          where participant_id=$1 and principal_id=$2 and session_id=$3
            and replaced_credential_id is not null
            and consumed_at is null and expires_at>clock_timestamp()`,
        [participantId, session.principal_id, sessionId],
      );
      const enrollmentId = uuidV7();
      const challenge = randomToken();
      const expiresAt = new Date(this.clock.now().getTime() + OIDC_TRANSACTION_MS);
      await client.query(
        `insert into control.webauthn_enrollment
          (enrollment_id,participant_id,principal_id,session_id,challenge_digest,rp_id,origin,
           expires_at,replaced_credential_id)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          enrollmentId,
          participantId,
          session.principal_id,
          sessionId,
          digest(challenge),
          rpId,
          origin,
          expiresAt,
          replacedCredentialId,
        ],
      );
      return {
        enrollmentId,
        challenge,
        rpId,
        origin,
        principalId: session.principal_id,
        displayLabel: principal.display_label,
        excludedCredentialIds: credentials.rows.map((credential) => credential.subject),
        expiresAt,
        replacedCredentialId,
      };
    });
  }

  async replacementWebAuthnEnrollmentContext(
    sessionToken: string,
    enrollmentId: string,
  ): Promise<ReplacementWebAuthnEnrollmentContext> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, 'ACT-IDENTITY_UPDATE_STEP_UP-V1', async (client) => {
      const session = await this.activeSession(client, participantId, sessionId, false);
      if (session.context_mode !== 'PARTICIPANT') throw new IdentityKernelError('PC-AUTH-0006');
      const enrollment = one(
        (
          await client.query<{
            challenge_digest: Buffer;
            origin: string;
            replaced_credential_id: string;
            rp_id: string;
          }>(
            `select challenge_digest,origin,replaced_credential_id,rp_id
               from control.webauthn_enrollment
              where participant_id=$1 and principal_id=$2 and session_id=$3 and enrollment_id=$4
                and replaced_credential_id is not null
                and consumed_at is null and expires_at>clock_timestamp()`,
            [participantId, session.principal_id, sessionId, enrollmentId],
          )
        ).rows,
        'PC-AUTH-0006',
      );
      return {
        expectedChallengeDigest: enrollment.challenge_digest,
        expectedOrigin: enrollment.origin,
        expectedRpId: enrollment.rp_id,
        replacedCredentialId: enrollment.replaced_credential_id,
      };
    });
  }

  async completeReplacementWebAuthnEnrollment(
    actor: AuthenticatedIdentityActor,
    enrollmentId: string,
    replacedCredentialId: string,
    registration: VerifiedWebAuthnRegistration,
  ): Promise<RegisteredWebAuthnCredential> {
    const candidate = webAuthnReplacementCandidate(
      enrollmentId,
      replacedCredentialId,
      registration,
    );
    const { sessionId } = parseSessionToken(actor.sessionToken);
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WEBAUTHN-REGISTER',
      'webauthn-credential',
      replacedCredentialId,
      candidate,
      async (client) => {
        const enrollment = one(
          (
            await client.query<{ origin: string; rp_id: string }>(
              `select origin,rp_id from control.webauthn_enrollment
                where participant_id=$1 and principal_id=$2 and session_id=$3 and enrollment_id=$4
                  and replaced_credential_id=$5
                  and consumed_at is null and expires_at>clock_timestamp() for update`,
              [
                actor.participantId,
                actor.principalId,
                sessionId,
                enrollmentId,
                replacedCredentialId,
              ],
            )
          ).rows,
          'PC-AUTH-0006',
        );
        const replaced = one(
          (
            await client.query<{ credential_epoch: string }>(
              `select credential_epoch::text from control.credential
                where participant_id=$1 and principal_id=$2 and credential_id=$3
                  and kind='WEBAUTHN' and state='ACTIVE'
                  and valid_from<=clock_timestamp()
                  and (valid_until is null or valid_until>clock_timestamp()) for update`,
              [actor.participantId, actor.principalId, replacedCredentialId],
            )
          ).rows,
          'PC-AUTH-0006',
        );
        if (!digest(registration.publicKeySpkiDer).equals(registration.publicKeyDigest)) {
          throw new IdentityKernelError('PC-AUTH-0006');
        }
        const duplicate = await client.query(
          `select 1 from control.credential
            where participant_id=$1 and kind='WEBAUTHN' and subject=$2 for share`,
          [actor.participantId, registration.externalCredentialId],
        );
        if (duplicate.rowCount !== 0) throw new IdentityKernelError('PC-AUTH-0006');
        const credentialId = uuidV7();
        const credentialEpoch = (BigInt(replaced.credential_epoch) + 1n).toString();
        await client.query(
          `insert into control.credential
            (credential_id,participant_id,principal_id,kind,issuer,subject,audience,
             public_key_digest,public_key_spki_der,authenticator_sign_count,state,credential_epoch,
             valid_from,rotated_from_credential_id)
           values ($1,$2,$3,'WEBAUTHN',$4,$5,$6,$7,$8,$9,'ACTIVE',$10,
                   clock_timestamp(),$11)`,
          [
            credentialId,
            actor.participantId,
            actor.principalId,
            `webauthn://${enrollment.rp_id}`,
            registration.externalCredentialId,
            enrollment.origin,
            registration.publicKeyDigest,
            registration.publicKeySpkiDer,
            registration.signCount,
            credentialEpoch,
            replacedCredentialId,
          ],
        );
        await saveHardwareAuthenticator(
          client,
          actor.participantId,
          actor.principalId,
          credentialId,
          registration,
        );
        const revoked = await client.query(
          `update control.credential
              set state='REVOKED',credential_epoch=credential_epoch+1,
                  row_version=row_version+1,updated_at=clock_timestamp()
            where participant_id=$1 and credential_id=$2 and state='ACTIVE'`,
          [actor.participantId, replacedCredentialId],
        );
        const consumed = await client.query(
          `update control.webauthn_enrollment
              set consumed_at=clock_timestamp(),credential_id=$3,attestation_digest=$4,
                  row_version=row_version+1
            where participant_id=$1 and enrollment_id=$2 and consumed_at is null`,
          [actor.participantId, enrollmentId, credentialId, registration.attestationDigest],
        );
        if (revoked.rowCount !== 1 || consumed.rowCount !== 1) {
          throw new IdentityKernelError('PC-IDENTITY-1001');
        }
        return {
          credentialId,
          externalCredentialId: registration.externalCredentialId,
          credentialEpoch,
          state: 'ACTIVE' as const,
        };
      },
      async () => ({ credential: [{ id: replacedCredentialId, write: true }] }),
    );
  }

  async sessionSnapshot(sessionToken: string): Promise<SessionSnapshot> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', async (client) => {
      const current = await this.activeSession(client, participantId, sessionId, true);
      const now = this.clock.now();
      const idleTimeoutMs = Number(current.idle_timeout_ms ?? IDLE_TIMEOUT_MS);
      const elapsedMs = now.getTime() - current.last_seen_at.getTime();
      // A burst of authenticated reads shares the stored heartbeat. Validation
      // and locking still run on every read; only the timestamp write is coalesced.
      if (elapsedMs >= 0 && elapsedMs < Math.min(1_000, idleTimeoutMs / 10)) {
        return sessionFromRow(current);
      }
      const idleExpiresAt = new Date(
        Math.min(now.getTime() + idleTimeoutMs, current.absolute_expires_at.getTime()),
      );
      const updated = await client.query<SessionRow>(
        `update control.session set last_seen_at=$3,idle_expires_at=$4,updated_at=clock_timestamp()
         where participant_id=$1 and session_id=$2
         returning *,authority_epoch::text,participant_epoch::text,session_epoch::text`,
        [participantId, sessionId, now, idleExpiresAt],
      );
      return sessionFromRow(one(updated.rows, 'PC-AUTH-0003'));
    });
  }

  async selectParticipantContext(
    sessionToken: string,
    selection: SessionContextSelection,
  ): Promise<SessionSnapshot> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    if (participantId !== selection.participantId) throw new IdentityKernelError('PC-AUTH-0003');
    const signer = this.identityRuntimeVerifier;
    if (signer === undefined || !('signCanonicalAssertion' in signer)) {
      throw new IdentityKernelError('PC-IDENTITY-1004');
    }
    return this.transaction(
      participantId,
      'ACT-IDENTITY_CREATE_SESSION-V1',
      async (client, operationId) => {
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,
                  'ACT-IDENTITY_CREATE_SESSION-V1',true),openpc.assert_request_context(true)`,
          [participantId, selection.privacyDomainId, operationId],
        );
        const session = await this.activeSession(client, participantId, sessionId, true);
        const now = this.clock.now();
        // Context rotation retains its original five-minute admission and
        // never transfers a source-bound QA proof to the new session.
        await this.assertPinnedStepUpCurrent(client, session);
        if (
          session.step_up_verified_at === null ||
          session.step_up_verified_at.getTime() < now.getTime() - STEP_UP_MAX_AGE_MS
        ) {
          throw new IdentityKernelError('PC-AUTH-0005');
        }
        const context = one(
          (
            await client.query<{
              representation: string;
              assignment_id: string;
              assignment_row_version: string;
              authority_envelope_id: string;
              envelope_epoch: string;
              participant_epoch: string;
              principal_epoch: string;
              delegation_epoch: string;
            }>(
              `select ae.representation,a.assignment_id,a.row_version::text assignment_row_version,
                      ae.authority_envelope_id,ae.authority_epoch::text envelope_epoch,
                      participant.authority_epoch::text participant_epoch,
                      principal.authority_epoch::text principal_epoch,
                      coalesce((select max(candidate.delegation_epoch)
                        from control.assignment candidate
                       where candidate.participant_id=$1 and candidate.principal_id=$3
                         and candidate.state='ACTIVE'
                         and candidate.valid_during @> clock_timestamp()),0)::text delegation_epoch
                 from control.privacy_domain privacy
                 join control.participant participant
                   on participant.participant_id=privacy.participant_id and participant.state='ACTIVE'
                 join control.principal principal
                   on principal.participant_id=privacy.participant_id
                  and principal.principal_id=$3 and principal.state='ACTIVE'
                 join control.assignment a
                   on a.participant_id=privacy.participant_id and a.principal_id=principal.principal_id
                  and a.state='ACTIVE' and a.valid_during @> clock_timestamp()
                  and $2::text=any(a.privacy_domain_ids)
                  and 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'=any(a.action_intent_ids)
                 join control.authority_envelope ae
                   on ae.participant_id=a.participant_id
                  and ae.authority_envelope_id=a.authority_envelope_id and ae.state='ACTIVE'
                and ${currentPlatformEnvelopeSql('ae', false, true)}
                  and ae.valid_from<=clock_timestamp()
                  and (ae.valid_until is null or ae.valid_until>clock_timestamp())
                  and $2::text=any(ae.privacy_domain_ids)
                  and 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'=any(ae.action_intent_ids)
                  and (ae.representation<>'RECOVERY_V1' or (
                    openpc.administration_resource_permits(a.resource_ids,$3::text,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',$1,$3,$4,a.authority_envelope_id)
                    and openpc.administration_resource_permits(ae.resource_ids,$3::text,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',$1,$3,$4,ae.authority_envelope_id)))
                where privacy.participant_id=$1 and privacy.privacy_domain_id=$2::uuid
                  and privacy.state='ACTIVE'
                order by a.assignment_id limit 1`,
              [participantId, selection.privacyDomainId, session.principal_id, sessionId],
            )
          ).rows,
          'PC-AUTH-0003',
        );
        if (context.representation === 'RECOVERY_V1')
          await fenceBoundAuthorities(
            client,
            participantId,
            [
              {
                principalId: session.principal_id,
                participantEpoch: context.participant_epoch,
                principalEpoch: context.principal_epoch,
                assignmentId: context.assignment_id,
                assignmentRowVersion: context.assignment_row_version,
                authorityEnvelopeId: context.authority_envelope_id,
                authorityEpoch: context.envelope_epoch,
                delegationEpoch: context.delegation_epoch,
                privacyDomainId: selection.privacyDomainId,
                actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
                resourceId: session.principal_id,
                sessionId,
                sessionEpoch: session.session_epoch,
              },
            ],
            { session: [{ id: sessionId, write: true }] },
          );
        const credential = one(
          (
            await client.query<{ credential_id: string }>(
              `select credential_id from control.credential
                where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN' and state='ACTIVE'
                  and valid_from<=clock_timestamp()
                  and (valid_until is null or valid_until>clock_timestamp())
                order by credential_id limit 1 for share`,
              [participantId, session.principal_id],
            )
          ).rows,
          'PC-AUTH-0005',
        );
        await client.query(
          `update control.session set state='REVOKED',refresh_used=true,
                  revoked_at=$3,revoked_reason='context-rotation',row_version=row_version+1,
                  updated_at=clock_timestamp()
            where participant_id=$1 and session_id=$2 and state='ACTIVE'`,
          [participantId, sessionId, now],
        );
        const nextSessionId = uuidV7();
        const nextFamilyId = uuidV7();
        const absoluteExpiresAt = new Date(now.getTime() + this.sessionTimeouts.absoluteMs);
        const idleExpiresAt = new Date(now.getTime() + this.sessionTimeouts.idleMs);
        const inserted = one(
          (
            await client.query<SessionRow>(
              `insert into control.session
                (session_id,participant_id,principal_id,context_mode,privacy_domain_id,context_epoch,
                 opaque_token_digest,state,authority_epoch,participant_epoch,delegation_epoch,session_epoch,
                 refresh_family_id,refresh_token_digest,refresh_used,csrf_secret,issued_at,last_seen_at,
                 idle_expires_at,absolute_expires_at,step_up_verified_at,client_fingerprint_digest,duration_profile,idle_timeout_ms,absolute_timeout_ms)
               values ($1,$2,$3,'PARTICIPANT',$4,$5,$6,'ACTIVE',$7,$8,$9,$10,$11,$12,false,$13,
                       $14,$14,$15,$16,$14,$17,'${this.sessionTimeouts.durationProfile ?? 'C17'}',${this.sessionTimeouts.idleMs},${this.sessionTimeouts.absoluteMs})
               returning *,authority_epoch::text,participant_epoch::text,session_epoch::text,
                         context_epoch::text`,
              [
                nextSessionId,
                participantId,
                session.principal_id,
                selection.privacyDomainId,
                nextEpoch(session.context_epoch),
                digest(`${participantId}.${nextSessionId}`),
                context.principal_epoch,
                context.participant_epoch,
                context.delegation_epoch,
                nextEpoch(session.session_epoch),
                nextFamilyId,
                digest(randomToken()),
                randomBytes(32),
                now,
                idleExpiresAt,
                absoluteExpiresAt,
                digest('server-controlled-context-selection'),
              ],
            )
          ).rows,
          'PC-AUTH-0003',
        );
        const candidateDigest = `sha256:${stableDigest({
          previousSessionId: sessionId,
          nextSessionId,
          participantId,
          privacyDomainId: selection.privacyDomainId,
          contextEpoch: inserted.context_epoch,
          signerCredentialId: credential.credential_id,
        }).toString('hex')}`;
        const evidenceCbor = createIdentityRuntimeAuthorizationAssertion(
          operationId,
          {
            participantId,
            principalId: session.principal_id,
            sessionId,
            sessionEpoch: session.session_epoch,
            sessionIssuedAt: session.issued_at,
            sessionIdleExpiresAt: session.idle_expires_at,
            sessionAbsoluteExpiresAt: session.absolute_expires_at,
            participantEpoch: context.participant_epoch,
            principalEpoch: context.principal_epoch,
            assignmentId: context.assignment_id,
            assignmentRowVersion: context.assignment_row_version,
            authorityEnvelopeId: context.authority_envelope_id,
            authorityEpoch: context.envelope_epoch,
            delegationEpoch: context.delegation_epoch,
            actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
            catalogOperationId: 'ID-OP-SESSION-CONTEXT-SELECT',
            resourceId: nextSessionId,
            candidateDigest,
            sessionToken,
          },
          now,
        );
        const signed = await (signer as IdentityRuntimeEvidenceSigner).signCanonicalAssertion(
          evidenceCbor,
        );
        await this.appendDirectSignedOutbox(
          client,
          participantId,
          selection.privacyDomainId,
          'session',
          nextSessionId,
          'openpc.identity.session.context-selected.v1',
          signed,
        );
        return sessionFromRow(inserted);
      },
      selection.privacyDomainId,
    );
  }

  async refreshBrowserSession(
    actor: AuthenticatedIdentityActor,
    reason: string,
  ): Promise<IdentityMutationCommit<SessionSnapshot>> {
    const { participantId, sessionId } = parseSessionToken(actor.sessionToken);
    return this.mutationTxWithCommit(
      actor,
      'ACT-IDENTITY_CREATE_SESSION-V1',
      'ID-OP-SESSION-REFRESH',
      'session',
      sessionId,
      { sessionId, operation: 'REFRESH', reason },
      async (client) => {
        const current = await this.activeSession(client, participantId, sessionId, true);
        if (current.refresh_used) {
          await client.query(
            `update control.session set state='COMPROMISED',revoked_at=clock_timestamp(),revoked_reason='refresh-replay'
           where participant_id=$1 and refresh_family_id=$2 and state not in ('REVOKED','COMPROMISED')`,
            [participantId, current.refresh_family_id],
          );
          throw new IdentityKernelError('PC-AUTH-0004');
        }
        const now = this.clock.now();
        await client.query(
          `update control.session set state='REVOKED',refresh_used=true,revoked_at=$3,
         revoked_reason='refresh-rotation',row_version=row_version+1,updated_at=clock_timestamp()
         where participant_id=$1 and session_id=$2`,
          [participantId, sessionId, now],
        );
        const newSessionId = uuidV7();
        const idleExpiresAt = new Date(
          Math.min(
            now.getTime() + Number(current.idle_timeout_ms ?? IDLE_TIMEOUT_MS),
            current.absolute_expires_at.getTime(),
          ),
        );
        const inserted = await client.query<SessionRow>(
          `insert into control.session
         (session_id,participant_id,principal_id,context_mode,privacy_domain_id,context_epoch,
          opaque_token_digest,state,authority_epoch,participant_epoch,
          delegation_epoch,session_epoch,refresh_family_id,refresh_token_digest,refresh_used,csrf_secret,
          issued_at,last_seen_at,idle_expires_at,absolute_expires_at,client_fingerprint_digest,duration_profile,idle_timeout_ms,absolute_timeout_ms)
         values ($1,$2,$3,$4,$5,$6,$7,'ACTIVE',$8,$9,$10,$11,$12,$13,false,$14,$15,$16,$17,$18,$19,'${current.duration_profile ?? 'C17'}',${current.idle_timeout_ms ?? IDLE_TIMEOUT_MS},${current.absolute_timeout_ms ?? ABSOLUTE_TIMEOUT_MS})
         returning *,authority_epoch::text,participant_epoch::text,session_epoch::text`,
          [
            newSessionId,
            participantId,
            current.principal_id,
            current.context_mode,
            current.privacy_domain_id,
            current.context_epoch,
            digest(`${participantId}.${newSessionId}`),
            current.authority_epoch,
            current.participant_epoch,
            current.delegation_epoch,
            nextEpoch(current.session_epoch),
            current.refresh_family_id,
            digest(randomToken()),
            randomBytes(32),
            current.issued_at,
            now,
            idleExpiresAt,
            current.absolute_expires_at,
            digest('server-controlled'),
          ],
        );
        return sessionFromRow(one(inserted.rows));
      },
    );
  }

  async revokeSession(
    actor: AuthenticatedIdentityActor,
    reason: string,
  ): Promise<IdentityOperationRecord> {
    const { participantId, sessionId } = parseSessionToken(actor.sessionToken);
    const committed = await this.mutationTxWithCommit(
      actor,
      'ACT-IDENTITY_DELETE_SESSION-V1',
      'ID-OP-SESSION-REVOKE',
      'session',
      sessionId,
      { sessionId, reason },
      async (client) => {
        const result = await client.query(
          `update control.session set state='REVOKED',session_epoch=session_epoch+1,
           revoked_at=clock_timestamp(),revoked_reason=$3,row_version=row_version+1,updated_at=clock_timestamp()
           where participant_id=$1 and session_id=$2 and state in ('ACTIVE','STEP_UP_REQUIRED','AUTHENTICATING')`,
          [participantId, sessionId, reason],
        );
        if (result.rowCount !== 1) throw new IdentityKernelError('PC-AUTH-0003');
      },
    );
    return committed.operation;
  }

  async sessionMutationContext(
    input: SessionMutationContextInput,
  ): Promise<SessionMutationContext> {
    const { participantId, sessionId } = parseSessionToken(input.sessionToken);
    const validPair =
      (input.actionIntentId === 'ACT-IDENTITY_CREATE_SESSION-V1' &&
        input.catalogOperationId === 'ID-OP-SESSION-REFRESH') ||
      (input.actionIntentId === 'ACT-IDENTITY_DELETE_SESSION-V1' &&
        input.catalogOperationId === 'ID-OP-SESSION-REVOKE');
    if (
      !validPair ||
      (input.privacyDomainId !== undefined && !UUID_V7_PATTERN.test(input.privacyDomainId)) ||
      input.idempotencyKey.length < 16 ||
      input.idempotencyKey.length > 128 ||
      !/^sha256:[0-9a-f]{64}$/u.test(input.candidateDigest)
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1009');
    }
    // A committed replay uses its original revoked session. Resolve only its
    // routing scope here; the existing command/replay checks still authenticate it.
    const privacyDomainId =
      input.privacyDomainId ??
      (await this.scopedTx(participantId, input.actionIntentId, async (client) => {
        const selected = await client.query<{ privacy_domain_id: string | null }>(
          `select coalesce(session.privacy_domain_id,participant.root_privacy_domain_id)::text privacy_domain_id
             from control.session session
             join control.participant participant on participant.participant_id=session.participant_id
            where session.participant_id=$1 and session.session_id=$2 and session.opaque_token_digest=$3`,
          [participantId, sessionId, digest(input.sessionToken)],
        );
        const value = one(selected.rows, 'PC-AUTH-0003').privacy_domain_id;
        if (value === null || !UUID_V7_PATTERN.test(value))
          throw new IdentityKernelError('PC-AUTH-0003');
        return value;
      }));
    return this.scopedPrivacyTx(
      participantId,
      privacyDomainId,
      input.actionIntentId,
      async (client) => {
        const sessionResult = await client.query<SessionRow>(
          `select *,authority_epoch::text,participant_epoch::text,delegation_epoch::text,
                session_epoch::text,row_version::text
           from control.session where participant_id=$1 and session_id=$2`,
          [participantId, sessionId],
        );
        const session = one(sessionResult.rows, 'PC-AUTH-0003');
        const now = this.clock.now();
        if (
          session.state === 'ACTIVE' &&
          sameBuffer(session.opaque_token_digest, digest(input.sessionToken)) &&
          session.idle_expires_at > now &&
          session.absolute_expires_at > now
        ) {
          const actionIntentDigest = await this.actionIntentDigest(client, input.actionIntentId);
          return {
            participantId,
            principalId: session.principal_id,
            privacyDomainId,
            expectedRevision: session.row_version,
            actionIntentDigest: `sha256:${actionIntentDigest.toString('hex')}`,
            replay: false,
          };
        }
        const replay = await this.committedSessionMutationReplayRow(client, {
          ...input,
          privacyDomainId,
        });
        if (replay.revoked_at <= new Date(now.getTime() - SESSION_MUTATION_REPLAY_GRACE_MS)) {
          throw new IdentityKernelError('PC-AUTH-0003');
        }
        const replayEpoch =
          input.catalogOperationId === 'ID-OP-SESSION-REVOKE'
            ? (BigInt(replay.session_epoch) - 1n).toString()
            : replay.session_epoch;
        return {
          participantId,
          principalId: replay.principal_id,
          privacyDomainId,
          expectedRevision: replay.expected_aggregate_version,
          actionIntentDigest: `sha256:${replay.action_intent_digest.toString('hex')}`,
          replay: true,
          replayCsrfToken: sessionCsrfToken(
            replay.csrf_secret,
            replayEpoch,
            input.actionIntentId,
            input.origin,
            input.host,
          ),
        };
      },
    );
  }

  async replayCommittedSessionMutation(
    input: SessionMutationReplayInput,
  ): Promise<SessionMutationReplay> {
    const { participantId } = parseSessionToken(input.sessionToken);
    if (!UUID_V7_PATTERN.test(input.privacyDomainId)) {
      throw new IdentityKernelError('PC-IDENTITY-1009');
    }
    return this.scopedPrivacyTx(
      participantId,
      input.privacyDomainId,
      input.actionIntentId,
      async (client) => {
        const replay = await this.committedSessionMutationReplayRow(client, input);
        if (
          input.actionIntentDigest !== `sha256:${replay.action_intent_digest.toString('hex')}` ||
          replay.expected_aggregate_version !== input.expectedRevision
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1009');
        }
        const replayEpoch =
          input.catalogOperationId === 'ID-OP-SESSION-REVOKE'
            ? (BigInt(replay.session_epoch) - 1n).toString()
            : replay.session_epoch;
        const expectedCsrf = sessionCsrfToken(
          replay.csrf_secret,
          replayEpoch,
          input.actionIntentId,
          input.origin,
          input.host,
        );
        const suppliedCsrf = Buffer.from(input.csrfToken);
        const expectedCsrfBytes = Buffer.from(expectedCsrf);
        if (
          suppliedCsrf.length !== expectedCsrfBytes.length ||
          !timingSafeEqual(suppliedCsrf, expectedCsrfBytes) ||
          !stableDigest(replay.result_payload).equals(replay.result_digest)
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1009');
        }
        const result = replay.result_payload ?? undefined;
        const committed = await this.committedMutation(
          client,
          participantId,
          replay.operation_id,
          parseSessionToken(input.sessionToken).sessionId,
          input.actionIntentId,
          replay.action_intent_digest,
          input.idempotencyKey,
          result,
        );
        let nextSessionToken: string | undefined;
        if (
          input.catalogOperationId === 'ID-OP-SESSION-REFRESH' &&
          replay.revoked_at >
            new Date(this.clock.now().getTime() - SESSION_MUTATION_REPLAY_GRACE_MS) &&
          result !== undefined &&
          typeof result === 'object' &&
          'sessionToken' in result &&
          typeof result.sessionToken === 'string'
        ) {
          const next = parseSessionToken(result.sessionToken);
          if (next.participantId !== participantId)
            throw new IdentityKernelError('PC-IDENTITY-1009');
          const nextSession = await this.activeSession(
            client,
            next.participantId,
            next.sessionId,
            false,
          );
          if (
            nextSession.principal_id !== replay.principal_id ||
            nextSession.refresh_family_id !== replay.refresh_family_id
          ) {
            throw new IdentityKernelError('PC-IDENTITY-1009');
          }
          nextSessionToken = result.sessionToken;
        }
        return {
          operation: committed.operation,
          ...(nextSessionToken === undefined ? {} : { nextSessionToken }),
        };
      },
    );
  }

  async csrfToken(
    sessionToken: string,
    actionIntentId: string,
    origin: string,
    host: string,
  ): Promise<string> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, actionIntentId, async (client) => {
      const session = await this.activeSession(client, participantId, sessionId, false);
      return sessionCsrfToken(
        session.csrf_secret,
        session.session_epoch,
        actionIntentId,
        origin,
        host,
      );
    });
  }

  async verifyCsrf(
    sessionToken: string,
    actionIntentId: string,
    origin: string,
    host: string,
    supplied: string,
  ): Promise<void> {
    const expected = await this.csrfToken(sessionToken, actionIntentId, origin, host);
    const left = Buffer.from(expected);
    const right = Buffer.from(supplied);
    if (left.length !== right.length || !timingSafeEqual(left, right)) {
      throw new IdentityKernelError('PC-AUTH-0001');
    }
  }

  async issueStepUpChallenge(
    actor: AuthenticatedIdentityActor,
    actionIntentId: string,
    resourceDigest: string,
    rpIdHash: string,
  ): Promise<{ challenge: string }> {
    const { participantId, sessionId } = parseSessionToken(actor.sessionToken);
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WEBAUTHN-REGISTER',
      'webauthn-registration',
      sessionId,
      { actionIntentId, resourceDigest, rpIdHash },
      async (client) => {
        const session = await this.activeSession(client, participantId, sessionId, false);
        const challenge = randomToken();
        await client.query(
          `insert into control.mfa_challenge
           (participant_id,session_id,principal_id,action_intent_id,resource_digest,challenge_digest,rp_id_hash,expires_at)
           values ($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '5 minutes')`,
          [
            participantId,
            sessionId,
            session.principal_id,
            actionIntentId,
            Buffer.from(resourceDigest.slice(7), 'hex'),
            digest(challenge),
            Buffer.from(rpIdHash.slice(7), 'hex'),
          ],
        );
        return { challenge };
      },
    );
  }

  async issueStepUpAssertionChallenge(
    sessionToken: string,
    actionIntentId: string,
    resourceDigest: string,
    rpIdHash: string,
    resourceId?: string,
  ): Promise<StepUpChallenge> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, actionIntentId, async (client) => {
      const session = await this.activeSession(client, participantId, sessionId, true);
      const credentials = await client.query<{ credential_id: string }>(
        `select coalesce(subject,credential_id::text) credential_id from control.credential
          where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN' and state='ACTIVE'
            and public_key_spki_der is not null and valid_from<=clock_timestamp()
            and (valid_until is null or valid_until>clock_timestamp())
          order by credential_id`,
        [participantId, session.principal_id],
      );
      if (credentials.rowCount === 0) throw new IdentityKernelError('PC-AUTH-0006');

      await client.query(
        `update control.mfa_challenge set expires_at=clock_timestamp(),row_version=row_version+1
          where participant_id=$1 and session_id=$2 and principal_id=$3 and action_intent_id=$4
            and resource_digest=$5 and consumed_at is null and used_at is null
            and expires_at>clock_timestamp()`,
        [
          participantId,
          sessionId,
          session.principal_id,
          actionIntentId,
          Buffer.from(resourceDigest.slice(7), 'hex'),
        ],
      );
      const qaChallenge =
        session.duration_profile === 'LOCAL_QA_10X' &&
        localQaDurationMultiplier(process.env) === 10;
      const challengeExpiresAt = new Date(
        Math.min(
          this.clock.now().getTime() + (qaChallenge ? 3_000_000 : 300_000),
          session.idle_expires_at.getTime(),
          session.absolute_expires_at.getTime(),
        ),
      );
      const challenge = randomToken();
      await client.query(
        `insert into control.mfa_challenge
         (participant_id,session_id,principal_id,action_intent_id,resource_digest,challenge_digest,rp_id_hash,expires_at,resource_id,verified_proof_max_age_ms)
         values ($1,$2,$3,$4,$5,$6,$7,$9,$8,$10)`,
        [
          participantId,
          sessionId,
          session.principal_id,
          actionIntentId,
          Buffer.from(resourceDigest.slice(7), 'hex'),
          digest(challenge),
          Buffer.from(rpIdHash.slice(7), 'hex'),
          resourceId ?? null,
          challengeExpiresAt,
          qaChallenge ? 3_000_000 : 300_000,
        ],
      );
      return {
        challenge,
        expiresAt: challengeExpiresAt.toISOString(),
        ...(qaChallenge ? { durationProfile: 'LOCAL_QA_10X' as const } : {}),
        credentialIds: credentials.rows.map((credential) => credential.credential_id),
      };
    });
  }

  async verifyStepUp(actor: AuthenticatedIdentityActor, proof: StepUpProof): Promise<void> {
    const { participantId, sessionId } = parseSessionToken(proof.sessionToken);
    this.owns(actor, participantId);
    let authorizationCandidate: StepUpAuthorizationCandidate;
    try {
      authorizationCandidate = stepUpAuthorizationCandidate(proof);
    } catch {
      throw new IdentityKernelError('PC-AUTH-0006');
    }
    const assertion = proof.verifiedAssertion;
    if (
      assertion.principalId !== actor.principalId ||
      assertion.sessionId !== sessionId ||
      assertion.actionIntentId !== proof.actionIntentId ||
      assertion.resourceDigest !== proof.resourceDigest ||
      assertion.challengeDigest !== `sha256:${digest(proof.challenge).toString('hex')}` ||
      assertion.rpIdHash !== proof.rpIdHash
    ) {
      throw new IdentityKernelError('PC-AUTH-0006');
    }
    await this.mutationTx(
      actor,
      'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      'ID-OP-WEBAUTHN-VERIFY',
      'webauthn-verification',
      sessionId,
      authorizationCandidate,
      async (client, operationId) => {
        const session = await this.activeSession(client, participantId, sessionId, true);
        const challenge = await client.query<{ mfa_challenge_id: string }>(
          `select mfa_challenge_id from control.mfa_challenge
           where participant_id=$1 and session_id=$2 and principal_id=$3 and action_intent_id=$4
           and resource_digest=$5 and challenge_digest=$6 and rp_id_hash=$7
           and resource_id is not distinct from $8::text
           and consumed_at is null and expires_at>clock_timestamp() for update`,
          [
            participantId,
            sessionId,
            session.principal_id,
            proof.actionIntentId,
            Buffer.from(proof.resourceDigest.slice(7), 'hex'),
            digest(proof.challenge),
            Buffer.from(proof.rpIdHash.slice(7), 'hex'),
            proof.resourceId ?? null,
          ],
        );
        const challengeId = one(challenge.rows, 'PC-AUTH-0006').mfa_challenge_id;
        const credential = one(
          (
            await client.query<{
              authenticator_sign_count: string;
              credential_epoch: string;
              public_key_digest: Buffer;
              public_key_spki_der: Buffer;
            }>(
              `select authenticator_sign_count::text,credential_epoch::text,public_key_digest,public_key_spki_der
                 from control.credential
                where participant_id=$1 and principal_id=$2 and credential_id=$3
                  and kind='WEBAUTHN' and state='ACTIVE'
                  and valid_from<=clock_timestamp() and (valid_until is null or valid_until>clock_timestamp())
                  and $4::timestamptz>clock_timestamp()-interval '5 minutes'
                  and $4::timestamptz<=clock_timestamp()+interval '5 seconds' for update`,
              [participantId, session.principal_id, assertion.credentialId, assertion.verifiedAt],
            )
          ).rows,
          'PC-AUTH-0006',
        );
        if (
          assertion.credentialPublicKeyDigest !==
            `sha256:${credential.public_key_digest.toString('hex')}` ||
          !digest(credential.public_key_spki_der).equals(credential.public_key_digest) ||
          (BigInt(assertion.signCount) !== 0n &&
            BigInt(assertion.signCount) <= BigInt(credential.authenticator_sign_count))
        ) {
          throw new IdentityKernelError('PC-AUTH-0006');
        }
        await client.query(
          `update control.credential set authenticator_sign_count=$4,last_used_at=clock_timestamp(),
             row_version=row_version+1,updated_at=clock_timestamp()
            where participant_id=$1 and principal_id=$2 and credential_id=$3`,
          [participantId, session.principal_id, assertion.credentialId, assertion.signCount],
        );
        // Keep the exact PostgreSQL microsecond timestamp inside the original
        // verification transaction. A JS Date round trip loses that binding.
        const verification = one(
          (
            await client.query<{ challenge_count: number; session_count: number }>(
              `with consumed as (
                 update control.mfa_challenge set consumed_at=clock_timestamp(),row_version=row_version+1,
                   signer_credential_id=$4,signer_credential_epoch=$5
                 where participant_id=$1 and session_id=$2 and mfa_challenge_id=$3
                   and principal_id=$6 and consumed_at is null and used_at is null
                   and expires_at>clock_timestamp()
                 returning mfa_challenge_id,principal_id,consumed_at
               ), receiving as (
                 update control.session session set state='ACTIVE',step_up_verified_at=consumed.consumed_at,
                   step_up_mfa_challenge_id=consumed.mfa_challenge_id,
                   row_version=session.row_version+1,updated_at=clock_timestamp()
                 from consumed where session.participant_id=$1 and session.session_id=$2
                   and session.principal_id=consumed.principal_id
                   and session.state='ACTIVE' and session.idle_expires_at>clock_timestamp()
                   and session.absolute_expires_at>clock_timestamp()
                 returning session.session_id
               ) select (select count(*)::integer from consumed) challenge_count,
                        (select count(*)::integer from receiving) session_count`,
              [
                participantId,
                sessionId,
                challengeId,
                assertion.credentialId,
                credential.credential_epoch,
                session.principal_id,
              ],
            )
          ).rows,
          'PC-AUTH-0006',
        );
        if (verification.challenge_count !== 1 || verification.session_count !== 1)
          throw new IdentityKernelError('PC-AUTH-0006');
        await appendAuthenticationOccurrence(client, {
          sessionId,
          operationId,
          method: 'WEBAUTHN_ASSERTION',
          sourceId: challengeId,
          credentialId: assertion.credentialId,
          proofDigest: verifiedWebAuthnAssertionDigest(assertion),
          occurredAt: this.clock.now(),
        });
        return { challengeId };
      },
      async () => ({ credential: [{ id: assertion.credentialId, write: true }] }),
      assertion,
    );
  }

  async requireFreshStepUp(sessionToken: string): Promise<void> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    await this.scopedTx(participantId, 'ACT-IDENTITY_UPDATE_STEP_UP-V1', async (client) => {
      const session = await this.activeSession(client, participantId, sessionId, false);
      const stepUpSourceId = session.step_up_mfa_challenge_id;
      if (stepUpSourceId !== null && stepUpSourceId !== undefined) {
        await this.assertPinnedStepUpCurrent(client, session);
        return;
      }
      if (
        session.step_up_verified_at === null ||
        session.step_up_verified_at.getTime() + STEP_UP_MAX_AGE_MS <= this.clock.now().getTime()
      ) {
        throw new IdentityKernelError('PC-AUTH-0005');
      }
    });
  }

  private async assertPinnedStepUpCurrent(client: PoolClient, session: SessionRow): Promise<void> {
    const stepUpSourceId = session.step_up_mfa_challenge_id;
    if (stepUpSourceId === null || stepUpSourceId === undefined) return;
    const result = await client.query<{ fresh: boolean | null }>(
      `select openpc.session_step_up_valid_until($1::uuid,$2::uuid,$3::uuid)>clock_timestamp() fresh`,
      [session.participant_id, session.session_id, session.principal_id],
    );
    if (result.rowCount !== 1 || result.rows[0]?.fresh !== true)
      throw new IdentityKernelError('PC-AUTH-0005');
  }

  async sessionAggregateVersion(sessionToken: string): Promise<string> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, 'ACT-IDENTITY_UPDATE_STEP_UP-V1', async (client) => {
      await this.activeSession(client, participantId, sessionId, false);
      const result = await client.query<{ row_version: string }>(
        `select row_version::text from control.session
          where participant_id=$1 and session_id=$2`,
        [participantId, sessionId],
      );
      return one(result.rows, 'PC-AUTH-0003').row_version;
    });
  }

  async webAuthnCredentialAggregateVersion(
    sessionToken: string,
    credentialId: string,
  ): Promise<string> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, 'ACT-IDENTITY_UPDATE_STEP_UP-V1', async (client) => {
      const session = await this.activeSession(client, participantId, sessionId, false);
      if (session.context_mode !== 'PARTICIPANT') throw new IdentityKernelError('PC-AUTH-0006');
      const result = await client.query<{ row_version: string }>(
        `select credential_epoch::text as row_version from control.credential
          where participant_id=$1 and principal_id=$2 and credential_id=$3
            and kind='WEBAUTHN' and state='ACTIVE'
            and valid_from<=clock_timestamp()
            and (valid_until is null or valid_until>clock_timestamp())`,
        [participantId, session.principal_id, credentialId],
      );
      return one(result.rows, 'PC-AUTH-0006').row_version;
    });
  }

  async actionIntentSemanticDigest(sessionToken: string, actionIntentId: string): Promise<string> {
    const { participantId, sessionId } = parseSessionToken(sessionToken);
    return this.scopedTx(participantId, actionIntentId, async (client) => {
      await this.activeSession(client, participantId, sessionId, false);
      const result = await client.query<{ semantic_digest: Buffer }>(
        `select semantic_digest from control.action_intent where action_intent_id=$1`,
        [actionIntentId],
      );
      return `sha256:${one(result.rows, 'PC-IDENTITY-1004').semantic_digest.toString('hex')}`;
    });
  }

  async provisionPrincipal(actor: AuthenticatedIdentityActor, principal: PrincipalRecord) {
    this.owns(actor, principal.participantId);
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      'ID-OP-PRINCIPAL-PROVISION',
      'principal',
      principal.principalId,
      principal,
      async (client) => {
        if (actor.principalId === principal.principalId) {
          throw new IdentityKernelError('PC-IDENTITY-1005');
        }
        const inserted = await client.query<{
          principal_id: string;
          participant_id: string;
          display_label: string;
          kind: PrincipalRecord['kind'];
          state: PrincipalRecord['state'];
          authority_epoch: string;
        }>(
          `insert into control.principal
           (principal_id,participant_id,kind,display_label,state,authority_epoch)
           values ($1,$2,$3,$4,'PROVISIONED',$5)
           returning principal_id,participant_id,display_label,kind,state,authority_epoch::text`,
          [
            principal.principalId,
            principal.participantId,
            principal.kind,
            principal.displayLabel,
            principal.identityEpoch,
          ],
        );
        await createInitialHumanMembership(client, principal);
        return this.principalFromRow(one(inserted.rows));
      },
    );
  }

  async activatePrincipal(actor: AuthenticatedIdentityActor, principalId: string) {
    this.owns(actor, actor.participantId);
    if (actor.principalId === principalId) throw new IdentityKernelError('PC-IDENTITY-1005');
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-PRINCIPAL-ACTIVATE',
      'principal',
      principalId,
      { principalId, state: 'ACTIVE' },
      (client) => activatePrincipal(client, actor.participantId, principalId),
      async () => ({ principal: [{ id: principalId, write: true }] }),
    );
  }

  async principalReadback(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
  ): Promise<PrincipalReadback> {
    return this.identityScopedRead(actor, principalId, authority, (client) =>
      readPrincipal(client, actor.participantId, authority.privacyDomainId, principalId),
    );
  }

  async resolveIdentitySubjectMembership(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    subjectId: string,
  ) {
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) => resolveSubjectMembership(client, actor.participantId, subjectId),
    );
  }

  async identitySubjectReadback(
    actor: AuthenticatedIdentityActor,
    membershipId: string,
    subjectId: string,
    authority: BoundAuthority,
  ) {
    return this.identityScopedRead(actor, membershipId, authority, (client) =>
      readIdentitySubject(
        client,
        actor.participantId,
        authority.privacyDomainId,
        membershipId,
        subjectId,
      ),
    );
  }

  async resolvePrincipalProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    candidateDigest: string,
  ) {
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) =>
        resolvePrincipalProposal(client, actor.participantId, privacyDomainId, candidateDigest),
    );
  }

  async principalProposal(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
    candidateDigest: string,
  ) {
    return this.identityScopedRead(actor, principalId, authority, (client) =>
      readPrincipalProposal(
        client,
        actor.participantId,
        authority.privacyDomainId,
        principalId,
        candidateDigest,
      ),
    );
  }

  async webAuthnCredentials(
    actor: AuthenticatedIdentityActor,
    authority: BoundAuthority,
    cursor?: string,
  ) {
    return this.identityScopedRead(actor, actor.principalId, authority, (client) =>
      readWebAuthnCredentials(client, actor.participantId, actor.principalId, cursor),
    );
  }

  async resolveWebAuthnProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) =>
        resolveWebAuthnProposal(
          client,
          actor.participantId,
          privacyDomainId,
          candidateDigest,
          binding,
        ),
    );
  }

  async webAuthnProposal(
    actor: AuthenticatedIdentityActor,
    resourceId: string,
    authority: BoundAuthority,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.identityScopedRead(actor, resourceId, authority, (client) =>
      readWebAuthnProposal(
        client,
        actor.participantId,
        authority.privacyDomainId,
        resourceId,
        candidateDigest,
        binding,
      ),
    );
  }

  async resolveWorkloadProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) =>
        resolveWorkloadProposal(
          client,
          actor.participantId,
          privacyDomainId,
          candidateDigest,
          binding,
        ),
    );
  }

  async workloadProposal(
    actor: AuthenticatedIdentityActor,
    resourceId: string,
    authority: BoundAuthority,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
    preapproval?: { readonly recoveryId: string; readonly enrollmentId: string },
  ) {
    return this.identityScopedRead(actor, resourceId, authority, (client) =>
      readWorkloadProposal(
        client,
        actor.participantId,
        authority.privacyDomainId,
        resourceId,
        candidateDigest,
        binding,
        preapproval ? { authority, ...preapproval } : undefined,
      ),
    );
  }

  async workloadCertificate(
    actor: AuthenticatedIdentityActor,
    credentialId: string,
    authority: BoundAuthority,
  ) {
    return this.identityScopedRead(actor, credentialId, authority, (client) =>
      readWorkloadCertificate(client, actor.participantId, credentialId),
    );
  }

  async walletBinding(
    actor: AuthenticatedIdentityActor,
    walletBindingId: string,
    authority: BoundAuthority,
  ) {
    return this.identityScopedRead(actor, walletBindingId, authority, (client) =>
      readWalletBinding(client, actor.participantId, authority.privacyDomainId, walletBindingId),
    );
  }

  async createWalletBinding(actor: AuthenticatedIdentityActor, input: WalletBindingCreation) {
    const proof = actor.mutationAuthorization;
    if (!proof || proof.aggregateVersion !== '0') throw new IdentityKernelError('PC-IDENTITY-1005');
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WALLET-BINDING-CREATE',
      'wallet-binding',
      input.walletBindingId,
      { ...input, participantId: actor.participantId },
      (client, operationId) =>
        createWalletBinding(client, actor.participantId, proof.privacyDomainId, operationId, input),
      async () => ({ principal: [{ id: input.subjectId }] }),
    );
  }

  async revokeWalletBinding(actor: AuthenticatedIdentityActor, walletBindingId: string) {
    const proof = actor.mutationAuthorization;
    if (!proof) throw new IdentityKernelError('PC-IDENTITY-1005');
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WALLET-BINDING-REVOKE',
      'wallet-binding',
      walletBindingId,
      { walletBindingId, state: 'REVOKED' },
      async (client, operationId) => {
        const result = await revokeWalletBinding(
          client,
          actor.participantId,
          proof.privacyDomainId,
          operationId,
          walletBindingId,
          proof.aggregateVersion,
        );
        await client.query(
          `update control.principal set authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
          where participant_id=$1 and principal_id=$2`,
          [actor.participantId, result.subjectId],
        );
        await client.query(
          `update control.session set state='REVOKED',session_epoch=session_epoch+1,
           revoked_at=clock_timestamp(),revoked_reason='wallet-binding-revoked',
           row_version=row_version+1,updated_at=clock_timestamp()
          where participant_id=$1 and principal_id=$2 and state in ('ACTIVE','STEP_UP_REQUIRED')`,
          [actor.participantId, result.subjectId],
        );
        return result;
      },
      async (client) => {
        const target = await client.query<{ subject_id: string }>(
          `select subject_id from control.wallet_binding
          where participant_id=$1 and privacy_domain_id=$2 and wallet_binding_id=$3`,
          [actor.participantId, proof.privacyDomainId, walletBindingId],
        );
        if (target.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
        return principalInvalidationFence(
          client,
          actor.participantId,
          target.rows[0]!.subject_id,
          false,
        );
      },
    );
  }

  async resolveRecoveryProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.scopedPrivacyTx(
      actor.participantId,
      privacyDomainId,
      'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      (client) =>
        resolveRecoveryProposal(
          client,
          actor.participantId,
          privacyDomainId,
          candidateDigest,
          binding,
        ),
    );
  }

  async recoveryProposal(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.identityScopedRead(actor, principalId, authority, (client) =>
      readRecoveryProposal(
        client,
        actor.participantId,
        authority.privacyDomainId,
        principalId,
        candidateDigest,
        binding,
      ),
    );
  }

  principalCatalogueCandidates(
    actor: AuthenticatedIdentityActor,
    authority: BoundAuthority,
    query: PrincipalCatalogueQuery,
  ) {
    return this.identityScopedRead(
      actor,
      actor.participantId,
      authority,
      (client) =>
        principalCatalogueCandidates(
          client,
          actor.participantId,
          actor.principalId,
          authority.privacyDomainId,
          query,
        ),
      'ACT-PARTICIPANTS_READ_COLLECTION-V1',
    );
  }

  fencePrincipalCatalogue(actor: AuthenticatedIdentityActor, authority: BoundAuthority) {
    return this.identityScopedRead(
      actor,
      actor.participantId,
      authority,
      async () => undefined,
      'ACT-PARTICIPANTS_READ_COLLECTION-V1',
    );
  }

  private async identityScopedRead<T>(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
    read: (client: PoolClient) => Promise<T>,
    actionIntentId = 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  ): Promise<T> {
    const session = parseSessionToken(actor.sessionToken);
    if (
      authority.principalId !== actor.principalId ||
      authority.sessionId !== session.sessionId ||
      session.participantId !== actor.participantId ||
      authority.actionIntentId !== actionIntentId ||
      authority.resourceId !== principalId
    )
      throw new IdentityKernelError('PC-IDENTITY-1008');
    return this.scopedPrivacyTx(
      actor.participantId,
      authority.privacyDomainId,
      authority.actionIntentId,
      async (client) => {
        await fenceBoundAuthorities(client, actor.participantId, [authority]);
        return read(client);
      },
    );
  }

  async removeMembership(actor: AuthenticatedIdentityActor, principalId: string) {
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-MEMBERSHIP-REMOVE',
      'principal',
      principalId,
      { principalId, state: 'OFFBOARDED' },
      (client, operationId) =>
        removeMembership(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          principalId,
          actor.principalId,
          operationId,
        ),
      (client) => membershipRemovalFence(client, actor.participantId, principalId),
    );
  }

  async suspendPrincipal(actor: AuthenticatedIdentityActor, principalId: string) {
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-PRINCIPAL-SUSPEND',
      'principal',
      principalId,
      { principalId, state: 'SUSPENDED' },
      async (client) => {
        if (actor.principalId === principalId) throw new IdentityKernelError('PC-IDENTITY-1005');
        const result = await client.query<{
          principal_id: string;
          participant_id: string;
          display_label: string;
          kind: PrincipalRecord['kind'];
          state: PrincipalRecord['state'];
          authority_epoch: string;
        }>(
          `update control.principal set state='SUSPENDED',authority_epoch=authority_epoch+1,
           row_version=row_version+1,updated_at=clock_timestamp()
           where participant_id=$1 and principal_id=$2 and state='ACTIVE'
           returning principal_id,participant_id,display_label,kind,state,authority_epoch::text`,
          [actor.participantId, principalId],
        );
        const value = this.principalFromRow(one(result.rows, 'PC-IDENTITY-1002'));
        await client.query(
          `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='principal-suspended'
           where participant_id=$1 and principal_id=$2 and state in ('ACTIVE','STEP_UP_REQUIRED')`,
          [actor.participantId, principalId],
        );
        return value;
      },
      (client) => principalInvalidationFence(client, actor.participantId, principalId, false),
    );
  }

  validateWorkloadCredential(input: WorkloadCredentialInput): void {
    const workloadUuid = input.workloadId.split(':').at(-1) ?? '';
    const expectedSan = `urn:openpc:participant:${input.participantId}:workload:${workloadUuid}`;
    const lifetime = input.notAfter.getTime() - input.notBefore.getTime();
    if (
      input.tlsVersion !== 'TLS1.3' ||
      input.uriSan !== expectedSan ||
      !/^sha256:[0-9a-f]{64}$/u.test(input.keyId) ||
      !Buffer.isBuffer(input.certificateFingerprint) ||
      input.certificateFingerprint.length !== 32 ||
      !/^(?:0|[1-9][0-9]*)$/u.test(input.participantEpoch) ||
      !/^(?:0|[1-9][0-9]*)$/u.test(input.workloadEpoch) ||
      !Number.isFinite(input.notBefore.getTime()) ||
      !Number.isFinite(input.notAfter.getTime()) ||
      lifetime <= 0 ||
      lifetime > WORKLOAD_MAX_LIFETIME_MS ||
      input.notBefore > this.clock.now() ||
      input.notAfter <= this.clock.now() ||
      !input.issuerTrusted ||
      !input.keyTrusted ||
      input.revoked ||
      BigInt(input.participantEpoch) > 18_446_744_073_709_551_615n ||
      BigInt(input.workloadEpoch) > 18_446_744_073_709_551_615n
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1006');
    }
  }

  async authenticateWorkload(
    input: WorkloadCredentialInput,
    runtimeContext?: RuntimePublicationContext,
    transport?: PresentedCertificate,
  ): Promise<AuthenticatedWorkloadIdentity> {
    this.validateWorkloadCredential(input);
    const transportProof =
      transport === undefined
        ? undefined
        : consumeWorkloadTransportProof(transport, input, runtimeContext);
    if (
      runtimeContext !== undefined &&
      (!UUID_V7_PATTERN.test(runtimeContext.privacyDomainId) ||
        !UUID_V7_PATTERN.test(runtimeContext.targetRuntimeId) ||
        this.runtimeSnapshotPublisher === undefined)
    )
      throw new IdentityKernelError('PC-IDENTITY-1006');
    return this.transaction(
      input.participantId,
      'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      async (client, operationId) => {
        // Resolve identities only, then lock in the shared authority order and
        // revalidate all credential facts. A prior TLS lookup grants no lease
        // across a concurrent credential replacement or principal suspension.
        const dependency = one(
          (
            await client.query<{ credential_id: string; principal_id: string }>(
              `select credential_id,principal_id from control.credential
                where participant_id=$1 and kind='WORKLOAD_MTLS'
                  and subject=$2 and audience=$3 and state='ACTIVE'`,
              [input.participantId, input.uriSan, input.workloadId],
            )
          ).rows,
          'PC-IDENTITY-1006',
        );
        await lockAuthorityFence(client, input.participantId, {
          participant: [{ id: input.participantId, write: runtimeContext !== undefined }],
          principal: [{ id: dependency.principal_id }],
          credential: [{ id: dependency.credential_id, write: true }],
        });
        const result = await client.query<{
          credential_id: string;
          principal_id: string;
          participant_id: string;
          workload_id: string;
          participant_epoch: string;
          principal_epoch: string;
          workload_epoch: string;
          key_id: Buffer;
          uri_san: string;
          not_before: Date;
          not_after: Date;
        }>(
          `update control.credential credential
              set last_used_at=clock_timestamp(),updated_at=clock_timestamp()
             from control.participant participant,control.principal principal
            where credential.participant_id=$1 and credential.kind='WORKLOAD_MTLS'
              and credential.state='ACTIVE' and credential.subject=$2 and credential.audience=$3
              and credential.public_key_digest=$4 and credential.credential_epoch=$5
              and credential.secret_fingerprint=$9 and credential.credential_id=$10
              and credential.principal_id=$11
              and credential.valid_from=$6 and credential.valid_until=$7
              and credential.valid_from<=clock_timestamp() and credential.valid_until>clock_timestamp()
              and participant.participant_id=credential.participant_id and participant.state='ACTIVE'
              and participant.authority_epoch=$8
              and principal.participant_id=credential.participant_id
              and principal.principal_id=credential.principal_id
              and principal.kind='WORKLOAD' and principal.state='ACTIVE'
          returning credential.credential_id,credential.principal_id,credential.participant_id,
                    credential.audience workload_id,participant.authority_epoch::text participant_epoch,
                    principal.authority_epoch::text principal_epoch,
                    credential.credential_epoch::text workload_epoch,
                    credential.public_key_digest key_id,credential.subject uri_san,
                    credential.valid_from not_before,credential.valid_until not_after`,
          [
            input.participantId,
            input.uriSan,
            input.workloadId,
            Buffer.from(input.keyId.slice(7), 'hex'),
            input.workloadEpoch,
            input.notBefore,
            input.notAfter,
            input.participantEpoch,
            input.certificateFingerprint,
            dependency.credential_id,
            dependency.principal_id,
          ],
        );
        const row = one(result.rows, 'PC-IDENTITY-1006');
        const identity: AuthenticatedWorkloadIdentity = {
          credentialId: row.credential_id,
          principalId: row.principal_id,
          participantId: row.participant_id,
          workloadId: row.workload_id,
          participantEpoch: row.participant_epoch,
          principalEpoch: row.principal_epoch,
          workloadEpoch: row.workload_epoch,
          keyId: `sha256:${row.key_id.toString('hex')}`,
          uriSan: row.uri_san,
          notBefore: row.not_before,
          notAfter: row.not_after,
        };
        if (transportProof !== undefined)
          await appendWorkloadAuthenticationOccurrence(client, {
            credentialId: row.credential_id,
            operationId,
            proofDigest: transportProof,
          });
        if (runtimeContext === undefined) return identity;
        const runtime = await this.runtimeSnapshotPublisher!.publishForAuthenticatedWorkload(
          client,
          runtimeContext,
          { ...identity, certificateFingerprint: input.certificateFingerprint },
        );
        return { ...identity, runtime };
      },
      runtimeContext?.privacyDomainId,
    );
  }

  async issueWorkload(actor: AuthenticatedIdentityActor, credential: WorkloadRecord) {
    this.owns(actor, credential.participantId);
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WORKLOAD-ISSUE',
      'workload-credential',
      credential.credentialId,
      credential,
      async (client) => {
        const lifetime = credential.notAfter.getTime() - credential.notBefore.getTime();
        if (
          credential.state !== 'ISSUED' ||
          !/^sha256:[0-9a-f]{64}$/u.test(credential.keyId) ||
          credential.uriSan !==
            `urn:openpc:participant:${credential.participantId}:workload:${credential.workloadId.split(':').at(-1) ?? ''}` ||
          !Number.isFinite(lifetime) ||
          lifetime <= 0 ||
          lifetime > WORKLOAD_MAX_LIFETIME_MS ||
          credential.issuer === undefined ||
          credential.certificateFingerprint?.length !== 32 ||
          credential.publicKeySpkiDer === undefined ||
          !digest(credential.publicKeySpkiDer).equals(Buffer.from(credential.keyId.slice(7), 'hex'))
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1006');
        }
        await this.activePrincipal(
          client,
          credential.participantId,
          credential.principalId,
          'WORKLOAD',
        );
        const result = await client.query(
          `insert into control.credential
           (credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,
            public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
           values ($1,$2,$3,'WORKLOAD_MTLS',$4,$5,$6,$7,$8,$9,'ACTIVE',$10,$11,$12)
           returning credential_id`,
          [
            credential.credentialId,
            credential.participantId,
            credential.principalId,
            credential.issuer,
            credential.uriSan,
            credential.workloadId,
            Buffer.from(credential.keyId.slice(7), 'hex'),
            credential.publicKeySpkiDer,
            credential.certificateFingerprint,
            credential.workloadEpoch,
            credential.notBefore,
            credential.notAfter,
          ],
        );
        one(result.rows, 'PC-IDENTITY-1006');
        return { ...credential, state: 'ACTIVE' as const };
      },
      async () => ({ principal: [{ id: credential.principalId }] }),
    );
  }

  async issueWorkloadFromIssuer(
    actor: AuthenticatedIdentityActor,
    request: WorkloadCertificateRequest,
    issuer: WorkloadCredentialIssuer,
  ) {
    this.owns(actor, request.participantId);
    const candidate = {
      credentialId: request.credentialId,
      participantId: request.participantId,
      principalId: request.principalId,
      workloadId: request.workloadId,
      publicKeySpkiDer: request.publicKeySpkiDer.toString('base64'),
    };
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WORKLOAD-ISSUE',
      'workload-credential',
      request.credentialId,
      candidate,
      async (client) => {
        await this.activePrincipal(client, request.participantId, request.principalId, 'WORKLOAD');
        let issued;
        try {
          issued = await issuer.issue(request);
        } catch {
          throw new IdentityKernelError('PC-IDENTITY-1006');
        }
        if (
          issued.credentialId !== request.credentialId ||
          issued.participantId !== request.participantId ||
          issued.principalId !== request.principalId ||
          issued.workloadId !== request.workloadId ||
          !issued.publicKeySpkiDer.equals(request.publicKeySpkiDer) ||
          !Buffer.isBuffer(issued.certificateDer) ||
          !digest(issued.certificateDer).equals(issued.certificateFingerprint) ||
          issued.certificateFingerprint.length !== 32 ||
          !/^sha256:[0-9a-f]{64}$/u.test(issued.keyId) ||
          !digest(issued.publicKeySpkiDer).equals(Buffer.from(issued.keyId.slice(7), 'hex')) ||
          issued.uriSan !==
            `urn:openpc:participant:${request.participantId}:workload:${request.workloadId.split(':').at(-1) ?? ''}` ||
          issued.notBefore > this.clock.now() ||
          issued.notAfter <= this.clock.now() ||
          issued.notAfter.getTime() - issued.notBefore.getTime() > WORKLOAD_MAX_LIFETIME_MS
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1006');
        }
        const inserted = await client.query(
          `insert into control.credential
            (credential_id,participant_id,principal_id,kind,issuer,subject,audience,
             public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,
             valid_from,valid_until,certificate_der)
           values ($1,$2,$3,'WORKLOAD_MTLS',$4,$5,$6,$7,$8,$9,'ACTIVE',1,$10,$11,$12)
           returning credential_id`,
          [
            request.credentialId,
            request.participantId,
            request.principalId,
            issued.issuer,
            issued.uriSan,
            issued.workloadId,
            Buffer.from(issued.keyId.slice(7), 'hex'),
            issued.publicKeySpkiDer,
            issued.certificateFingerprint,
            issued.notBefore,
            issued.notAfter,
            issued.certificateDer,
          ],
        );
        one(inserted.rows, 'PC-IDENTITY-1006');
        return {
          credentialId: request.credentialId,
          principalId: request.principalId,
          participantId: request.participantId,
          workloadId: request.workloadId,
          state: 'ACTIVE' as const,
          workloadEpoch: '1',
          keyId: issued.keyId,
          uriSan: issued.uriSan,
          notBefore: issued.notBefore,
          notAfter: issued.notAfter,
          issuer: issued.issuer,
          certificateFingerprint: `sha256:${issued.certificateFingerprint.toString('hex')}`,
        };
      },
      async () => ({ principal: [{ id: request.principalId }] }),
    );
  }

  async rotateWorkload(actor: AuthenticatedIdentityActor, credentialId: string) {
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WORKLOAD-ROTATE',
      'workload-credential',
      credentialId,
      { credentialId, state: 'ROTATING' },
      async (client) => {
        const result = await client.query(
          `update control.credential set state='ROTATING',credential_epoch=credential_epoch+1,
           row_version=row_version+1,updated_at=clock_timestamp()
           where participant_id=$1 and credential_id=$2 and kind='WORKLOAD_MTLS' and state='ACTIVE'
           returning credential_id`,
          [actor.participantId, credentialId],
        );
        one(result.rows, 'PC-IDENTITY-1006');
        return { credentialId, state: 'ROTATING' as const };
      },
      async () => ({ credential: [{ id: credentialId, write: true }] }),
    );
  }

  async rotateWorkloadFromIssuer(
    actor: AuthenticatedIdentityActor,
    replacedCredentialId: string,
    credentialId: string,
    publicKeySpkiDer: Buffer,
    issuer: WorkloadCredentialIssuer,
  ) {
    const candidate = {
      replacedCredentialId,
      credentialId,
      publicKeySpkiDer: publicKeySpkiDer.toString('base64'),
    };
    const readRotation = async (client: PoolClient): Promise<WorkloadRotationEffectInput> => {
      const current = one(
        (
          await client.query<{
            principal_id: string;
            audience: string;
            credential_epoch: string;
          }>(
            `select principal_id,audience,credential_epoch::text from control.credential
                where participant_id=$1 and credential_id=$2 and kind='WORKLOAD_MTLS'
                  and state='ACTIVE'
                for update`,
            [actor.participantId, replacedCredentialId],
          )
        ).rows,
        'PC-IDENTITY-1006',
      );
      await this.activePrincipal(client, actor.participantId, current.principal_id, 'WORKLOAD');
      return {
        participantId: actor.participantId,
        replacedCredentialId,
        credentialId,
        principalId: current.principal_id,
        workloadId: current.audience,
        predecessorEpoch: current.credential_epoch,
        publicKeySpkiDer,
      };
    };
    const readWrites = async (client: PoolClient) => {
      const target = await client.query<{ principal_id: string }>(
        `select principal_id from control.credential where participant_id=$1 and credential_id=$2 and kind='WORKLOAD_MTLS'`,
        [actor.participantId, replacedCredentialId],
      );
      return {
        credential: [{ id: replacedCredentialId, write: true }],
        principal: target.rows.map((row) => ({ id: row.principal_id })),
      };
    };
    if (actor.platform) {
      // The authenticated actor flag selects a path only. Shared admission and
      // the preparation SQL independently establish the actual Platform session,
      // selected exact discovery purpose, current custody and maker/checker.
      const recovery = issuer.recovery;
      const proof = actor.mutationAuthorization;
      if (!recovery || !proof) throw new IdentityKernelError('PC-IDENTITY-1006');
      const admitted = await this.admittedMutation<never, DiscoveryCertificatePreparation>(
        actor,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-WORKLOAD-ROTATE',
        'workload-credential',
        replacedCredentialId,
        candidate,
        async () => {
          throw new IdentityKernelError('PC-IDENTITY-1006');
        },
        readWrites,
        undefined,
        async (client, operationId, authority) =>
          prepareDiscoveryCertificateIssuance(client, {
            participantId: actor.participantId,
            operationId,
            rotation: await readRotation(client),
            candidate,
            proof,
            authority,
            issuer: recovery,
            policy: this.discoveryIssuancePolicy,
            now: this.clock.now(),
            newId: uuidV7,
          }),
      );
      if (!('preparation' in admitted)) return admitted.result;
      const prepared = admitted.preparation;
      if (prepared.kind === 'UNAVAILABLE') throw new IdentityKernelError('PC-IDENTITY-1006');
      if (prepared.kind === 'CLAIM') {
        // No I/O begins before the durable claim transaction has committed.
        // An aborted/failed request is UNKNOWN, never proof of no issuance.
        let observed: IssuedWorkloadCertificate | undefined;
        try {
          const remaining = prepared.deadline.getTime() - this.clock.now().getTime();
          if (remaining <= 0) throw new IdentityKernelError('PC-IDENTITY-1006');
          const issued = await issuer.issue(
            prepared.request,
            AbortSignal.timeout(Math.max(1, Math.floor(remaining))),
          );
          observed = recovery.verifyObservation(
            prepared.request,
            issued.certificateDer,
            this.clock.now(),
          );
        } catch {
          // Retain the original attempt even if the caller's authority expired.
        }
        await this.scopedPrivacyTx(
          actor.participantId,
          proof.privacyDomainId,
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          (client) =>
            finishDiscoveryCertificateIssuerAttempt(
              client,
              {
                participantId: actor.participantId,
                privacyDomainId: proof.privacyDomainId,
                issuanceId: prepared.issuanceId,
                attemptId: prepared.attemptId,
              },
              observed,
            ),
        );
        if (!observed) throw new IdentityKernelError('PC-IDENTITY-1006');
      }
      // Recheck the complete current authority/approval/one-use proof after I/O.
      // This final transaction consumes only the original verified observation.
      return this.mutationTx(
        actor,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-WORKLOAD-ROTATE',
        'workload-credential',
        replacedCredentialId,
        candidate,
        async (client) =>
          applyObservedWorkloadCredentialEffect(
            client,
            await readRotation(client),
            await readDiscoveryCertificateObservation(
              client,
              {
                participantId: actor.participantId,
                privacyDomainId: proof.privacyDomainId,
                issuanceId: prepared.issuanceId,
                request: prepared.request,
              },
              recovery,
              this.clock.now(),
            ),
            () => this.clock.now(),
          ),
        readWrites,
      );
    }
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WORKLOAD-ROTATE',
      'workload-credential',
      replacedCredentialId,
      candidate,
      async (client) =>
        rotateWorkloadCredentialEffect(client, await readRotation(client), issuer, () =>
          this.clock.now(),
        ),
      readWrites,
    );
  }

  async workloadCredential(actor: AuthenticatedIdentityActor, credentialId: string) {
    const { participantId, sessionId } = parseSessionToken(actor.sessionToken);
    this.owns(actor, participantId);
    return this.scopedTx(participantId, 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', async (client) => {
      const session = await this.activeSession(client, participantId, sessionId, false);
      if (session.context_mode !== 'PARTICIPANT' || session.privacy_domain_id === null) {
        throw new IdentityKernelError('PC-AUTH-0003');
      }
      const row = one(
        (
          await client.query<{
            credential_id: string;
            principal_id: string;
            audience: string;
            state: WorkloadRecord['state'];
            credential_epoch: string;
            public_key_digest: Buffer;
            secret_fingerprint: Buffer;
            subject: string;
            issuer: string;
            valid_from: Date;
            valid_until: Date;
            rotated_from_credential_id: string | null;
          }>(
            `select credential_id,principal_id,audience,state,credential_epoch::text,
                    public_key_digest,secret_fingerprint,subject,issuer,valid_from,valid_until,
                    rotated_from_credential_id
               from control.credential
              where participant_id=$1 and credential_id=$2 and kind='WORKLOAD_MTLS'
                and issuer is not null and public_key_digest is not null
                and secret_fingerprint is not null and subject is not null and audience is not null
                and valid_until is not null`,
            [participantId, credentialId],
          )
        ).rows,
        'PC-IDENTITY-1006',
      );
      return {
        credentialId: row.credential_id,
        principalId: row.principal_id,
        participantId,
        workloadId: row.audience,
        state: row.state,
        workloadEpoch: row.credential_epoch,
        keyId: `sha256:${row.public_key_digest.toString('hex')}`,
        uriSan: row.subject,
        notBefore: row.valid_from,
        notAfter: row.valid_until,
        issuer: row.issuer,
        certificateFingerprint: `sha256:${row.secret_fingerprint.toString('hex')}`,
        ...(row.rotated_from_credential_id === null
          ? {}
          : { rotatedFromCredentialId: row.rotated_from_credential_id }),
      };
    });
  }

  async revokeWorkload(actor: AuthenticatedIdentityActor, credentialId: string) {
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-WORKLOAD-REVOKE',
      'workload-credential',
      credentialId,
      { credentialId, state: 'REVOKED' },
      async (client) => {
        const result = await client.query(
          `update control.credential set state='REVOKED',credential_epoch=credential_epoch+1,
           row_version=row_version+1,updated_at=clock_timestamp()
           where participant_id=$1 and credential_id=$2 and kind='WORKLOAD_MTLS' and state in ('ISSUED','ACTIVE','ROTATING')
           returning credential_id`,
          [actor.participantId, credentialId],
        );
        one(result.rows, 'PC-IDENTITY-1006');
        return { credentialId, state: 'REVOKED' as const };
      },
      async () => ({ credential: [{ id: credentialId, write: true }] }),
    );
  }

  recoveryReadback(
    actor: AuthenticatedIdentityActor,
    recoveryId: string,
    authority: BoundAuthority,
  ) {
    return this.identityScopedRead(actor, recoveryId, authority, (client) =>
      readRecovery(client, actor.participantId, authority.privacyDomainId, recoveryId),
    );
  }

  async qualifyRecoveryPrincipal(
    actor: AuthenticatedIdentityActor,
    request: RecoveryQualification,
  ) {
    if (
      [actor.principalId, actor.mutationAuthorization?.checkerPrincipalId].includes(
        request.principalId,
      )
    )
      throw new IdentityKernelError('PC-IDENTITY-1007');
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-RECOVERY-PRINCIPAL-QUALIFY',
      'recovery-principal',
      request.principalId,
      request,
      (client) =>
        qualifyRecoveryPrincipal(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          request,
        ),
      async (client) => ({
        ...(await principalInvalidationFence(
          client,
          actor.participantId,
          request.principalId,
          false,
        )),
        credential: [{ id: request.credentialId }],
      }),
    );
  }

  async revokeRecoveryPrincipal(actor: AuthenticatedIdentityActor, principalId: string) {
    if ([actor.principalId, actor.mutationAuthorization?.checkerPrincipalId].includes(principalId))
      throw new IdentityKernelError('PC-IDENTITY-1007');
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-RECOVERY-PRINCIPAL-REVOKE',
      'recovery-principal',
      principalId,
      { principalId, state: 'REVOKED' },
      (client) =>
        revokeRecoveryPrincipal(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          principalId,
        ),
      (client) => principalInvalidationFence(client, actor.participantId, principalId, false),
    );
  }

  recoveryPrincipalReadback(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
  ) {
    return this.identityScopedRead(actor, principalId, authority, (client) =>
      readRecoveryPrincipal(client, actor.participantId, authority.privacyDomainId, principalId),
    );
  }

  async postReviewRecovery(actor: AuthenticatedIdentityActor, recoveryId: string, note: string) {
    if (note.trim().length < 10 || note.length > 1024)
      throw new IdentityKernelError('PC-IDENTITY-1007');
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-RECOVERY-POST-REVIEW',
      'recovery',
      recoveryId,
      { recoveryId, note },
      async (client, operationId) => {
        const signerReview = await postReviewIdentityEnvelopeRecovery(client, {
          participantId: actor.participantId,
          privacyDomainId: actor.mutationAuthorization!.privacyDomainId,
          recoveryId,
          principalId: actor.principalId,
          checkerPrincipalId: actor.mutationAuthorization!.checkerPrincipalId!,
          operationId,
          note,
        });
        if (signerReview) return signerReview;
        const review = await client.query<{ reviewed_at: Date }>(
          `update control.recovery_challenge set reviewed_by_principal_id=$4,reviewed_at=clock_timestamp(),review_note=$5,row_version=row_version+1
         where participant_id=$1 and privacy_domain_id=$2 and recovery_challenge_id=$3 and outcome='COMPLETED' and consumed_at is not null and reviewed_at is null
           and (not replacement_required or replacement_credential_id is not null)
           and $4 not in (principal_id,recovery_principal_id) and $6 not in (principal_id,recovery_principal_id) returning reviewed_at`,
          [
            actor.participantId,
            actor.mutationAuthorization!.privacyDomainId,
            recoveryId,
            actor.principalId,
            note,
            actor.mutationAuthorization!.checkerPrincipalId,
          ],
        );
        const row = one(review.rows, 'PC-IDENTITY-1007');
        return {
          recoveryId,
          state: 'COMPLETED' as const,
          postReviewStatus: 'REVIEWED' as const,
          reviewedAt: row.reviewed_at.toISOString(),
        };
      },
    );
  }

  async beginRecovery(actor: AuthenticatedIdentityActor, request: RecoveryRequest) {
    this.owns(actor, request.participantId);
    return this.mutationTx(
      actor,
      request.actionIntentId,
      'ID-OP-RECOVERY-BEGIN',
      'recovery',
      request.recoveryId,
      request,
      async (client) => {
        const [first, second] = request.custodianPrincipalIds;
        await assertQualifiedRecoveryPrincipal(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          request.recoveryPrincipalId,
        );
        const pending = await client.query(
          `select 1 from control.recovery_challenge where participant_id=$1 and recovery_principal_id=$2
          and ((outcome='COMPLETED' and reviewed_at is null) or (outcome in ('REQUESTED','CUSTODIAN_ONE_APPROVED','CUSTODIAN_TWO_APPROVED','LEASE_ACTIVE') and expires_at>clock_timestamp()))`,
          [actor.participantId, request.recoveryPrincipalId],
        );
        if (pending.rowCount !== 0) throw new IdentityKernelError('PC-IDENTITY-1007');
        if (
          actor.principalId === request.subjectId ||
          [request.subjectId, request.recoveryPrincipalId].includes(
            actor.mutationAuthorization!.checkerPrincipalId!,
          )
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1007');
        }
        const [currentEpoch, recoveryEpoch, firstEpoch, secondEpoch] = await currentRecoveryEpochs(
          client,
          request.participantId,
          request,
        );
        const issuedAt = this.clock.now();
        await client.query(
          `insert into control.recovery_challenge
         (recovery_challenge_id,participant_id,principal_id,recovery_principal_id,challenge_digest,
          purpose_digest,action_intent_id,current_epoch,custodian_one_principal_id,custodian_two_principal_id,
          issued_at,expires_at,outcome,recovery_principal_epoch,custodian_one_epoch,custodian_two_epoch,privacy_domain_id)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'REQUESTED',$13,$14,$15,$16)`,
          [
            request.recoveryId,
            request.participantId,
            request.subjectId,
            request.recoveryPrincipalId,
            digest(randomToken()),
            Buffer.from(request.purposeDigest.slice(7), 'hex'),
            request.actionIntentId,
            currentEpoch,
            first,
            second,
            issuedAt,
            new Date(issuedAt.getTime() + RECOVERY_LEASE_MS),
            recoveryEpoch,
            firstEpoch,
            secondEpoch,
            actor.mutationAuthorization!.privacyDomainId,
          ],
        );
        return { recoveryId: request.recoveryId, state: 'REQUESTED' as const };
      },
      async (client) => ({
        principal: recoveryPrincipalIds(request).map((id) => ({
          id,
          write: id === request.recoveryPrincipalId,
        })),
        credential: [
          {
            id: await assertQualifiedRecoveryPrincipal(
              client,
              actor.participantId,
              actor.mutationAuthorization!.privacyDomainId,
              request.recoveryPrincipalId,
            ),
          },
        ],
      }),
    );
  }

  async approveRecovery(
    actor: AuthenticatedIdentityActor,
    recoveryId: string,
    purposeDigest: string,
  ) {
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-RECOVERY-APPROVE',
      'recovery',
      recoveryId,
      { recoveryId, purposeDigest },
      async (client) => {
        const recovery = await client.query<
          RecoveryAuthorityRow & {
            custodian_one_principal_id: string;
            custodian_two_principal_id: string;
            custodian_one_approved_at: Date | null;
            custodian_two_approved_at: Date | null;
            purpose_digest: Buffer;
            outcome: string;
          }
        >(
          `select * from control.recovery_challenge where participant_id=$1 and recovery_challenge_id=$2 and privacy_domain_id=$3
           and consumed_at is null and expires_at>clock_timestamp() for update`,
          [actor.participantId, recoveryId, actor.mutationAuthorization!.privacyDomainId],
        );
        const row = one(recovery.rows, 'PC-IDENTITY-1007');
        if (
          [row.principal_id, row.recovery_principal_id].includes(
            actor.mutationAuthorization!.checkerPrincipalId!,
          )
        )
          throw new IdentityKernelError('PC-IDENTITY-1007');
        await assertRecoveryAuthority(client, actor.participantId, row);
        await assertQualifiedRecoveryPrincipal(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          row.recovery_principal_id,
        );
        if (!sameBuffer(row.purpose_digest, Buffer.from(purposeDigest.slice(7), 'hex'))) {
          throw new IdentityKernelError('PC-IDENTITY-1007');
        }
        const approvalCount =
          Number(row.custodian_one_approved_at !== null) +
          Number(row.custodian_two_approved_at !== null);
        const expectedState =
          approvalCount === 0
            ? 'REQUESTED'
            : approvalCount === 1
              ? 'CUSTODIAN_ONE_APPROVED'
              : 'CUSTODIAN_TWO_APPROVED';
        if (approvalCount >= 2 || row.outcome !== expectedState) {
          throw new IdentityKernelError('PC-IDENTITY-1007');
        }
        let column: 'custodian_one_approved_at' | 'custodian_two_approved_at';
        if (
          actor.principalId === row.custodian_one_principal_id &&
          row.custodian_one_approved_at === null
        ) {
          column = 'custodian_one_approved_at';
        } else if (
          actor.principalId === row.custodian_two_principal_id &&
          row.custodian_two_approved_at === null
        ) {
          column = 'custodian_two_approved_at';
        } else {
          throw new IdentityKernelError('PC-IDENTITY-1007');
        }
        const custodyAuthority = await captureCustodianAuthority(client, {
          participantId: actor.participantId,
          privacyDomainId: actor.mutationAuthorization!.privacyDomainId,
          principalId: actor.principalId,
          recoveryId,
          approvalRequestId: actor.mutationAuthorization!.approvalRequestId!,
          signerCredentialId: await this.recoveryStepUpSigner(client, actor),
        });
        const authorityColumn =
          column === 'custodian_one_approved_at'
            ? 'custodian_one_authority'
            : 'custodian_two_authority';
        const successState =
          approvalCount === 0 ? 'CUSTODIAN_ONE_APPROVED' : 'CUSTODIAN_TWO_APPROVED';
        const updated = await client.query<{ outcome: string }>(
          `update control.recovery_challenge set ${column}=clock_timestamp(),${authorityColumn}=$5,outcome=$3,row_version=row_version+1
           where participant_id=$1 and recovery_challenge_id=$2 and outcome=$4 and ${column} is null
           returning outcome`,
          [actor.participantId, recoveryId, successState, expectedState, custodyAuthority],
        );
        const committed = one(updated.rows, 'PC-IDENTITY-1007').outcome;
        if (committed !== successState) throw new IdentityKernelError('PC-IDENTITY-1007');
        return { recoveryId, state: successState };
      },
      (client) =>
        recoveryAuthorityFence(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          recoveryId,
        ),
    );
  }

  async completeRecovery(actor: AuthenticatedIdentityActor, recoveryId: string) {
    return this.mutationTx(
      actor,
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ID-OP-RECOVERY-COMPLETE',
      'recovery',
      recoveryId,
      { recoveryId, state: 'COMPLETED' },
      async (client) => {
        const recovery = await client.query<
          RecoveryAuthorityRow & {
            principal_id: string;
            recovery_principal_id: string;
            current_epoch: string;
            custodian_one_approved_at: Date | null;
            custodian_two_approved_at: Date | null;
            outcome: string;
          }
        >(
          `select * from control.recovery_challenge where participant_id=$1 and recovery_challenge_id=$2 and privacy_domain_id=$3
           and consumed_at is null and expires_at>clock_timestamp() for update`,
          [actor.participantId, recoveryId, actor.mutationAuthorization!.privacyDomainId],
        );
        const row = one(recovery.rows, 'PC-IDENTITY-1007');
        if (actor.mutationAuthorization!.checkerPrincipalId === row.principal_id)
          throw new IdentityKernelError('PC-IDENTITY-1007');
        await assertRecoveryAuthority(client, actor.participantId, row);
        const hardwareCredentialId = await assertQualifiedRecoveryPrincipal(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          row.recovery_principal_id,
        );
        if ((await this.recoveryStepUpSigner(client, actor)) !== hardwareCredentialId)
          throw new IdentityKernelError('PC-IDENTITY-1007');
        if (
          actor.principalId !== row.recovery_principal_id ||
          row.custodian_one_approved_at === null ||
          row.custodian_two_approved_at === null ||
          !['CUSTODIAN_TWO_APPROVED', 'LEASE_ACTIVE'].includes(row.outcome)
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1007');
        }
        const principal = await client.query<{ authority_epoch: string }>(
          `update control.principal set authority_epoch=authority_epoch+1,row_version=row_version+1,
           updated_at=clock_timestamp() where participant_id=$1 and principal_id=$2
           and authority_epoch=$3 and state='ACTIVE' returning authority_epoch::text`,
          [actor.participantId, row.principal_id, row.current_epoch],
        );
        const newEpoch = one(principal.rows, 'PC-IDENTITY-1001').authority_epoch;
        await client.query(
          `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='recovery-complete'
           where participant_id=$1 and principal_id=$2 and state in ('ACTIVE','STEP_UP_REQUIRED')`,
          [actor.participantId, row.principal_id],
        );
        await client.query(
          `update control.credential set state=case when kind='OIDC_SUBJECT' and state='ACTIVE' then 'ACTIVE'::control.credential_state else 'REVOKED'::control.credential_state end,credential_epoch=credential_epoch+1,
             row_version=row_version+1,updated_at=clock_timestamp()
           where participant_id=$1 and principal_id=$2 and state in ('PENDING','ACTIVE','ROTATING')`,
          [actor.participantId, row.principal_id],
        );
        const completed = await client.query<{ outcome: string }>(
          `update control.recovery_challenge set consumed_at=clock_timestamp(),outcome='COMPLETED',row_version=row_version+1,
             replacement_required=exists(select 1 from control.credential where participant_id=$1 and principal_id=$4 and kind='OIDC_SUBJECT' and state='ACTIVE')
               and exists(select 1 from control.credential where participant_id=$1 and principal_id=$4 and kind='WEBAUTHN')
           where participant_id=$1 and recovery_challenge_id=$2 and consumed_at is null and outcome=$3
           returning outcome`,
          [actor.participantId, recoveryId, row.outcome, row.principal_id],
        );
        if (one(completed.rows, 'PC-IDENTITY-1007').outcome !== 'COMPLETED') {
          throw new IdentityKernelError('PC-IDENTITY-1007');
        }
        return { recoveryId, state: 'COMPLETED' as const, newEpoch };
      },
      (client) =>
        recoveryAuthorityFence(
          client,
          actor.participantId,
          actor.mutationAuthorization!.privacyDomainId,
          recoveryId,
          true,
        ),
    );
  }

  private recoveryStepUpSigner(client: PoolClient, actor: AuthenticatedIdentityActor) {
    const proof = actor.mutationAuthorization!;
    return identityStepUpSigner(client, {
      participantId: actor.participantId,
      privacyDomainId: proof.privacyDomainId,
      principalId: actor.principalId,
      sessionId: parseSessionToken(actor.sessionToken).sessionId,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      candidateDigest: Buffer.from(proof.candidateDigest.slice(7), 'hex'),
      assertionBindingDigest: proof.webauthnAssertionBindingDigest,
    });
  }

  private async actionIntentDigest(client: PoolClient, actionIntentId: string): Promise<Buffer> {
    const result = await client.query<{ semantic_digest: Buffer }>(
      `select semantic_digest from control.action_intent where action_intent_id=$1`,
      [actionIntentId],
    );
    return one(result.rows, 'PC-IDENTITY-1004').semantic_digest;
  }

  private async committedSessionMutationReplayRow(
    client: PoolClient,
    input: SessionMutationContextInput | SessionMutationReplayInput,
  ): Promise<SessionMutationReplayRow> {
    const { participantId, sessionId } = parseSessionToken(input.sessionToken);
    const validPair =
      (input.actionIntentId === 'ACT-IDENTITY_CREATE_SESSION-V1' &&
        input.catalogOperationId === 'ID-OP-SESSION-REFRESH') ||
      (input.actionIntentId === 'ACT-IDENTITY_DELETE_SESSION-V1' &&
        input.catalogOperationId === 'ID-OP-SESSION-REVOKE');
    if (
      !validPair ||
      input.idempotencyKey.length < 16 ||
      input.idempotencyKey.length > 128 ||
      !/^sha256:[0-9a-f]{64}$/u.test(input.candidateDigest)
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1009');
    }
    const now = this.clock.now();
    const result = await client.query<SessionMutationReplayRow>(
      `select action.semantic_digest action_intent_digest,record.created_at,
              session.csrf_secret,record.expected_aggregate_version::text,
              record.operation_id::text,session.principal_id::text,session.refresh_family_id::text,
              session.revoked_at,record.result_digest,record.result_payload,session.session_epoch::text,
              coalesce(evidence.occurred_at,record.created_at) updated_at
         from control.session session
         join control.idempotency_record record
           on record.participant_id=session.participant_id
          and record.principal_id=session.principal_id
          and record.action_intent_id=$3 and record.catalog_operation_id=$4
          and record.idempotency_key=$5 and record.input_digest=$7
          and record.terminal_state='COMMITTED' and record.result_digest is not null
          and record.result_aggregate_version is not null and record.expires_at>$8
         join control.mutation_evidence evidence
           on evidence.participant_id=record.participant_id
          and evidence.operation_id=record.operation_id
          and evidence.principal_id=record.principal_id
          and evidence.action_intent_id=record.action_intent_id
          and evidence.catalog_operation_id=record.catalog_operation_id
          and evidence.aggregate_type='session' and evidence.aggregate_id=session.session_id
          and evidence.aggregate_version=record.expected_aggregate_version
          and evidence.candidate_digest=record.input_digest
         join control.action_intent action on action.action_intent_id=record.action_intent_id
        where session.participant_id=$1 and session.session_id=$2
          and session.opaque_token_digest=$6 and session.state='REVOKED'
          and (($4='ID-OP-SESSION-REFRESH' and session.revoked_reason='refresh-rotation')
            or $4='ID-OP-SESSION-REVOKE')
        for share of session,record`,
      [
        participantId,
        sessionId,
        input.actionIntentId,
        input.catalogOperationId,
        input.idempotencyKey,
        digest(input.sessionToken),
        Buffer.from(input.candidateDigest.slice(7), 'hex'),
        now,
      ],
    );
    return one(result.rows, 'PC-AUTH-0003');
  }

  private async activeSession(
    client: PoolClient,
    participantId: string,
    sessionId: string,
    lock: boolean,
  ): Promise<SessionRow> {
    if (lock) {
      // Session writes also take this root through the lifecycle trigger. Take
      // it first, matching authority checks and Participant lifecycle changes.
      try {
        await lockAuthorityFence(client, participantId, {
          participant: [{ id: participantId }],
        });
      } catch (error) {
        if (error instanceof AuthorityFenceError) throw new IdentityKernelError('PC-AUTH-0003');
        throw error;
      }
    }
    const result = await client.query<SessionRow>(
      `select *,authority_epoch::text,participant_epoch::text,session_epoch::text from control.session
       where participant_id=$1 and session_id=$2 ${lock ? 'for update' : ''}`,
      [participantId, sessionId],
    );
    const session = one(result.rows, 'PC-AUTH-0003');
    const now = this.clock.now();
    if (
      session.state !== 'ACTIVE' ||
      !sameBuffer(session.opaque_token_digest, digest(`${participantId}.${sessionId}`)) ||
      session.idle_expires_at <= now ||
      session.absolute_expires_at <= now
    ) {
      throw new IdentityKernelError('PC-AUTH-0003');
    }
    const authority = one(
      (
        await client.query<{
          participant_epoch: string;
          participant_state: string;
          principal_epoch: string;
          principal_state: string;
          privacy_state: string | null;
          delegation_epoch: string;
        }>(
          `select participant.authority_epoch::text participant_epoch,
                  participant.state::text participant_state,
                  principal.authority_epoch::text principal_epoch,
                  principal.state::text principal_state,
                  privacy.state::text privacy_state,
                  coalesce((select max(assignment.delegation_epoch)
                    from control.assignment assignment
                   where assignment.participant_id=participant.participant_id
                     and assignment.principal_id=principal.principal_id
                     and assignment.state='ACTIVE'
                     and assignment.valid_during @> clock_timestamp()),0)::text delegation_epoch
             from control.participant participant
             join control.principal principal
               on principal.participant_id=participant.participant_id
              and principal.principal_id=$2
             left join control.privacy_domain privacy
               on privacy.participant_id=participant.participant_id
              and privacy.privacy_domain_id=$3
            where participant.participant_id=$1`,
          [participantId, session.principal_id, session.privacy_domain_id],
        )
      ).rows,
      'PC-AUTH-0003',
    );
    if (
      authority.participant_state !== 'ACTIVE' ||
      authority.principal_state !== 'ACTIVE' ||
      authority.participant_epoch !== session.participant_epoch ||
      authority.principal_epoch !== session.authority_epoch ||
      authority.delegation_epoch !== session.delegation_epoch ||
      (session.context_mode === 'PARTICIPANT' && authority.privacy_state !== 'ACTIVE') ||
      (session.context_mode === 'PLATFORM' && session.privacy_domain_id !== null)
    ) {
      throw new IdentityKernelError('PC-AUTH-0003');
    }
    return session;
  }

  private async appendDirectSignedOutbox(
    client: PoolClient,
    participantId: string,
    privacyDomainId: string,
    aggregateType: string,
    aggregateId: string,
    eventType: string,
    signed: {
      readonly evidenceCbor: Buffer;
      readonly evidenceDigest: Buffer;
      readonly coseSign1: Buffer;
    },
  ): Promise<void> {
    const sequence = one(
      (
        await client.query<{ last_sequence: string }>(
          `insert into control.outbox_aggregate_head
            (participant_id,aggregate_type,aggregate_id,last_sequence)
           values ($1,$2,$3,1)
           on conflict (participant_id,aggregate_type,aggregate_id) do update
             set last_sequence=control.outbox_aggregate_head.last_sequence+1,
                 updated_at=clock_timestamp()
           returning last_sequence::text`,
          [participantId, aggregateType, aggregateId],
        )
      ).rows,
    ).last_sequence;
    await client.query(
      `insert into control.outbox_event
        (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
         aggregate_sequence,payload_cbor,payload_digest,cose_sign1,occurred_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp())`,
      [
        participantId,
        privacyDomainId,
        uuidV7(),
        eventType,
        aggregateType,
        aggregateId,
        sequence,
        signed.evidenceCbor,
        signed.evidenceDigest,
        signed.coseSign1,
      ],
    );
  }

  private async activePrincipal(
    client: PoolClient,
    participantId: string,
    principalId: string,
    kind?: PrincipalRecord['kind'],
  ) {
    const result = await client.query(
      `select 1 from control.principal
        where participant_id=$1 and principal_id=$2 and state='ACTIVE'
          and ($3::control.principal_kind is null or kind=$3)`,
      [participantId, principalId, kind ?? null],
    );
    one(result.rows, 'PC-IDENTITY-1002');
  }

  private principalFromRow(row: {
    principal_id: string;
    participant_id: string;
    display_label: string;
    kind: PrincipalRecord['kind'];
    state: PrincipalRecord['state'];
    authority_epoch: string;
  }): PrincipalRecord {
    return {
      principalId: row.principal_id,
      participantId: row.participant_id,
      displayLabel: row.display_label,
      kind: row.kind,
      state: row.state,
      identityEpoch: row.authority_epoch,
    };
  }

  private owns(actor: AuthenticatedIdentityActor, participantId: string): void {
    if (!actor.platform && actor.participantId !== participantId) {
      throw new IdentityKernelError('PC-IDENTITY-1000');
    }
  }

  private async systemTx<T>(actionIntentId: string, operation: ScopedOperation<T>): Promise<T> {
    return this.transaction(undefined, actionIntentId, operation);
  }

  private async scopedTx<T>(
    participantId: string,
    actionIntentId: string,
    operation: ScopedOperation<T>,
  ): Promise<T> {
    return this.transaction(participantId, actionIntentId, operation);
  }

  private async scopedPrivacyTx<T>(
    participantId: string,
    privacyDomainId: string,
    actionIntentId: string,
    operation: ScopedOperation<T>,
  ): Promise<T> {
    return this.transaction(participantId, actionIntentId, operation, privacyDomainId);
  }

  private async mutationTx<T>(
    actor: AuthenticatedIdentityActor,
    actionIntentId: string,
    catalogOperationId: string,
    aggregateType: string,
    aggregateId: string,
    request: unknown,
    operation: MutationOperation<T>,
    writeDependencies?: (
      client: PoolClient,
    ) => Promise<AuthorityFence & { readonly authorities?: readonly BoundAuthority[] }>,
    verifiedAssertion?: VerifiedWebAuthnAssertion,
  ): Promise<T> {
    return (
      await this.mutationTxWithCommit(
        actor,
        actionIntentId,
        catalogOperationId,
        aggregateType,
        aggregateId,
        request,
        operation,
        writeDependencies,
        verifiedAssertion,
      )
    ).result;
  }

  private async mutationTxWithCommit<T>(
    actor: AuthenticatedIdentityActor,
    actionIntentId: string,
    catalogOperationId: string,
    aggregateType: string,
    aggregateId: string,
    request: unknown,
    operation: MutationOperation<T>,
    writeDependencies?: (
      client: PoolClient,
    ) => Promise<AuthorityFence & { readonly authorities?: readonly BoundAuthority[] }>,
    verifiedAssertion?: VerifiedWebAuthnAssertion,
  ): Promise<IdentityMutationCommit<T>> {
    const admitted = await this.admittedMutation<T>(
      actor,
      actionIntentId,
      catalogOperationId,
      aggregateType,
      aggregateId,
      request,
      operation,
      writeDependencies,
      verifiedAssertion,
    );
    if ('preparation' in admitted) throw new IdentityKernelError('PC-IDENTITY-1004');
    return admitted;
  }

  /** The preparation branch shares all real mutation admission. It returns a
   * durable preparation outcome before consuming any business candidate,
   * idempotency record or one-use step-up; callers perform issuer I/O afterward. */
  private async admittedMutation<T, P = never>(
    actor: AuthenticatedIdentityActor,
    actionIntentId: string,
    catalogOperationId: string,
    aggregateType: string,
    aggregateId: string,
    request: unknown,
    operation: MutationOperation<T>,
    writeDependencies?: (
      client: PoolClient,
    ) => Promise<AuthorityFence & { readonly authorities?: readonly BoundAuthority[] }>,
    verifiedAssertion?: VerifiedWebAuthnAssertion,
    preparation?: MutationOperation<P>,
  ): Promise<IdentityMutationCommit<T> | { readonly preparation: P }> {
    if (preparation !== undefined && catalogOperationId !== 'ID-OP-WORKLOAD-ROTATE')
      throw new IdentityKernelError('PC-AUTH-0005');
    const proof = actor.mutationAuthorization;
    const { sessionId } = parseSessionToken(actor.sessionToken);
    const candidateDigest = stableDigest(request);
    let webauthnAssertionBindingDigest = proof?.webauthnAssertionBindingDigest;
    if (catalogOperationId === 'ID-OP-WEBAUTHN-VERIFY') {
      const binding = (request as StepUpAuthorizationCandidate).verifiedAssertionDigest;
      if (
        !/^sha256:[0-9a-f]{64}$/u.test(binding) ||
        !verifiedAssertion ||
        verifiedAssertion.principalId !== actor.principalId ||
        verifiedAssertion.sessionId !== sessionId ||
        `sha256:${verifiedWebAuthnAssertionDigest(verifiedAssertion).toString('hex')}` !== binding
      ) {
        throw new IdentityKernelError('PC-AUTH-0006');
      }
      const verifiedAssertionBindingDigest = Buffer.from(binding.slice(7), 'hex');
      if (
        webauthnAssertionBindingDigest !== undefined &&
        !webauthnAssertionBindingDigest.equals(verifiedAssertionBindingDigest)
      ) {
        throw new IdentityKernelError('PC-AUTH-0006');
      }
      webauthnAssertionBindingDigest = verifiedAssertionBindingDigest;
    }
    if (
      proof === undefined ||
      !proof.authorized ||
      !proof.candidateDigest.startsWith('sha256:') ||
      !candidateDigest.equals(Buffer.from(proof.candidateDigest.slice(7), 'hex')) ||
      !digest(proof.evidenceCbor).equals(proof.evidenceDigest) ||
      proof.coseSign1.length === 0 ||
      (webauthnAssertionBindingDigest !== undefined &&
        webauthnAssertionBindingDigest.length !== 32) ||
      BigInt(proof.aggregateVersion) < 0n ||
      !CATALOG_OPERATION_PATTERN.test(catalogOperationId)
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1005');
    }
    return this.scopedTx(actor.participantId, actionIntentId, async (client, operationId) => {
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
        [actor.participantId, proof.privacyDomainId, operationId, actionIntentId],
      );
      const actionIntent = one(
        (
          await client.query<{
            idempotency_required: boolean;
            operation_class: string;
            resource_type: string;
            semantic_digest: Buffer;
          }>(
            `select idempotency_required,operation_class,resource_type,semantic_digest
               from control.action_intent where action_intent_id=$1`,
            [actionIntentId],
          )
        ).rows,
        'PC-IDENTITY-1004',
      );
      const operationContract = identityGovernanceOperations.find(
        (candidate) => candidate.id === catalogOperationId,
      );
      if (
        operationContract === undefined ||
        operationContract.actionIntentId !== actionIntentId ||
        !actionIntent.idempotency_required ||
        proof.idempotencyKey.length === 0
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1009');
      }
      const requirements = {
        maker_checker_required: operationContract.makerCheckerRequired,
        step_up_required: operationContract.webauthnStepUpRequired,
      };
      let session = await this.activeSession(client, actor.participantId, sessionId, false);
      if (
        requirements.maker_checker_required &&
        (session.context_mode !== 'PARTICIPANT' ||
          session.privacy_domain_id !== proof.privacyDomainId) &&
        !(
          catalogOperationId === 'ID-OP-WORKLOAD-ROTATE' &&
          session.context_mode === 'PLATFORM' &&
          session.privacy_domain_id === null
        )
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1005');
      }
      const authority = one(
        (
          await client.query<{
            assignment_id: string;
            assignment_row_version: string;
            authority_envelope_id: string;
            envelope_epoch: string;
            participant_epoch: string;
            principal_epoch: string;
            delegation_epoch: string;
          }>(
            `with recursive authority_chain as (
               select a.assignment_id,null::uuid current_delegation_id,a.principal_id terminal_principal_id,0 depth
                 from control.assignment a
                where a.participant_id=$1 and a.state='ACTIVE' and a.valid_during @> clock_timestamp()
                  and $4=any(a.action_intent_ids) and $2::text=any(a.privacy_domain_ids)
                  and openpc.administration_resource_permits(a.resource_ids,$3::text,$4,$1,$5,$6,a.authority_envelope_id)
               union all
               select c.assignment_id,d.delegation_id,d.delegate_principal_id,c.depth+1
                 from authority_chain c join control.delegation d on d.participant_id=$1
                  and ((c.current_delegation_id is null and d.parent_assignment_id=c.assignment_id)
                    or d.parent_delegation_id=c.current_delegation_id)
                  and d.grantor_principal_id=c.terminal_principal_id and d.state='ACTIVE'
                  and d.valid_during @> clock_timestamp() and $4=any(d.action_intent_ids)
                  and $2::text=any(d.privacy_domain_ids)
                  and ($3::text=any(d.resource_ids) or '*'=any(d.resource_ids))
                where c.depth<32
             )
             select a.assignment_id,a.row_version::text assignment_row_version,
                    ae.authority_envelope_id,ae.authority_epoch::text envelope_epoch,
                    p.authority_epoch::text participant_epoch,pr.authority_epoch::text principal_epoch,
                    s.delegation_epoch::text delegation_epoch
               from authority_chain c
               join control.assignment a on a.participant_id=$1 and a.assignment_id=c.assignment_id
               join control.authority_envelope ae on ae.participant_id=$1
                and ae.authority_envelope_id=a.authority_envelope_id and ae.state='ACTIVE'
                and ${currentPlatformEnvelopeSql('ae', false, true)}
                and ae.valid_from<=clock_timestamp() and (ae.valid_until is null or ae.valid_until>clock_timestamp())
                and $4=any(ae.action_intent_ids) and $2::text=any(ae.privacy_domain_ids)
                and openpc.administration_resource_permits(ae.resource_ids,$3::text,$4,$1,$5,$6,ae.authority_envelope_id)
               join control.participant p on p.participant_id=$1 and p.state='ACTIVE'
               join control.principal pr on pr.participant_id=$1 and pr.principal_id=$5 and pr.state='ACTIVE'
               join control.session s on s.participant_id=$1 and s.session_id=$6
              where c.terminal_principal_id=$5`,
            [
              actor.participantId,
              proof.privacyDomainId,
              aggregateId,
              actionIntentId,
              actor.principalId,
              sessionId,
            ],
          )
        ).rows,
        'PC-IDENTITY-1002',
      );
      if (
        requirements.maker_checker_required &&
        session.context_mode === 'PLATFORM' &&
        !(await discoveryCertificateRecoveryContextEligible(client, {
          participantId: actor.participantId,
          privacyDomainId: proof.privacyDomainId,
          authorityEnvelopeId: authority.authority_envelope_id,
          principalId: actor.principalId,
          catalogOperationId,
          actionIntentId,
          resourceId: aggregateId,
          expectedRevision: proof.aggregateVersion,
          candidate: request,
        }))
      )
        throw new IdentityKernelError('PC-IDENTITY-1005');
      if (
        requirements.maker_checker_required &&
        (proof.evidenceKind !== 'USER_WEBAUTHN' ||
          proof.approvalRequestId === undefined ||
          proof.approvalRequestId.length === 0 ||
          proof.checkerPrincipalId === undefined ||
          proof.checkerPrincipalId.length === 0 ||
          proof.checkerPrincipalId === actor.principalId)
      )
        throw new IdentityKernelError('PC-IDENTITY-1005');
      const approval = requirements.maker_checker_required
        ? await approvalAuthorityDependencies(
            client,
            { participantId: actor.participantId, privacyDomainId: proof.privacyDomainId },
            proof.approvalRequestId ?? '',
            true,
          )
        : undefined;
      // Provisional, read-only classification. It cannot create or replace an
      // idempotency record and grants no authority before the ranked fence.
      const committedInput: CommittedIdentityStepUpInput | undefined =
        requirements.maker_checker_required &&
        requirements.step_up_required &&
        proof.evidenceKind === 'USER_WEBAUTHN'
          ? {
              participantId: actor.participantId,
              privacyDomainId: proof.privacyDomainId,
              principalId: actor.principalId,
              sessionId,
              actionIntentId,
              candidateDigest,
              assertionBindingDigest: webauthnAssertionBindingDigest,
              idempotencyKey: proof.idempotencyKey,
              catalogOperationId,
              resourceId: aggregateId,
              aggregateType,
              expectedRevision: proof.aggregateVersion,
              approvalRequestId: proof.approvalRequestId ?? '',
              checkerPrincipalId: proof.checkerPrincipalId ?? '',
              checkerCredentialId: proof.signerCredentialId,
              evidenceCbor: proof.evidenceCbor,
              evidenceDigest: proof.evidenceDigest,
              coseSign1: proof.coseSign1,
            }
          : undefined;
      const committedOriginal =
        committedInput === undefined
          ? undefined
          : await selectCommittedIdentityStepUp(client, committedInput);
      const committedHistory =
        committedOriginal === undefined || committedInput === undefined
          ? undefined
          : { ...committedInput, operationId: committedOriginal.operationId };
      const stepUpSignerInput = {
        participantId: actor.participantId,
        privacyDomainId: proof.privacyDomainId,
        principalId: actor.principalId,
        sessionId,
        actionIntentId,
        candidateDigest,
        assertionBindingDigest: webauthnAssertionBindingDigest,
        ...(committedHistory === undefined ? {} : { committedHistory }),
      };
      const stepUpSigner = requirements.step_up_required
        ? await identityStepUpSigner(client, stepUpSignerInput)
        : undefined;
      if (catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
        process.stdout.write(
          JSON.stringify({
            boundary: 'workload_issue_commit',
            stage: 'step_up_signer_admitted',
            aggregateId,
          }) + '\n',
        );
      const writes = await writeDependencies?.(client);
      const makerAuthority: BoundAuthority = {
        principalId: actor.principalId,
        sessionId,
        sessionEpoch: session.session_epoch,
        participantEpoch: authority.participant_epoch,
        principalEpoch: authority.principal_epoch,
        assignmentId: authority.assignment_id,
        assignmentRowVersion: authority.assignment_row_version,
        authorityEnvelopeId: authority.authority_envelope_id,
        authorityEpoch: authority.envelope_epoch,
        delegationEpoch: authority.delegation_epoch,
        privacyDomainId: proof.privacyDomainId,
        actionIntentId,
        resourceId: aggregateId,
        catalogOperationId,
      };
      const committedCredentialId = committedOriginal?.currentAssurance.credentialId ?? null;
      await fenceBoundAuthorities(
        client,
        actor.participantId,
        [makerAuthority, ...(approval?.authorities ?? []), ...(writes?.authorities ?? [])],
        {
          ...writes,
          session: [{ id: sessionId, write: true }, ...(writes?.session ?? [])],
          credential: [
            ...(proof.evidenceKind === 'USER_WEBAUTHN' ? [{ id: proof.signerCredentialId }] : []),
            ...(stepUpSigner === undefined ? [] : [{ id: stepUpSigner }]),
            ...(committedCredentialId === null ? [] : [{ id: committedCredentialId }]),
            ...(approval?.rows.credential ?? []),
            ...(writes?.credential ?? []),
          ],
        },
      );
      if (catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
        process.stdout.write(
          JSON.stringify({
            boundary: 'workload_issue_commit',
            stage: 'authority_fence_admitted',
            aggregateId,
          }) + '\n',
        );
      if (
        stepUpSigner !== undefined &&
        (await identityStepUpSigner(client, stepUpSignerInput)) !== stepUpSigner
      )
        throw new IdentityKernelError('PC-AUTH-0005');
      if (
        writes?.authorities !== undefined &&
        JSON.stringify((await writeDependencies!(client)).authorities) !==
          JSON.stringify(writes.authorities)
      )
        throw new IdentityKernelError('PC-IDENTITY-1007');
      session = await this.activeSession(client, actor.participantId, sessionId, true);
      if (catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
        process.stdout.write(
          JSON.stringify({
            boundary: 'workload_issue_commit',
            stage: 'session_admitted',
            aggregateId,
          }) + '\n',
        );
      if (requirements.maker_checker_required) {
        await approvalAuthorityDependencies(
          client,
          { participantId: actor.participantId, privacyDomainId: proof.privacyDomainId },
          proof.approvalRequestId ?? '',
          true,
        );
      }
      if (committedHistory !== undefined) {
        if (
          session.step_up_mfa_challenge_id !== null &&
          session.step_up_mfa_challenge_id !== undefined
        )
          await this.assertPinnedStepUpCurrent(client, session);
        else if (
          session.step_up_verified_at === null ||
          session.step_up_verified_at.getTime() + STEP_UP_MAX_AGE_MS <= this.clock.now().getTime()
        )
          throw new IdentityKernelError('PC-AUTH-0005');
        // Reread the independently selected C2 pin under the same ranked
        // session/credential fence, before taking any idempotency/aggregate lock.
        const currentOriginal = await selectCommittedIdentityStepUp(client, committedHistory);
        const before = committedOriginal!.currentAssurance;
        const after = currentOriginal?.currentAssurance;
        if (
          !after ||
          currentOriginal?.operationId !== committedHistory.operationId ||
          before.sourceId !== after.sourceId ||
          before.verifiedAt.getTime() !== after.verifiedAt.getTime() ||
          before.credentialId !== after.credentialId ||
          before.credentialEpoch !== after.credentialEpoch ||
          (session.step_up_mfa_challenge_id ?? null) !== after.sourceId ||
          session.step_up_verified_at?.getTime() !== after.verifiedAt.getTime()
        )
          throw new IdentityKernelError('PC-AUTH-0005');
      }
      const committedLocked =
        committedHistory === undefined
          ? undefined
          : await selectCommittedIdentityStepUp(client, committedHistory, true);
      if (
        committedHistory !== undefined &&
        (committedLocked === undefined ||
          committedLocked.operationId !== committedHistory.operationId)
      )
        throw new IdentityKernelError('PC-IDENTITY-1009');
      const idempotency: MutationIdempotency<T> =
        committedLocked === undefined
          ? await this.beginMutationIdempotency<T>(
              client,
              actor,
              actionIntentId,
              catalogOperationId,
              proof.idempotencyKey,
              candidateDigest,
              webauthnAssertionBindingDigest,
              proof.aggregateVersion,
              operationId,
              preparation !== undefined,
            )
          : {
              expectedAggregateVersion: committedLocked.expectedAggregateVersion,
              operationId: committedLocked.operationId,
              replay: true,
              result: (committedLocked.result ?? undefined) as T,
              resultAggregateVersion: committedLocked.resultAggregateVersion,
            };
      if (catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
        process.stdout.write(
          JSON.stringify({
            boundary: 'workload_issue_commit',
            stage: 'idempotency_admitted',
            aggregateId,
          }) + '\n',
        );
      const aggregateVersion = await this.currentAggregateVersion(
        client,
        actor.participantId,
        aggregateType,
        aggregateId,
        proof.privacyDomainId,
        catalogOperationId,
      );
      const authorizedAggregateVersion = idempotency.replay
        ? idempotency.resultAggregateVersion
        : proof.aggregateVersion;
      if (
        idempotency.expectedAggregateVersion !== proof.aggregateVersion ||
        authorizedAggregateVersion === undefined ||
        aggregateVersion !== authorizedAggregateVersion
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1001');
      }
      if (catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
        process.stdout.write(
          JSON.stringify({
            boundary: 'workload_issue_commit',
            stage: 'aggregate_version_admitted',
            aggregateId,
          }) + '\n',
        );
      if (
        authority.participant_epoch !== session.participant_epoch ||
        authority.principal_epoch !== session.authority_epoch
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1001');
      }
      let checkerPrincipalId: string | undefined;
      if (requirements.maker_checker_required) {
        if (
          proof.evidenceKind !== 'USER_WEBAUTHN' ||
          proof.approvalRequestId === undefined ||
          proof.checkerPrincipalId === undefined ||
          proof.checkerPrincipalId === actor.principalId
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1005');
        }
        const approval = one(
          (
            await client.query<{
              cose_sign1: Buffer;
              evidence_cbor: Buffer;
              public_key_digest: Buffer;
              public_key_spki_der: Buffer;
            }>(
              `select ad.cose_sign1,ad.evidence_cbor,c.public_key_digest,c.public_key_spki_der
                 from control.approval_request ar
                 join control.mutation_candidate candidate
                   on candidate.participant_id=ar.participant_id
                  and candidate.privacy_domain_id=ar.privacy_domain_id
                  and candidate.mutation_candidate_id=ar.subject_id
                  and candidate.action_intent_id=ar.action_intent_id
                  and candidate.candidate_digest=ar.subject_digest
                  and candidate.expected_revision=ar.subject_version
                  and candidate.resource_id=$5::uuid
                  and candidate.catalog_operation_id=$11
                  and candidate.idempotency_key=$12
                  and candidate.resource_type=$13
                  and candidate.operation_class=$14
                  and candidate.candidate_document=$15::jsonb
                  and candidate.maker_principal_id=$8::uuid
                  and (candidate.state='APPROVED'
                    or (candidate.state='CONSUMED' and candidate.consumed_operation_id=$16::uuid))
                  and candidate.expires_at>clock_timestamp()
                 join control.approval_decision_record ad on ad.participant_id=ar.participant_id
                  and ad.approval_request_id=ar.approval_request_id
                 join control.principal checker on checker.participant_id=ar.participant_id
                  and checker.principal_id=ad.approver_principal_id and checker.state='ACTIVE'
                  and checker.authority_epoch=ad.approver_principal_epoch
                 join control.credential c on c.participant_id=ar.participant_id
                  and c.credential_id=ad.signer_credential_id and c.principal_id=checker.principal_id
                  and c.kind='WEBAUTHN' and c.state='ACTIVE'
                  and c.valid_from<=clock_timestamp() and (c.valid_until is null or c.valid_until>clock_timestamp())
                 join control.assignment ca on ca.participant_id=ar.participant_id
                  and ca.assignment_id=ad.approver_assignment_id and ca.principal_id=checker.principal_id
                  and ca.state='ACTIVE' and ca.valid_during @> clock_timestamp()
                  and $4=any(ca.action_intent_ids) and $2::uuid::text=any(ca.privacy_domain_ids)
                  and ($5::text=any(ca.resource_ids) or '*'=any(ca.resource_ids))
                 join control.authority_envelope ce on ce.participant_id=ar.participant_id
                  and ce.authority_envelope_id=ad.approver_authority_envelope_id
                  and ce.authority_envelope_id=ca.authority_envelope_id and ce.state='ACTIVE'
                  and ce.authority_epoch=ad.approver_envelope_epoch
                  and ce.valid_from<=clock_timestamp() and (ce.valid_until is null or ce.valid_until>clock_timestamp())
                where ar.participant_id=$1::uuid and ar.privacy_domain_id=$2::uuid
                  and ar.approval_request_id=$3::uuid
                  and ar.action_intent_id=$4 and ar.subject_digest=$6
                  and ar.subject_version=$7 and ar.subject_type='CONFIGURATION_CANDIDATE'
                  and ar.maker_principal_id=$8::uuid and ar.state='APPROVED'
                  and ar.expires_at>clock_timestamp() and ad.decision='APPROVE'
                  and ad.approver_principal_id=$9::uuid and ad.approver_principal_id<>ar.maker_principal_id
                  and ad.aggregate_version=$7 and ad.candidate_digest=$6
                  and ad.signer_credential_id=$10::uuid for update of ar,candidate`,
              [
                actor.participantId,
                proof.privacyDomainId,
                proof.approvalRequestId,
                actionIntentId,
                aggregateId,
                candidateDigest,
                proof.aggregateVersion,
                actor.principalId,
                proof.checkerPrincipalId,
                proof.signerCredentialId,
                catalogOperationId,
                proof.idempotencyKey,
                actionIntent.resource_type,
                actionIntent.operation_class,
                request,
                idempotency.operationId,
              ],
            )
          ).rows,
          'PC-IDENTITY-1005',
        );
        if (
          !approval.evidence_cbor.equals(proof.evidenceCbor) ||
          !approval.cose_sign1.equals(proof.coseSign1) ||
          !digest(approval.public_key_spki_der).equals(approval.public_key_digest)
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1005');
        }
        if (
          !(await verifyStoredStepUpEvidence(
            client,
            {
              participantId: actor.participantId,
              privacyDomainId: proof.privacyDomainId,
              principalId: proof.checkerPrincipalId,
              credentialId: proof.signerCredentialId,
              approvalRequestId: proof.approvalRequestId,
              credentialPublicKey: approval.public_key_spki_der,
              evidenceCbor: proof.evidenceCbor,
              coseSign1: proof.coseSign1,
            },
            this.identityRuntimeVerifier,
          ))
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1005');
        }
        checkerPrincipalId = proof.checkerPrincipalId;
        if (catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
          process.stdout.write(
            JSON.stringify({
              boundary: 'workload_issue_commit',
              stage: 'checker_evidence_admitted',
              aggregateId,
            }) + '\n',
          );
      } else if (proof.evidenceKind === 'USER_WEBAUTHN') {
        const signer = one(
          (
            await client.query<{ public_key_digest: Buffer; public_key_spki_der: Buffer }>(
              `select c.public_key_digest,c.public_key_spki_der from control.credential c
                join control.principal p on p.participant_id=c.participant_id and p.principal_id=c.principal_id
               where c.participant_id=$1 and c.credential_id=$2 and c.principal_id=$3
                 and c.kind='WEBAUTHN' and c.state='ACTIVE' and p.state='ACTIVE'
                 and c.valid_from<=clock_timestamp() and (c.valid_until is null or c.valid_until>clock_timestamp())`,
              [actor.participantId, proof.signerCredentialId, actor.principalId],
            )
          ).rows,
          'PC-IDENTITY-1005',
        );
        if (!digest(signer.public_key_spki_der).equals(signer.public_key_digest)) {
          throw new IdentityKernelError('PC-IDENTITY-1005');
        }
        if (
          !verifyCoseSign1Es256(
            signer.public_key_spki_der,
            proof.evidenceCbor,
            proof.coseSign1,
            identityCredentialCoseContext,
          )
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1005');
        }
      } else {
        const verified = await this.identityRuntimeVerifier?.verifyCanonicalAssertion(
          proof.evidenceCbor,
          proof.coseSign1,
        );
        const runtimeContext: IdentityRuntimeAuthorizationContext = {
          participantId: actor.participantId,
          principalId: actor.principalId,
          sessionId,
          sessionEpoch: session.session_epoch,
          sessionIssuedAt: session.issued_at,
          sessionIdleExpiresAt: session.idle_expires_at,
          sessionAbsoluteExpiresAt: session.absolute_expires_at,
          participantEpoch: authority.participant_epoch,
          principalEpoch: authority.principal_epoch,
          assignmentId: authority.assignment_id,
          assignmentRowVersion: authority.assignment_row_version,
          authorityEnvelopeId: authority.authority_envelope_id,
          authorityEpoch: authority.envelope_epoch,
          delegationEpoch: authority.delegation_epoch,
          actionIntentId,
          catalogOperationId,
          resourceId: aggregateId,
          candidateDigest: proof.candidateDigest,
          sessionToken: actor.sessionToken,
        };
        if (
          verified === undefined ||
          !sameBuffer(verified.signerKeyDigest, proof.signerKeyDigest) ||
          verifyIdentityRuntimeAuthorizationAssertion(
            proof.evidenceCbor,
            runtimeContext,
            this.clock.now(),
          ) === undefined
        ) {
          throw new IdentityKernelError('PC-IDENTITY-1005');
        }
      }
      if (committedLocked !== undefined) {
        if (
          committedLocked.boundParticipantEpoch !== authority.participant_epoch ||
          committedLocked.boundPrincipalEpoch !== authority.principal_epoch ||
          committedLocked.boundAuthorityEnvelopeId !== authority.authority_envelope_id ||
          committedLocked.boundEnvelopeEpoch !== authority.envelope_epoch ||
          committedLocked.boundAssignmentId !== authority.assignment_id ||
          !committedLocked.resultDigest.equals(stableDigest(committedLocked.result ?? null)) ||
          !digest(committedLocked.credentialPublicKey).equals(
            committedLocked.credentialPublicKeyDigest,
          ) ||
          !digest(committedLocked.verificationEvidenceCbor).equals(
            committedLocked.verificationEvidenceDigest,
          ) ||
          !webauthnAssertionBindingDigest?.equals(committedLocked.assertionBindingDigest)
        )
          throw new IdentityKernelError('PC-IDENTITY-1005');
        const legacy = verifyCoseSign1Es256(
          committedLocked.credentialPublicKey,
          committedLocked.verificationEvidenceCbor,
          committedLocked.verificationCoseSign1,
          identityCredentialCoseContext,
        );
        if (!legacy) {
          const signed = await this.identityRuntimeVerifier?.verifyCanonicalAssertion(
            committedLocked.verificationEvidenceCbor,
            committedLocked.verificationCoseSign1,
          );
          if (
            signed === undefined ||
            !authenticateHistoricalRuntimeStepUpEvidence(
              {
                participantId: actor.participantId,
                principalId: actor.principalId,
                evidenceCbor: committedLocked.verificationEvidenceCbor,
              },
              {
                candidate_digest: committedLocked.verificationCandidateDigest,
                session_id: committedLocked.verificationSessionId,
                occurred_at: committedLocked.verificationOccurredAt,
              },
            )
          )
            throw new IdentityKernelError('PC-IDENTITY-1005');
        }
        // No live C1 admission, issuer/provider callback or business mutation is
        // reached. Current C2 assurance and both original signatures are intact.
        return this.committedMutation(
          client,
          actor.participantId,
          committedLocked.operationId,
          aggregateId,
          actionIntentId,
          actionIntent.semantic_digest,
          proof.idempotencyKey,
          idempotency.result as T,
        );
      }
      let challengeId: string | undefined;
      if (requirements.step_up_required) {
        const challenge = await client.query<{ mfa_challenge_id: string }>(
          `select challenge.mfa_challenge_id from control.mfa_challenge challenge
            join control.session proof_session
              on proof_session.participant_id=challenge.participant_id
             and proof_session.session_id=challenge.session_id
             and proof_session.principal_id=challenge.principal_id
            join control.mutation_evidence verification
              on verification.participant_id=challenge.participant_id
             and verification.privacy_domain_id=$7::uuid
             and verification.principal_id=challenge.principal_id
             and verification.mfa_challenge_id=challenge.mfa_challenge_id
             and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
             and verification.aggregate_type='webauthn-verification'
             and verification.aggregate_id=challenge.session_id
             and verification.webauthn_assertion_binding_digest=$8
            join control.idempotency_record verification_idempotency
              on verification_idempotency.participant_id=verification.participant_id
             and verification_idempotency.privacy_domain_id=verification.privacy_domain_id
             and verification_idempotency.operation_id=verification.operation_id
             and verification_idempotency.catalog_operation_id=verification.catalog_operation_id
             and verification_idempotency.input_digest=verification.candidate_digest
             and verification_idempotency.webauthn_assertion_binding_digest=
                 verification.webauthn_assertion_binding_digest
             and verification_idempotency.terminal_state='COMMITTED'
            join control.outbox_event verification_event
              on verification_event.participant_id=verification.participant_id
             and verification_event.privacy_domain_id=verification.privacy_domain_id
             and verification_event.aggregate_type=verification.aggregate_type
             and verification_event.aggregate_id=verification.aggregate_id
             and verification_event.event_type=
                 'openpc.identity.webauthn-verification.mutation.committed.v1'
             and verification_event.webauthn_assertion_binding_digest=
                 verification.webauthn_assertion_binding_digest
             and verification_event.payload_cbor=verification.evidence_cbor
             and verification_event.payload_digest=verification.evidence_digest
             and verification_event.cose_sign1=verification.cose_sign1
           where challenge.participant_id=$1 and challenge.session_id=$2
             and challenge.principal_id=$3 and challenge.action_intent_id=$4
             and challenge.resource_digest=$5
             and case when proof_session.step_up_mfa_challenge_id is null
               then challenge.consumed_at>clock_timestamp()-interval '5 minutes'
               else proof_session.step_up_mfa_challenge_id=challenge.mfa_challenge_id
                 and openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id)>clock_timestamp()
               end
             and (challenge.used_at is null or challenge.used_operation_id=$6)
           for update of challenge`,
          [
            actor.participantId,
            sessionId,
            actor.principalId,
            actionIntentId,
            candidateDigest,
            idempotency.operationId,
            proof.privacyDomainId,
            webauthnAssertionBindingDigest ?? null,
          ],
        );
        if (catalogOperationId === 'ID-OP-WORKLOAD-ISSUE')
          process.stdout.write(
            JSON.stringify({
              boundary: 'workload_issue_commit',
              stage: 'challenge_selected',
              aggregateId,
              count: challenge.rowCount,
            }) + '\n',
          );
        challengeId = one(challenge.rows, 'PC-AUTH-0005').mfa_challenge_id;
      }
      if (idempotency.replay) {
        return this.committedMutation(
          client,
          actor.participantId,
          idempotency.operationId,
          aggregateId,
          actionIntentId,
          actionIntent.semantic_digest,
          proof.idempotencyKey,
          idempotency.result as T,
        );
      }
      await assertPlatformRecoveryCommitPurpose(client, {
        participantId: actor.participantId,
        privacyDomainId: proof.privacyDomainId,
        authorityEnvelopeId: makerAuthority.authorityEnvelopeId,
        catalogOperationId,
        resourceId: aggregateId,
        candidate: request,
        expectedRevision: proof.aggregateVersion,
        principalId: actor.principalId,
        ...(verifiedAssertion === undefined ? {} : { verifiedStepUp: verifiedAssertion }),
      });
      if (preparation !== undefined) {
        return {
          preparation: await preparation(client, operationId, {
            makerAuthority,
            approvalAuthorities: approval?.authorities ?? [],
            makerSignerCredentialId: stepUpSigner,
            checkerSignerCredentialId:
              proof.evidenceKind === 'USER_WEBAUTHN' ? proof.signerCredentialId : undefined,
          }),
        };
      }
      const result = await operation(client, operationId, {
        makerAuthority,
        approvalAuthorities: approval?.authorities ?? [],
        makerSignerCredentialId: stepUpSigner,
        checkerSignerCredentialId:
          proof.evidenceKind === 'USER_WEBAUTHN' ? proof.signerCredentialId : undefined,
      });
      if (requirements.maker_checker_required && !idempotency.replay) {
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
              and candidate.state='APPROVED'`,
          [actor.participantId, proof.privacyDomainId, proof.approvalRequestId, operationId],
        );
        if (consumedCandidate.rowCount !== 1) {
          throw new IdentityKernelError('PC-IDENTITY-1005');
        }
      }
      const evidenceChallengeId =
        catalogOperationId === 'ID-OP-WEBAUTHN-VERIFY' &&
        typeof result === 'object' &&
        result !== null &&
        'challengeId' in result &&
        typeof result.challengeId === 'string'
          ? result.challengeId
          : challengeId;
      if (challengeId !== undefined) {
        await client.query(
          `update control.mfa_challenge set used_at=clock_timestamp(),used_operation_id=$2
            where mfa_challenge_id=$1 and used_at is null`,
          [challengeId, operationId],
        );
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
           bound_assignment_id,signer_credential_id,webauthn_assertion_binding_digest,evidence_cbor,evidence_digest,cose_sign1)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
        [
          actor.participantId,
          proof.privacyDomainId,
          operationId,
          actor.principalId,
          checkerPrincipalId ?? null,
          actionIntentId,
          catalogOperationId,
          aggregateType,
          aggregateId,
          aggregateVersion,
          candidateDigest,
          proof.approvalRequestId ?? null,
          evidenceChallengeId ?? null,
          session.participant_epoch,
          session.authority_epoch,
          authority.authority_envelope_id,
          authority.envelope_epoch,
          authority.assignment_id,
          catalogOperationId === 'ID-OP-WEBAUTHN-VERIFY'
            ? verifiedAssertion!.credentialId
            : proof.evidenceKind === 'USER_WEBAUTHN'
              ? proof.signerCredentialId
              : null,
          webauthnAssertionBindingDigest ?? null,
          proof.evidenceCbor,
          proof.evidenceDigest,
          proof.coseSign1,
        ],
      );
      await client.query(
        `insert into control.outbox_event
          (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
           aggregate_sequence,payload_cbor,payload_digest,cose_sign1,webauthn_assertion_binding_digest,occurred_at)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())`,
        [
          actor.participantId,
          proof.privacyDomainId,
          uuidV7(),
          `openpc.identity.${aggregateType}.mutation.committed.v1`,
          aggregateType,
          aggregateId,
          one(sequence.rows).last_sequence,
          proof.evidenceCbor,
          proof.evidenceDigest,
          proof.coseSign1,
          webauthnAssertionBindingDigest ?? null,
        ],
      );
      const resultAggregateVersion = await this.currentAggregateVersion(
        client,
        actor.participantId,
        aggregateType,
        aggregateId,
        proof.privacyDomainId,
        catalogOperationId,
      );
      await client.query(
        `update control.idempotency_record set result_digest=$2,result_payload=$3,terminal_state='COMMITTED'
            ,result_aggregate_version=$5
          where participant_id=$1 and operation_id=$4`,
        [
          actor.participantId,
          stableDigest(result ?? null),
          result ?? null,
          operationId,
          resultAggregateVersion,
        ],
      );
      if (catalogOperationId === 'ID-OP-WORKLOAD-ROTATE')
        await completeDiscoveryCertificateRecoveryMutation(client, {
          participantId: actor.participantId,
          privacyDomainId: proof.privacyDomainId,
          operationId,
          predecessorCredentialId: aggregateId,
          authorityEnvelopeId: makerAuthority.authorityEnvelopeId,
          candidateDigest,
        });
      return this.committedMutation(
        client,
        actor.participantId,
        operationId,
        aggregateId,
        actionIntentId,
        actionIntent.semantic_digest,
        proof.idempotencyKey,
        result,
      );
    });
  }

  private async committedMutation<T>(
    client: PoolClient,
    participantId: string,
    operationId: string,
    aggregateId: string,
    actionIntentId: string,
    intentDigest: Buffer,
    idempotencyKey: string,
    result: T,
  ): Promise<IdentityMutationCommit<T>> {
    const selected = one(
      (
        await client.query<{
          created_at: Date;
          revision: string;
          updated_at: Date;
        }>(
          `select record.created_at,record.result_aggregate_version::text revision,
                  coalesce(evidence.occurred_at,record.created_at) updated_at
             from control.idempotency_record record
             left join control.mutation_evidence evidence
               on evidence.participant_id=record.participant_id
              and evidence.operation_id=record.operation_id
            where record.participant_id=$1 and record.operation_id=$2
              and record.terminal_state='COMMITTED'`,
          [participantId, operationId],
        )
      ).rows,
      'PC-IDENTITY-1009',
    );
    return {
      result,
      operation: {
        operationId,
        resourceRef: `urn:openpc:resource:${aggregateId}`,
        actionIntentId,
        intentDigest: `sha256:${intentDigest.toString('hex')}`,
        idempotencyKey,
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        createdAt: timestamp(selected.created_at),
        updatedAt: timestamp(selected.updated_at),
        revision: selected.revision,
      },
    };
  }

  private async currentAggregateVersion(
    client: PoolClient,
    participantId: string,
    aggregateType: string,
    aggregateId: string,
    privacyDomainId: string,
    catalogOperationId: string,
  ): Promise<string> {
    if (aggregateType === 'recovery' && catalogOperationId === 'ID-OP-RECOVERY-POST-REVIEW') {
      const signerVersion = await lockIdentityEnvelopeRecoveryReviewVersion(
        client,
        participantId,
        privacyDomainId,
        aggregateId,
      );
      if (signerVersion !== undefined) return signerVersion;
    }
    const lookup: Readonly<Record<string, { readonly table: string; readonly id: string }>> = {
      'directory-connector': { table: 'directory_connector', id: 'connector_id' },
      'participant-invitation': { table: 'participant_invitation', id: 'invitation_id' },
      'principal': { table: 'principal', id: 'principal_id' },
      'workload-credential': { table: 'credential', id: 'credential_id' },
      'wallet-binding': { table: 'wallet_binding', id: 'wallet_binding_id' },
      'recovery-principal': { table: 'recovery_principal', id: 'principal_id' },
      'recovery': { table: 'recovery_challenge', id: 'recovery_challenge_id' },
      'session': { table: 'session', id: 'session_id' },
      'webauthn-credential': { table: 'credential', id: 'credential_id' },
      'webauthn-registration': { table: 'session', id: 'session_id' },
      'webauthn-verification': { table: 'session', id: 'session_id' },
    };
    const target = lookup[aggregateType];
    if (target === undefined) throw new IdentityKernelError('PC-IDENTITY-1004');
    // Authentication advances the replay counter and row version, but does not change
    // the approved credential lifecycle. Revocation/replacement advances credential_epoch.
    const revisionColumn =
      aggregateType === 'webauthn-credential' ? 'credential_epoch' : 'row_version';
    const version = await client.query<{ row_version: string }>(
      `select ${revisionColumn}::text as row_version from control.${target.table}
        where participant_id=$1 and ${target.id}=$2 for update`,
      [participantId, aggregateId],
    );
    return version.rows[0]?.row_version ?? '0';
  }

  private async beginMutationIdempotency<T>(
    client: PoolClient,
    actor: AuthenticatedIdentityActor,
    actionIntentId: string,
    catalogOperationId: string,
    idempotencyKey: string,
    inputDigest: Buffer,
    webauthnAssertionBindingDigest: Buffer | undefined,
    expectedAggregateVersion: string,
    operationId: string,
    preparationOnly = false,
  ): Promise<MutationIdempotency<T>> {
    if (!preparationOnly) {
      const inserted = await client.query<{ operation_id: string }>(
        `insert into control.idempotency_record
        (participant_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,operation_id,
         input_digest,webauthn_assertion_binding_digest,expected_aggregate_version,expires_at,privacy_domain_id)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '24 hours',$10)
        on conflict (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key)
        do update set operation_id=excluded.operation_id,input_digest=excluded.input_digest,
          webauthn_assertion_binding_digest=excluded.webauthn_assertion_binding_digest,
          expected_aggregate_version=excluded.expected_aggregate_version,result_digest=null,
          result_payload=null,result_aggregate_version=null,terminal_state=null,
          created_at=clock_timestamp(),expires_at=excluded.expires_at
        where control.idempotency_record.expires_at<=clock_timestamp()
        returning operation_id`,
        [
          actor.participantId,
          actor.principalId,
          actionIntentId,
          catalogOperationId,
          idempotencyKey,
          operationId,
          inputDigest,
          webauthnAssertionBindingDigest ?? null,
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
    }
    const prior = await client.query<{
      expected_aggregate_version: string;
      input_digest: Buffer;
      operation_id: string;
      result_aggregate_version: string | null;
      result_payload: T | null;
      terminal_state: string | null;
      webauthn_assertion_binding_digest: Buffer | null;
    }>(
      `select operation_id,input_digest,webauthn_assertion_binding_digest,expected_aggregate_version::text,
              result_aggregate_version::text,result_payload,terminal_state
         from control.idempotency_record
        where participant_id=$1 and privacy_domain_id=$2::uuid and principal_id=$3
          and action_intent_id=$4 and catalog_operation_id=$5 and idempotency_key=$6
        for update`,
      [
        actor.participantId,
        actor.mutationAuthorization!.privacyDomainId,
        actor.principalId,
        actionIntentId,
        catalogOperationId,
        idempotencyKey,
      ],
    );
    if (preparationOnly && prior.rowCount === 0) {
      return {
        expectedAggregateVersion,
        operationId,
        replay: false,
        result: undefined,
        resultAggregateVersion: undefined,
      };
    }
    const row = one(prior.rows, 'PC-IDENTITY-1009');
    if (
      !row.input_digest.equals(inputDigest) ||
      (webauthnAssertionBindingDigest === undefined
        ? row.webauthn_assertion_binding_digest !== null
        : row.webauthn_assertion_binding_digest === null ||
          !row.webauthn_assertion_binding_digest.equals(webauthnAssertionBindingDigest)) ||
      row.expected_aggregate_version !== expectedAggregateVersion ||
      row.terminal_state !== 'COMMITTED' ||
      row.result_aggregate_version === null
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1009');
    }
    return {
      expectedAggregateVersion: row.expected_aggregate_version,
      operationId: row.operation_id,
      replay: true,
      result: row.result_payload ?? undefined,
      resultAggregateVersion: row.result_aggregate_version,
    };
  }

  private async transaction<T>(
    participantId: string | undefined,
    actionIntentId: string,
    operation: ScopedOperation<T>,
    privacyDomainId?: string,
    reservedOperationId?: string,
  ): Promise<T> {
    if (!ACTION_PATTERN.test(actionIntentId)) throw new IdentityKernelError('PC-IDENTITY-1004');
    try {
      return await runScopedTransaction(
        this.pool,
        {
          ...(participantId === undefined ? {} : { participantId }),
          ...(privacyDomainId === undefined ? {} : { privacyDomainId }),
          actionIntentId,
        },
        reservedOperationId === undefined ? uuidV7 : () => reservedOperationId,
        operation,
      );
    } catch (error) {
      if (error instanceof AuthorityFenceError) throw new IdentityKernelError('PC-IDENTITY-1001');
      if (error instanceof ScopedTransactionSecurityError) {
        throw new IdentityKernelError('PC-IDENTITY-1004');
      }
      throw error;
    }
  }
}

function unavailable(): never {
  throw new IdentityKernelError('PC-IDENTITY-1004');
}

const unavailableRepository = new Proxy({} as PostgresIdentityRepository, {
  get: () => unavailable,
});

/** Thin service coordinator; it never owns process-local identity state. */
export class IdentityKernel {
  platformRecoveryCommand(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    enrollmentId: string,
    command: PlatformRecoveryCommand,
    origin: string,
  ) {
    return this.repository.platformRecoveryCommand(
      actor,
      privacyDomainId,
      enrollmentId,
      command,
      origin,
    );
  }
  discoveryCertificateRecoveryCommand(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    enrollmentId: string,
    command: DiscoveryCertificateRecoveryCommand,
    origin: string,
  ) {
    return this.repository.discoveryCertificateRecoveryCommand(
      actor,
      privacyDomainId,
      enrollmentId,
      command,
      origin,
    );
  }
  discoveryRecoveryCertificate(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    enrollmentId: string,
    recoveryId: string,
    credentialId: string,
  ) {
    return this.repository.discoveryRecoveryCertificate(
      actor,
      privacyDomainId,
      enrollmentId,
      recoveryId,
      credentialId,
    );
  }
  bootstrapAcceptance(
    scope: BootstrapSessionScope,
    command: BootstrapCommand,
    origin: string,
    registration: WebAuthnRegistrationAdapter,
  ) {
    return this.repository.bootstrapAcceptance(scope, command, origin, registration);
  }
  constructor(private readonly repository: PostgresIdentityRepository = unavailableRepository) {}

  resolveInvitationProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    digest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.resolveInvitationProposalResource(
      actor,
      privacyDomainId,
      digest,
      binding,
    );
  }
  invitationProposal(
    actor: AuthenticatedIdentityActor,
    invitationId: string,
    authority: BoundAuthority,
    digest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.invitationProposal(actor, invitationId, authority, digest, binding);
  }

  invitationReadback(
    actor: AuthenticatedIdentityActor,
    invitationId: string,
    authority: BoundAuthority,
  ) {
    return this.repository.invitationReadback(actor, invitationId, authority);
  }
  mutateInvitation(
    actor: AuthenticatedIdentityActor,
    candidate: InvitationCandidate,
    roleAuthority?: BoundAuthority,
  ) {
    return this.repository.mutateInvitation(actor, candidate, roleAuthority);
  }

  directoryProfileReadback(
    actor: AuthenticatedIdentityActor,
    authority: BoundAuthority,
    profiles: readonly { profileId: string; label: string }[],
  ) {
    return this.repository.directoryProfileReadback(actor, authority, profiles);
  }

  resolveDirectoryMemberResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    connectorId: string,
    externalId: string,
  ) {
    return this.repository.resolveDirectoryMemberResource(
      actor,
      privacyDomainId,
      connectorId,
      externalId,
    );
  }
  directoryMemberReadback(
    actor: AuthenticatedIdentityActor,
    connectorId: string,
    externalId: string,
    connectorAuthority: BoundAuthority,
    memberAuthority: BoundAuthority,
  ) {
    return this.repository.directoryMemberReadback(
      actor,
      connectorId,
      externalId,
      connectorAuthority,
      memberAuthority,
    );
  }

  directoryReconciliationContext(
    actor: AuthenticatedIdentityActor,
    connectorId: string,
    authority: BoundAuthority,
    externalIds: readonly string[],
  ) {
    return this.repository.directoryReconciliationContext(
      actor,
      connectorId,
      authority,
      externalIds,
    );
  }
  reconcileDirectoryMembers(
    actor: AuthenticatedIdentityActor,
    candidate: DirectoryReconciliationCandidate,
    profile: RegisteredDirectoryProfile,
  ) {
    return this.repository.reconcileDirectoryMembers(actor, candidate, profile);
  }

  directoryConnectorReadback(
    actor: AuthenticatedIdentityActor,
    connectorId: string,
    authority: BoundAuthority,
  ) {
    return this.repository.directoryConnectorReadback(actor, connectorId, authority);
  }
  resolveDirectoryProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    digest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.resolveDirectoryProposalResource(
      actor,
      privacyDomainId,
      digest,
      binding,
    );
  }
  directoryProposal(
    actor: AuthenticatedIdentityActor,
    connectorId: string,
    authority: BoundAuthority,
    digest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.directoryProposal(actor, connectorId, authority, digest, binding);
  }
  mutateDirectoryConnector(
    actor: AuthenticatedIdentityActor,
    candidate: DirectoryConnectorCandidate,
  ) {
    return this.repository.mutateDirectoryConnector(actor, candidate);
  }

  beginOidc(configuration: OidcClientConfiguration, selectedParticipantId?: string) {
    return this.repository.beginOidc(configuration, selectedParticipantId);
  }
  beginInvitationProof(
    scope: InvitationScope & { readonly tokenVersion: string; readonly token: string },
    configuration: OidcClientConfiguration,
  ) {
    return this.repository.beginInvitationProof(scope, configuration);
  }
  invitationProofContext(
    request: InvitationProofRequest,
    custody: OidcTransactionCustody,
    configuration: OidcClientConfiguration,
  ) {
    return this.repository.invitationProofContext(request, custody, configuration);
  }
  completeInvitationProof(
    request: InvitationProofRequest,
    custody: OidcTransactionCustody,
    identity: VerifiedOidcIdentity,
  ) {
    return this.repository.completeInvitationProof(request, custody, identity);
  }
  issueLocalDevelopmentSession(participantId: string, principalId: string, freshStepUp: boolean) {
    return this.repository.issueLocalDevelopmentSession(participantId, principalId, freshStepUp);
  }
  oidcExchangeContext(transactionId: string, custody: OidcTransactionCustody) {
    return this.repository.oidcExchangeContext(transactionId, custody);
  }
  completeOidc(transactionId: string, custody: OidcTransactionCustody, callback: OidcCallback) {
    return this.repository.completeOidc(transactionId, custody, callback);
  }
  beginInitialWebAuthnEnrollment(
    sessionToken: string,
    rpId: string,
    origin: string,
    hardwareAttestation?: boolean,
  ) {
    return hardwareAttestation === undefined
      ? this.repository.beginInitialWebAuthnEnrollment(sessionToken, rpId, origin)
      : this.repository.beginInitialWebAuthnEnrollment(
          sessionToken,
          rpId,
          origin,
          hardwareAttestation,
        );
  }
  initialWebAuthnEnrollmentContext(sessionToken: string, enrollmentId: string) {
    return this.repository.initialWebAuthnEnrollmentContext(sessionToken, enrollmentId);
  }
  webAuthnEnrollmentReadback(sessionToken: string, enrollmentId: string) {
    return this.repository.webAuthnEnrollmentReadback(sessionToken, enrollmentId);
  }
  completeInitialWebAuthnEnrollment(
    sessionToken: string,
    enrollmentId: string,
    registration: VerifiedWebAuthnRegistration,
  ) {
    return this.repository.completeInitialWebAuthnEnrollment(
      sessionToken,
      enrollmentId,
      registration,
    );
  }
  beginReplacementWebAuthnEnrollment(
    sessionToken: string,
    replacedCredentialId: string,
    rpId: string,
    origin: string,
  ) {
    return this.repository.beginReplacementWebAuthnEnrollment(
      sessionToken,
      replacedCredentialId,
      rpId,
      origin,
    );
  }
  replacementWebAuthnEnrollmentContext(sessionToken: string, enrollmentId: string) {
    return this.repository.replacementWebAuthnEnrollmentContext(sessionToken, enrollmentId);
  }
  completeReplacementWebAuthnEnrollment(
    actor: AuthenticatedIdentityActor,
    enrollmentId: string,
    replacedCredentialId: string,
    registration: VerifiedWebAuthnRegistration,
  ) {
    return this.repository.completeReplacementWebAuthnEnrollment(
      actor,
      enrollmentId,
      replacedCredentialId,
      registration,
    );
  }
  sessionSnapshot(sessionToken: string) {
    return this.repository.sessionSnapshot(sessionToken);
  }
  selectParticipantContext(sessionToken: string, selection: SessionContextSelection) {
    return this.repository.selectParticipantContext(sessionToken, selection);
  }
  refreshBrowserSession(actor: AuthenticatedIdentityActor, reason: string) {
    return this.repository.refreshBrowserSession(actor, reason);
  }
  revokeSession(actor: AuthenticatedIdentityActor, reason: string) {
    return this.repository.revokeSession(actor, reason);
  }
  sessionMutationContext(input: SessionMutationContextInput) {
    return this.repository.sessionMutationContext(input);
  }
  replayCommittedSessionMutation(input: SessionMutationReplayInput) {
    return this.repository.replayCommittedSessionMutation(input);
  }
  csrfToken(sessionToken: string, actionIntentId: string, origin: string, host: string) {
    return this.repository.csrfToken(sessionToken, actionIntentId, origin, host);
  }
  verifyCsrf(
    sessionToken: string,
    actionIntentId: string,
    origin: string,
    host: string,
    supplied: string,
  ) {
    return this.repository.verifyCsrf(sessionToken, actionIntentId, origin, host, supplied);
  }
  issueStepUpChallenge(
    actor: AuthenticatedIdentityActor,
    actionIntentId: string,
    resourceDigest: string,
    rpIdHash: string,
  ) {
    return this.repository.issueStepUpChallenge(actor, actionIntentId, resourceDigest, rpIdHash);
  }
  issueStepUpAssertionChallenge(
    sessionToken: string,
    actionIntentId: string,
    resourceDigest: string,
    rpIdHash: string,
    resourceId?: string,
  ) {
    return this.repository.issueStepUpAssertionChallenge(
      sessionToken,
      actionIntentId,
      resourceDigest,
      rpIdHash,
      resourceId,
    );
  }
  verifyStepUp(actor: AuthenticatedIdentityActor, proof: StepUpProof) {
    return this.repository.verifyStepUp(actor, proof);
  }
  requireFreshStepUp(sessionToken: string) {
    return this.repository.requireFreshStepUp(sessionToken);
  }
  sessionAggregateVersion(sessionToken: string) {
    return this.repository.sessionAggregateVersion(sessionToken);
  }
  webAuthnCredentialAggregateVersion(sessionToken: string, credentialId: string) {
    return this.repository.webAuthnCredentialAggregateVersion(sessionToken, credentialId);
  }
  actionIntentSemanticDigest(sessionToken: string, actionIntentId: string) {
    return this.repository.actionIntentSemanticDigest(sessionToken, actionIntentId);
  }
  provisionPrincipal(actor: AuthenticatedIdentityActor, principal: PrincipalRecord) {
    return this.repository.provisionPrincipal(actor, principal);
  }
  activatePrincipal(actor: AuthenticatedIdentityActor, principalId: string) {
    return this.repository.activatePrincipal(actor, principalId);
  }
  principalReadback(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
  ) {
    return this.repository.principalReadback(actor, principalId, authority);
  }
  resolvePrincipalProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    candidateDigest: string,
  ) {
    return this.repository.resolvePrincipalProposalResource(
      actor,
      privacyDomainId,
      candidateDigest,
    );
  }
  webAuthnCredentials(
    actor: AuthenticatedIdentityActor,
    authority: BoundAuthority,
    cursor?: string,
  ) {
    return this.repository.webAuthnCredentials(actor, authority, cursor);
  }

  resolveWebAuthnProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.resolveWebAuthnProposalResource(
      actor,
      privacyDomainId,
      candidateDigest,
      binding,
    );
  }

  webAuthnProposal(
    actor: AuthenticatedIdentityActor,
    resourceId: string,
    authority: BoundAuthority,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.webAuthnProposal(actor, resourceId, authority, candidateDigest, binding);
  }

  resolveRecoveryProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.resolveRecoveryProposalResource(
      actor,
      privacyDomainId,
      candidateDigest,
      binding,
    );
  }
  resolveIdentitySubjectMembership(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    subjectId: string,
  ) {
    return this.repository.resolveIdentitySubjectMembership(actor, privacyDomainId, subjectId);
  }
  identitySubjectReadback(
    actor: AuthenticatedIdentityActor,
    membershipId: string,
    subjectId: string,
    authority: BoundAuthority,
  ) {
    return this.repository.identitySubjectReadback(actor, membershipId, subjectId, authority);
  }
  principalProposal(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
    candidateDigest: string,
  ) {
    return this.repository.principalProposal(actor, principalId, authority, candidateDigest);
  }
  recoveryProposal(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.recoveryProposal(
      actor,
      principalId,
      authority,
      candidateDigest,
      binding,
    );
  }
  suspendPrincipal(actor: AuthenticatedIdentityActor, principalId: string) {
    return this.repository.suspendPrincipal(actor, principalId);
  }
  removeMembership(actor: AuthenticatedIdentityActor, principalId: string) {
    return this.repository.removeMembership(actor, principalId);
  }
  principalCatalogueCandidates(
    actor: AuthenticatedIdentityActor,
    authority: BoundAuthority,
    query: PrincipalCatalogueQuery,
  ) {
    return this.repository.principalCatalogueCandidates(actor, authority, query);
  }
  fencePrincipalCatalogue(actor: AuthenticatedIdentityActor, authority: BoundAuthority) {
    return this.repository.fencePrincipalCatalogue(actor, authority);
  }
  validateWorkloadCredential(input: WorkloadCredentialInput) {
    return this.repository.validateWorkloadCredential(input);
  }
  authenticateWorkload(
    input: WorkloadCredentialInput,
    runtimeContext?: RuntimePublicationContext,
    transport?: PresentedCertificate,
  ) {
    return this.repository.authenticateWorkload(input, runtimeContext, transport);
  }
  issueWorkload(actor: AuthenticatedIdentityActor, credential: WorkloadRecord) {
    return this.repository.issueWorkload(actor, credential);
  }
  issueWorkloadFromIssuer(
    actor: AuthenticatedIdentityActor,
    request: WorkloadCertificateRequest,
    issuer: WorkloadCredentialIssuer,
  ) {
    return this.repository.issueWorkloadFromIssuer(actor, request, issuer);
  }
  rotateWorkload(actor: AuthenticatedIdentityActor, credentialId: string) {
    return this.repository.rotateWorkload(actor, credentialId);
  }
  rotateWorkloadFromIssuer(
    actor: AuthenticatedIdentityActor,
    replacedCredentialId: string,
    credentialId: string,
    publicKeySpkiDer: Buffer,
    issuer: WorkloadCredentialIssuer,
  ) {
    return this.repository.rotateWorkloadFromIssuer(
      actor,
      replacedCredentialId,
      credentialId,
      publicKeySpkiDer,
      issuer,
    );
  }
  workloadCertificate(
    actor: AuthenticatedIdentityActor,
    credentialId: string,
    authority: BoundAuthority,
  ) {
    return this.repository.workloadCertificate(actor, credentialId, authority);
  }
  walletBinding(
    actor: AuthenticatedIdentityActor,
    walletBindingId: string,
    authority: BoundAuthority,
  ) {
    return this.repository.walletBinding(actor, walletBindingId, authority);
  }
  createWalletBinding(actor: AuthenticatedIdentityActor, input: WalletBindingCreation) {
    return this.repository.createWalletBinding(actor, input);
  }
  revokeWalletBinding(actor: AuthenticatedIdentityActor, walletBindingId: string) {
    return this.repository.revokeWalletBinding(actor, walletBindingId);
  }
  resolveWorkloadProposalResource(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
  ) {
    return this.repository.resolveWorkloadProposalResource(
      actor,
      privacyDomainId,
      candidateDigest,
      binding,
    );
  }
  workloadProposal(
    actor: AuthenticatedIdentityActor,
    resourceId: string,
    authority: BoundAuthority,
    candidateDigest: string,
    binding: RecoveryProposalBinding,
    preapproval?: { readonly recoveryId: string; readonly enrollmentId: string },
  ) {
    return this.repository.workloadProposal(
      actor,
      resourceId,
      authority,
      candidateDigest,
      binding,
      preapproval,
    );
  }
  workloadCredential(actor: AuthenticatedIdentityActor, credentialId: string) {
    return this.repository.workloadCredential(actor, credentialId);
  }
  revokeWorkload(actor: AuthenticatedIdentityActor, credentialId: string) {
    return this.repository.revokeWorkload(actor, credentialId);
  }
  qualifyRecoveryPrincipal(actor: AuthenticatedIdentityActor, request: RecoveryQualification) {
    return this.repository.qualifyRecoveryPrincipal(actor, request);
  }
  revokeRecoveryPrincipal(actor: AuthenticatedIdentityActor, principalId: string) {
    return this.repository.revokeRecoveryPrincipal(actor, principalId);
  }
  recoveryPrincipalReadback(
    actor: AuthenticatedIdentityActor,
    principalId: string,
    authority: BoundAuthority,
  ) {
    return this.repository.recoveryPrincipalReadback(actor, principalId, authority);
  }
  postReviewRecovery(actor: AuthenticatedIdentityActor, recoveryId: string, note: string) {
    return this.repository.postReviewRecovery(actor, recoveryId, note);
  }
  beginRecovery(actor: AuthenticatedIdentityActor, request: RecoveryRequest) {
    return this.repository.beginRecovery(actor, request);
  }
  recoveryReadback(
    actor: AuthenticatedIdentityActor,
    recoveryId: string,
    authority: BoundAuthority,
  ) {
    return this.repository.recoveryReadback(actor, recoveryId, authority);
  }
  approveRecovery(actor: AuthenticatedIdentityActor, recoveryId: string, purposeDigest: string) {
    return this.repository.approveRecovery(actor, recoveryId, purposeDigest);
  }
  completeRecovery(actor: AuthenticatedIdentityActor, recoveryId: string) {
    return this.repository.completeRecovery(actor, recoveryId);
  }
  verifyFrozenEs256Vector(
    publicKeySpkiDerHex: string,
    sigStructureHex: string,
    signatureHex: string,
  ): boolean {
    return verifyEs256P1363(
      Buffer.from(publicKeySpkiDerHex, 'hex'),
      Buffer.from(sigStructureHex, 'hex'),
      Buffer.from(signatureHex, 'hex'),
    );
  }
  workloadRotationDue(notBefore: Date): Date {
    return new Date(notBefore.getTime() + WORKLOAD_ROTATION_MS);
  }
}
