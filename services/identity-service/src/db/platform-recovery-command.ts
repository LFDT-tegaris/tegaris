import { executeRootExpiryRecoveryCommand } from './root-expiry-recovery-command.js';
import {
  defaultRecoveryLifetimes,
  recoveryLifetimeSettings,
  type RecoveryLifetimeSettings,
} from '../domain/platform-recovery-lifetimes.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import type { PlatformRecoveryIntent } from '../contracts/platform-recovery.js';
import type { PlatformRecoveryPhase } from '../domain/platform-recovery-ceremony.js';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import {
  PlatformRecoveryError,
  platformRecoverySourceCeiling,
  pendingAdministrationExpiryReason,
} from '../domain/platform-recovery-policy.js';
import {
  createPlatformRecoveryCase,
  readPlatformRecoveryCeremony,
  readPlatformRecoverySource,
} from './platform-recovery-case.js';
import {
  issuePlatformRecoveryChallenge,
  acceptPlatformRecoveryProof,
  readPlatformRecoverySession,
} from './platform-recovery-proof.js';
import { readPlatformScopeReplacementSource } from './platform-scope-replacement-store.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { platformScopeReplacementPreparation } from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import {
  createDiscoveryCertificateRecoveryCase,
  readDiscoveryCertificateRecoveryCeremony,
} from './discovery-certificate-recovery-case.js';
import { readDiscoveryCertificateRecoverySource } from './discovery-certificate-recovery-source.js';
import { activateDiscoveryCertificateRecoveryLease } from './platform-recovery-activation.js';
import { readDiscoveryCertificateRecoveryReceipt } from './platform-recovery-readback.js';
import { activatePlatformRecoveryLease } from './platform-recovery-activation.js';
import { readPlatformRecoveryReceipt } from './platform-recovery-readback.js';
import { readExpiredRecoverySupersession } from './platform-recovery-supersession.js';
import { closePlatformRecoveryCase } from './platform-recovery-closure.js';
import { readRecoveryEnrollmentPurpose } from './recovery-enrollment-purpose.js';
import { executeIdentityEnvelopeRecoveryCommand } from './identity-envelope-recovery-command.js';

export type PlatformRecoveryCommand =
  | { readonly kind: 'SOURCE' }
  | { readonly kind: 'CREATE'; readonly preparation: PlatformRecoveryIntent['preparation'] }
  | { readonly kind: 'CREATE' }
  | { readonly kind: 'ROTATION_CREATE'; readonly recoveryId: string }
  | {
      readonly kind: 'ROTATION_ADVANCE';
      readonly recoveryId: string;
      readonly expectedRevision: string;
      readonly idempotencyKey: string;
    }
  | { readonly kind: 'READ'; readonly recoveryId: string; readonly preparationDigest?: string }
  | {
      readonly kind: 'CHALLENGE';
      readonly recoveryId: string;
      readonly phase: PlatformRecoveryPhase;
    }
  | {
      readonly kind: 'PROVE';
      readonly recoveryId: string;
      readonly phase: PlatformRecoveryPhase;
      readonly proof: {
        readonly challengeId: string;
        readonly challenge: string;
        readonly intentDigest: string;
        readonly assertion: string;
      };
    }
  | { readonly kind: 'CLOSE'; readonly recoveryId: string };

/** One caller transaction owns proof consumption, counter CAS, state and lease effects. No ordinary grant substitutes for enrolled trust. */
export async function executePlatformRecoveryCommand(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  command: PlatformRecoveryCommand,
  origin: string,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
  lifetimes: RecoveryLifetimeSettings = defaultRecoveryLifetimes,
) {
  recoveryLifetimeSettings.parse(lifetimes);
  if (lifetimes.profile === 'LOCAL_QA' && !localQaEnabled) throw new PlatformRecoveryError();
  const purpose = await readRecoveryEnrollmentPurpose(client, actor.participantId, enrollmentId);
  if (
    command.kind === 'READ' &&
    command.preparationDigest !== undefined &&
    purpose !== 'pc.identity.platform-recovery-enrollment'
  )
    throw new PlatformRecoveryError();
  if (purpose === 'pc.identity.local-root-expiry-recovery-enrollment')
    return executeRootExpiryRecoveryCommand(
      client,
      actor,
      enrollmentId,
      command,
      origin,
      operationId,
      localQaEnabled,
      signer,
    );
  if (purpose === 'pc.identity.identity-envelope-recovery-enrollment')
    return executeIdentityEnvelopeRecoveryCommand(
      client,
      actor,
      enrollmentId,
      command,
      origin,
      operationId,
      localQaEnabled,
      signer,
      lifetimes,
    );
  if (purpose !== 'pc.identity.platform-recovery-enrollment') throw new PlatformRecoveryError();
  if (command.kind === 'ROTATION_CREATE' || command.kind === 'ROTATION_ADVANCE')
    throw new PlatformRecoveryError();
  if (command.kind === 'SOURCE') {
    const source = await readPlatformRecoverySource(client, enrollmentId, localQaEnabled, signer);
    if (
      lifetimes.profile === 'LOCAL_QA' &&
      source.enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'
    )
      throw new PlatformRecoveryError();
    const enrolled = [
      source.enrollment.recoveryPrincipal.principalId,
      ...source.enrollment.custodians.map((v) => v.principalId),
      ...source.enrollment.administratorPrincipalIds,
    ];
    if (!enrolled.includes(actor.principalId)) throw new PlatformRecoveryError();
    await readPlatformRecoverySession(client, actor, source.enrollment);
    if (source.enrollment.schemaVersion === 3) {
      if (!source.recoveryContinuation) throw new PlatformRecoveryError();
      return {
        enrollmentId,
        lifetimes,
        continuation: source.recoveryContinuation,
        assurance: source.enrollment.assurance,
        authority: 'NONE' as const,
        source: {
          platformContextId: source.enrollment.platformContextId,
          rootEpoch: source.enrollment.rootEpoch,
          rootRevision: source.enrollment.rootRevision,
          rootDigest: source.enrollment.rootDigest,
          recoverySource: source.enrollment.source,
          executorPrincipalId: source.enrollment.recoveryPrincipal.principalId,
          custodianPrincipalIds: source.enrollment.custodians.map((v) => v.principalId),
          administratorPrincipalIds: source.enrollment.administratorPrincipalIds,
        },
        preparation: platformScopeReplacementPreparation.parse(source.preparation),
        proposalBefore: new Date(
          Math.min(source.now.getTime() + 60000, Date.parse(source.enrollment.validUntil)),
        ).toISOString(),
      };
    }
    if (source.enrollment.schemaVersion === 4 && source.approvalContinuation) {
      return {
        enrollmentId,
        lifetimes,
        pendingExpiry: source.pendingExpiry,
        approvalContinuation: source.approvalContinuation,
        assurance: source.enrollment.assurance,
        authority: 'NONE' as const,
        source: {
          platformContextId: source.enrollment.platformContextId,
          rootEpoch: source.enrollment.rootEpoch,
          rootRevision: source.enrollment.rootRevision,
          rootDigest: source.enrollment.rootDigest,
          recoverySource: source.enrollment.source,
          executorPrincipalId: source.enrollment.recoveryPrincipal.principalId,
          custodianPrincipalIds: source.enrollment.custodians.map((v) => v.principalId),
          administratorPrincipalIds: source.enrollment.administratorPrincipalIds,
        },
        preparation: platformScopeReplacementPreparation.parse(source.preparation),
        proposalBefore: new Date(
          Math.min(source.now.getTime() + 60000, Date.parse(source.enrollment.validUntil)),
        ).toISOString(),
      };
    }
    const live = await readPlatformScopeReplacementSource(
      client,
      actor.participantId,
      source.enrollment.privacyDomainId,
      source.enrollment.platformContextId,
    );
    const supersession = source.pendingExpiry
      ? undefined
      : await readExpiredRecoverySupersession(client, actor, source, signer);
    const preparation = structuredClone(source.preparation);
    const oldNames = [
      preparation.replacementId,
      ...preparation.administrators.flatMap((v) => [v.envelopeId, v.assignmentId]),
    ];
    const names = oldNames.map(() => localOperationId());
    const replaceNames = (values: string[]) =>
      [
        ...new Set(values.map((v) => (oldNames.includes(v) ? names[oldNames.indexOf(v)]! : v))),
      ].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    preparation.replacementId = names[0]!;
    preparation.predecessorEpoch = source.enrollment.rootEpoch;
    preparation.predecessorDigest = source.enrollment.rootDigest;
    preparation.expectedRootRevision = source.enrollment.rootRevision;
    if (!source.pendingExpiry) preparation.successorScope = platformRecoverySourceCeiling(source);
    else if ('rootExpiryPendingBridge' in source && source.rootExpiryPendingBridge) {
      preparation.successorScope.validFromNs = source.root.grantable.validFromNs;
      preparation.successorScope.validUntilNs = source.root.grantable.validUntilNs;
    }
    preparation.successorScope.administration.resourceIds = replaceNames(
      // The verified predecessor already replaced its installation placeholders.
      // Preserve that exact target set before substituting the five new names.
      source.uneffectedPreparation?.successorScope.administration.resourceIds ??
        preparation.successorScope.administration.resourceIds,
    );
    if (
      source.pendingExpiry &&
      canonicalAuthorizationJson(preparation.affectedTargets) !==
        canonicalAuthorizationJson(live.affectedTargets)
    )
      throw new PlatformRecoveryError();
    preparation.affectedTargets = live.affectedTargets;
    delete preparation.supersedes;
    if (supersession)
      preparation.supersedes = {
        replacementId: supersession.replacementId,
        expectedRevision: supersession.expectedRevision,
        successorDigest: supersession.successorDigest,
      };
    if (source.pendingExpiry)
      preparation.supersedes = {
        replacementId: source.pendingExpiry.preparation.replacementId,
        expectedRevision: source.pendingExpiry.preparation.expectedRevision,
        successorDigest: source.pendingExpiry.preparation.successorDigest,
      };
    preparation.reason = source.pendingExpiry
      ? pendingAdministrationExpiryReason
      : 'Restore only the expired Platform administrator handoff through enrolled independent recovery custody.';
    for (const [index, administrator] of preparation.administrators.entries()) {
      administrator.envelopeId = names[1 + index * 2]!;
      administrator.assignmentId = names[2 + index * 2]!;
      for (const key of ['usable', 'grantable'] as const) {
        administrator[key].validFromNs = (
          BigInt(source.now.getTime() + 60000) * 1000000n
        ).toString();
        administrator[key].validUntilNs = (
          BigInt(
            Math.min(
              source.now.getTime() + lifetimes.administratorMs,
              Number(BigInt(source.root.grantable.validUntilNs) / 1000000n),
            ),
          ) * 1000000n
        ).toString();
        administrator[key].administration.resourceIds = replaceNames(
          administrator[key].administration.resourceIds,
        );
      }
    }
    return {
      enrollmentId,
      lifetimes,
      ...(supersession ? { supersession } : {}),
      ...(source.pendingExpiry ? { pendingExpiry: source.pendingExpiry } : {}),
      assurance: source.enrollment.assurance,
      authority: 'NONE' as const,
      source: {
        platformContextId: source.enrollment.platformContextId,
        rootEpoch: source.enrollment.rootEpoch,
        rootRevision: source.enrollment.rootRevision,
        rootDigest: source.enrollment.rootDigest,
        ...(source.enrollment.schemaVersion !== 1
          ? { recoverySource: source.enrollment.source }
          : { expiredReplacementId: source.enrollment.expiredReplacementId }),
        executorPrincipalId: source.enrollment.recoveryPrincipal.principalId,
        custodianPrincipalIds: source.enrollment.custodians.map((v) => v.principalId),
        administratorPrincipalIds: source.enrollment.administratorPrincipalIds,
      },
      preparation: platformScopeReplacementPreparation.parse(preparation),
      proposalBefore: new Date(source.now.getTime() + 60000).toISOString(),
    };
  }
  if (command.kind === 'CREATE') {
    if (!('preparation' in command)) throw new PlatformRecoveryError();
    return createPlatformRecoveryCase(
      client,
      actor,
      enrollmentId,
      command.preparation,
      localQaEnabled,
      lifetimes,
      signer,
    );
  }
  if (command.kind === 'READ' && command.preparationDigest !== undefined) {
    return (
      await readPlatformRecoveryReceipt(
        client,
        actor,
        enrollmentId,
        command.recoveryId,
        signer,
        command.preparationDigest,
      )
    ).receipt;
  }
  return executeRecoveryCustodyCommand(
    client,
    actor,
    enrollmentId,
    command,
    origin,
    operationId,
    localQaEnabled,
    signer,
    readPlatformRecoveryReceipt,
    (client, actor, enrollmentId, recoveryId, qa) =>
      readPlatformRecoveryCeremony(client, actor, enrollmentId, recoveryId, qa, signer),
    activatePlatformRecoveryLease,
  );
}

export type DiscoveryCertificateRecoveryCommand =
  | Exclude<
      PlatformRecoveryCommand,
      { readonly kind: 'CREATE' | 'ROTATION_CREATE' | 'ROTATION_ADVANCE' }
    >
  | { readonly kind: 'CREATE' };

/** Separate public command purpose. No preparation or caller certificate binding is accepted. */
export async function executeDiscoveryCertificateRecoveryCommand(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  command: DiscoveryCertificateRecoveryCommand,
  origin: string,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
  configuredLifetimes: RecoveryLifetimeSettings = defaultRecoveryLifetimes,
) {
  if (command.kind === 'READ' && command.preparationDigest !== undefined)
    throw new PlatformRecoveryError();
  const lifetimes = recoveryLifetimeSettings.parse(configuredLifetimes);
  if (command.kind === 'CREATE')
    return createDiscoveryCertificateRecoveryCase(
      client,
      actor,
      enrollmentId,
      localQaEnabled,
      lifetimes,
      signer,
    );
  if (command.kind === 'SOURCE') {
    const source = await readDiscoveryCertificateRecoverySource(
      client,
      enrollmentId,
      localQaEnabled,
      actor,
      null,
      signer,
    );
    if (
      lifetimes.profile === 'LOCAL_QA' &&
      (!localQaEnabled || source.enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR')
    )
      throw new PlatformRecoveryError();
    return {
      enrollmentId,
      lifetimes,
      assurance: source.enrollment.assurance,
      authority: 'NONE' as const,
      source: {
        platformContextId: source.enrollment.platformContextId,
        rootEpoch: source.enrollment.rootEpoch,
        rootRevision: source.enrollment.rootRevision,
        rootDigest: source.enrollment.rootDigest,
        ...(source.enrollment.schemaVersion === 1
          ? { expiredReplacementId: source.enrollment.expiredReplacementId }
          : { recoverySource: source.enrollment.source }),
        executorPrincipalId: source.enrollment.recoveryPrincipal.principalId,
        custodianPrincipalIds: source.enrollment.custodians.map((v) => v.principalId),
        administratorPrincipalIds: source.enrollment.administratorPrincipalIds,
      },
      certificateRecovery: source.enrollment.certificateRecovery,
    };
  }
  return executeRecoveryCustodyCommand(
    client,
    actor,
    enrollmentId,
    command,
    origin,
    operationId,
    localQaEnabled,
    signer,
    readDiscoveryCertificateRecoveryReceipt,
    readDiscoveryCertificateRecoveryCeremony,
    activateDiscoveryCertificateRecoveryLease,
  );
}

async function executeRecoveryCustodyCommand(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  command: Exclude<
    PlatformRecoveryCommand,
    { readonly kind: 'SOURCE' | 'CREATE' | 'ROTATION_CREATE' | 'ROTATION_ADVANCE' }
  >,
  origin: string,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
  readReceipt: typeof readPlatformRecoveryReceipt | typeof readDiscoveryCertificateRecoveryReceipt,
  readCeremony: typeof readDiscoveryCertificateRecoveryCeremony,
  activate: typeof activatePlatformRecoveryLease,
) {
  if (command.kind === 'READ')
    return (await readReceipt(client, actor, enrollmentId, command.recoveryId, signer)).receipt;
  if (command.kind === 'CLOSE') {
    // Declare the Participant root write before source/case/session children.
    await client.query('select * from openpc.lock_platform_recovery_enrollment($1)', [
      enrollmentId,
    ]);
    const read = await readReceipt(client, actor, enrollmentId, command.recoveryId, signer);
    if (
      ![
        read.enrollment.recoveryPrincipal.principalId,
        ...read.enrollment.custodians.map((v) => v.principalId),
      ].includes(actor.principalId)
    )
      throw new PlatformRecoveryError();
    if (['COMPLETED', 'REVOKED', 'EXPIRED'].includes(read.receipt.state)) return read.receipt;
    await closePlatformRecoveryCase(
      client,
      actor,
      read.enrollment,
      command.recoveryId,
      read.receipt.revision,
      read.session,
      operationId,
      signer,
    );
    return (await readReceipt(client, actor, enrollmentId, command.recoveryId, signer)).receipt;
  }
  if (command.kind === 'PROVE') {
    // Reconcile an exact consumed proof before attempting mutation. This path
    // returns a historical receipt and never signs or reissues a lease.
    const prior = await client.query<{
      assertion: unknown;
      sessionId: string;
      sessionEpoch: string;
    }>(
      `select proof.assertion_evidence->'assertion' as assertion,proof.session_id::text as "sessionId",proof.session_epoch::text as "sessionEpoch"
       from control.platform_recovery_proof proof join control.platform_recovery_challenge challenge
        on challenge.participant_id=proof.participant_id and challenge.recovery_id=proof.recovery_id
         and challenge.challenge_id=proof.challenge_id and challenge.proof_id=proof.proof_id
       join control.platform_recovery_case c on c.participant_id=proof.participant_id and c.recovery_id=proof.recovery_id
       where proof.participant_id=$1 and c.enrollment_id=$2 and proof.recovery_id=$3 and proof.principal_id=$4
        and proof.phase=$5 and proof.challenge_id=$6 and proof.intent_digest=$7 and challenge.origin=$8
        and challenge.challenge_digest=$9 and challenge.consumed_at is not null`,
      [
        actor.participantId,
        enrollmentId,
        command.recoveryId,
        actor.principalId,
        command.phase,
        command.proof.challengeId,
        Buffer.from(command.proof.intentDigest.slice(7), 'hex'),
        origin,
        createHash('sha256').update(command.proof.challenge).digest(),
      ],
    );
    if (prior.rowCount !== 0) {
      const row = prior.rows[0];
      if (
        prior.rowCount !== 1 ||
        !row ||
        canonicalAuthorizationJson(row.assertion) !==
          canonicalAuthorizationJson(JSON.parse(command.proof.assertion))
      )
        throw new PlatformRecoveryError();
      const read = await readReceipt(client, actor, enrollmentId, command.recoveryId, signer);
      if (
        row.sessionId !== read.session.sessionId ||
        row.sessionEpoch !== read.session.sessionEpoch
      )
        throw new PlatformRecoveryError();
      return read.receipt;
    }
  }
  const context = await readCeremony(
    client,
    actor,
    enrollmentId,
    command.recoveryId,
    localQaEnabled,
    signer,
  );
  if (command.kind === 'CHALLENGE')
    return issuePlatformRecoveryChallenge(client, context, actor, command.phase, origin);
  const proof = await acceptPlatformRecoveryProof(
    client,
    context,
    actor,
    command.phase,
    origin,
    command.proof,
  );
  if (command.phase === 'ACTIVATE') {
    await activate(client, context, proof, operationId, signer);
  } else if (command.phase === 'REQUEST') {
    const requested = await client.query(
      `update control.platform_recovery_case set state='REQUESTED',row_version=row_version+1,updated_at=clock_timestamp()
       where participant_id=$1 and enrollment_id=$2 and recovery_id=$3 and state='DRAFT' and valid_until>clock_timestamp()`,
      [actor.participantId, enrollmentId, command.recoveryId],
    );
    if (requested.rowCount !== 1) throw new PlatformRecoveryError();
  }
  return (await readReceipt(client, actor, enrollmentId, command.recoveryId, signer)).receipt;
}
