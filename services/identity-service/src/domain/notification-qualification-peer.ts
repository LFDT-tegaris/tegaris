import { createHash } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import type { Pool, PoolClient } from 'pg';
import type { IdentityKernel, AuthenticatedWorkloadIdentity } from './identity-kernel.js';
import {
  withAuthenticatedWorkloadPeer,
  type ConfirmWorkloadAuthorities,
  type WorkloadPeerDependencyResolver,
} from './workload-peer.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { localOperationId } from './local-operation-id.js';
import {
  qualificationPeerSchema,
  qualificationRunSelectorSchema,
  qualificationSelectionSchema,
  type QualificationSelection,
  type QualificationPeer,
  type NotificationQualificationSelector,
  type QualificationNativeExecutionOwner,
  type QualificationSignedOriginal,
  reject,
} from '../../../control-api/src/configuration/operations/notification-qualification-contract.js';
import {
  bindNotificationQualificationSource,
  dispatchNotificationQualification,
  prepareQualificationOrigin,
  retainQualificationOrigin,
  retainLateQualificationOrigin,
  reserveNotificationQualificationRun,
  readNotificationQualificationOriginal,
  withQualificationNativeBracket,
  notificationQualificationSigningIntent,
  retainNotificationQualificationSignedOriginal,
  resolveNotificationQualificationSigningAuthorities,
} from '../../../control-api/src/configuration/operations/notification-qualification-store.js';
import {
  sampleNotificationQualification,
  retainNotificationQualificationCase,
  sealNotificationQualification,
} from '../../../control-api/src/configuration/operations/notification-qualification-run.js';
import {
  retainNotificationQualificationNormalization,
  reviewNotificationQualification,
} from '../../../control-api/src/configuration/operations/notification-qualification-review.js';
function actualPeer(socket: TLSSocket, identity: AuthenticatedWorkloadIdentity): QualificationPeer {
  const raw = socket.getPeerCertificate(true).raw;
  if (!raw || socket.destroyed || !socket.authorized || socket.getProtocol() !== 'TLSv1.3')
    throw new Error('NOTIFICATION_QUALIFICATION_TLS');
  return qualificationPeerSchema.parse({
    principalId: identity.principalId,
    credentialId: identity.credentialId,
    participantEpoch: identity.participantEpoch,
    principalEpoch: identity.principalEpoch,
    credentialEpoch: identity.workloadEpoch,
    workloadId: identity.workloadId,
    keyDigest: identity.keyId,
    certificateDigest: 'sha256:' + createHash('sha256').update(raw).digest('hex'),
  });
}
/** Privileged installation-root composition only. The pool must already have
 * the exact qualification-owner role. Native host owner is REQUIRED; the
 * request surface never accepts a peer, capability, native reader or reviewer
 * decision. Canonical must compose its real native implementation before use. */
export function createNotificationQualificationPeer(options: {
  ownerPool: Pool;
  kernel: IdentityKernel;
  nativeExecution: QualificationNativeExecutionOwner;
}) {
  const authenticated = <T>(
    socket: TLSSocket,
    selection: QualificationSelection,
    use: (
      client: PoolClient,
      peer: QualificationPeer,
      identity: AuthenticatedWorkloadIdentity,
      confirm: () => Promise<void>,
      confirmAuthorities: ConfirmWorkloadAuthorities,
    ) => Promise<T>,
    dependencies?: WorkloadPeerDependencyResolver,
  ) => {
    const s = qualificationSelectionSchema.parse({
      participantId: selection.participantId,
      privacyDomainId: selection.privacyDomainId,
      installationId: selection.installationId,
    });
    return withAuthenticatedWorkloadPeer(
      options.ownerPool,
      options.kernel,
      socket,
      async (c, identity, confirm, confirmAuthorities) => {
        await confirm();
        const result = await use(
          c,
          actualPeer(socket, identity),
          identity,
          confirm,
          confirmAuthorities,
        );
        await confirm();
        return result;
      },
      s,
      dependencies,
    );
  };
  const native = <T>(
    socket: TLSSocket,
    selector: NotificationQualificationSelector,
    capability: 'QUALIFICATION_RUN' | 'QUALIFICATION_REVIEW',
    use: (client: PoolClient, peer: QualificationPeer) => Promise<T>,
  ) => {
    const s = qualificationRunSelectorSchema.parse(selector);
    return authenticated(socket, s, (c, peer) =>
      withQualificationNativeBracket(c, s, capability, socket, options.nativeExecution, (same) =>
        use(same, peer),
      ),
    );
  };
  const historical = <T>(
    selector: NotificationQualificationSelector,
    use: (client: PoolClient) => Promise<T>,
  ) => {
    const s = qualificationRunSelectorSchema.parse(selector);
    return runScopedTransaction(
      options.ownerPool,
      {
        participantId: s.participantId,
        privacyDomainId: s.privacyDomainId,
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      },
      localOperationId,
      use,
    );
  };
  return Object.freeze({
    prepareOrigin(
      socket: TLSSocket,
      s: QualificationSelection,
      kind: 'SUBJECT' | 'HARNESS',
      source: Buffer,
      build: Buffer,
    ) {
      if (
        !Buffer.isBuffer(source) ||
        !Buffer.isBuffer(build) ||
        source.length > 16777216 ||
        build.length > 16777216
      )
        reject();
      const sourceCopy = Buffer.from(source),
        buildCopy = Buffer.from(build);
      return authenticated(socket, s, (c, p) =>
        prepareQualificationOrigin(c, s, p, kind, sourceCopy, buildCopy),
      );
    },
    retainOrigin(
      socket: TLSSocket,
      s: QualificationSelection,
      originId: string,
      signatureHex: string,
    ) {
      return authenticated(socket, s, (c, p) =>
        retainQualificationOrigin(c, s, p, originId, signatureHex),
      );
    },
    reserve(socket: TLSSocket, s: NotificationQualificationSelector) {
      return authenticated(socket, s, (c, p) => reserveNotificationQualificationRun(c, s, p));
    },
    async dispatch(socket: TLSSocket, s: NotificationQualificationSelector) {
      const original = await historical(s, (c) => readNotificationQualificationOriginal(c, s));
      if (original.records.some((r) => r.record.kind === 'DISPATCH'))
        return { execute: false, original };
      return native(socket, s, 'QUALIFICATION_RUN', (c, p) =>
        dispatchNotificationQualification(c, s, p),
      );
    },
    bindSource(socket: TLSSocket, s: NotificationQualificationSelector, eventId: string) {
      return native(socket, s, 'QUALIFICATION_RUN', (c, p) =>
        bindNotificationQualificationSource(c, s, p, eventId),
      );
    },
    sample(socket: TLSSocket, s: NotificationQualificationSelector) {
      return native(socket, s, 'QUALIFICATION_RUN', (c, p) =>
        sampleNotificationQualification(c, s, p),
      );
    },
    recordCase(socket: TLSSocket, s: NotificationQualificationSelector, result: unknown) {
      return native(socket, s, 'QUALIFICATION_RUN', (c, p) =>
        retainNotificationQualificationCase(c, s, p, result),
      );
    },
    normalize(socket: TLSSocket, s: NotificationQualificationSelector) {
      return native(socket, s, 'QUALIFICATION_RUN', (c, p) =>
        retainNotificationQualificationNormalization(c, s, p),
      );
    },
    review(socket: TLSSocket, s: NotificationQualificationSelector) {
      return native(socket, s, 'QUALIFICATION_REVIEW', (c, p) =>
        reviewNotificationQualification(c, s, p),
      );
    },
    signingIntent(
      socket: TLSSocket,
      s: NotificationQualificationSelector,
      family: 'input' | 'capacity',
    ) {
      return authenticated(
        socket,
        s,
        (c, _p, identity, confirmCurrent, confirmAuthorities) =>
          notificationQualificationSigningIntent(
            c,
            { ...s, family },
            { socket, identity, confirmCurrent, confirmAuthorities },
            async (_same, intent) => intent,
          ),
        resolveNotificationQualificationSigningAuthorities({ ...s, family }),
      );
    },
    retainSigned(
      socket: TLSSocket,
      s: NotificationQualificationSelector,
      original: QualificationSignedOriginal,
    ) {
      if (
        !Buffer.isBuffer(original.payload) ||
        !Buffer.isBuffer(original.cose) ||
        original.payload.length > 65536 ||
        original.cose.length > 66560
      )
        reject();
      const value = {
        ...original,
        payload: Buffer.from(original.payload),
        cose: Buffer.from(original.cose),
      };
      return authenticated(
        socket,
        s,
        (c, _p, identity, confirmCurrent, confirmAuthorities) =>
          retainNotificationQualificationSignedOriginal(
            c,
            { ...s, family: value.family },
            { socket, identity, confirmCurrent, confirmAuthorities },
            value,
          ),
        resolveNotificationQualificationSigningAuthorities({ ...s, family: value.family }),
      );
    },
    // Protected root-local recovery. It cannot create another run, reexecute a
    // dispatched attempt, sign, approve or upgrade absent cases to PASS.
    retainLateOrigin(s: NotificationQualificationSelector, originId: string, signatureHex: string) {
      return historical(s, (c) => retainLateQualificationOrigin(c, s, originId, signatureHex));
    },
    sealOriginal(s: NotificationQualificationSelector) {
      return historical(s, (c) => sealNotificationQualification(c, s));
    },
    readOriginal(s: NotificationQualificationSelector) {
      return historical(s, (c) => readNotificationQualificationOriginal(c, s));
    },
  });
}
export type NotificationQualificationPeer = ReturnType<typeof createNotificationQualificationPeer>;
