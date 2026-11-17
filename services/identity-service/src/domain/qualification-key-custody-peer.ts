import { createHash, X509Certificate } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import type { Pool, PoolClient } from 'pg';
import type { IdentityKernel, AuthenticatedWorkloadIdentity } from './identity-kernel.js';
import {
  withAuthenticatedWorkloadPeer,
  type WorkloadPeerDependencyResolver,
  type ConfirmWorkloadAuthorities,
} from './workload-peer.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { localOperationId } from './local-operation-id.js';
import { createHttpQualificationKeyProvider } from './http-qualification-key-provider.js';
import type { PinnedSigningTlsConfiguration } from './pinned-signing-transport.js';
import {
  qualificationKeyPeerSchema,
  qualificationKeyCopy,
  type QualificationKeyObservation,
  type QualificationKeyInstallation,
  type QualificationKeyPeer,
} from './qualification-key-provider.js';
import {
  readQualificationKeyAttempt,
  readQualificationKeyInstallation,
  withCurrentQualificationKeyIssuer,
  reserveQualificationKeyObservation,
  retainQualificationKeyObservation,
  readCurrentQualificationKeyObservation,
  qualificationKeySelectionSchema,
  qualificationKeyIntentSchema,
  type QualificationKeySelection,
  type QualificationKeyIntent,
} from '../../../control-api/src/configuration/operations/qualification-key-custody.js';
import type { InstalledQualificationIssuer } from '../../../control-api/src/configuration/operations/provider-retry-qualification.js';

/** This is independently installed observer B, never the subject's TLS key.
 * The private-key/certificate match and exact provider pins are checked by the
 * actual transport constructor; no network I/O occurs in this transaction. */
async function currentObserver(
  client: PoolClient,
  pins: QualificationKeyInstallation,
  tls: PinnedSigningTlsConfiguration,
) {
  if (pins.schemaVersion !== 2) return async () => {};
  const provider = createHttpQualificationKeyProvider({ ...tls, trust: pins });
  provider.close();
  const certificate = new X509Certificate(tls.certificate),
    p = pins.observer;
  const subject = `urn:openpc:participant:${pins.participantId}:workload:${p.workloadId.split(':').at(-1)}`;
  if (certificate.subjectAltName !== `URI:${subject}`)
    throw new Error('Qualification observer unavailable');
  const confirm = async () => {
    const result = await client.query(
      `select 1 from control.participant p
      join control.privacy_domain d on d.participant_id=p.participant_id
      join control.principal a on a.participant_id=p.participant_id
      join control.credential c on c.participant_id=a.participant_id and c.principal_id=a.principal_id
      where p.participant_id=$1 and d.privacy_domain_id=$2 and a.principal_id=$3 and c.credential_id=$4
      and p.state='ACTIVE' and p.archived_at is null and d.state='ACTIVE'
      and a.state='ACTIVE' and a.kind='WORKLOAD' and c.state='ACTIVE' and c.kind='WORKLOAD_MTLS'
      and p.authority_epoch=$5 and a.authority_epoch=$6 and c.credential_epoch=$7
      and c.audience=$8 and c.subject=$9 and c.public_key_digest=$10 and c.secret_fingerprint=$11
      and c.certificate_der=$12 and c.valid_from=$13 and c.valid_until=$14
      and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()`,
      [
        pins.participantId,
        pins.privacyDomainId,
        p.principalId,
        p.credentialId,
        p.participantEpoch,
        p.principalEpoch,
        p.credentialEpoch,
        p.workloadId,
        subject,
        Buffer.from(p.keyDigest.slice(7), 'hex'),
        Buffer.from(p.certificateDigest.slice(7), 'hex'),
        certificate.raw,
        certificate.validFromDate,
        certificate.validToDate,
      ],
    );
    if (result.rowCount !== 1) throw new Error('Qualification observer unavailable');
  };
  await confirm();
  return confirm;
}

export interface CurrentQualificationKeySource {
  readonly installed: Awaited<ReturnType<typeof readQualificationKeyInstallation>>;
  readonly issuer: Readonly<InstalledQualificationIssuer>;
  readonly peer: QualificationKeyPeer;
  readonly identity: AuthenticatedWorkloadIdentity;
  readonly confirmCurrent: () => Promise<void>;
  readonly confirmAuthorities: ConfirmWorkloadAuthorities;
}

function peer(socket: TLSSocket, identity: AuthenticatedWorkloadIdentity) {
  const raw = socket.getPeerCertificate(true).raw;
  if (!raw || !socket.authorized || socket.destroyed || socket.getProtocol() !== 'TLSv1.3')
    throw new Error('Qualification peer unavailable');
  return qualificationKeyPeerSchema.parse({
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
/** OBSERVED rechecks local peer/installed issuer authority. The remote descriptor
 * remains an observation at observedAtMs, never a lease on a provider policy,
 * hardware assurance, current key-access permission or signing capability. */
export type QualificationKeyReadback = Readonly<{
  attemptId: string;
  state: 'UNKNOWN' | 'HISTORICAL' | 'OBSERVED';
  observation?: QualificationKeyObservation;
}>;

/** Trusted root composition. ownerPool must ALREADY have an allowed actual
 * current role and narrow Identity fence/read grants; this adapter never SETs a
 * role or broadens a role list. kernel uses its real Identity repository.
 * TLS material is the installed observer's client, not a request parameter. */
export function createQualificationKeyCustodyPeer(options: {
  ownerPool: Pool;
  kernel: IdentityKernel;
  tls: PinnedSigningTlsConfiguration;
}) {
  const tls = {
    ...options.tls,
    certificate: Buffer.from(options.tls.certificate),
    privateKey: Buffer.from(options.tls.privateKey),
    trustCa: Buffer.from(options.tls.trustCa),
  };
  const dependencies =
    (
      selection: QualificationKeySelection,
      additional?: WorkloadPeerDependencyResolver,
    ): WorkloadPeerDependencyResolver =>
    async (client, identity) => {
      const installed = await readQualificationKeyInstallation(client, selection, false);
      if (installed.state !== 'ACTIVE') throw new Error('Qualification installation unavailable');
      const confirmObserver = await currentObserver(client, installed.pins, tls);
      const extra = await additional?.(client, identity);
      return {
        dependencies: [
          installed.pins.peer,
          ...(installed.pins.schemaVersion === 2 ? [installed.pins.observer] : []),
          ...(extra?.dependencies ?? []),
        ],
        confirmCurrent: async () => {
          const current = await readQualificationKeyInstallation(client, selection, false);
          if (current.state !== 'ACTIVE' || current.digest !== installed.digest)
            throw new Error('Qualification installation changed');
          await confirmObserver();
          await extra?.confirmCurrent();
        },
      };
    };
  const historical = <T>(
    s: QualificationKeySelection,
    fn: Parameters<typeof runScopedTransaction<T>>[3],
  ) =>
    runScopedTransaction(
      options.ownerPool,
      {
        participantId: s.participantId,
        privacyDomainId: s.privacyDomainId,
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      },
      localOperationId,
      fn,
    );
  const lookup = async (
    s: QualificationKeySelection,
    attemptId: string,
  ): Promise<QualificationKeyReadback> => {
    const original = await historical(s, (c) => readQualificationKeyAttempt(c, s, attemptId));
    if (original.state !== 'DISPATCHED')
      throw new Error('Qualification key original was not dispatched');
    if (original.observation)
      return Object.freeze({ attemptId, state: 'HISTORICAL', observation: original.observation });
    const provider = createHttpQualificationKeyProvider({ ...tls, trust: original.installed.pins });
    let observation: QualificationKeyObservation | undefined;
    try {
      observation = await provider.lookup(original.request);
    } catch {
      return Object.freeze({ attemptId, state: 'UNKNOWN' });
    } finally {
      provider.close();
    }
    if (!observation) return Object.freeze({ attemptId, state: 'UNKNOWN' });
    // Provider truth survives a later current-authority denial.
    await historical(s, (c) => retainQualificationKeyObservation(c, s, attemptId, observation));
    return Object.freeze({ attemptId, state: 'HISTORICAL', observation });
  };
  return {
    /** Native database reservation/adoption bracket. A real current subject
     * socket, installed observer private key and A/B Identity fences are held
     * with installed source/issuer fences. The callback performs no external
     * I/O and must independently admit its exact purpose and original selector. */
    async withCurrentIssuer<T>(
      socket: TLSSocket,
      selection: QualificationKeySelection,
      consume: (
        sameClient: PoolClient,
        source: Readonly<CurrentQualificationKeySource>,
      ) => Promise<T>,
      additionalDependencies: WorkloadPeerDependencyResolver,
    ): Promise<T> {
      const s = qualificationKeyCopy(qualificationKeySelectionSchema.parse(selection));
      if (typeof additionalDependencies !== 'function')
        throw new Error('Qualification authority dependencies required');
      return withAuthenticatedWorkloadPeer(
        options.ownerPool,
        options.kernel,
        socket,
        async (client, identity, confirmCurrent, confirmAuthorities) => {
          const actual = peer(socket, identity);
          return withCurrentQualificationKeyIssuer(
            client,
            s,
            actual,
            async (same, installed, issuer) => {
              await confirmCurrent();
              const result = await consume(
                same,
                Object.freeze({
                  installed,
                  issuer,
                  peer: actual,
                  identity,
                  confirmCurrent,
                  confirmAuthorities,
                }),
              );
              await confirmCurrent();
              return result;
            },
          );
        },
        s,
        dependencies(s, additionalDependencies),
      );
    },
    /** Historical recovery is root-local and lookup-only. No detached grant. */
    async reconcile(s: QualificationKeySelection, attemptId: string) {
      return lookup(qualificationKeyCopy(qualificationKeySelectionSchema.parse(s)), attemptId);
    },
    async observe(
      socket: TLSSocket,
      selection: QualificationKeySelection,
      intent: QualificationKeyIntent,
    ): Promise<QualificationKeyReadback> {
      const s = qualificationKeyCopy(qualificationKeySelectionSchema.parse(selection)),
        wanted = qualificationKeyCopy(qualificationKeyIntentSchema.parse(intent));
      // withAuthenticatedWorkloadPeer commits actual authentication, then fences
      // it in the reservation transaction. Returning is the commit boundary.
      const reserved = await withAuthenticatedWorkloadPeer(
        options.ownerPool,
        options.kernel,
        socket,
        async (client, identity, confirm) => {
          await confirm();
          const result = await reserveQualificationKeyObservation(
            client,
            s,
            peer(socket, identity),
            wanted,
          );
          await confirm();
          return result;
        },
        s,
        dependencies(s),
      );
      if (reserved.dispatch) {
        const provider = createHttpQualificationKeyProvider({
          ...tls,
          trust: reserved.installed.pins,
        });
        let observation: QualificationKeyObservation;
        try {
          observation = await provider.perform(reserved.request);
        } catch {
          return Object.freeze({ attemptId: wanted.attemptId, state: 'UNKNOWN' });
        } finally {
          provider.close();
        }
        await historical(s, (c) =>
          retainQualificationKeyObservation(c, s, wanted.attemptId, observation),
        );
      }
      const retained = await lookup(s, wanted.attemptId);
      if (retained.state === 'UNKNOWN') return retained;
      try {
        const observation = await withAuthenticatedWorkloadPeer(
          options.ownerPool,
          options.kernel,
          socket,
          async (client, identity, confirm) => {
            await confirm();
            const result = await readCurrentQualificationKeyObservation(
              client,
              s,
              peer(socket, identity),
              wanted.attemptId,
            );
            await confirm();
            return result;
          },
          s,
          dependencies(s),
        );
        return Object.freeze({
          attemptId: wanted.attemptId,
          state: 'OBSERVED',
          observation,
        });
      } catch {
        return retained;
      }
    },
  };
}
