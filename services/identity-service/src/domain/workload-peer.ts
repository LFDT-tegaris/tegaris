import type { TLSSocket } from 'node:tls';
import type { Pool, PoolClient } from 'pg';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { lockAuthorityFence } from '../db/authority-fence.js';
import { IdentityKernel, type AuthenticatedWorkloadIdentity } from './identity-kernel.js';
import { IdentityKernelError } from './identity-errors.js';
import { localOperationId } from './local-operation-id.js';
import { presentedCertificate, type PresentedCertificate } from './workload-transport.js';

type RuntimeContext = Parameters<IdentityKernel['authenticateWorkload']>[1];

export interface WorkloadPeerAuthorityDependency {
  readonly principalId: string;
  readonly credentialId: string;
}
export type ConfirmWorkloadAuthorities = (
  sameClient: PoolClient,
  dependencies: readonly WorkloadPeerAuthorityDependency[],
) => Promise<void>;
/** Privileged composition only. Read immutable installed selectors without
 * business locks; all Identity dependencies are then locked in one C04 order.
 * Revalidation runs under those fences, through the outer transaction commit. */
export type WorkloadPeerDependencyResolver = (
  client: PoolClient,
  identity: Readonly<AuthenticatedWorkloadIdentity>,
) => Promise<{
  readonly dependencies: readonly WorkloadPeerAuthorityDependency[];
  readonly confirmCurrent: () => Promise<void>;
}>;

async function authenticatePresented(
  pool: Pool,
  kernel: IdentityKernel,
  presented: PresentedCertificate,
  runtimeContext?: RuntimeContext,
): Promise<AuthenticatedWorkloadIdentity> {
  const current = await runScopedTransaction(
    pool,
    {
      participantId: presented.participantId,
      actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    },
    localOperationId,
    async (client) =>
      client.query<{ participantEpoch: string; workloadEpoch: string }>(
        `select participant.authority_epoch::text "participantEpoch",
                    credential.credential_epoch::text "workloadEpoch"
               from control.credential credential
               join control.participant participant
                 on participant.participant_id=credential.participant_id and participant.state='ACTIVE'
               join control.principal principal
                 on principal.participant_id=credential.participant_id
                and principal.principal_id=credential.principal_id
                and principal.kind='WORKLOAD' and principal.state='ACTIVE'
              where credential.participant_id=$1 and credential.kind='WORKLOAD_MTLS'
                and credential.state='ACTIVE' and credential.subject=$2
                and credential.audience=$3 and credential.public_key_digest=$4
                and credential.valid_from=$5 and credential.valid_until=$6
                and credential.secret_fingerprint=$7
                and credential.valid_from<=clock_timestamp() and credential.valid_until>clock_timestamp()`,
        [
          presented.participantId,
          presented.uriSan,
          presented.workloadId,
          Buffer.from(presented.keyId.slice(7), 'hex'),
          presented.notBefore,
          presented.notAfter,
          presented.certificateFingerprint,
        ],
      ),
  );
  const epochs = current.rows[0];
  if (epochs === undefined || current.rows.length !== 1) {
    throw new IdentityKernelError('PC-IDENTITY-1006');
  }
  return kernel.authenticateWorkload(
    {
      ...presented,
      participantEpoch: epochs.participantEpoch,
      workloadEpoch: epochs.workloadEpoch,
      tlsVersion: 'TLS1.3',
      issuerTrusted: true,
      keyTrusted: true,
      revoked: false,
    },
    runtimeContext,
    presented,
  );
}

/** Reuses the real TLS proof and committed Identity authentication occurrence.
 * The returned metadata is not a grant, recipient binding, or authority lease.
 */
export async function authenticateWorkloadPeer(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  runtimeContext?: RuntimeContext,
): Promise<AuthenticatedWorkloadIdentity> {
  const presented = presentedCertificate(socket, runtimeContext);
  if (!presented) throw new IdentityKernelError('PC-IDENTITY-1006');
  return authenticatePresented(pool, kernel, presented, runtimeContext);
}

/** Trusted server composition only. First commit the actual TLS authentication,
 * then reacquire and revalidate its current authority dependencies. The callback
 * cannot run on fabricated identity metadata or across committed revocation.
 *
 * This fence authenticates identity only. The owning callback must independently
 * authorize the installed service, exact secret/version and installation generation.
 * It grants neither secret delivery nor ongoing database-session authority. External
 * publication needs its own rollback/expiry protocol; this transaction cannot undo it.
 */
export async function withAuthenticatedWorkloadPeer<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  operation: (
    client: PoolClient,
    identity: AuthenticatedWorkloadIdentity,
    confirmCurrent: () => Promise<void>,
    confirmAuthorities: ConfirmWorkloadAuthorities,
  ) => Promise<T>,
  scope?: { readonly privacyDomainId: string },
  resolveDependencies?: WorkloadPeerDependencyResolver,
): Promise<T> {
  if (
    scope &&
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      scope.privacyDomainId,
    )
  )
    throw new IdentityKernelError('PC-IDENTITY-1006');
  const presented = presentedCertificate(socket);
  if (!presented) throw new IdentityKernelError('PC-IDENTITY-1006');
  const identity = await authenticatePresented(pool, kernel, presented);
  return runScopedTransaction(
    pool,
    {
      participantId: identity.participantId,
      privacyDomainId: scope?.privacyDomainId,
      actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    },
    localOperationId,
    async (client) => {
      const resolved = await resolveDependencies?.(client, identity);
      if ((resolved?.dependencies.length ?? 0) > 64)
        throw new IdentityKernelError('PC-IDENTITY-1006');
      const dependencies = [identity, ...(resolved?.dependencies ?? [])].map((row) => {
        for (const id of [row.principalId, row.credentialId])
          if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(id))
            throw new IdentityKernelError('PC-IDENTITY-1006');
        return { principalId: row.principalId, credentialId: row.credentialId };
      });
      await lockAuthorityFence(client, identity.participantId, {
        participant: [{ id: identity.participantId }],
        privacy_domain: scope ? [{ id: scope.privacyDomainId }] : [],
        principal: dependencies.map((row) => ({ id: row.principalId })),
        credential: dependencies.map((row) => ({ id: row.credentialId })),
      });
      const values = [
        identity.participantId,
        identity.principalId,
        identity.credentialId,
        identity.participantEpoch,
        identity.principalEpoch,
        identity.workloadEpoch,
        identity.workloadId,
        identity.uriSan,
        Buffer.from(identity.keyId.slice(7), 'hex'),
        presented.certificateFingerprint,
        identity.notBefore,
        identity.notAfter,
      ];
      const binding = await client.query<{
        tx: string;
        backend: number;
        login: string;
        role: string;
        operation: string;
      }>(
        'select pg_current_xact_id()::text tx,pg_backend_pid() backend,session_user login,current_user role,openpc.current_operation_id()::text operation',
      );
      const transaction = binding.rows[0];
      if (binding.rowCount !== 1 || !transaction) throw new IdentityKernelError('PC-IDENTITY-1006');
      let live = true;
      const confirm = async () => {
        if (!live || socket.destroyed || !socket.authorized || socket.getProtocol() !== 'TLSv1.3')
          throw new IdentityKernelError('PC-IDENTITY-1006');
        // A PoolClient object can outlive COMMIT/ROLLBACK. Its identity alone
        // must never carry native TLS admission into a replacement transaction.
        const bound = await client.query<{ current: boolean }>(
          `select pg_current_xact_id()::text=$1 and pg_backend_pid()=$2
            and session_user=$3 and current_user=$4
            and openpc.current_participant_id()=$5::uuid
            and nullif(current_setting('openpc.privacy_domain_id',true),'')::uuid is not distinct from $6::uuid
            and openpc.current_operation_id()::text=$7
            and current_setting('row_security')='on' and current_setting('transaction_isolation')='read committed'
            and openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' current`,
          [
            transaction.tx,
            transaction.backend,
            transaction.login,
            transaction.role,
            identity.participantId,
            scope?.privacyDomainId ?? null,
            transaction.operation,
          ],
        );
        if (bound.rows[0]?.current !== true) throw new IdentityKernelError('PC-IDENTITY-1006');
        if (scope) {
          const privacy = await client.query(
            "select 1 from control.privacy_domain where participant_id=$1 and privacy_domain_id=$2 and state='ACTIVE'",
            [identity.participantId, scope.privacyDomainId],
          );
          if (privacy.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1006');
        }
        const result = await client.query(
          `select 1 from control.participant p
          join control.principal a on a.participant_id=p.participant_id
          join control.credential c on c.participant_id=p.participant_id and c.principal_id=a.principal_id
          where p.participant_id=$1 and a.principal_id=$2 and c.credential_id=$3
            and p.state='ACTIVE' and a.state='ACTIVE' and a.kind='WORKLOAD'
            and c.state='ACTIVE' and c.kind='WORKLOAD_MTLS'
            and p.authority_epoch=$4 and a.authority_epoch=$5 and c.credential_epoch=$6
            and c.audience=$7 and c.subject=$8 and c.public_key_digest=$9
            and c.secret_fingerprint=$10 and c.valid_from=$11 and c.valid_until=$12
            and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()`,
          values,
        );
        if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1006');
        await resolved?.confirmCurrent();
      };
      const confirmAuthorities: ConfirmWorkloadAuthorities = async (sameClient, required) => {
        if (sameClient !== client) throw new IdentityKernelError('PC-IDENTITY-1006');
        await confirm();
        if (
          required.some(
            (wanted) =>
              !dependencies.some(
                (held) =>
                  held.principalId === wanted.principalId &&
                  held.credentialId === wanted.credentialId,
              ),
          )
        )
          throw new IdentityKernelError('PC-IDENTITY-1006');
      };
      try {
        await confirm();
        const result = await operation(client, identity, confirm, confirmAuthorities);
        await confirm();
        return result;
      } finally {
        live = false;
      }
    },
  );
}
