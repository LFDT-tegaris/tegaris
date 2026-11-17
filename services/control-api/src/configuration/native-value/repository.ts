import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { resolveExecutionPrincipal } from '../execution-principal.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import { nativeValueCore } from './core.js';
import {
  nativeValueAuthorizationResponseSchema,
  type CreateNativeValueAuthorization,
} from './contract.js';

const id = (value: string) => value.slice(value.lastIndexOf(':') + 1);
const hex = (value: Buffer) => `0x${value.toString('hex')}`;

/** Native Value is the independent grant owner. Issuance does not prepare a
 * deployment, reserve an address, authorize RPC submission or spend the grant. */
export class NativeValueAuthorizationRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(pool: Pool, verifier?: IdentityRuntimeVerifier) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  create(context: MutationContext, input: CreateNativeValueAuthorization) {
    return this.mutations.execute(context, async (client, authorizationId, operationId) => {
      const authority = context.authorization;
      const actor =
        (await resolveExecutionPrincipal(
          client,
          authority.participantId,
          input.executionWorkloadId,
        )) ?? authority.principalId;
      const wallet = await client.query<{ epoch: string; nowMs: string }>(
        `select binding_epoch::text as epoch, floor(extract(epoch from clock_timestamp())*1000)::text as "nowMs"
         from control.wallet_binding where participant_id=$1 and privacy_domain_id=$2
          and wallet_binding_id=$3 and subject_id=$4 and chain_id=$5 and state='ACTIVE' for share`,
        [
          authority.participantId,
          authority.privacyDomainId,
          id(input.walletBindingId),
          actor,
          input.chainId,
        ],
      );
      const owner = wallet.rows[0];
      if (wallet.rowCount !== 1 || !owner) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const nowMs = Number(owner.nowMs);
      const deadline = Date.parse(input.validUntil);
      if (
        !Number.isSafeInteger(nowMs) ||
        !Number.isSafeInteger(deadline) ||
        deadline <= nowMs ||
        deadline > nowMs + 300_000
      )
        throw new ConfigurationRepositoryError('PC-DATA-6004');
      const grant = nativeValueCore('ENCODE_NATIVE_VALUE_AUTHORIZATION', {
        document: {
          authorizationId: `urn:openpc:resource:${authorizationId}`,
          participantId: authority.participantId,
          participantEpoch: authority.participantEpoch,
          actorSubjectId: actor,
          chainEnvironmentId: `${input.chainId}:${input.networkId}:${input.genesisDigest}`,
          chainId: input.chainId,
          genesisHash: input.genesisDigest.slice(7),
          purpose: 'CONTRACT_CREATION_ENDOWMENT',
          amountMode: input.amountMode,
          maxAmountWei: input.maxAmountWei,
          oneUse: true,
          used: false,
          policyDecisionDigest: authority.evidenceDigest.toString('hex'),
          validUntil: input.validUntil,
        },
      });
      const inserted = await client.query(
        `insert into control.native_value_authorization(native_value_authorization_id,participant_id,privacy_domain_id,
          actor_principal_id,wallet_binding_id,wallet_binding_epoch,execution_workload_id,document_bytes,semantic_digest,
          creation_operation_id,creation_authority_digest,valid_until)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 where $12::timestamptz>clock_timestamp()`,
        [
          authorizationId,
          authority.participantId,
          authority.privacyDomainId,
          actor,
          id(input.walletBindingId),
          owner.epoch,
          input.executionWorkloadId ?? null,
          Buffer.from(grant.documentBytes.slice(2), 'hex'),
          `sha256:${grant.semanticDigest}`,
          operationId,
          `sha256:${authority.evidenceDigest.toString('hex')}`,
          input.validUntil,
        ],
      );
      if (inserted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'openpc.native-value.authorization.issued.v1',
      };
    });
  }

  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<{
        documentBytes: Buffer;
        issuedDigest: string;
        walletBindingId: string;
        creationOperationId: string;
        createdAt: Date;
        validUntil: Date;
        consumed: boolean;
        expired: boolean;
        currentWallet: boolean;
      }>(
        `select issued_grant.document_bytes as "documentBytes", issued_grant.semantic_digest as "issuedDigest",
          issued_grant.wallet_binding_id::text as "walletBindingId", issued_grant.creation_operation_id::text as "creationOperationId",
          issued_grant.created_at as "createdAt", issued_grant.valid_until as "validUntil", issued_grant.valid_until<=clock_timestamp() as expired,
          exists(select 1 from control.deployment_address_reservation reservation
            where reservation.native_value_authorization_id=issued_grant.native_value_authorization_id and reservation.state='HANDOFF') as consumed,
          exists(select 1 from control.wallet_binding wallet join control.principal principal
            on principal.participant_id=wallet.participant_id and principal.principal_id=wallet.subject_id and principal.state='ACTIVE'
            where wallet.participant_id=issued_grant.participant_id and wallet.privacy_domain_id=issued_grant.privacy_domain_id
             and wallet.wallet_binding_id=issued_grant.wallet_binding_id and wallet.binding_epoch=issued_grant.wallet_binding_epoch
             and wallet.subject_id=issued_grant.actor_principal_id and wallet.state='ACTIVE'
             and (issued_grant.execution_workload_id is null or exists(select 1 from control.credential credential
               where credential.participant_id=issued_grant.participant_id and credential.principal_id=issued_grant.actor_principal_id
                and credential.kind='WORKLOAD_MTLS' and credential.audience=issued_grant.execution_workload_id and credential.state='ACTIVE'
                and credential.valid_from<=clock_timestamp() and credential.valid_until>clock_timestamp()))) as "currentWallet"
         from control.native_value_authorization issued_grant
         where issued_grant.native_value_authorization_id=$1 and issued_grant.participant_id=$2 and issued_grant.privacy_domain_id=$3`,
        [
          context.resourceId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
        ],
      );
      const row = result.rows[0];
      if (result.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const issued = nativeValueCore('READ_NATIVE_VALUE_AUTHORIZATION', {
        documentBytes: hex(row.documentBytes),
        consumed: false,
      });
      if (
        `sha256:${issued.semanticDigest}` !== row.issuedDigest ||
        issued.authorizationId !== `urn:openpc:resource:${context.resourceId}`
      )
        throw new ConfigurationRepositoryError('PC-DATA-6004');
      const current = row.consumed
        ? nativeValueCore('READ_NATIVE_VALUE_AUTHORIZATION', {
            documentBytes: hex(row.documentBytes),
            consumed: true,
          })
        : issued;
      const state = row.consumed
        ? 'CONSUMED'
        : row.expired
          ? 'EXPIRED'
          : !row.currentWallet || issued.participantEpoch !== context.authorization.participantEpoch
            ? 'INVALIDATED'
            : 'UNUSED';
      return nativeValueAuthorizationResponseSchema.parse({
        nativeValueAuthorizationId: issued.authorizationId,
        walletBindingId: `urn:openpc:resource:${row.walletBindingId}`,
        state,
        revision: '1',
        runtimePermission: 'NONE',
        authorizationDocument: current.documentBytes,
        authorizationDigest: `sha256:${current.semanticDigest}`,
        issuedAuthorizationDigest: row.issuedDigest,
        creationOperationId: row.creationOperationId,
        createdAt: new Date(row.createdAt).toISOString(),
        validUntil: new Date(row.validUntil).toISOString(),
      });
    });
  }
}
