import type { PoolClient } from 'pg';
import { z } from 'zod';
import { IdentityKernelError } from './identity-errors.js';

const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const chain = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((v) => BigInt(v) <= 18_446_744_073_709_551_615n);
export const walletBindingCreation = z.strictObject({
  walletBindingId: uuid,
  subjectId: uuid,
  chainId: chain,
  walletAddress: z.string().regex(/^0x[0-9a-f]{40}$/u),
});
export const walletBindingRevocation = z.strictObject({
  walletBindingId: uuid,
  state: z.literal('REVOKED'),
});
export type WalletBindingCreation = z.infer<typeof walletBindingCreation>;

interface Row {
  wallet_binding_id: string;
  participant_id: string;
  privacy_domain_id: string;
  subject_id: string;
  chain_id: string;
  wallet_address: string;
  state: 'ACTIVE' | 'REVOKED';
  binding_epoch: string;
  row_version: string;
  last_operation_id: string;
}
function project(row: Row | undefined) {
  if (!row) throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    walletBindingId: row.wallet_binding_id,
    participantId: row.participant_id,
    privacyDomainId: row.privacy_domain_id,
    subjectId: row.subject_id,
    chainId: row.chain_id,
    walletAddress: row.wallet_address,
    state: row.state,
    bindingEpoch: row.binding_epoch,
    revision: row.row_version,
    operationId: row.last_operation_id,
    permissionEffect: 'NONE_WITHOUT_EFFECTIVE_AUTHORITY' as const,
  };
}

/** Called only inside the ordinary fenced maker/checker mutation transaction. */
export async function createWalletBinding(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  operationId: string,
  input: WalletBindingCreation,
) {
  walletBindingCreation.parse(input);
  const subject = await client.query(
    `select 1 from control.principal subject join control.participant participant using(participant_id)
       join control.privacy_domain privacy on privacy.participant_id=subject.participant_id and privacy.privacy_domain_id=$3
      where subject.participant_id=$1 and subject.principal_id=$2 and subject.state='ACTIVE'
        and subject.kind in ('USER','WALLET','WORKLOAD') and participant.state='ACTIVE'
        and participant.archived_at is null and privacy.state='ACTIVE'`,
    [participantId, input.subjectId, privacyDomainId],
  );
  if (subject.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1002');
  const inserted = await client.query<Row>(
    `insert into control.wallet_binding(wallet_binding_id,participant_id,privacy_domain_id,subject_id,chain_id,wallet_address,state,binding_epoch,row_version,last_operation_id)
       values($1,$2,$3,$4,$5,$6,'ACTIVE',1,1,$7) returning *,chain_id::text,binding_epoch::text,row_version::text`,
    [
      input.walletBindingId,
      participantId,
      privacyDomainId,
      input.subjectId,
      input.chainId,
      input.walletAddress,
      operationId,
    ],
  );
  return project(inserted.rows[0]);
}

export async function revokeWalletBinding(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  operationId: string,
  walletBindingId: string,
  expectedRevision: string,
) {
  const updated = await client.query<Row>(
    `update control.wallet_binding set state='REVOKED',binding_epoch=binding_epoch+1,row_version=row_version+1,
       last_operation_id=$4,updated_at=clock_timestamp()
     where participant_id=$1 and privacy_domain_id=$2 and wallet_binding_id=$3 and state='ACTIVE' and row_version=$5
     returning *,chain_id::text,binding_epoch::text,row_version::text`,
    [participantId, privacyDomainId, walletBindingId, operationId, expectedRevision],
  );
  return project(updated.rows[0]);
}

export async function readWalletBinding(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  walletBindingId: string,
) {
  const result = await client.query<Row>(
    `select *,chain_id::text,binding_epoch::text,row_version::text from control.wallet_binding
     where participant_id=$1 and privacy_domain_id=$2 and wallet_binding_id=$3 for share`,
    [participantId, privacyDomainId, walletBindingId],
  );
  return project(result.rows[0]);
}
