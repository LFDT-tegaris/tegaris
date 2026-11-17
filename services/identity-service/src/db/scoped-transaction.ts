import type { Pool, PoolClient } from 'pg';

export class ScopedTransactionSecurityError extends Error {}

export interface ScopedTransactionContext {
  readonly participantId?: string;
  readonly privacyDomainId?: string;
  readonly actionIntentId: string;
  readonly isolation?: 'SERIALIZABLE';
}

export type ScopedTransactionOperation<T> = (client: PoolClient, operationId: string) => Promise<T>;

function securityFailure(): ScopedTransactionSecurityError {
  return new ScopedTransactionSecurityError('scoped transaction security invariant failed');
}

export async function runScopedTransaction<T>(
  pool: Pool,
  context: ScopedTransactionContext,
  operationIdFactory: () => string,
  operation: ScopedTransactionOperation<T>,
): Promise<T> {
  if (context.participantId === undefined && context.privacyDomainId !== undefined) {
    throw securityFailure();
  }
  const client = await pool.connect();
  try {
    const operationId = operationIdFactory();
    await client.query('discard all');
    const checkout = await client.query<{ clean: boolean }>(
      `select nullif(current_setting('openpc.context_mode',true),'') is null
              and nullif(current_setting('openpc.participant_id',true),'') is null
              and nullif(current_setting('openpc.privacy_domain_id',true),'') is null
              and nullif(current_setting('openpc.operation_id',true),'') is null
              and nullif(current_setting('openpc.action_intent_id',true),'') is null
              and nullif(current_setting('openpc.context_scope',true),'') is null as clean`,
    );
    if (checkout.rows.length !== 1 || checkout.rows[0]?.clean !== true) throw securityFailure();

    await client.query(
      context.isolation === 'SERIALIZABLE' ? 'begin isolation level serializable' : 'begin',
    );
    await client.query('set local row_security=on');
    if (context.participantId !== undefined) {
      const privacyDomainId = context.privacyDomainId ?? null;
      const requirePrivacy = context.privacyDomainId !== undefined;
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,$5),
                openpc.assert_request_context($5)`,
        [
          context.participantId,
          privacyDomainId,
          operationId,
          context.actionIntentId,
          requirePrivacy,
        ],
      );
    }

    const guard = await client.query<{
      action_intent_id: string | null;
      bypass: boolean;
      context_mode: string | null;
      context_scope: string | null;
      operation_id: string | null;
      participant_id: string | null;
      privacy_domain_id: string | null;
      row_security: string;
      superuser: boolean;
    }>(
      `select nullif(current_setting('openpc.context_mode',true),'') context_mode,
              nullif(current_setting('openpc.context_scope',true),'') context_scope,
              nullif(current_setting('openpc.participant_id',true),'') participant_id,
              nullif(current_setting('openpc.privacy_domain_id',true),'') privacy_domain_id,
              nullif(current_setting('openpc.operation_id',true),'') operation_id,
              nullif(current_setting('openpc.action_intent_id',true),'') action_intent_id,
              current_setting('row_security') row_security,
              r.rolbypassrls bypass,r.rolsuper superuser
         from pg_roles r where r.rolname=current_user`,
    );
    if (guard.rows.length !== 1) throw securityFailure();
    const actual = guard.rows[0]!;
    const unscoped = context.participantId === undefined;
    if (
      actual.bypass ||
      actual.superuser ||
      actual.row_security !== 'on' ||
      (unscoped
        ? actual.context_mode !== null ||
          actual.context_scope !== null ||
          actual.participant_id !== null ||
          actual.privacy_domain_id !== null ||
          actual.operation_id !== null ||
          actual.action_intent_id !== null
        : actual.context_mode !== 'PARTICIPANT' ||
          actual.context_scope !== 'TRANSACTION_LOCAL' ||
          actual.participant_id !== context.participantId ||
          actual.privacy_domain_id !== (context.privacyDomainId ?? null) ||
          actual.operation_id !== operationId ||
          actual.action_intent_id !== context.actionIntentId)
    ) {
      throw securityFailure();
    }

    const value = await operation(client, operationId);
    await client.query('commit');
    await client.query('discard all');
    return value;
  } catch (error) {
    await client.query('rollback').catch(() => undefined);
    await client.query('discard all').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
