/** Immutable installed epochs. The joining current root selects exactly one;
 * the genesis installation remains evidence after a successor is committed. */
export const platformScopeRowsSql = `(select platform_context_id,platform_authority_epoch,
  owner_participant_id,installation_privacy_domain_id,admission_digest from control.platform_envelope_scope
  union all select platform_context_id,platform_authority_epoch,owner_participant_id,
    installation_privacy_domain_id,admission_digest from control.platform_envelope_scope_successor
  union all select platform_context_id,platform_authority_epoch,owner_participant_id,
    installation_privacy_domain_id,admission_digest from control.root_expiry_recovery_scope)`;

/** Query fragment only; aliases are internal identifiers, never request data.
 * A future or superseded root binding supplies no current authority. Legacy
 * unbound envelopes retain their existing compatibility semantics. */
export function currentPlatformEnvelopeSql(
  alias: string,
  runtime = false,
  recovery = false,
): string {
  if (!/^[a-z][a-z0-9_]*$/u.test(alias)) throw new Error('Invalid envelope alias');
  return `((${alias}.representation<>'RECOVERY_V1'${recovery && !runtime ? ` or openpc.platform_recovery_envelope_current(${alias}.authority_envelope_id)` : ''}) and (${alias}.platform_context_id is null or exists(
    select 1 from control.platform_context current_root
    where current_root.platform_context_id=${alias}.platform_context_id
      and current_root.state='ACTIVE'
      and current_root.authority_epoch=${alias}.platform_authority_epoch
      ${
        runtime
          ? `and not exists(select 1 from control.platform_scope_replacement pending_root
        where pending_root.platform_context_id=current_root.platform_context_id
          and pending_root.state='WITHDRAWING')`
          : ''
      })))`;
}
