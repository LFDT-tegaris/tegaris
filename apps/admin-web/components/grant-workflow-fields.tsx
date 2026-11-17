import { grantCapabilities, type Grant, type GrantKind } from './grant-workflow-contract';

const field = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
function localTime(delta: number) {
  const date = new Date(Date.now() + delta);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
export function GrantFields({
  kind,
  initialPrincipalId,
  initialAuthorityEnvelopeId,
  initialRoleId,
  initialCapabilityIds = [],
  initialResourceIds,
}: {
  kind: GrantKind;
  initialPrincipalId?: string;
  initialAuthorityEnvelopeId?: string;
  initialRoleId?: string;
  initialCapabilityIds?: readonly string[];
  initialResourceIds?: string;
}) {
  return (
    <>
      <label className="grid gap-1">
        {kind === 'assignment' ? 'Principal ID' : 'Grantee principal ID'}
        <input
          className={field}
          name={kind === 'assignment' ? 'principalId' : 'granteeId'}
          defaultValue={kind === 'assignment' ? initialPrincipalId : undefined}
          required
        />
      </label>
      {kind === 'assignment' ? (
        <>
          <label className="grid gap-1">
            Authority envelope ID
            <input
              className={field}
              name="authorityEnvelopeId"
              defaultValue={initialAuthorityEnvelopeId}
              required
            />
          </label>
          <label className="grid gap-1">
            Role reference (optional)
            <input
              className={field}
              name="roleId"
              defaultValue={initialRoleId}
              placeholder="urn:openpc:role:…"
            />
          </label>
          <label className="grid gap-1">
            Group ID (optional)
            <input className={field} name="groupId" aria-describedby="grant-group-help" />
          </label>
          <p id="grant-group-help" className="text-sm text-[color:var(--muted)]">
            The principal must remain a current member of this Participant-local group. Removing
            membership revokes this assignment and its delegations. Rejoining does not restore them.
          </p>
        </>
      ) : (
        <>
          <label className="grid gap-1">
            Parent grant type
            <select className={field} name="parentKind">
              <option value="assignment">Assignment</option>
              <option value="delegation">Delegation</option>
            </select>
          </label>
          <label className="grid gap-1">
            Parent grant ID
            <input className={field} name="parentId" required />
          </label>
        </>
      )}
      <p className="text-sm text-[color:var(--muted)]">
        Use an active principal and authority in the selected privacy domain. A delegation must stay
        within its complete parent chain.
      </p>
      <label className="grid gap-1">
        Administrative action IDs
        <textarea className={field} name="actions" aria-describedby="grant-actions-help" />
      </label>
      <p id="grant-actions-help" className="text-sm text-[color:var(--muted)]">
        One registered action per line. Leave empty for a grant with no administrative capabilities.
      </p>
      <fieldset className="grid min-w-0 gap-2">
        <legend className="mb-2 font-medium">Runtime capabilities</legend>
        {grantCapabilities.map((capability) => (
          <label key={capability} className="flex min-w-0 items-start gap-2 text-sm">
            <input
              className="mt-1"
              type="checkbox"
              name="capabilityIds"
              value={capability}
              defaultChecked={initialCapabilityIds.includes(capability)}
            />
            <span className="min-w-0 break-all">{capability}</span>
          </label>
        ))}
      </fieldset>
      <label className="grid gap-1">
        Resource IDs
        <textarea
          className={field}
          name="resourceIds"
          defaultValue={initialResourceIds}
          required
          aria-describedby="grant-resources-help"
        />
      </label>
      <p id="grant-resources-help" className="text-sm text-[color:var(--muted)]">
        One resource per line. Use * only when all resources are intended and permitted by the
        source authority.
      </p>
      <label className="grid gap-1">
        Risk classes
        <input
          className={field}
          name="riskClasses"
          required
          defaultValue="LOW"
          aria-describedby="grant-risk-help"
        />
      </label>
      <p id="grant-risk-help" className="text-sm text-[color:var(--muted)]">
        Comma-separated classes within the source authority, for example LOW or HIGH.
      </p>
      <label className="grid gap-1">
        Valid from
        <input
          className={field}
          type="datetime-local"
          name="validFrom"
          step="1"
          required
          defaultValue={localTime(-300000)}
        />
      </label>
      <label className="grid gap-1">
        Valid until
        <input
          className={field}
          type="datetime-local"
          name="validUntil"
          step="1"
          required
          defaultValue={localTime(86400000)}
        />
      </label>
      <label className="grid gap-1">
        Onward delegation depth
        <input
          className={field}
          type="number"
          name="onwardDelegationDepth"
          min={0}
          max={32}
          required
          defaultValue={0}
        />
      </label>
      <label className="flex items-center gap-2">
        <input type="checkbox" name="makerCheckerRequired" defaultChecked />
        Require maker and checker
      </label>
      <label className="flex items-center gap-2">
        <input type="checkbox" name="stepUpRequired" defaultChecked />
        Require fresh WebAuthn
      </label>
      <label className="grid gap-1">
        Reason
        <textarea className={field} name="reason" minLength={10} maxLength={1024} required />
      </label>
    </>
  );
}

export function GrantDetails({
  value,
  proposed = false,
  revision,
}: {
  value: Grant;
  proposed?: boolean;
  revision?: string;
}) {
  const items = [
    ['Grant ID', value.id],
    [
      proposed ? 'Proposed state' : 'State',
      `${value.state}${revision ? ` · revision ${revision}` : ''}`,
    ],
    ...('principalId' in value
      ? [
          ['Principal ID', value.principalId],
          ['Authority envelope ID', value.authorityEnvelopeId],
          ['Role reference', value.roleId ?? 'None'],
          ['Group membership constraint', value.groupId ?? 'None'],
        ]
      : [
          ['Grantor principal ID', value.grantorId],
          ['Grantee principal ID', value.granteeId],
          ['Parent grant ID', value.parentId],
        ]),
    ['Administrative action IDs', value.actionIntentIds.join(', ') || 'None'],
    ['Runtime capabilities', value.capabilityIds.join(', ') || 'None'],
    ['Resource IDs', value.resourceIds.join(', ')],
    ['Risk classes', value.riskClasses.join(', ')],
    ['Privacy domain', value.privacyDomainIds.join(', ')],
    ['Valid from', value.validFrom],
    ['Valid until', value.validUntil ?? 'No end date'],
    ['Maker and checker', value.makerCheckerRequired ? 'Required' : 'Not required by this grant'],
    ['Fresh WebAuthn', value.stepUpRequired ? 'Required' : 'Not required by this grant'],
    ['Onward delegation depth', String(value.onwardDelegationDepth)],
    [
      'Delegation epoch',
      proposed && value.state === 'ACTIVE' && value.delegationEpoch === '0'
        ? 'Bound to source authority at commit'
        : value.delegationEpoch,
    ],
    ['Scope digest', value.scopeDigest],
  ];
  return (
    <dl className="mt-3 grid min-w-0 gap-3 text-sm sm:grid-cols-2">
      {items.map(([label, text]) => (
        <div key={label} className="min-w-0">
          <dt className="font-medium">{label}</dt>
          <dd className="break-all">{text}</dd>
        </div>
      ))}
    </dl>
  );
}
