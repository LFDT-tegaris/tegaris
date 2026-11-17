import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export async function bootstrapPrivacyAuthority(
  admin,
  participantId,
  principal,
  otherPrivacy,
  envelope,
  assignment,
  { allowContextSelection = false } = {},
) {
  // Initial trust for a second explicit context only. All operation and approval
  // state above/below is created through public owners; no business proof is seeded.
  await admin.query(
    `insert into control.privacy_domain
    (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
    values($1,$2,$3,'PARTICIPANT_LOCAL','LOCAL_DEVELOPMENT','ACTIVE')`,
    [otherPrivacy, participantId, `Privacy test ${otherPrivacy}`],
  );
  const actions = ['ACT-OPERATIONS_READ_OPERATION-V1', 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'];
  if (allowContextSelection) actions.push('ACT-POLICY_READ_EFFECTIVE_ACCESS-V1');
  const registered = await admin.query(
    `select action_intent_id,resource_type,operation_class from control.action_intent where action_intent_id=any($1::text[]) order by action_intent_id`,
    [actions],
  );
  assert.deepEqual(
    registered.rows,
    [
      {
        action_intent_id: actions[1],
        resource_type: 'approval-requests',
        operation_class: 'CREATE',
      },
      { action_intent_id: actions[0], resource_type: 'operations', operation_class: 'READ' },
      ...(allowContextSelection
        ? [{ action_intent_id: actions[2], resource_type: 'policy', operation_class: 'READ' }]
        : []),
    ].sort((a, b) => a.action_intent_id.localeCompare(b.action_intent_id)),
    'fixture actions must be registered under their exact owners',
  );
  const trustScope = Buffer.concat([
    Buffer.from('a20050', 'hex'),
    Buffer.from(envelope.replaceAll('-', ''), 'hex'),
    Buffer.from('0150', 'hex'),
    Buffer.from(otherPrivacy.replaceAll('-', ''), 'hex'),
  ]);
  await admin.query(
    `insert into control.authority_envelope
    (authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
     authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,
     privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
    select $1,participant_id,principal_id,maker_principal_id,checker_principal_id,1,1,'ACTIVE',
      clock_timestamp()-interval '1 minute',$6,$7,cose_sign1,
      array[$3]::text[],$4::text[],array['*']::text[],risk_classes,false,false,0
      from control.authority_envelope where participant_id=$2 and principal_id=$5 and state='ACTIVE'
      order by authority_envelope_id limit 1`,
    [
      envelope,
      participantId,
      otherPrivacy,
      actions,
      principal,
      trustScope,
      createHash('sha256').update(trustScope).digest(),
    ],
  );
  await admin.query(
    `insert into control.assignment
    (assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,
     valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,
     risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
    select $1,$2,$3,$4,1,semantic_digest,tstzrange(clock_timestamp()-interval '1 minute',null,'[)'),
      'ACTIVE',$3,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,false,false,0
      from control.authority_envelope where authority_envelope_id=$4`,
    [assignment, participantId, principal, envelope],
  );
}
