begin;
select openpc.set_request_context('PARTICIPANT','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902',uuidv7(),'ACT-POLICY_ACTIVATE_RELEASE-V1',true);
-- Registered local-only PostgreSQL 18.6 lifecycle candidate for runtime tests.
insert into control.authority_envelope(
  authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
  risk_classes,maker_checker_required,step_up_required,onward_delegation_depth
) values(
  '018f0000-0000-7000-8000-000000000914','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000904','018f0000-0000-7000-8000-000000000903',
  '018f0000-0000-7000-8000-000000000904',6,1,'ACTIVE',clock_timestamp()-interval '1 hour',
  clock_timestamp()+interval '1 hour',decode('a0','hex'),decode(repeat('14',32),'hex'),
  decode('d28440a04040','hex'),array['018f0000-0000-7000-8000-000000000902'],
  array['ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1'],array[
    '018f0000-0000-7000-8000-000000000911',
    '018f0000-0000-7000-8000-000000000931',
    '018f0000-0000-7000-8000-000000000941',
    '018f0000-0000-7000-8000-000000000920'
  ],
  array['HIGH'],true,true,0
);
insert into control.assignment(
  assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
  scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
  action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
  onward_delegation_depth
) values(
  '018f0000-0000-7000-8000-000000000915','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000904','018f0000-0000-7000-8000-000000000914',1,
  decode(repeat('31',32),'hex'),tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),
  'ACTIVE','018f0000-0000-7000-8000-000000000903',array['018f0000-0000-7000-8000-000000000902'],
  array['ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1'],array[
    '018f0000-0000-7000-8000-000000000911','018f0000-0000-7000-8000-000000000920'
  ],
  array['HIGH'],true,true,0
);
insert into control.assignment(
  assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
  scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
  action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
  onward_delegation_depth
) values
('018f0000-0000-7000-8000-000000000935','018f0000-0000-7000-8000-000000000901',
 '018f0000-0000-7000-8000-000000000904','018f0000-0000-7000-8000-000000000914',1,
 decode(repeat('32',32),'hex'),tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),
 'ACTIVE','018f0000-0000-7000-8000-000000000903',array['018f0000-0000-7000-8000-000000000902'],
 array['ACT-POLICY_ACTIVATE_RELEASE-V1'],array['018f0000-0000-7000-8000-000000000931'],
 array['HIGH'],true,true,0),
('018f0000-0000-7000-8000-000000000945','018f0000-0000-7000-8000-000000000901',
 '018f0000-0000-7000-8000-000000000904','018f0000-0000-7000-8000-000000000914',1,
 decode(repeat('42',32),'hex'),tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),
 'ACTIVE','018f0000-0000-7000-8000-000000000903',array['018f0000-0000-7000-8000-000000000902'],
 array['ACT-POLICY_ACTIVATE_RELEASE-V1'],array['018f0000-0000-7000-8000-000000000941'],
 array['HIGH'],true,true,0);
insert into control.credential(
  credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,
  state,valid_from,credential_epoch
) values(
  '018f0000-0000-7000-8000-000000000916','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000904','WEBAUTHN',decode(repeat('16',32),'hex'),
  decode('3059301306072a8648ce3d020106082a8648ce3d030107034200040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40','hex'),
  'ACTIVE',clock_timestamp()-interval '1 hour',3
);
insert into control.session(
  session_id,participant_id,principal_id,opaque_token_digest,state,authority_epoch,
  delegation_epoch,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,
  step_up_verified_at,client_fingerprint_digest,participant_epoch,session_epoch,
  refresh_family_id,refresh_token_digest,csrf_secret
) values(
  '018f0000-0000-7000-8000-000000000920','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000904',decode(repeat('20',32),'hex'),'ACTIVE',6,1,
  statement_timestamp()-interval '5 minutes',statement_timestamp()-interval '1 minute',
  statement_timestamp()+interval '29 minutes',statement_timestamp()+interval '11 hours 55 minutes',
  statement_timestamp()-interval '1 minute',decode(repeat('21',32),'hex'),4,1,
  '018f0000-0000-7000-8000-000000000921',decode(repeat('22',32),'hex'),decode(repeat('23',32),'hex')
);
insert into control.mfa_challenge(
  mfa_challenge_id,participant_id,session_id,principal_id,action_intent_id,
  resource_digest,challenge_digest,rp_id_hash,expires_at,consumed_at
) values(
  '018f0000-0000-7000-8000-000000000922','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000920','018f0000-0000-7000-8000-000000000904',
  'ACT-POLICY_ACTIVATE_RELEASE-V1',decode(repeat('11',32),'hex'),decode(repeat('24',32),'hex'),
  decode(repeat('25',32),'hex'),clock_timestamp()+interval '30 minutes',clock_timestamp()
);
insert into control.mfa_challenge(
  mfa_challenge_id,participant_id,session_id,principal_id,action_intent_id,
  resource_digest,challenge_digest,rp_id_hash,expires_at,consumed_at
) values
('018f0000-0000-7000-8000-000000000936','018f0000-0000-7000-8000-000000000901',
 '018f0000-0000-7000-8000-000000000920','018f0000-0000-7000-8000-000000000904',
 'ACT-POLICY_ACTIVATE_RELEASE-V1',decode(repeat('33',32),'hex'),decode(repeat('37',32),'hex'),
 decode(repeat('39',32),'hex'),clock_timestamp()+interval '30 minutes',clock_timestamp()),
('018f0000-0000-7000-8000-000000000946','018f0000-0000-7000-8000-000000000901',
 '018f0000-0000-7000-8000-000000000920','018f0000-0000-7000-8000-000000000904',
 'ACT-POLICY_ACTIVATE_RELEASE-V1',decode(repeat('43',32),'hex'),decode(repeat('47',32),'hex'),
 decode(repeat('49',32),'hex'),clock_timestamp()+interval '30 minutes',clock_timestamp()),
('018f0000-0000-7000-8000-000000000951','018f0000-0000-7000-8000-000000000901',
 '018f0000-0000-7000-8000-000000000920','018f0000-0000-7000-8000-000000000904',
 'ACT-POLICY_ACTIVATE_RELEASE-V1',decode(repeat('33',32),'hex'),decode(repeat('51',32),'hex'),
 decode(repeat('39',32),'hex'),clock_timestamp()+interval '30 minutes',clock_timestamp()),
('018f0000-0000-7000-8000-000000000952','018f0000-0000-7000-8000-000000000901',
 '018f0000-0000-7000-8000-000000000920','018f0000-0000-7000-8000-000000000904',
 'ACT-POLICY_ACTIVATE_RELEASE-V1',decode(repeat('43',32),'hex'),decode(repeat('52',32),'hex'),
 decode(repeat('49',32),'hex'),clock_timestamp()+interval '30 minutes',clock_timestamp());
insert into control.policy(policy_id,participant_id,privacy_domain_id,policy_name)
values('018f0000-0000-7000-8000-000000000910','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000902','I03 immutable policy');
insert into control.policy_version(
  policy_version_id,policy_id,participant_id,privacy_domain_id,version,schema_digest,
  semantic_cbor,semantic_digest,cose_sign1,created_by_principal_id
) values(
  '018f0000-0000-7000-8000-000000000911','018f0000-0000-7000-8000-000000000910',
  '018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902',
  '1.0.0',decode(repeat('10',32),'hex'),decode('a0','hex'),decode(repeat('11',32),'hex'),
  decode('d28440a04040','hex'),'018f0000-0000-7000-8000-000000000903'
);
insert into control.policy_simulation(
  simulation_id,participant_id,privacy_domain_id,policy_version_id,input_digest,result_digest,
  fact_generation_digest,dependency_closure_digest,truth_state,result_document,completed_at
) values(
  '018f0000-0000-7000-8000-000000000912','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000911',
  decode(repeat('11',32),'hex'),decode(repeat('13',32),'hex'),decode(repeat('21',32),'hex'),
  decode(repeat('22',32),'hex'),'SUCCESS','{"authority":"SIMULATION_ONLY","truthState":"SUCCESS"}'::jsonb,
  clock_timestamp()
);
insert into control.approval_request(
  approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
  subject_id,subject_digest,subject_version,maker_principal_id,required_approvals,state,expires_at
) values(
  '018f0000-0000-7000-8000-000000000913','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000902','ACT-POLICY_APPROVE_REQUEST-V1','policy-version',
  '018f0000-0000-7000-8000-000000000911',decode(repeat('11',32),'hex'),1,
  '018f0000-0000-7000-8000-000000000903',1,'APPROVED',clock_timestamp()+interval '30 minutes'
);
-- Activation-specific signed approval decisions are inserted by the live runtime harness so
-- their exact candidate, action, approval request, aggregate identity/version and decision
-- fields are cryptographically bound before any policy activation attempt.
insert into control.policy_generation(
  policy_generation_id,participant_id,privacy_domain_id,policy_version_id,simulation_id,
  approval_request_id,generation,scope_digest,generation_digest,fact_generation_digest,
  artifact_digest,compiler_manifest_digest,dependency_closure_digest,state
) values(
  '018f0000-0000-7000-8000-000000000917','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000911',
  '018f0000-0000-7000-8000-000000000912','018f0000-0000-7000-8000-000000000913',1,
  decode(repeat('31',32),'hex'),decode(repeat('17',32),'hex'),decode(repeat('21',32),'hex'),
  decode(repeat('18',32),'hex'),decode(repeat('19',32),'hex'),decode(repeat('22',32),'hex'),'PREPARED'
);
insert into control.policy_activation(
  policy_activation_id,participant_id,privacy_domain_id,policy_generation_id,approval_request_id,
  mfa_challenge_id,exact_cohort_digest,webauthn_assertion_binding_digest,state
) values(
  '018f0000-0000-7000-8000-000000000918','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000917',
  '018f0000-0000-7000-8000-000000000913','018f0000-0000-7000-8000-000000000922',
  decode(repeat('23',32),'hex'),decode(repeat('24',32),'hex'),'PREPARED'
);
insert into control.policy_activation_prerequisite(
  policy_activation_id,participant_id,privacy_domain_id,prerequisite_type,
  prerequisite_subject_digest,receipt_digest,ready,observed_at
)
select '018f0000-0000-7000-8000-000000000918','018f0000-0000-7000-8000-000000000901',
  '018f0000-0000-7000-8000-000000000902',prerequisite,
  case prerequisite
    when 'SIMULATION' then decode(repeat('11',32),'hex')
    when 'APPROVAL' then decode(repeat('11',32),'hex')
    when 'FACT_READINESS' then decode(repeat('21',32),'hex')
    when 'FLEET_READY' then decode(repeat('23',32),'hex')
    when 'DEPENDENCY_CLOSURE' then decode(repeat('22',32),'hex')
    else decode(repeat('17',32),'hex') end,
  decode(lpad(to_hex(row_number() over ()::int),64,'0'),'hex'),true,clock_timestamp()
from unnest(enum_range(null::control.policy_prerequisite_type)) prerequisite;

-- Two independent exact scopes with active predecessors for concurrent activation proof.
insert into control.policy(policy_id,participant_id,privacy_domain_id,policy_name) values
('018f0000-0000-7000-8000-000000000930','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','I03 scope two'),
('018f0000-0000-7000-8000-000000000940','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','I03 scope three');
insert into control.policy_version(
  policy_version_id,policy_id,participant_id,privacy_domain_id,version,schema_digest,
  semantic_cbor,semantic_digest,cose_sign1,created_by_principal_id
) values
('018f0000-0000-7000-8000-000000000931','018f0000-0000-7000-8000-000000000930','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','1.0.0',decode(repeat('10',32),'hex'),decode('a0','hex'),decode(repeat('33',32),'hex'),decode('d28440a04040','hex'),'018f0000-0000-7000-8000-000000000903'),
('018f0000-0000-7000-8000-000000000941','018f0000-0000-7000-8000-000000000940','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','1.0.0',decode(repeat('10',32),'hex'),decode('a0','hex'),decode(repeat('43',32),'hex'),decode('d28440a04040','hex'),'018f0000-0000-7000-8000-000000000903');
insert into control.policy_simulation(
  simulation_id,participant_id,privacy_domain_id,policy_version_id,input_digest,result_digest,
  fact_generation_digest,dependency_closure_digest,truth_state,result_document,completed_at
) values
('018f0000-0000-7000-8000-000000000932','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000931',decode(repeat('33',32),'hex'),decode(repeat('3a',32),'hex'),decode(repeat('21',32),'hex'),decode(repeat('22',32),'hex'),'SUCCESS','{"authority":"SIMULATION_ONLY","truthState":"SUCCESS"}'::jsonb,clock_timestamp()),
('018f0000-0000-7000-8000-000000000942','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000941',decode(repeat('43',32),'hex'),decode(repeat('4a',32),'hex'),decode(repeat('21',32),'hex'),decode(repeat('22',32),'hex'),'SUCCESS','{"authority":"SIMULATION_ONLY","truthState":"SUCCESS"}'::jsonb,clock_timestamp());
insert into control.approval_request(
  approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
  subject_id,subject_digest,subject_version,maker_principal_id,required_approvals,state,expires_at
) values
('018f0000-0000-7000-8000-000000000933','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','ACT-POLICY_APPROVE_REQUEST-V1','policy-version','018f0000-0000-7000-8000-000000000931',decode(repeat('33',32),'hex'),1,'018f0000-0000-7000-8000-000000000903',1,'APPROVED',clock_timestamp()+interval '30 minutes'),
('018f0000-0000-7000-8000-000000000943','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','ACT-POLICY_APPROVE_REQUEST-V1','policy-version','018f0000-0000-7000-8000-000000000941',decode(repeat('43',32),'hex'),1,'018f0000-0000-7000-8000-000000000903',1,'APPROVED',clock_timestamp()+interval '30 minutes');
-- See the activation-specific decision insertion in postgres18-runtime.test.ts.
insert into control.policy_generation(
  policy_generation_id,participant_id,privacy_domain_id,policy_version_id,simulation_id,
  approval_request_id,generation,scope_digest,generation_digest,fact_generation_digest,
  artifact_digest,compiler_manifest_digest,dependency_closure_digest,state,active
) values
('018f0000-0000-7000-8000-000000000934','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000931','018f0000-0000-7000-8000-000000000932','018f0000-0000-7000-8000-000000000933',1,decode(repeat('32',32),'hex'),decode(repeat('34',32),'hex'),decode(repeat('21',32),'hex'),decode(repeat('3b',32),'hex'),decode(repeat('19',32),'hex'),decode(repeat('22',32),'hex'),'ACTIVE',true),
('018f0000-0000-7000-8000-000000000939','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000931','018f0000-0000-7000-8000-000000000932','018f0000-0000-7000-8000-000000000933',2,decode(repeat('32',32),'hex'),decode(repeat('35',32),'hex'),decode(repeat('21',32),'hex'),decode(repeat('3c',32),'hex'),decode(repeat('19',32),'hex'),decode(repeat('22',32),'hex'),'PREPARED',false),
('018f0000-0000-7000-8000-000000000944','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000941','018f0000-0000-7000-8000-000000000942','018f0000-0000-7000-8000-000000000943',1,decode(repeat('42',32),'hex'),decode(repeat('44',32),'hex'),decode(repeat('21',32),'hex'),decode(repeat('4b',32),'hex'),decode(repeat('19',32),'hex'),decode(repeat('22',32),'hex'),'ACTIVE',true),
('018f0000-0000-7000-8000-000000000949','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000941','018f0000-0000-7000-8000-000000000942','018f0000-0000-7000-8000-000000000943',2,decode(repeat('42',32),'hex'),decode(repeat('45',32),'hex'),decode(repeat('21',32),'hex'),decode(repeat('4c',32),'hex'),decode(repeat('19',32),'hex'),decode(repeat('22',32),'hex'),'PREPARED',false);
insert into control.policy_activation(
  policy_activation_id,participant_id,privacy_domain_id,policy_generation_id,approval_request_id,
  mfa_challenge_id,exact_cohort_digest,prior_generation_digest,webauthn_assertion_binding_digest,
  receipt_digest,state,row_version,activated_at
) values
('018f0000-0000-7000-8000-000000000937','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000934','018f0000-0000-7000-8000-000000000933','018f0000-0000-7000-8000-000000000951',decode(repeat('36',32),'hex'),null,decode(repeat('51',32),'hex'),decode(repeat('3d',32),'hex'),'ACTIVE',2,clock_timestamp()),
('018f0000-0000-7000-8000-000000000938','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000939','018f0000-0000-7000-8000-000000000933','018f0000-0000-7000-8000-000000000936',decode(repeat('36',32),'hex'),decode(repeat('34',32),'hex'),decode(repeat('37',32),'hex'),null,'PREPARED',1,null),
('018f0000-0000-7000-8000-000000000947','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000944','018f0000-0000-7000-8000-000000000943','018f0000-0000-7000-8000-000000000952',decode(repeat('46',32),'hex'),null,decode(repeat('52',32),'hex'),decode(repeat('4d',32),'hex'),'ACTIVE',2,clock_timestamp()),
('018f0000-0000-7000-8000-000000000948','018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000949','018f0000-0000-7000-8000-000000000943','018f0000-0000-7000-8000-000000000946',decode(repeat('46',32),'hex'),decode(repeat('44',32),'hex'),decode(repeat('47',32),'hex'),null,'PREPARED',1,null);
insert into control.policy_activation_prerequisite(
  policy_activation_id,participant_id,privacy_domain_id,prerequisite_type,
  prerequisite_subject_digest,receipt_digest,ready,observed_at
)
select activation_id,'018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902',prerequisite,
  case prerequisite when 'SIMULATION' then candidate when 'APPROVAL' then candidate
    when 'FACT_READINESS' then decode(repeat('21',32),'hex') when 'FLEET_READY' then cohort
    when 'DEPENDENCY_CLOSURE' then decode(repeat('22',32),'hex') else generation end,
  decode(lpad(to_hex(receipt_base + row_number() over (partition by activation_id order by prerequisite)),64,'0'),'hex'),
  true,clock_timestamp()
from (values
  ('018f0000-0000-7000-8000-000000000938'::uuid,decode(repeat('33',32),'hex'),decode(repeat('36',32),'hex'),decode(repeat('35',32),'hex'),100),
  ('018f0000-0000-7000-8000-000000000948'::uuid,decode(repeat('43',32),'hex'),decode(repeat('46',32),'hex'),decode(repeat('45',32),'hex'),200)
) candidate(activation_id,candidate,cohort,generation,receipt_base)
cross join unnest(enum_range(null::control.policy_prerequisite_type)) prerequisite;

select 'POSTGRES_18_6_POPULATED_PREDECESSOR_PASS',current_setting('server_version'),
  (select count(*) from control.policy_activation_prerequisite);

commit;
