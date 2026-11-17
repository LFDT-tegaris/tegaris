-- Registered local-only PostgreSQL 18.6 predecessor and least-privilege runtime fixture.
create role openpc_i03_runtime login inherit password 'openpc_i03_local_only';
grant openpc_control_runtime to openpc_i03_runtime;

insert into control.participant(participant_id,display_name,state,authority_epoch) values
('018f0000-0000-7000-8000-000000000901','I03 tenant A','ACTIVE',4),
('018f0000-0000-7000-8000-000000000a01','I03 tenant B','ACTIVE',7);
insert into control.privacy_domain(
  privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state
) values
('018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000901','I03 tenant A privacy','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE'),
('018f0000-0000-7000-8000-000000000a02','018f0000-0000-7000-8000-000000000a01','I03 tenant B privacy','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE');
update control.participant
set root_privacy_domain_id=case participant_id
  when '018f0000-0000-7000-8000-000000000901' then '018f0000-0000-7000-8000-000000000902'::uuid
  else '018f0000-0000-7000-8000-000000000a02'::uuid end;
insert into control.principal(
  principal_id,participant_id,kind,display_label,state,authority_epoch
) values
('018f0000-0000-7000-8000-000000000903','018f0000-0000-7000-8000-000000000901','USER','maker-a','ACTIVE',5),
('018f0000-0000-7000-8000-000000000904','018f0000-0000-7000-8000-000000000901','USER','checker-a','ACTIVE',6),
('018f0000-0000-7000-8000-000000000a03','018f0000-0000-7000-8000-000000000a01','USER','maker-b','ACTIVE',8),
('018f0000-0000-7000-8000-000000000a04','018f0000-0000-7000-8000-000000000a01','USER','checker-b','ACTIVE',9);
insert into control.action_intent(
  action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
  step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class
) values
('ACT-POLICY_APPROVE_REQUEST-V1','policy','APPROVE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','POLICY_MUTATION'),
('ACT-POLICY_ACTIVATE_RELEASE-V1','policy','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','POLICY_MUTATION'),
('ACT-IDENTITY_UPDATE_STEP_UP-V1','identity','UPDATE','HIGH',false,false,true,'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION');
