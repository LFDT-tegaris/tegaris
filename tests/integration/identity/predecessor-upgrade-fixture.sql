-- Deterministic local-only I02 predecessor rows. Apply after 0003 and before 0004.
insert into control.action_intent values
  ('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','identity','UPDATE','HIGH',true,true,true,
   'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION',clock_timestamp());
insert into control.participant
  (participant_id,display_name,state,authority_epoch,root_privacy_domain_id) values
  ('018f0000-0000-7000-8000-000000000901','predecessor populated','ACTIVE',4,
   '018f0000-0000-7000-8000-000000000902');
insert into control.privacy_domain
  (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values
  ('018f0000-0000-7000-8000-000000000902','018f0000-0000-7000-8000-000000000901',
   'predecessor privacy','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE');
insert into control.principal
  (principal_id,participant_id,kind,display_label,state,authority_epoch) values
  ('018f0000-0000-7000-8000-000000000903','018f0000-0000-7000-8000-000000000901',
   'USER','predecessor maker','ACTIVE',5),
  ('018f0000-0000-7000-8000-000000000904','018f0000-0000-7000-8000-000000000901',
   'USER','predecessor checker','ACTIVE',6);
insert into control.credential
  (credential_id,participant_id,principal_id,kind,public_key_digest,state,valid_from) values
  ('018f0000-0000-7000-8000-000000000905','018f0000-0000-7000-8000-000000000901',
   '018f0000-0000-7000-8000-000000000904','WEBAUTHN',decode(repeat('11',32),'hex'),
   'ACTIVE',clock_timestamp()-interval '1 hour');
insert into control.session
  (session_id,participant_id,principal_id,opaque_token_digest,state,authority_epoch,
   delegation_epoch,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,
   client_fingerprint_digest,participant_epoch,session_epoch,refresh_family_id,
   refresh_token_digest,refresh_used,csrf_secret) values
  ('018f0000-0000-7000-8000-000000000906','018f0000-0000-7000-8000-000000000901',
   '018f0000-0000-7000-8000-000000000903',decode(repeat('12',32),'hex'),'ACTIVE',5,0,
   transaction_timestamp(),transaction_timestamp(),transaction_timestamp()+interval '30 minutes',
   transaction_timestamp()+interval '12 hours',decode(repeat('13',32),'hex'),4,1,
   '018f0000-0000-7000-8000-000000000907',decode(repeat('14',32),'hex'),false,
   decode(repeat('15',32),'hex'));
insert into control.mfa_challenge
  (mfa_challenge_id,participant_id,session_id,principal_id,action_intent_id,
   resource_digest,challenge_digest,rp_id_hash,expires_at,consumed_at) values
  ('018f0000-0000-7000-8000-000000000908','018f0000-0000-7000-8000-000000000901',
   '018f0000-0000-7000-8000-000000000906','018f0000-0000-7000-8000-000000000903',
   'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',decode(repeat('16',32),'hex'),
   decode(repeat('17',32),'hex'),decode(repeat('18',32),'hex'),
   clock_timestamp()+interval '5 minutes',clock_timestamp());
insert into control.approval_request
  (approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
   subject_id,subject_digest,maker_principal_id,required_approvals,state,expires_at) values
  ('018f0000-0000-7000-8000-000000000909','018f0000-0000-7000-8000-000000000901',
   '018f0000-0000-7000-8000-000000000902','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
   'predecessor','018f0000-0000-7000-8000-000000000903',decode(repeat('19',32),'hex'),
   '018f0000-0000-7000-8000-000000000903',1,'APPROVED',clock_timestamp()+interval '10 minutes');
insert into control.approval_decision_record
  (participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
   decision,decision_digest,cose_sign1) values
  ('018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902',
   '018f0000-0000-7000-8000-000000000909','018f0000-0000-7000-8000-000000000904',
   'APPROVE',decode(repeat('20',32),'hex'),decode('d28440a04040','hex'));
insert into control.mutation_evidence
  (participant_id,privacy_domain_id,operation_id,principal_id,checker_principal_id,
   action_intent_id,aggregate_type,aggregate_id,candidate_digest,approval_request_id,
   mfa_challenge_id,bound_participant_epoch,bound_authority_epoch,evidence_cbor,
   evidence_digest,cose_sign1) values
  ('018f0000-0000-7000-8000-000000000901','018f0000-0000-7000-8000-000000000902',
   '018f0000-0000-7000-8000-000000000910','018f0000-0000-7000-8000-000000000903',
   '018f0000-0000-7000-8000-000000000904','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
   'principal','018f0000-0000-7000-8000-000000000903',decode(repeat('19',32),'hex'),
   '018f0000-0000-7000-8000-000000000909','018f0000-0000-7000-8000-000000000908',
   4,5,decode('a0','hex'),decode(repeat('21',32),'hex'),decode('d28440a04040','hex'));
