-- Deterministic local-only R6 predecessor rows. Apply after 0005 and before 0006.
insert into control.action_intent
  (action_intent_id, resource_type, operation_class, risk_class, maker_checker_required,
   step_up_required, idempotency_required, existence_disclosure, payload_disclosure,
   evidence_class)
values
  ('ACT-IDENTITY_UPDATE_STEP_UP-V1', 'identity', 'UPDATE', 'HIGH', false, false, true,
   'AUTHORIZED_ONLY', 'REDACTED', 'IDENTITY_MUTATION')
on conflict (action_intent_id) do nothing;

alter table control.mutation_evidence disable trigger mutation_evidence_immutable;
update control.mutation_evidence
set action_intent_id = 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    catalog_operation_id = 'ID-OP-WEBAUTHN-VERIFY',
    webauthn_assertion_binding_digest = decode(repeat('aa', 32), 'hex')
where participant_id = '018f0000-0000-7000-8000-000000000901'
  and operation_id = '018f0000-0000-7000-8000-000000000910';
alter table control.mutation_evidence enable trigger mutation_evidence_immutable;

insert into control.idempotency_record
  (participant_id, principal_id, action_intent_id, idempotency_key, operation_id,
   input_digest, result_digest, terminal_state, expires_at, result_payload,
   catalog_operation_id, expected_aggregate_version, result_aggregate_version)
values
  ('018f0000-0000-7000-8000-000000000901',
   '018f0000-0000-7000-8000-000000000903',
   'ACT-IDENTITY_UPDATE_STEP_UP-V1', 'r6-populated-webauthn-binding',
   '018f0000-0000-7000-8000-000000000910', decode(repeat('bb', 32), 'hex'),
   decode(repeat('cc', 32), 'hex'), 'COMPLETED', clock_timestamp() + interval '1 hour',
   'null'::jsonb, 'ID-OP-WEBAUTHN-VERIFY', 1, 2);

insert into control.outbox_event
  (outbox_event_id, participant_id, event_id, event_type, aggregate_type, aggregate_id,
   aggregate_sequence, payload_cbor, payload_digest, cose_sign1, occurred_at,
   privacy_domain_id, webauthn_assertion_binding_digest)
values
  ('018f0000-0000-7000-8000-000000000911',
   '018f0000-0000-7000-8000-000000000901',
   '018f0000-0000-7000-8000-000000000912', 'identity.step-up.verified.v1',
   'webauthn-verification', '018f0000-0000-7000-8000-000000000906', 1,
   decode('a0', 'hex'), decode(repeat('dd', 32), 'hex'), decode('d28440a04040', 'hex'),
   clock_timestamp(), '018f0000-0000-7000-8000-000000000902',
   decode(repeat('aa', 32), 'hex'));
