/** Module admission and initial lifecycle share the same governed evidence owner. */
export const moduleReceiptGuardSql = `
CREATE OR REPLACE FUNCTION openpc.check_module_admission_receipt(receipt control.audit_occurrence)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE projection jsonb; candidate control.mutation_candidate%ROWTYPE;
BEGIN
 IF receipt.catalog_operation_id NOT IN ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') OR receipt.aggregate_type<>'module-registration'
  OR receipt.after_existence<>1 OR (receipt.catalog_operation_id='MOD-OP-REGISTER' AND
   (receipt.before_existence<>0 OR receipt.before_revision<>0 OR receipt.after_revision<>1))
  OR (receipt.catalog_operation_id<>'MOD-OP-REGISTER' AND
   (receipt.before_existence<>1 OR receipt.before_revision<1 OR receipt.after_revision<>receipt.before_revision+1))
 THEN RAISE EXCEPTION 'DATA-6021-MODULE-TRANSITION'; END IF;
 candidate:=openpc.check_governed_configuration_receipt(receipt);
 projection:=openpc.business_cbor(receipt.after_state_preimage)->8;
 IF receipt.catalog_operation_id<>'MOD-OP-REGISTER' THEN
  PERFORM openpc.check_module_lifecycle_state(receipt);
  RETURN;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM control.module_installation m JOIN control.module_version v USING(module_version_id)
  JOIN control.module_configuration_generation c USING(module_installation_id)
  WHERE m.participant_id=receipt.participant_id AND m.privacy_domain_id=receipt.privacy_domain_id
   AND m.module_installation_id=receipt.aggregate_id AND c.participant_id=m.participant_id AND c.privacy_domain_id=m.privacy_domain_id
   AND m.state='ADMITTED' AND m.aggregate_version=1 AND m.active_manifest_digest IS NULL
   AND c.generation=1 AND c.active=false AND v.release_payload_cbor IS NOT NULL
   AND v.module_id=candidate.candidate_document->>'name'
   AND v.semantic_version=candidate.candidate_document->>'semanticVersion'
   AND 'sha256:'||encode(v.manifest_digest,'hex')=candidate.candidate_document->>'manifestDigest'
   AND projection=jsonb_build_object('0',v.module_id,'1',v.semantic_version,'2',openpc.business_bytes(v.manifest_digest),
    '3',openpc.business_bytes(m.admission_dependency_digest),'4',openpc.business_bytes(c.configuration_digest),
    '5','ADMITTED','6',0,'7',1,'8',0))
 THEN RAISE EXCEPTION 'DATA-6021-MODULE-DURABLE-STATE'; END IF;
END $$;
`;
