/** Forward-migration projection, consumed only by the owning Drizzle generator. */
export const idempotencyPrivacyUpgrade = `
DO $idempotency_privacy_upgrade$
DECLARE
  relation_name text;
  forced_relations text[] := ARRAY[]::text[];
  resource_key text;
BEGIN
  -- The migration runs as the schema owner. Temporarily remove FORCE, never RLS
  -- itself, so it can reconcile all Participants without guessing request GUCs.
  -- Application roles remain subject to their policies throughout the migration.
  FOREACH relation_name IN ARRAY ARRAY[
    'idempotency_record','mutation_evidence','configuration_work',
    'approval_request','policy_release_bundle','policy_activation_occurrence'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class
                WHERE oid=to_regclass('control.'||relation_name) AND relforcerowsecurity) THEN
      forced_relations := array_append(forced_relations,relation_name);
      EXECUTE format('ALTER TABLE control.%I NO FORCE ROW LEVEL SECURITY',relation_name);
    END IF;
  END LOOP;

  CREATE TEMP TABLE idempotency_privacy_binding (
    participant_id uuid NOT NULL, operation_id uuid NOT NULL, privacy_domain_id uuid NOT NULL
  ) ON COMMIT DROP;
  INSERT INTO pg_temp.idempotency_privacy_binding
    SELECT evidence.participant_id,evidence.operation_id,evidence.privacy_domain_id
      FROM control.mutation_evidence evidence JOIN control.idempotency_record record
        ON record.participant_id=evidence.participant_id AND record.operation_id=evidence.operation_id
       AND record.privacy_domain_id IS NULL;

  -- Later-owned tables exist on upgrades, but not on a greenfield identity migration.
  IF to_regclass('control.configuration_work') IS NOT NULL THEN
    EXECUTE 'INSERT INTO pg_temp.idempotency_privacy_binding
      SELECT work.participant_id,work.operation_id,work.privacy_domain_id
        FROM control.configuration_work work JOIN control.idempotency_record record
          ON record.participant_id=work.participant_id AND record.operation_id=work.operation_id
         AND record.privacy_domain_id IS NULL';
  END IF;
  FOR relation_name,resource_key IN
    SELECT * FROM (VALUES
      ('approval_request','approval_request_id'),
      ('policy_release_bundle','release_bundle_id'),
      ('policy_activation_occurrence','activation_occurrence_id')
    ) AS resource_owner(relation_name,resource_key)
  LOOP
    IF to_regclass('control.'||relation_name) IS NOT NULL THEN
      EXECUTE format('INSERT INTO pg_temp.idempotency_privacy_binding
        SELECT record.participant_id,record.operation_id,resource.privacy_domain_id
          FROM control.idempotency_record record JOIN control.%I resource
            ON resource.participant_id=record.participant_id
           AND record.result_payload->>''resourceRef''=''urn:openpc:resource:''||resource.%I::text
         WHERE record.privacy_domain_id IS NULL',relation_name,resource_key);
    END IF;
  END LOOP;

  -- Assign only unambiguous durable ownership. No operation/result bytes change.
  UPDATE control.idempotency_record record SET privacy_domain_id=bound.privacy_domain_id
    FROM (SELECT participant_id,operation_id,min(privacy_domain_id::text)::uuid privacy_domain_id
            FROM pg_temp.idempotency_privacy_binding
           GROUP BY participant_id,operation_id HAVING count(DISTINCT privacy_domain_id)=1) bound
   WHERE record.participant_id=bound.participant_id AND record.operation_id=bound.operation_id
     AND record.privacy_domain_id IS NULL;

  -- An unknown old namespace could otherwise permit a second effect under the
  -- newly privacy-scoped key. Refuse the whole transaction instead of hiding the
  -- old operation and treating the same key as unused. Rollback preserves it.
  IF EXISTS (SELECT 1 FROM control.idempotency_record WHERE privacy_domain_id IS NULL) THEN
    RAISE EXCEPTION USING ERRCODE='P0001',
      MESSAGE='DATA-6021-INCOMPLETE-SECURITY-RECORD',
      DETAIL='idempotency privacy ownership requires reconciliation';
  END IF;

  FOREACH relation_name IN ARRAY forced_relations LOOP
    EXECUTE format('ALTER TABLE control.%I FORCE ROW LEVEL SECURITY',relation_name);
  END LOOP;
END
$idempotency_privacy_upgrade$;
`;
