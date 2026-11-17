#!/usr/bin/env bash
# Sourced by the real public runtime harness; no internal business state is seeded.
run_source_lifecycle_journey() {
  local source_path source_revision source_digest original_revision admission_revision
  local action body stale_operation fresh_operation output revision replacement attempt plan_digest
  local helper
  for helper in local_identity_session configuration_get operation_field action_digest \
    configuration_post approved_configuration_post poll_configuration_operation assert_json_equal; do
    if ! declare -F "$helper" >/dev/null; then
      printf 'OPENPC_SOURCE_JOURNEY_PREREQUISITE|missing=%s\n' "$helper" >&2
      return 1
    fi
  done
  configuration_operator_session="$(local_identity_session operator)"
  configuration_checker_session="$(local_identity_session viewer)"
  checker_session_id="${configuration_checker_session#*.}"
  next_checker_sign_count="$(printf '%s\n' "select authenticator_sign_count+1 from control.credential where credential_id='$checker_credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control)"
  next_operator_sign_count="$(printf '%s\n' "select authenticator_sign_count+1 from control.credential where credential_id='$operator_credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control)"
  source_path="http://127.0.0.1:53003/api/v1/indexer-profiles/$indexer_urn"
  configuration_get "$evidence_root/source-revision-before.json" "$source_path"
  source_revision="$(operation_field "$evidence_root/source-revision-before.json" revision)"
  original_revision="$source_revision"
  source_digest="$(operation_field "$evidence_root/source-revision-before.json" methodProfileDigest)"
  test "$(operation_field "$evidence_root/source-revision-before.json" state)" = QUALIFIED

  # A governed A -> B -> A change preserves the frozen UPDATE state while
  # invalidating the old successful qualification's exact revision.
  for attempt in before during; do
    for replacement in "sha256:$(printf '71%.0s' {1..32})" "$source_digest"; do
      action=ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1
      body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Governed source revision regression.\",\"expectedRevision\":\"$source_revision\",\"replacementDigest\":\"$replacement\"}"
      configuration_post "$evidence_root/source-update-$source_revision.json" "$body" \
        "$source_path" "source-revision-update-$source_revision-0001" \
        "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" "$source_revision")" PATCH
      source_revision="$((source_revision + 1))"
    done
    if [[ $attempt == before ]]; then
      "${compose[@]}" stop control-worker >/dev/null
      action=ACT-INDEXER_APPROVE_PROFILE-V1
      body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Requalify updated source.\",\"targetRef\":\"$indexer_urn\",\"expectedRevision\":\"$source_revision\",\"inputDigest\":\"$source_digest\"}"
      output="$evidence_root/source-stale-admission.json"
      approved_configuration_post "$output" "$body" "$source_path/admit" \
        "source-revision-stale-$source_revision-0001" \
        "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" "$source_revision")" \
        POST "source-stale-$original_revision" 202 0
      stale_operation="$(operation_field "$output" operationId)"
      admission_revision="$(operation_field "$output" revision)"
      source_revision="$admission_revision"
      test "$(operation_field "$output" state)" = ACCEPTED
    fi
  done

  "${compose[@]}" start control-worker >/dev/null
  for ((attempt=0; attempt<120; attempt++)); do
    configuration_get "$evidence_root/source-stale-result.json" \
      "http://127.0.0.1:53003/api/v1/operations/$stale_operation"
    [[ $(operation_field "$evidence_root/source-stale-result.json" state) == FAILED ]] && break
    sleep 0.25
  done
  test "$(operation_field "$evidence_root/source-stale-result.json" state)" = FAILED
  test "$(operation_field "$evidence_root/source-stale-result.json" revision)" = "$admission_revision"
  configuration_get "$evidence_root/source-after-stale.json" "$source_path"
  test "$(operation_field "$evidence_root/source-after-stale.json" revision)" = "$source_revision"
  test "$(operation_field "$evidence_root/source-after-stale.json" state)" = SHADOW
  test "$(operation_field "$evidence_root/source-after-stale.json" methodProfileDigest)" = "$source_digest"
  # Exact terminal evidence and a single attempt distinguish rejection from a
  # retry eventually hiding stale completion or quarantine of the new row.
  revision="$(printf '%s\n' "select w.attempt_count||'|'||w.last_error_code||'|'||count(event.event_id) from control.configuration_work w join control.outbox_event event on event.event_id=w.result_event_id where w.operation_id=:'operation' group by w.attempt_count,w.last_error_code;" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v operation="$stale_operation")"
  test "$revision" = '1|PC-DATA-6007|1'

  action=ACT-INDEXER_APPROVE_PROFILE-V1
  body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Qualify the current exact source revision.\",\"targetRef\":\"$indexer_urn\",\"expectedRevision\":\"$source_revision\",\"inputDigest\":\"$source_digest\"}"
  output="$evidence_root/source-fresh-admission.json"
  approved_configuration_post "$output" "$body" "$source_path/admit" \
    "source-revision-fresh-$source_revision-0001" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" "$source_revision")" \
    POST "source-fresh-$original_revision"
  fresh_operation="$(operation_field "$output" operationId)"
  configuration_post "$evidence_root/source-fresh-replay.json" "$body" "$source_path/admit" \
    "source-revision-fresh-$source_revision-0001" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" "$source_revision")"
  test "$(operation_field "$evidence_root/source-fresh-replay.json" operationId)" = "$fresh_operation"
  source_revision="$((source_revision + 2))"
  configuration_get "$evidence_root/source-requalified.json" "$source_path"
  test "$(operation_field "$evidence_root/source-requalified.json" state)" = QUALIFIED
  test "$(operation_field "$evidence_root/source-requalified.json" revision)" = "$source_revision"

  body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Do not requalify an unchanged current qualification.\",\"targetRef\":\"$indexer_urn\",\"expectedRevision\":\"$source_revision\",\"inputDigest\":\"$source_digest\"}"
  approved_configuration_post "$evidence_root/source-current-admission-denied.json" "$body" "$source_path/admit" \
    "source-revision-current-$source_revision-0001" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" "$source_revision")" \
    POST "source-current-$original_revision" 412

  # A projection requires a new current source receipt after requalification.
  configuration_get "$evidence_root/source-projection-before.json" \
    "http://127.0.0.1:53003/api/v1/projection-plans/$projection_urn"
  revision="$(operation_field "$evidence_root/source-projection-before.json" revision)"
  plan_digest="$(operation_field "$evidence_root/source-projection-before.json" planDigest)"
  # Exercise the real nullable-readiness UPDATE path against PostgreSQL. A
  # replacement keeps the public identity and requires a fresh validation.
  for replacement in "sha256:$(printf '72%.0s' {1..32})" "$plan_digest"; do
    action=ACT-PROJECTION_PLANS_UPDATE_RESOURCE-V1
    body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Governed projection mapping regression.\",\"expectedRevision\":\"$revision\",\"replacementDigest\":\"$replacement\"}"
    configuration_post "$evidence_root/source-projection-update-$revision.json" "$body" \
      "http://127.0.0.1:53003/api/v1/projection-plans/$projection_urn" \
      "source-projection-update-$revision-0001" \
      "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$projection_id" "$revision")" PATCH
    revision="$((revision + 1))"
    configuration_get "$evidence_root/source-projection-updated-$revision.json" \
      "http://127.0.0.1:53003/api/v1/projection-plans/$projection_urn"
    test "$(operation_field "$evidence_root/source-projection-updated-$revision.json" planDigest)" = "$replacement"
    test "$(operation_field "$evidence_root/source-projection-updated-$revision.json" revision)" = "$revision"
    test "$(operation_field "$evidence_root/source-projection-updated-$revision.json" state)" = DRAFT
  done
  replacement="$plan_digest"
  action=ACT-INDEXER_RECOVER_PLAN-V1
  body="{\"actionIntentId\":\"$action\",\"actionIntentDigest\":\"$(action_digest "$action")\",\"reason\":\"Revalidate the current source dependency.\",\"targetRef\":\"$projection_urn\",\"expectedRevision\":\"$revision\",\"inputDigest\":\"$replacement\"}"
  configuration_post "$evidence_root/source-projection-revalidated.json" "$body" \
    "http://127.0.0.1:53003/api/v1/projection-plans/$projection_urn/recover" \
    "source-revision-projection-$revision-0001" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$projection_id" "$revision")"
  "${compose[@]}" restart control-worker >/dev/null
  configuration_get "$evidence_root/source-after-restart.json" "$source_path"
  assert_json_equal "$evidence_root/source-requalified.json" "$evidence_root/source-after-restart.json"
  poll_configuration_operation "$fresh_operation" "$evidence_root/source-fresh-after-restart.json"
  configuration_get "$evidence_root/source-projection-after.json" \
    "http://127.0.0.1:53003/api/v1/projection-plans/$projection_urn"
  test "$(operation_field "$evidence_root/source-projection-after.json" readiness)" = READY
  test "$(operation_field "$evidence_root/source-projection-after.json" revision)" = "$((revision + 2))"
  printf 'OPENPC_SOURCE_REVISION_JOURNEY|PASS|governed-update|fresh-qualification|stale-work-single-failure|no-new-row-quarantine|exact-replay|current-qualification-denial|projection-revalidation|restart-readback\n'
}
