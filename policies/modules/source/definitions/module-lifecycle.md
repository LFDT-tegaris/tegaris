# OpenPC module lifecycle specification

Status: `FINAL_C04_AF18_AF19`

Normative language: `MUST`, `MUST NOT`, `SHALL`, `SHALL NOT` and `REQUIRED` are binding. This document specifies contracts only; it does not authorize implementation, deployment, migration execution, or release.

## 1. Authority and trace

The machine authorities are `module-manifest.schema.json`, `module-registry.json`, the 33 files under `manifests/`, `module-contract-catalog.json` and `module-conformance-fixtures.json`. `module-traceability.jsonl` closes every `LANE-MODULE` requirement. Each `traceSetId` expands through `module-trace-sets.json` to exact requirement, C03 decision, component and source-unit IDs. No implicit or conversation-derived trace is permitted.

This specification is bounded by `DEC-C03-003`, `DEC-C03-007`, `DEC-C03-010` through `DEC-C03-016`; components `pc.module.framework`, `pc.policy.lifecycle`, `LS-MODULE-REGISTRY`, `XCAP-MODULE-GOVERNANCE`, `XCAP-MIGRATION` and `XCAP-TERMINAL-DENIAL`; and trace sets `TS-MOD-MANIFEST`, `TS-MOD-LIFECYCLE`, `TS-MOD-DEPENDENCY` and `TS-MOD-OPERATIONS`.

## 2. Release and admission objects

A module version is the immutable tuple:

`(moduleId, semanticVersion, manifestSha256, releaseArtifactSha256, signingKeyId, stackLockSha256, targetProfile)`.

The C04 manifests have exact state `SPECIFIED_NOT_BUILT`. Their release-artifact, signature, SBOM, provenance and build-receipt values are therefore `null` by schema and do not claim build evidence. Admission MUST reject that state. A release pipeline may change the state only by producing all five exact values and a new immutable manifest version; it MUST NOT fill them in place in a released manifest.

Unknown manifest fields, duplicate JSON members, non-UTF-8 input, non-integer-safe numeric forms, non-canonical identifiers, a version range, a tag without a digest, or an unregistered capability MUST fail admission.

## 3. Module state machine

| State | Meaning | Admitted authority |
|---|---|---|
| `ABSENT` | No admitted version or owned state exists. | None. |
| `ADMITTED` | Schema, signature, provenance, exact profile and dependency closure pass. | None. |
| `INSTALLED_DISABLED` | Owned data/configuration and inert artifacts exist. | No runtime or UI contribution may grant or execute. |
| `ENABLING` | A prepared exact generation is being activated. | Previous active generation only. |
| `ENABLED` | One exact module generation is active. | Only its admitted, bounded contributions. |
| `DISABLING` | New use is fenced and references are draining. | Existing durable obligations only. |
| `UPGRADING` | A successor is expanded, migrated and shadowed. | Previous active generation only until atomic activation. |
| `DOWNGRADING` | An admitted predecessor is being proved capable of representing successor effects. | Current generation until atomic activation. |
| `ROLLING_BACK` | Exact prior generation activation is in progress. | Current generation until atomic activation. |
| `UNINSTALLING` | Reverse references, custody and retention are being closed. | No new use; durable obligations remain enforceable. |
| `REMOVED` | Executable/configurable contributions are absent and disposition evidence is final. | None. |
| `FAILED_FENCED` | A non-representable or ambiguous failure is isolated. | No new grant; last proven active generation or terminal denial. |

Only the operations registered as `MOD-OP-*` in `module-contract-catalog.json` may cause transitions. Each `actionIntentId` is an exact identifier in the frozen C03 AF-08 action-intent registry whose digest is pinned in the catalog; C04 defines no competing action intent. An operation MUST bind that immutable action intent, actor, Participant context, authority/delegation epochs, exact current aggregate version, target manifest digest, idempotency key, approval evidence when required, and expected transition. A stale or incomplete binding is terminal.

## 4. Common preflight

Every install, enable, disable, upgrade, downgrade, rollback and uninstall SHALL execute the following ordered gates:

1. Strictly parse and validate the closed manifest schema.
2. Verify manifest immutability, artifact digest, ES256 signature, key status, SBOM, provenance and build receipt.
3. Bind the authenticated C03 stack lock and exact target deployment profile; ranges are forbidden.
4. Resolve the frozen required-install DAG, exact providers, versions, manifest digests and capability IDs.
5. Reject cycles, missing nodes, ambiguous providers, declared conflicts and Future components satisfying R1.
6. Evaluate Platform terminal bounds, Participant envelope, assignment/delegation, scope, privacy domain and all relevant epochs.
7. Validate closed configuration, secret references, feature flags and ownership boundaries. Inline secret material is forbidden.
8. Enumerate reverse dependents, active policy releases, target generations, facts/projections, evidence, grants, UI registrations and owned data.
9. Run the production evaluator in side-effect-free simulation against immutable inputs and close every conflict.
10. Bind maker-checker and fresh WebAuthn step-up for production/high-risk mutation; maker and checker MUST be distinct principals.
11. Prepare desired state and migration evidence without activating authority.
12. Atomically revalidate versions/digests/epochs, commit desired state and outbox record, then reconcile rollout by exact generation.

Failure before step 12 has no authoritative effect and may be retried only with the same idempotency contract. An ambiguous failure at or after the commit boundary MUST reconcile; it MUST NOT blind-retry, select another provider, or report success from an unproved observation.

## 5. Operation contracts

| Operation | Permitted source | Success state | Additional binding rule |
|---|---|---|---|
| `MOD-OP-INSTALL` | `ABSENT` | `INSTALLED_DISABLED` | All predecessors installed and compatible; migrations additive/inactive; no implicit enable. |
| `MOD-OP-ENABLE` | `INSTALLED_DISABLED` | `ENABLED` | Exact prepared generation, conflict closure, simulation, approval and complete activation receipt. |
| `MOD-OP-DISABLE` | `ENABLED` | `INSTALLED_DISABLED` | Reverse dependents and durable obligations remain safe; no authority fallback. |
| `MOD-OP-UPGRADE` | `ENABLED` | `ENABLED` at successor digest | Expand/migrate/shadow/differential proof before exact-cohort activation. |
| `MOD-OP-DOWNGRADE` | `ENABLED` | `ENABLED` at predecessor digest | Allowed only when every successor effect is faithfully representable and rollback was rehearsed. |
| `MOD-OP-ROLLBACK` | `ENABLED` | `ENABLED` at admitted prior digest | Revoked/incompatible predecessor, missing evidence or non-representable effects require fencing and forward recovery. |
| `MOD-OP-UNINSTALL` | `INSTALLED_DISABLED` | `REMOVED` | Reverse references closed; archive/export/hold/delete/crypto-erasure disposition complete; sealed invariants remain. |

Disable and uninstall MUST NOT orphan active policies, invalidate required facts, discard evidence, bypass retention/legal hold, remove a provider needed by an active dependent, or erase historical identity. Referenced/evidenced objects archive and remain addressable. Cross-module table mutation is forbidden; disposition occurs through the C03-owned logical service transaction.

## 6. Migration and recovery

`MIG-GREENFIELD-V1` and `MIG-PREDECESSOR-V1` are the only admitted profiles. The latter executes M0 trace freeze, M1 additive inactive structures, M2 restartable checksummed migration, M3 shadow/differential proof, M4 exact-cohort activation and M5 predecessor retirement. At most one authority generation is active for an exact scope. Shadow never grants.

Migration steps MUST be ordered, signed, checksummed and idempotent. Reversibility is a proved property of an exact old/new pair, not a default. A failure that cannot safely return to the predecessor transitions to `FAILED_FENCED` and forward recovery.

## 7. Configuration, events and evidence

Configuration precedence is exactly: compiled safe defaults, one immutable named profile, site file, allowlisted environment variables, and secret-provider references for secret fields only. Unknown keys, duplicate sources and inline secrets fail startup. Feature flags default off and never grant.

Lifecycle events use CloudEvents 1.0.2 and the AF-08 event envelope. Per-aggregate sequence gaps block completeness. A duplicate event with the same digest is idempotent; the same event ID with a different digest is tamper. Errors use RFC 9457 and the `PC-MODULE-7000` and `PC-POLICY-2000` allocations in the contract catalog. Denial, validation, tamper and compatibility errors are not retryable.

## 8. Required negative behavior

The conformance suite MUST reject: a DAG cycle; missing dependency; incompatible version or digest; ambiguous provider; active reverse dependent; incomplete data custody; Future host as R1 authority; missing release evidence; unknown field; inline secret; unsigned migration; UI contribution outside the six slots; remote UI code; direct backend/store/provider access; automatic downgrade; permissive conflict winner; simulation that mutates state; and retry that converts denial to allow.

The 14 required scenario classes are exact IDs in each manifest and `module-contract-catalog.json`. `module-conformance-fixtures.json` binds every one of the eight negative profiles to every manifest: 264 unique cases covering cycle, missing dependency, incompatible version, digest mismatch, conflicting provider, active dependent, unclosed data custody and Future host as R1. The authoring validator verifies every fixture reference and oracle; empirical implementation execution remains a later verification/release evidence obligation and is not claimed here.
