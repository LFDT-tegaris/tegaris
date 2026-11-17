# OpenPC policy lifecycle, composition and conflict specification

Status: `FINAL_C04_AF19`

## 1. Contract and trace

The normative machine objects are the `POL-*` types, states, operations, errors, events, configuration, migrations and tests in `module-contract-catalog.json`. Each carries `TS-MOD-POLICY`, which expands in `module-trace-sets.json` to stable requirement, decision, component and source-unit IDs. This document does not create another policy evaluator or authority source.

## 2. Immutable lifecycle

1. `EDITABLE_DRAFT` is mutable, non-authoritative and cannot be compiled for active use.
2. `POL-OP-CREATE-VERSION` normalizes a draft and creates an immutable policy version bound to its schema, module versions, dependencies, facts, envelopes and digest.
3. A version enters `PENDING_APPROVAL`; approval binds the exact candidate/action digest, maker, checker, fresh step-up and expiry. Maker and checker MUST differ.
4. `POL-OP-RELEASE` creates an immutable release. Editing creates a new version; it never mutates a release.
5. Compilation creates an exact target generation through `DESIRED` and `PREPARED`. Preparation, shadow and simulation do not grant.
6. `POL-OP-ACTIVATE` revalidates all bound versions/epochs and atomically makes one exact generation `ACTIVE` for a scope.
7. A previous generation becomes `RETIRED` only after activation evidence and convergence. At most one authority generation is active per exact scope.

A stale dependency, incomplete checkpoint, unresolved conflict, missing simulation, invalid approval, partial fleet release, incompatible runtime profile, or unproved artifact leaves the candidate non-active.

## 3. Composition input

Every contribution declares a closed input/output type, module/version/digest, policy family, applicability predicate, scope, effect, obligations, explanation code and constrained priority. Inputs bind the Platform context, one Participant, privacy domain, action intent, actor/workload/wallet, authority/delegation epochs, policy/fact generations and exact request resource.

Unknown, unavailable, stale, conflicting, tampered, partial or incompatible required input cannot produce `ALLOW`. `AUTHORIZED_EMPTY` is permitted only with exact selector/window completeness evidence and is distinct from every denial/failure state.

## 4. Deterministic evaluator

The evaluator SHALL apply these layers in order:

1. Platform terminal deny and emergency bounds.
2. Participant authority-envelope upper bound.
3. Active assignment and downward delegation intersection.
4. Scope, epoch, privacy, actor/workload/wallet and action-intent bounds.
5. Typed module contributions grouped by policy family.
6. Native/runtime denial.
7. Independent existence, metadata, payload, evidence and export visibility decisions.

Within one non-terminal peer group, `priority` is an integer from 0 through 1000 and is ordered ascending, then by module ID, semantic version and manifest digest. Priority controls deterministic evaluation/explanation order only. It MUST NOT override a Platform bound, Participant envelope, narrower delegation, scope/epoch/privacy bound, explicit deny, missing required input or incompatible type. Final permission is the intersection of all required contributions; retry, fallback or reordering cannot convert denial to allow.

## 5. Conflict detection

The composer MUST detect and report:

- incompatible input/output types or schema digests;
- overlapping applicability with contradictory effects or obligations;
- duplicate provider/capability identity;
- incomparable priority claims across different terminal layers;
- broader delegation or Participant contribution;
- stale or mixed policy/fact/authority generations;
- different privacy/existence/payload rules for the same canonical selector;
- an unsupported rulebook/template presented as enforced semantics;
- missing bridge semantics or an attempted Future dependency.

No conflict has a permissive or last-writer winner. A typed, authorized resolution creates a new immutable version; it does not edit either conflicting release. Until resolution, activation is blocked and evaluation is terminal denial or the precise non-allow truth state.

## 6. Policy versioning and rollback

Every compilation, release, activation, retirement and rollback binds exact module manifests, schema digests, facts, Participant envelope, delegation/authority epochs, target profile and PC-CBOR-1 semantic digest. A rollback target must be admitted, unrevoked, compatible and able to represent every successor effect. Otherwise the system fences and forward-recovers.

Policy deletion cannot remove evidence, referenced versions or obligations. Retired releases remain immutable and addressable. Uninstall of a contributing module is blocked until policy/reference closure is complete.

## 7. Events, errors and configuration

Policy events are the exact `openpc.policy.*.v1` records in the contract catalog and use the AF-08 CloudEvents envelope. Errors occupy `PC-POLICY-2000` through `PC-POLICY-2005`, are non-retryable unless a separate operation contract explicitly proves safe reconciliation, and never expose hidden resources.

`approval.default_expiry` is a non-secret duration restricted to `PT5M..P30D`. It follows the C03 closed configuration precedence. It cannot modify policy meaning, terminal bounds or algorithm selection.

## 8. Required negatives

Conformance MUST prove that broadening by priority, incomplete maker-checker, stale epoch, mixed generation, missing fact, unavailable dependency, invalid schema, non-canonical bytes, conflicting transforms, Future substitution, simulation-only input, rollback to revoked state and hidden-resource probing all fail without partial authority.

