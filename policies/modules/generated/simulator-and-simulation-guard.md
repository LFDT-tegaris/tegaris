# OpenPC simulator and simulation-guard specification

Status: `FINAL_C04_AF19`

## 1. Single-evaluator rule

Simulation MUST invoke the same versioned evaluator, type registry, normalization, composition, conflict and visibility code used for production decisions. A separate permissive simulator, simplified policy interpreter, mocked allow path or result translation is forbidden. Trace authority is `TS-MOD-SIMULATION`; owning components are `pc.policy.simulation-guard` and `LS-SIMULATOR` under the C03 graph.

## 2. Immutable input binding

A `SIMULATION-REQUEST` SHALL bind:

- scenario and request IDs;
- actor, workload, wallet and exactly one Participant context;
- action intent, scope and privacy domain;
- Platform, Participant, assignment, delegation and credential epochs;
- immutable policy version/release and target-generation digests;
- exact module manifests and stack profile;
- fact/checkpoint/provider generations and completeness windows;
- chain, route and canonical resource identifiers;
- disclosure capability for every requested output component.

Missing, stale, unavailable, conflicting, tampered, partial or incompatible required input produces the corresponding non-allow result. The simulator does not substitute defaults or fetch a synchronous external authority answer.

## 3. Side-effect boundary

Simulation is read-only and side-effect free. It MUST NOT create or mutate a draft, release, assignment, delegation, grant, approval, action intent, target generation, provider route, transaction, evidence custody record or runtime activation. It MUST NOT submit, broadcast, activate, enable, install or acknowledge live authority. `pc.policy.simulation-guard` enforces this separation even if a caller has a separate live-operation capability.

Raw preflight, trace, state-diff, fact, evidence and payload output requires independent disclosure permission. Absent permission, output is reduced to the authorized component-level result and stable non-leaking explanation. Predictive output is never presented as an execution receipt, authorization grant, certification or external compatibility claim.

## 4. Evaluation result

A `SIMULATION-RESULT` contains the exact bound input digest, evaluator/profile versions, truth state, per-layer contribution, terminal-denial source, conflicts, obligations, completeness evidence, freshness, explanation codes and result digest. It clearly labels `SIMULATION_ONLY`. The result expires when any bound version, epoch, fact generation, route/anchor or compatibility profile changes.

## 5. Scenario obligations

The exact conformance set includes positive, negative, unknown, stale, unavailable, tampered, partial, conflict, reorg, replay, rollback, recovery, retirement and uninstall scenarios. Additional required negatives are:

- simulation result presented as an approval or grant;
- spoofed estimate/preflight result;
- wrong Participant or privacy domain;
- broader delegated authority than the live envelope;
- stale policy/fact/authority epoch;
- hidden existence/payload requested without disclosure;
- missing exact module/provider/profile digest;
- reorg that invalidates a pinned fact window;
- mutation or network egress from evaluator code;
- activation attempted directly from a simulation result.

All negatives fail closed and emit non-authoritative privacy-safe evidence. `policy.simulation_case_limit` is a closed non-secret `uint32` from 1 through 10000; exceeding it rejects the request and does not truncate silently.

## 6. Activation guard

An activation may reference a simulation result only when its complete immutable input digest equals the activation candidate digest and every dependency remains current. It still requires its own action intent, maker-checker, fresh step-up, exact cohort preparation and atomic activation. Simulation cannot satisfy or waive any of those gates.

