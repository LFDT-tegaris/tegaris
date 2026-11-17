# OpenPC dependency, provider and compatibility resolution

Status: `FINAL_C04_AF18_AF19`

## 1. Frozen graph

`module-registry.json` is the normative projection of `OPENPC-C03-MODULE-INSTALL-DAG`: exactly 33 nodes, exactly 69 `REQUIRED_INSTALL_BEFORE` edges and cycle policy `FORBIDDEN`. Each manifest dependency is a one-for-one projection of an incoming frozen edge. `TS-MOD-DEPENDENCY` resolves to the exact supporting requirements, decisions, components and source units.

The registry's `installOrder` is the sole deterministic topological order for the package. Runtime calls and UI contributions do not create installation edges. `DU-SUBQUERY` and `LS-INDEXER` are Future; neither may satisfy an R1 dependency or authority decision. `pc.indexing.dedicated-policy` declares the frozen host but excludes it from `r1AdmittedExecutionHostIds`.

## 2. Exact dependency identity

A required dependency is the tuple:

`(edgeId, providerModuleId, capabilityId, semanticVersion, providerManifestSha256)`.

All five values MUST match. A semantic version range, floating tag, preferred provider, fallback provider, unbound digest, or same-name substitution is incompatible. A provider is eligible only when its manifest declares the exact capability ID and version and its registry hash equals the dependency digest. There MUST be exactly one eligible provider.

## 3. Resolver algorithm

For one requested operation, the resolver SHALL:

1. Load the exact immutable target manifest and registry digest.
2. Validate all node and edge IDs against the frozen registry.
3. Build a capability-provider index from admitted manifest tuples only.
4. Resolve every required dependency to exactly one provider tuple.
5. Compare declared dependency edges to the frozen incoming-edge set; missing or extra edges fail.
6. Traverse the full transitive closure and reject any missing, disabled, revoked or incompatible provider.
7. Run deterministic cycle detection over the complete closure.
8. Apply explicit conflict declarations and typed policy-composition conflict detection; silence is not resolution.
9. Enforce exact platform/stack/profile compatibility and schema digest.
10. Enforce Platform/Participant/delegation/epoch/privacy bounds and the Future exclusion.
11. For disable, downgrade, rollback or uninstall, compute the active reverse-dependency closure and durable data/evidence custody closure.
12. Emit a canonical resolution record with ordered nodes, edges, provider tuples, inputs, result and failure code.

The resolver MUST produce the same canonical record for the same immutable inputs. Filesystem enumeration order, JSON member order, locale, wall-clock time, provider response order and network availability MUST NOT influence resolution.

## 4. Failure results

| Code | Condition | Result |
|---|---|---|
| `PC-MODULE-7000` | Closed-schema or manifest identity failure. | Reject before graph evaluation. |
| `PC-MODULE-7001` | Required node/capability absent or inactive. | Reject; no optional fallback. |
| `PC-MODULE-7002` | Cycle in declared or resolved closure. | Reject the complete closure. |
| `PC-MODULE-7003` | Version, schema, stack, profile or digest mismatch. | Reject as incompatible. |
| `PC-MODULE-7004` | Zero/multiple providers or conflict. | Reject; never select a silent winner. |
| `PC-MODULE-7005` | Active reverse dependent blocks mutation. | Keep current state. |
| `PC-MODULE-7006` | Data/evidence/retention custody incomplete. | Fence destructive transition. |
| `PC-MODULE-7007` | Future component offered as R1 satisfaction. | Reject and preserve Future classification. |
| `PC-MODULE-7008` | Signature, artifact, SBOM, provenance or receipt absent/invalid. | Reject admission. |

All results use non-leaking RFC 9457 problems. A caller not authorized to know a module/provider exists receives the same denial class as a hidden object and no dependency detail.

## 5. Upgrade, downgrade and rollback

An upgrade resolves both the current and proposed graphs and requires a complete compatible successor closure. Activation is atomic at an exact generation. A downgrade or rollback additionally proves every successor effect can be represented by the predecessor, the predecessor is admitted and unrevoked, and the exact path was rehearsed. Otherwise the active generation is fenced and forward recovery is required.

Provider or dependency removal is forbidden while any active reverse dependent exists. Disabling a provider cannot turn its consumers into a permissive, default or alternate-provider mode.

## 6. Six UI slots

The only registered slots are `UISLOT-NAV-PRIMARY`, `UISLOT-ROUTE-CONTENT`, `UISLOT-OBJECT-ACTION`, `UISLOT-DETAIL-PANEL`, `UISLOT-DASHBOARD-CARD` and `UISLOT-SETTINGS-SECTION`. C04 module manifests declare no C03-owned UI placement and therefore contain exact empty contributions with reason `NO_C03_UI_CONTRIBUTION_OWNERSHIP_ASSIGNED`. A later UI-owned contribution must bind a signed manifest, exact slot/capability, deterministic order, resource budget, accessibility tests and shell ownership; it cannot alter dependency resolution or authority.

## 7. Ownership preservation

Manifest `declaredExecutionHostIds` are copied from the C03 component registry. Physical store ownership remains with C03 logical services; every module declares an isolated data namespace and zero physical stores owned. The resolver cannot infer ownership from co-location and cannot create a new service, store, deployable or boundary.

