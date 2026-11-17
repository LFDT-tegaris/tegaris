# Delegated Participant policy governance

Status: `FINAL_C04_AF19`

## 1. Authority boundary

Participant administration is not runtime permission. A Participant envelope is a signed typed upper bound; assignments, groups, roles, delegated administration and policy releases operate only within its current version and epoch. `TS-MOD-PARTICIPANT` binds this specification to `pc.participant.governance`, `pc.identity`, `LS-PARTICIPANT`, `XCAP-AUTHORITY-INTERSECTION` and exact source-unit evidence.

Effective usable authority is:

`Platform bounds ∩ Participant envelope ∩ active assignment ∩ active delegation ∩ action/scope/privacy/epoch bounds ∩ policy contributions ∩ native/runtime denial`.

Every term is required. Denial is terminal and monotonic.

## 2. Governance objects

- A Participant has one monotonic Participant epoch, custody state and active envelope reference.
- An envelope version is immutable after submission and carries typed module-owned slices.
- An assignment binds one eligible subject or direct-only group to one role, Participant, bounded scope and time.
- A delegation binds grantor, grantee, parent, grantable authority, usable authority, purpose, expiry and delegation epoch.
- A role is a reusable Participant-local administrative capability set; archival prevents new assignment and invalidates authority by epoch.
- A policy release binds the exact Participant/envelope/delegation versions used at approval and activation.

Email equality, provider group membership, wallet possession, SCIM presence, UI state or co-location MUST NOT merge identities or grant authority.

## 3. Downward delegation

A child delegation MUST be a strict or equal narrowing on every dimension that the parent explicitly permits to be re-delegated, and MUST be a strict narrowing on at least one dimension. It cannot extend expiry, Participant set, privacy domain, action classes, resource scope, data classes, target profiles, grantable authority or usable authority. Incomparable sets fail. `grantable` and `usable` remain distinct; a grantee cannot re-delegate merely because it can use an action.

Issuance binds the current Platform, Participant, envelope, assignment and delegation epochs, exact parent digest, purpose, action intent and maker-checker evidence. Revocation or narrowing advances the owning epoch and invalidates stale sessions, releases and compiled generations without a permissive grace fallback.

## 4. Policy governance operations

Participant policy authors may create drafts within the envelope. Approvers may approve only exact immutable candidate digests for which they are separately authorized and not the maker. Activation additionally requires simulation, conflict closure, exact dependencies, current epochs and complete fleet preparation. Transfer, shrink, disable, rollback and uninstall are deny-first and evidence-bound.

An administrative capability cannot be compiled into runtime permission. A module cannot expand an envelope, create a parallel delegation primitive, treat provider attributes as authority, or use priority to overcome a narrower bound.

## 5. Negative behavior

The system SHALL reject cross-Participant assignment, multiple ordinary Participant contexts, self-approval, circular delegation, parentless delegated re-grant, broader/incomparable child scope, expired delegation, stale epoch, archived role, hidden-resource enumeration, partial transfer, and disable/uninstall that orphans active authority or evidence.

On missing/unknown/unavailable/conflicting/tampered inputs, the result is a non-allow truth state with no existence or payload leak. Recovery and break-glass use the separate identity recovery contract; they cannot bypass Platform terminal denial, Participant envelope or visibility denial.

