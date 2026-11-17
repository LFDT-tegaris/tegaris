# Propose a change

Use a proposal when a change affects public interfaces, authorization, privacy, storage or deployment. Small bug fixes and documentation corrections usually need only an issue or pull request.

Open a proposal issue in [LFDT-tegaris/tegaris](https://github.com/LFDT-tegaris/tegaris/issues). Describe the user task first. Include enough detail for another contributor to challenge the design or implement it without a private briefing.

## Proposal outline

1. **Problem:** Who is affected, what are they trying to do and what fails today?
2. **Expected behavior:** Give a concrete example, including a rejected request when relevant.
3. **Scope:** Identify the affected interfaces and components. State what the change leaves for later.
4. **Design:** Explain the data flow, durable state and authorization checks. Describe recovery after a timeout or restart.
5. **Compatibility:** Cover existing clients, stored data, migration and rollback.
6. **Alternatives:** Explain the other approaches considered and the tradeoff behind the choice.
7. **Verification:** List the outcomes that prove the change works, including failure and privacy cases.
8. **Documentation:** Identify the setup, API, user or release guidance that needs to change.

Do not put credentials, customer records or private deployment details in an issue. Report a suspected vulnerability through [SECURITY.md](../../SECURITY.md).

## Decision and implementation

Record unresolved questions in the issue. Once reviewers agree on the approach, summarize the decision and link the implementation pull requests. Update the proposal if the implementation changes its scope. Merging a proposal does not mean the feature has shipped.

## Make acceptance criteria falsifiable

Describe observable results rather than implementation activity. For example, a proposal to improve operation recovery should state how a caller identifies the original operation after a lost response, what durable state is returned, and how a second effect is prevented. Adding a retry button is an implementation detail, not the acceptance criterion.

For authorization or disclosure changes, include an allowed actor, a denied actor and an actor from another organization. State which information and effects must remain unavailable. For persistence changes, include populated state and interruption/restart behavior.

Use this table in a proposal when it helps reviewers:

| Scenario             | Preconditions/input                   | Expected result                    | Forbidden effect                     | Evidence                        |
| -------------------- | ------------------------------------- | ---------------------------------- | ------------------------------------ | ------------------------------- |
| Authorized request   | Named actor, scope and version        | Specific permitted result          | Unrelated resource change            | Test and authoritative readback |
| Unauthorized request | Explicitly insufficient authority     | Safe denial                        | Protected disclosure or mutation     | Negative test                   |
| Lost response        | Original operation may have completed | Reconciled original outcome        | Duplicate business effect            | Recovery test                   |
| Stale selection      | Version changes before submission     | Conflict or supported refresh path | Applying a different intent silently | Concurrency test                |

## Review operational consequences

Explain resource impact, migration ownership, certificate/credential implications and observability. Identify whether the change needs an outage, a new trust relationship or a different recovery procedure. Include a rollback or forward-recovery approach that respects already-applied migrations and completed effects.

For a bank-facing integration, document the boundary with institutional identity, custody, networks and evidence systems. Do not claim compatibility with a provider or deployment until the named configuration is tested.

## Changes to signed formats

Identify the owning definition before changing a receipt, profile or signing context. Record its schema identifier, version, purpose, definition digest, producer, verifier and generated registry entries in the proposal. Use synthetic examples; keep deployment keys and private operating records out of the discussion.

The [control definition digest](../../packages/security-kernel/src/business-transition/definition.ts) covers the full definition except its top-level `definitionDigest` and `signature` fields. This includes descriptive authority rules. The [profile generators](../../packages/security-kernel/scripts/generate-business-transition.mjs) compare the derived identity with the registered allocation and reject conflicting or stale definitions. Rewording such a definition is a compatibility change even if its field layout is unchanged.

| Proposed edit                                              | Compatibility question                                                   | Required treatment                                                                                                |
| ---------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Console label or explanatory guide                         | Is the text outside the signed object and its canonical preimage?        | Preserve stored identifiers and signed bytes; check the affected presentation.                                    |
| Field, authority rule, purpose or other definition content | Does the definition digest or signature context change?                  | Propose a new version or transition through the owning contract process.                                          |
| Generated profile or registry                              | Does it match its owning definition and allocated version?               | Regenerate through the existing owner and check the result; do not edit generated digests to suppress a conflict. |
| Previously signed record or applied migration              | Would the edit change historical identity or an already consumed effect? | Preserve the original and design an explicit compatible forward transition.                                       |

A signed-format proposal should cover these cases:

1. The producer and verifier agree on the canonical definition, payload types, purpose and additional authenticated data. Include each affected language implementation.
2. Existing records retain their original bytes, digest, signer reference and supported historical verification path after upgrade or restart.
3. The verifier rejects purpose, version, key and context substitutions. The consuming owner separately rejects records from another tenant or unauthorized scope.
4. Malformed, duplicate, noncanonical or unexpected fields are rejected through the relevant parser and verifier owners.
5. Historical integrity does not grant current authority. Expired, revoked or replaced authority still blocks a new operation where required.
6. Installation, rollout and rollback preserve both the old verification material and the new version's explicit admission requirements.

Run the owning generation check before broader tests. For the security-kernel definitions, the supported project wrapper is:

```sh
bash scripts/maintenance/run-project.sh -- \
  pnpm --filter @openpc/security-kernel run generate:check
```

This checks definition-to-generated-output consistency. It does not establish issuer trust, authorization, current validity, an executed business effect or complete release qualification. Follow the [testing guide](testing.md) for the affected runtime, database, cross-language and browser checks.

## Decision record

When the discussion reaches a decision, record the accepted scope, alternatives rejected and their reasons, unresolved conditions, implementation owner, reviewers and required validation. Use ordinary project terms; omit private planning history and internal dispatch records.

If implementation changes the authority model or public contract, return that change to review. A prior approval of a different design is not approval of the revised behavior. Link the eventual release notes so readers can distinguish an accepted proposal from a shipped capability.
