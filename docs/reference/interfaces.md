# API contracts

This page explains where contracts live, how to read them and which caller each surface serves. Use the files from the same source revision as the deployed component.

## Contract inventory

| Contract                | Location                                                         | Purpose                                                                            |
| ----------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| HTTP control API        | [OpenAPI](../../schemas/openapi/openpc-control-api.openapi.yaml) | Same-origin administrative BFF operations, parameters, errors and response schemas |
| Events                  | [AsyncAPI](../../schemas/asyncapi/openpc-events.asyncapi.yaml)   | Event envelopes, payloads and consumer-facing contract definitions                 |
| Shared and domain types | [JSON Schemas](../../schemas/json)                               | Field validation, identifiers and domain records referenced by other contracts     |
| Service interfaces      | [Protocol Buffers](../../proto/openpc)                           | Versioned service messages and RPC definitions                                     |
| Generated TypeScript    | [Generated contracts](../../generated/typescript/README.md)      | Generated projections consumed by application code                                 |

The OpenAPI document currently declares OpenAPI 3.1.1 and API version 1.0.0. Its API version header is a separate contract field; do not derive it from a package or product version.

## Administrative authentication

The control API declares the `bffSession` security scheme with the `__Host-openpc_session` cookie. Its session contract describes an HttpOnly, Secure, SameSite=Strict cookie. The API does not return that cookie's value as ordinary response data.

Use the supported sign-in and session flow. An application workload must use its runtime's identity contract rather than copy a human administrator's cookie. Browser-facing `/api/v1/ui/...` routes and service-side control routes also have distinct integration responsibilities; do not assume their credentials are interchangeable.

Mutation endpoints can additionally require CSRF proof, an action-intent digest, a version precondition, an idempotency key or step-up authentication. Inspect the selected operation's parameter list; there is no single header recipe valid for every request.

## Shared HTTP fields

| Field                      | Meaning                                              | Caller responsibility                                                                 |
| -------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `OpenPC-API-Version`       | Explicit API contract version                        | Supply the exact supported value; the current v1 contract specifies `1`               |
| `X-Request-ID`             | Request identifier                                   | Use the required UUID format and retain it for investigation                          |
| `X-Correlation-ID`         | Correlation across related work                      | Preserve the appropriate correlation without treating it as authorization             |
| `OpenPC-Participant-ID`    | Participant context                                  | Select a context the authenticated caller is entitled to use                          |
| `OpenPC-Privacy-Domain-ID` | Privacy-domain context on operations that require it | Do not substitute another domain to bypass a denial                                   |
| `Idempotency-Key`          | Identity of a particular mutation intent             | Preserve it across supported retries of that same intent                              |
| `If-Match`                 | Expected representation digest/version               | Use the current returned ETag where the endpoint requires it                          |
| `X-CSRF-Token`             | Session- and intent-bound mutation proof             | Obtain it through the supported flow; do not fabricate or reuse it for another action |

These definitions do not imply every operation requires every field. Shared schemas specify exact patterns, lengths and requiredness. For example, an arbitrary UUID string is not necessarily a valid UUIDv7, participant URN or resource reference.

## Contract administration and review

Contract administration registers an ABI, a logical contract, its network binding, argument restrictions and a method policy. These are administrative records; creating them does not activate runtime access.

The current request and response schemas for this family are in [contract-assets.ts](../../services/control-api/src/configuration/contract-assets.ts). Proposal and approval behavior is implemented by the [governed mutation boundary](../../services/control-api/src/configuration/governed-mutation-http.ts) and [candidate review contract](../../services/module-registry/src/approval-candidate-contract.ts). OpenAPI coverage of service extensions is incomplete, so use these owning schemas for the paths below. A console BFF workflow and a service endpoint are separate integration surfaces; use the interface published by your deployment.

| Record                  | Prepare for review with `POST`                   | Submit the approved creation with `POST` |
| ----------------------- | ------------------------------------------------ | ---------------------------------------- |
| ABI artifact            | `/api/v1/abi-artifacts/proposals`                | `/api/v1/abi-artifacts`                  |
| Logical contract        | `/api/v1/logical-contract-assets/proposals`      | `/api/v1/logical-contract-assets`        |
| Network/runtime binding | `/api/v1/contract-runtime-bindings/proposals`    | `/api/v1/contract-runtime-bindings`      |
| Argument-rule version   | `/api/v1/typed-argument-rule-versions/proposals` | `/api/v1/typed-argument-rule-versions`   |
| Method policy           | `/api/v1/contract-method-policies/proposals`     | `/api/v1/contract-method-policies`       |

### Prepare and review an argument rule

1. Select an existing runtime binding and ABI artifact in the intended organization and privacy domain. Retain their resource references and the ABI digest.
2. Set the exact canonical function signature, such as `balanceOf(address)`, and choose a new rule version. The ABI must contain that function, and the rule's operand type must match its selected input.
3. Build the request using the current `ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1` action and its discovered semantic digest. Include the request's reason and the required session, scope, CSRF and idempotency fields. The current schema requires `namedSetVersions: []`; it does not accept named-set expansion here.
4. Submit the proposal. A successful proposal returns its resource reference, candidate digest and expected revision with `runtimePermission: NONE`. The proposal route does not create the rule, even when an approval and fresh verification already exist.
5. Create the approval request for that exact candidate digest. The independently authorized checker reads `GET /api/v1/approval-requests/{approvalRef}/candidate` and reviews the binding, ABI, signature, version and ordered rule values before approving. Here, `approvalRef` is the returned resource URN, not a bare UUID.
6. Complete the maker's required action verification and submit the unchanged creation request under its original idempotency key. Preserve the same body and candidate identity; changing a rule requires new review.
7. Read the returned operation and `GET /api/v1/typed-argument-rule-versions/{resourceRef}`. Confirm the resulting rule version before referencing it from a method policy. Read-only review of a consumed candidate remains historical context and grants no execution permission.

For an address equality rule, the relevant fields are `parameterPath: "inputs[0]"`, `operandType: "ADDRESS"`, `operator: "EQ"` and an array of full lower-case hexadecimal addresses in `values`. Use the owning schema for other operand types and operators. Do not use a display-formatted or abbreviated address in a request.

The candidate endpoint accepts only registered, producer-validated field families and checks the canonical candidate digest. Extra fields, incompatible rule types and mismatched operation metadata are rejected. A foreign workspace or missing read authority must not disclose the candidate. Do not work around a rejected review by reading another organization's record or querying a database directly.

A completed rule or method-policy operation is distinct from policy publication, target activation and permission to disclose an RPC result. Follow the [integration guide](../development/integration.md) for the consuming application workflow.

## Read a concrete operation

The contract defines `GET /api/v1/operations/{operationId}` as `getOperation`, a read-only operation for reconciling a durable operation by its exact identifier. It references request, correlation, API-version and participant-context headers and uses BFF session authentication.

Its successful response includes operation state and associated intent/resource information. Read the actual response schema before implementing a client; a successful HTTP read does not mean the underlying operation has completed successfully.

Related administrative paths in the same contract include:

- `/api/v1/policy-sets` and `/api/v1/policy-sets/{policySetId}/simulate`.
- `/api/v1/policy-versions`.
- `/api/v1/approval-requests/{approvalRequestId}/approve`.
- `/api/v1/release-bundles/{releaseBundleId}/publish`.
- `/api/v1/activation-occurrences/{activationOccurrenceId}/activate`.
- `/api/v1/runtime-targets/{targetId}`.

These paths are a navigation aid, not a complete workflow specification. Read each method, request schema, authorization requirement, precondition and response before using it.

### Distinguish a successful read from a completed operation

The `getOperation` example in OpenAPI returns `state: ACCEPTED` with `truthState: SUCCESS`. The status read succeeded; the underlying operation has not thereby reached `SUCCEEDED`. Keep the response's two fields separate in client models and operator displays.

The administrative [Operation schema](../../schemas/json/control-api.schema.json) defines these states:

| State             | Interpretation for the client                                                                                                     |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `ACCEPTED`        | The operation is recorded. Continue the supported status-read workflow; do not report completion.                                 |
| `RUNNING`         | Work remains in progress. Preserve the same operation reference.                                                                  |
| `SUCCEEDED`       | The administrative operation reports success. Inspect the affected resource or runtime outcome required by the workflow.          |
| `FAILED`          | A failure is recorded. Read the permitted diagnostic and recovery contract before deciding whether another action is appropriate. |
| `WRITE_AMBIGUITY` | The write outcome needs reconciliation. Do not create another intent to make the uncertainty disappear.                           |

A service health result, successful status read and completed business outcome answer different questions. For a policy change, approval, publication and target activation also have separate records. Confirm the state required by the consuming application instead of treating any one of these observations as the entire workflow.

### Keep administrative and transaction records separate

The [JSON-RPC runtime schema](../../schemas/json/jsonrpc-runtime.schema.json) defines a different `OperationStatus` record. Its `operationId` is an OpenPC URN, while the administrative `Operation.operationId` is a UUIDv7. Runtime status also carries `signedTransactionHash`, `attemptId` and `evidenceDigest`. A transaction hash is not a replacement for either operation identifier.

Runtime status states are `PREPARED`, `ATTEMPT_STARTED`, `ACCEPTED`, `REJECTED`, `WRITE_AMBIGUITY`, `CONFIRMED`, `REORG` and `FAILED`. Do not deserialize this record with the administrative state enum or map unknown states to success. Handle reorganization and the selected finality requirement explicitly. Receipt or evidence access remains subject to its own disclosure rules.

### Preserve wire representations

Shared schemas represent revisions and unsigned 64-bit values as decimal strings. Keep those strings in request, persistence and response models; converting them to a JavaScript `number` can lose precision. Where arithmetic is necessary, use an appropriate integer representation and preserve the required string encoding at the interface.

`Rfc3339MicrosUtc` requires six fractional digits and a UTC `Z` suffix. For example, `2026-08-24T00:00:00.000000Z` has that representation. A display formatter can show a friendlier time, but it must not silently change a signed or replayed request's original bytes. Likewise, hexadecimal quantities, byte strings, UUIDs and URNs have distinct schemas. Validate the selected field rather than applying one generic identifier normalizer.

For signed contracts, follow the owning canonicalization and signing specification. JSON serialization, Protobuf encoding and a display representation do not by themselves establish the required signed bytes.

## Usable authority-envelope scopes

The Participant service's [typed envelope proposal](../../services/participant-service/src/contracts/envelope.ts) separates `usable` permissions from `grantable` bounds. The current permission model projects one usable section at a time:

| Intended usable permissions | Populated section | Section that must be empty |
| --------------------------- | ----------------- | -------------------------- |
| Administration actions      | `administration`  | `runtime`                  |
| Runtime capabilities        | `runtime`         | `administration`           |

An unused section must have empty permission and dimension arrays. Dimensions include `participantIds`, `privacyDomainIds`, `resourceIds`, `dataClasses`, `targetProfileIds` and `riskClasses`. Setting `runtime.capabilityIds` to an empty array while retaining runtime participant or privacy-domain selections still produces a rejected usable scope.

Build `usable` for the intended operation and keep `grantable` within the issuer's separately checked bounds. Schema validation and approval do not establish that a scope can be projected into permissions. A change to either scope changes the candidate digest and needs the corresponding approval. Preserve and reconcile an earlier request rather than replacing its body under an existing approval or idempotency key.

## Errors and information disclosure

The control contract uses `application/problem+json` responses and structured fields such as a safe code, status, truth state and trace identifier. Interpret the endpoint's documented response rather than relying on a human-readable title alone.

Hidden and nonexistent resources are intentionally indistinguishable in relevant responses. A caller must not use a denied lookup as an inventory mechanism. Do not change application behavior to expose the distinction through logs, alternate queries or error text.

Treat conflict, stale precondition, denial and unavailability as distinct outcomes. Retry only as the endpoint permits. Preserve the original operation reference when effects may already exist.

## Collections and streams

Collection endpoints define their own pagination, sorting and filtering parameters. The shared limit schema defaults to 50 and permits values from 1 through 200 where referenced. Cursors are opaque: retain and return them as documented rather than parsing or inventing them.

Unknown or unauthorized filter fields are rejected by the contract. Do not silently omit a rejected filter and then present the broader result as if it were filtered.

For service streams, use the required durable cursor or receipt and reauthorize after reconnect. Message fields do not replace mTLS identity where the service contract requires it. Protobuf encoding is a message projection; it is not a substitute for the canonical bytes required by a signing contract.

## Change and generation workflow

Update the owning schema first, run the generation/check commands in [package.json](../../package.json), and review the resulting clients and validators together. Do not hand-edit generated files as the only implementation of a contract change.

Changing requiredness, enum closure, authority semantics or the meaning of a result can break clients even if JSON parsing still succeeds. Include compatibility analysis and negative cases in the [proposal](../development/proposals.md) and [tests](../development/testing.md).
