# Integrate an application

Start with one business operation and define which data the caller may receive. To connect it to Tegaris, prepare a workload identity, scoped permissions, an active policy and a governed runtime endpoint. Plan how the application will reconcile a write when its response is lost.

This guide covers the integration sequence and caller responsibilities. Check the selected release's [support limits](../releases/README.md), identity and custody options, and network requirements before implementation. Use contracts from the same revision as the deployed runtime.

## Separate the integration surfaces

| Surface                                    | Intended caller                                                                  | Use                                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Administration console and its control API | Authenticated human administrator or reviewer through the supported session flow | Configure identities, contracts, policies, reviews and releases          |
| Governed application endpoint              | Admitted workload using the selected runtime's authentication contract           | Submit permitted application reads and writes                            |
| Service-to-service interfaces              | Authenticated services with the specified transport identity and metadata        | Internal coordination between deployed components                        |
| Event and evidence interfaces              | Authorized consumers within the relevant scope                                   | Observe permitted outcomes, reconcile progress and investigate decisions |

Do not turn a console session cookie into a service credential. The [Control API schema](../../schemas/openapi/openpc-control-api.openapi.yaml) is a same-origin BFF session contract; it is not a universal bearer-token API for bank applications. Select the runtime/workload contract appropriate to the intended application path.

## Step 1: define a narrow integration case

Use a synthetic contract and two independent test organizations. For example, one organization may read selected fields of a payment-instruction record while another is denied that record. The example should contain fabricated identifiers and values, with no real customer data or funds.

Record:

- The caller's organization, workload and required role.
- The contract, network, method and relevant argument constraints.
- The data that may be returned, including receipt and event visibility.
- The decision inputs required by the policy and their freshness assumptions.
- The expected denial for an unauthorized or foreign-organization caller.
- The durable reference used to investigate an uncertain write.

Agree on the expected result before implementation. A successful HTTP response alone is insufficient evidence of correct disclosure or execution.

## Step 2: admit identity and credentials

Register the workload under the correct organization using the supported administration workflow. Bind credentials and wallets through their owning services, then verify the effective authority. A registered credential and an active permission grant are different records.

Keep signing keys in the application's wallet or custody provider. Store application credentials using the institution's chosen secret-management process. Development account passwords and local signing fixtures are unsuitable for production deployment.

Test an expired credential and a revoked grant independently. A failure caused by expiry does not demonstrate that live revocation is enforced. Request-body identifiers must never be accepted as replacements for authenticated identity.

## Step 3: configure the governed resource

Confirm the modules required by the selected application path, including their full dependency closure. Each required module must have a current enabled binding in the same privacy workspace. Use the [module operations guide](../operations/modules.md) for the publisher handoff and governed registration, installation and activation. A checked-in manifest, registered release or healthy service is insufficient evidence of an enabled runtime binding.

Retain the exact manifest and configuration identities supplied by the owning service. If bindings are missing, resolve that setup before preparing a policy version. Module activation does not admit workload credentials or grant their authority; verify those independently as described in Step 2.

Register the contract definition and canonical ABI, establish its network/runtime binding, and select the operations the workload needs. Confirm that a contract address belongs to the intended chain and binding; an address string alone is not a complete resource identity.

Define the smallest useful policy. Include argument restrictions and disclosure rules where applicable. Test both allowed and denied inputs before requesting approval. See the [console workflow](../user-guide/README.md).

## Step 4: review, publish and observe activation

An authorized reviewer must evaluate the selected policy version and its effect. After approval, publish the intended release and inspect the target's activation state. Retain the version and release identifiers used for the evaluation.

Do not begin an application acceptance test against an unconfirmed target and then attribute its behavior to the new policy. A target may still be enforcing an earlier version, or its state may be unavailable.

### Check the activation prerequisites

Complete the runtime configuration before requesting short-lived approval. Check the following records in the same participant and privacy workspace:

| Prerequisite           | Required evidence                                                                                                                                                                                            |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Workload identity      | The intended application principal and credential are active; the certificate, audience and runtime binding match the target.                                                                                |
| Runtime discovery      | The target is currently available through its required authenticated discovery connection. Retain its current revision and predecessor generation.                                                           |
| Provider               | Exactly one selected provider is `QUALIFIED` or `ACTIVE`. Its current conformance observation is unexpired and matches the selected configuration, provider fingerprint and revision.                        |
| Indexer and projection | The selected indexer is `QUALIFIED` or `ACTIVE`; its projection is `VALIDATED` or `RUNNING` with readiness `READY`. The activation cohort requires these records even when the policy has no required facts. |
| Policy and release     | The intended release is `PUBLISHED`, with the expected immutable policy, artifact and dependency identities.                                                                                                 |
| Current approval       | Approval and authenticator proof cover the exact activation intent and remain valid when that intent is consumed. Historical publication approval alone does not establish current activation authority.     |

Read the release's activation preview before creating the occurrence. Check every target and the reported cohort totals. After requesting activation, retain both the occurrence reference and operation reference. Follow their supported readback routes; an accepted response establishes that the service accepted the request, not that a target installed the policy.

### Separate publication, installation and application behavior

Use these observations together when qualifying the integration:

| Observation                             | What to verify next                                                                                                        |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Release is `PUBLISHED`                  | Confirm the intended activation occurrence and exact target cohort.                                                        |
| Occurrence is `REQUESTED` or `STAGING`  | Inspect its original operation and target work. Application execution remains unconfirmed.                                 |
| Occurrence is `ACTIVE_MATCHED`          | Confirm that every intended target reports the installed runtime generation and selected policy generation.                |
| Target reports the expected generations | Authenticate the actual application and submit a permitted request through the governed endpoint.                          |
| Permitted request succeeds              | Submit a valid request outside that application's grant and confirm an explicit policy denial without a successful result. |

The policy generation identifies compiled policy semantics. The runtime configuration generation identifies the installed combination of policy, provider, projection and target. Record both; they are different digests and should not be compared for equality.

### Handle expiry or a changed target before execution

If approval expires during preparation, preserve the published release and original approval record. Request the activation occurrence's current renewal preview and use its supported proposal, independent approval and execution workflow. The preview binds the current root authority, configuration, provider observation and target revisions. Review that complete candidate before approving it; do not reconstruct current values from an older screenshot or request.

A connection refresh can change a target revision without installing a generation. For an untouched initial activation, the supported fresh-approval workflow checks whether that change is eligible and binds the current revision while retaining the original occurrence snapshot. Another change after approval makes that approved source stale. Obtain current readback before deciding whether a new proposal is appropriate.

This initial path does not settle partially dispatched or uncertain work. If work exists, preserve its operation, signed observations and prior effects, and use the owning service's reconciliation workflow. Do not delete the workspace, change policy content, replace credentials or choose another request key to escape a denied or uncertain operation. For certificate expiry and normal renewal, follow the [identity lifecycle guide](../operations/certificates.md).

## Step 5: construct requests from the selected contract

Use machine-readable schemas from the same revision as the runtime. Validate required fields, formats, versions and enums before sending a request, while retaining server-side checks as authoritative.

For JSON-RPC integrations, the familiar JSON-RPC body is only one part of the request. This example illustrates a body shape, not a complete authorized invocation:

```json
{
  "jsonrpc": "2.0",
  "id": "receipt-evaluation-1",
  "method": "eth_getTransactionReceipt",
  "params": ["0x1111111111111111111111111111111111111111111111111111111111111111"]
}
```

The transaction hash is synthetic. Replace it with a transaction from the intended test network that the workload is entitled to inspect. The selected policy must permit the method, and the receipt must pass the applicable disclosure checks. Supply the required transport authentication and invocation context using the selected runtime's contract. Do not invent headers or bypass the governed endpoint when a request is denied.

### Workload authentication in the local runtime

The local runtime uses a client certificate to authenticate the workload to Identity, then carries the returned signed assertion to the governed endpoint. This is separate from console sign-in. The sequence below describes the implemented local development adapter; it is not a promise that another deployment exposes the same Identity listener.

Before trying it, obtain these values from the operator of your isolated workspace:

| Input                             | Required value                                                                                    |
| --------------------------------- | ------------------------------------------------------------------------------------------------- |
| Identity origin                   | The HTTPS origin of the workload mTLS listener, with a certificate matching its hostname          |
| Governed endpoint                 | The complete HTTPS runtime URL, including its configured path                                     |
| Trust certificates                | The CA files used to verify each server; these may differ                                         |
| Workload certificate and key      | The credential admitted for this application, accessible through its approved custody arrangement |
| Privacy domain and runtime target | The exact UUIDv7 identifiers for the authorized context and admitted target                       |
| Policy and activation             | A current target configuration permitting the method and inputs being tested                      |

Do not use the console hostname as a guessed workload-authentication endpoint. The local adapter's listener must already be configured and reachable from the application network.

#### 1. Request a runtime-bound assertion

Send `POST /internal/v1/workload/authenticate` over mutually authenticated TLS 1.3. The server derives workload identity from the verified client certificate. The request selects the runtime context; it does not supply a principal or grant authority.

```json
{
  "runtimeContext": {
    "privacyDomainId": "018f0000-0000-7000-8000-000000000201",
    "targetRuntimeId": "018f0000-0000-7000-8000-000000000301"
  }
}
```

These identifiers illustrate the shape. Substitute the identifiers returned by your own workspace. Both fields are required when `runtimeContext` is present, and additional fields are rejected. Runtime requests need the runtime-bound assertion; a successful identity response without that assertion is insufficient.

For a command-line evaluation, place that JSON in a private `runtime-context.json` file and set the following variables to the operator-provided values. The certificate variables name files, not their contents:

```sh
umask 077
curl --silent --show-error --fail-with-body \
  --tlsv1.3 --tls-max 1.3 \
  --cacert "$TEGARIS_IDENTITY_CA" \
  --cert "$TEGARIS_WORKLOAD_CERT" \
  --key "$TEGARIS_WORKLOAD_KEY" \
  --header 'Content-Type: application/json' \
  --data-binary @runtime-context.json \
  --output workload-authentication.private.json \
  "$TEGARIS_IDENTITY_ORIGIN/internal/v1/workload/authenticate"
```

Continue only after a successful HTTP response containing `runtime.assertionCoseSign1`. The local adapter returns `400` with `PC-IDENTITY-1006` for a JSON request that fails its schema, and `401` with that code when workload authentication fails. Invalid JSON syntax, unsupported content types and body-size limits can be rejected earlier by the HTTP framework with a different response. A TLS failure occurs before the HTTP handler; inspect certificate validity, trust, hostname and credential admission separately.

#### 2. Encode the assertion for the runtime header

Identity returns `runtime.assertionCoseSign1` as base64. The local runtime request header carries the same bytes as hexadecimal. Convert the bytes, rather than hex-encoding the base64 text:

```sh
node --input-type=module <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';

const response = JSON.parse(readFileSync('workload-authentication.private.json', 'utf8'));
const assertion = response.runtime?.assertionCoseSign1;
if (typeof assertion !== 'string' || assertion.length === 0) {
  throw new Error('Identity did not return a runtime-bound assertion.');
}
const hex = Buffer.from(assertion, 'base64').toString('hex');
if (hex.length === 0) throw new Error('The runtime assertion is empty.');
writeFileSync('runtime-header.private.txt', `x-openpc-identity-assertion: ${hex}\n`, {
  mode: 0o600,
  flag: 'wx',
});
JS
```

The exclusive file creation prevents silently replacing a previous attempt's header. Keep these files in a private working directory outside the checkout. Assertions are authentication material: do not print them in diagnostic logs or attach them to an issue.

#### 3. Submit one governed read

Save the JSON-RPC body being tested in `rpc-request.json`. For the receipt example above, use the actual transaction hash returned by the test workflow and confirm its method and disclosure prerequisites. A contract read additionally needs the permitted contract, canonical calldata and block selector.

```sh
curl --silent --show-error \
  --tlsv1.3 --tls-max 1.3 \
  --cacert "$TEGARIS_RPC_CA" \
  --cert "$TEGARIS_WORKLOAD_CERT" \
  --key "$TEGARIS_WORKLOAD_KEY" \
  --header 'Content-Type: application/json' \
  --header @runtime-header.private.txt \
  --data-binary @rpc-request.json \
  --output rpc-response.private.json \
  --write-out 'HTTP %{http_code}\n' \
  "$TEGARIS_RPC_URL"
```

The header file keeps the assertion out of the command's argument list. Inspect both the HTTP status and JSON-RPC body. A JSON-RPC error is not a successful application result merely because a connection completed. Conversely, an HTTP error can still contain the permitted structured diagnostic that explains the decision.

Obtain a fresh runtime-bound assertion immediately before use through the supported identity flow. Authentication does not create new permissions. Retain the original request and response when investigating an uncertain write; this read example does not define a transaction retry or signing procedure. The [local runtime evidence fixture](../../tests/integration/local-runtime/evidence-rpc-runtime.mjs) shows the implemented handshake and checks allowed and denied requests. Running these snippets alone does not execute that fixture's full recovery scenarios.

## Step 6: interpret outcomes explicitly

| Observation                              | Application behavior                                                     |
| ---------------------------------------- | ------------------------------------------------------------------------ |
| Permitted read with data                 | Consume only the returned authorized projection                          |
| Permitted empty result                   | Preserve its meaning; do not assume a hidden record is absent            |
| Denial                                   | Retain the safe error and stop the unauthorized action                   |
| Required input unavailable               | Treat the decision as unavailable; do not substitute a permissive policy |
| Configuration conflict or stale revision | Re-read and reassess the intended change                                 |
| Write accepted but final outcome unknown | Track the original operation and reconcile before resubmitting           |
| Rate or capacity response                | Follow the endpoint's retry contract and bounded backoff                 |

Execution permission and disclosure permission are separate. A transaction accepted for submission does not grant the caller unrestricted access to its receipt, related records or events. A chain inclusion observation also does not automatically establish the finality required by an application workflow.

## Idempotency and uncertain writes

Create an idempotency key for one intended mutation where the API requires it. Retain the request's canonical intent and returned operation reference. Reusing a key with different content is a conflict; using a different key after a timeout may submit another operation.

After a lost response, query the original outcome through the authorized read path. Distinguish not found, not visible, pending, failed and unavailable using the actual contract. Do not equate absence of a visible response with proof that nothing happened.

## Events and reconnection

Use the [event contracts](../../schemas/asyncapi/openpc-events.asyncapi.yaml) for envelope and payload requirements. Keep the durable cursor or receipt required by the selected interface. Reauthorize when reconnecting; a transport connection or previous subscription is not perpetual access.

Test duplicate delivery, ordering changes, reconnect after interruption, revocation while disconnected and chain reorganization where relevant. Do not reconstruct confidential payloads from metadata that the caller is not entitled to combine or disclose.

## Build the application adapter

Keep transport authentication, business intent, response interpretation and reconciliation explicit in the application's integration layer. This structure is implementation guidance, not a supplied SDK or an additional API contract.

### Bind configuration to one environment

Resolve the intended endpoint, expected peer identity, organization/privacy context, workload credential reference and contract/runtime version together. Keep the credential material in the approved secret store rather than the application configuration file. A hostname or request-body organization identifier does not establish authenticated authority.

Test with at least two independently authorized scopes. A connection pool or shared client must not carry one caller's context into another request. Include concurrent requests from both scopes in the test; a sequential happy path can miss context reuse. When credentials or selected context change, invalidate dependent cached results and in-flight responses before showing them to the next caller.

### Persist the identity of an intended write

Before sending a governed mutation, retain enough protected application state to identify the same intent after a process restart. Depending on the selected contract, that record includes:

| Item                                         | Why the application needs it                                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Application business reference               | Associates the technical operation with the institution's workflow. It does not grant authority. |
| Authenticated scope and selected environment | Prevents recovery against the wrong organization, privacy context or deployment.                 |
| Exact action, resource and precondition      | Identifies what the caller intended to change and the version it reviewed.                       |
| Idempotency key and canonical intent binding | Distinguishes a retry of the same request from a different mutation.                             |
| Returned operation and attempt references    | Supports authorized readback and investigation of the original work.                             |
| Last authoritative observation and its time  | Keeps an unavailable status read from overwriting a known outcome with an invented result.       |

These records can contain sensitive business data. Apply the institution's access and retention controls; publish only a synthetic reproduction when contributing a bug report. Correlation identifiers and safe error codes usually belong in routine diagnostics. Credentials, session cookies, private keys and confidential request bodies do not.

### Separate submission from reconciliation

Treat a transport timeout as an uncertain observation. Reconcile using the exact original operation or other durable lookup defined by the endpoint. An administrative operation UUID, runtime operation URN, attempt identifier and transaction hash have different purposes; keep distinct fields for them. The [interface guide](../reference/interfaces.md#keep-administrative-and-transaction-records-separate) explains their schema differences.

If the initial response was lost before the application learned the operation identifier, use only the endpoint's documented same-intent recovery or retry mechanism. Do not invent an idempotency-key lookup route, broaden a search across organizations or generate another key merely to obtain a new response. If the interface provides no safe way to determine the result, retain an unresolved state for operator investigation.

Bound status polling according to the deployment's capacity and the endpoint's contract. Expiry of a client-side polling deadline means observation has stopped; it does not cancel or fail the server-side operation. Resume readback of the same operation after reconnect or restart.

### Keep errors actionable without widening access

| Result                                  | Adapter behavior                                                                                                                    |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Authentication failure                  | Recover the supported session or workload authentication, then re-read the original state before any uncertain mutation is retried. |
| Authorization denial or hidden resource | Preserve the safe result. Do not probe alternate organizations, endpoints or identifiers to disclose the hidden record.             |
| Conflict or stale precondition          | Read the permitted current representation and return the changed assumptions for review. Do not silently replace the precondition.  |
| Rate limit                              | Follow the documented rate-limit fields and use bounded retry behavior for eligible requests.                                       |
| Service or transport unavailable        | Keep the last known observation and show that freshness is unavailable. An uncertain submitted write still needs reconciliation.    |
| Unrecognized state or invalid response  | Stop automatic progression, retain a redacted diagnostic and investigate the version/contract mismatch.                             |

Use the chosen interface's actual status and error schema when implementing this table. Administrative HTTP problems, JSON-RPC errors and service RPC errors are different encodings; a generic HTTP-only interceptor cannot interpret every surface correctly.

## Verify the institutional boundary

Exercise failures at the boundaries the application actually uses. For a synthetic governed write, interrupt the response after submission and restart the application before reconciliation. Verify the original operation and resulting resource, and check that recovery did not create a second effect. A successful second submission with a new identifier does not prove recovery.

Repeat permitted and denied reads with the second organization, including receipts and events. Revoke a still-current grant separately from credential expiry, and test reconnect after that change. Where the workflow depends on blockchain confirmation, exercise its configured finality and reorganization behavior rather than treating a returned transaction hash as completion.

Retain the tested identity/custody provider configuration, network path, runtime version and evidence-system integration in the institution's private qualification record. Scope the result to that configuration. A local fixture passing does not establish support for every enterprise provider or production topology. Use the [validation matrix](../evaluation/README.md) to record completed cases and explicit gaps, and the [operations guide](../operations/README.md) for deployment and recovery responsibilities.

## Integration completion record

Before calling an integration ready for wider evaluation, retain its source/runtime versions, identity setup, policy/release references, endpoint identity, allowed/denied results, recovery results and known limits. The [validation plan](../evaluation/README.md) provides a matrix. Do not include secrets in the record or publish private deployment details in a contribution.
