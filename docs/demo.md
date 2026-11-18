# Demo guide

Explore how Tegaris Application Layer Privacy controls access to shared contract data. The institutional payments scenario follows two fictional organizations, Bank Alpha and Bank Beta, through settlement workflows, payment records and application requests.

All organizations, accounts, instructions and amounts in this guide are synthetic. Amounts are expressed in test units; they do not represent funds or settlement obligations.

## Try the interactive demo

Open [sandbox.tegaris.io](https://sandbox.tegaris.io/demo/). No account, wallet, installation or per-request human approval is required. Choose a scenario, inspect its request, then select **Run request**. Switch between **Request** and **Response** to inspect the details. Selecting a different scenario clears the previous result.

The three permitted examples read the populated test blockchain through Tegaris. The other examples exercise access restrictions; they do not submit blockchain transactions.

| Example                       | Expected result | What it demonstrates                                              |
| ----------------------------- | --------------- | ----------------------------------------------------------------- |
| Payment details               | Allowed         | Read a synthetic payment between Bank Alpha and Bank Beta.        |
| Settlement workflow           | Allowed         | Read the configured settlement workflow.                          |
| Restricted reference          | Allowed         | Read a reference value covered by the application's permission.   |
| Unapproved method             | Denied          | A contract binding does not authorize every method.               |
| Unassigned contract           | Denied          | Permission for one contract does not authorize another.           |
| Missing application assertion | Rejected        | A request must supply the required application identity evidence. |

The application uses pre-approved, read-only access to these fixed examples. Visitors cannot supply arbitrary contracts, change permissions or submit transactions. Requests are rate-limited; wait briefly before trying again if the page asks you to slow down. Only fictional records are available.

These six examples demonstrate permitted reads, method and contract restrictions, and rejection of missing identity evidence. They do not demonstrate field redaction, debtor-role enforcement or downstream contract isolation. The reference scenarios below describe separate console walkthroughs.

## Reference console scenarios

| Walkthrough             | What to examine                                                     | Expected boundary                                                                                                       |
| ----------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Contract library        | Registered contracts, imported methods and network bindings         | A contract definition identifies the interface; an active permission determines who can use it.                         |
| Selective disclosure    | A workflow's name and restricted reference field                    | The configured response exposes only the fields permitted for the application.                                          |
| Payment records         | A payment between Bank Alpha and Bank Beta                          | Access depends on the caller and the policy for that record.                                                            |
| Role-based instructions | An instruction that requires the debtor role                        | An admitted debtor can read the instruction; an unrelated caller is denied.                                             |
| Contract interactions   | A gateway calling a processing service and restricted data contract | Access to the entry method does not imply unrestricted access to every downstream method.                               |
| Decision evidence       | The result of a permitted request and a denied request              | The decision identifies the request and its outcome without exposing protected response data to an unauthorized caller. |

These are reference scenarios for a prepared workspace. The [release notes](releases/v0.9.0.md#known-issues-and-limits) identify the supported scope and known issues for v0.9.0. A populated contract library alone does not establish that its application requests are enabled.

## Invited console access

The interactive examples above require no account. For a separately invited console walkthrough, use the account and organization supplied with your invitation. Console access details are issued privately through the [project contacts](../MAINTAINERS.md). Passwords, application certificates and private keys are never published in this guide.

1. Sign in with the supplied demo account.
2. Confirm the account and organization on **Account & workspace** before opening a scenario.
3. If verification is requested, use the authenticator registered for that account. Register an authenticator only when the invitation explicitly describes first-time enrollment.
4. Open the prepared contract and policy records. Use existing records for the introductory walkthrough; creating another policy or approval is unnecessary for inspecting them.
5. Use only the synthetic inputs provided for the selected scenario.

An invited console user's access should be approved before the session and limited to the selected demonstration. Routine application reads can use a bounded grant that does not require a person to approve each call. Administrative changes and writes follow the configured review and authentication requirements.

For a local workspace, follow [getting started](getting-started.md), then use the [console guide](user-guide/README.md). Local setup creates the initial workspace; it does not import the reference dataset automatically.

## Reference dataset

The [sample data](examples/demo-data.json) provides stable names and inputs for a repeatable walkthrough:

- Two fictional organizations and three wallet aliases, including an unrelated caller for denial checks.
- Three settlement workflows with synthetic restricted references.
- Twelve payment records, including four to complete after creation.
- Three payment instructions requiring the debtor role.

Wallet aliases are labels to resolve to wallets created for the demonstration. They are not addresses or credentials. Contract addresses, transaction hashes, timestamps and deployment identifiers must come from the actual test network.

The demonstration operator supplies the contract fixtures and matching ABIs listed below. They are separate from the sample JSON and are not installed by the local setup command. Obtain those fixtures before attempting to reproduce this scenario on another network.

| Display name              | Contract interface  | Main example                           |
| ------------------------- | ------------------- | -------------------------------------- |
| Settlement Workflows      | `WorkflowData`      | `getWorkflowDetails(101)`              |
| Payment Register          | `PaymentRegistry`   | `getPaymentInfo("PAY-DEMO-1001")`      |
| Payment Instructions      | `PaymentInfo`       | `viewPayment("INSTRUCTION-DEMO-1001")` |
| Application Gateway       | `PublicGateway`     | `peekInside()`                         |
| Processing Service        | `InternalLogic`     | `forwardRequest()`                     |
| Restricted Reference Data | `SensitiveContract` | `getSecretData()`                      |

These contracts are demonstration fixtures. Their Solidity visibility modifiers do not provide blockchain confidentiality. Tegaris governs access through its configured application endpoint; direct node access is a separate boundary. See the [privacy model](security/privacy-model.md).

## Follow a request

Start with a prepared read policy and the application identity assigned to it. Inspect the contract address, method, organization and permitted result fields before submitting the request.

Run the permitted input first. Confirm both the returned value and the recorded decision. Then change one policy-relevant input, such as the caller or contract address, to the supplied denial case. Confirm that the request is denied and that no protected result is returned. Keep the request identifiers so that the two decisions can be compared in the evidence view.

For selective disclosure, inspect the decoded result. A successful HTTP response is insufficient: the restricted field must be absent or transformed exactly as the configured policy specifies. For role-based instructions, compare the admitted debtor with the unrelated caller against the same instruction.

If the workspace uses a controlled response provider, its results demonstrate the configured policy boundary. Only a walkthrough connected to a test blockchain can establish that a transaction was submitted and included on that chain. The operator should identify which provider the session uses.

## Review a change

A guided change uses separate maker and reviewer accounts. The maker prepares the intended policy or operation; the reviewer checks its scope and approves it; the maker completes execution. Inspect the resulting resource and operation status after execution. An approval is not itself an executed change.

Use separate browser profiles for the two accounts. Keep the originating session open until its operation has completed. If the result is uncertain, inspect the existing request before retrying. See [troubleshooting](user-guide/troubleshooting.md).

## Prepare a hosted session

Operators should use the [hosting guide](development/hosted-demo.md) to configure the origin, identity provider, resource limits and credential lifetimes. Before sharing access:

1. Import the intended contract interfaces and bind them to the actual test deployments.
2. Resolve the sample wallet aliases and populate records through the supported contract and governance flows. Record the resulting transaction identifiers; do not substitute invented receipts or pre-completed approval records.
3. Approve narrowly scoped visitor access and the intended application read grant. Keep administration and reviewer credentials private.
4. Verify the permitted, denied and disclosure cases with the exact accounts and endpoint that visitors will use.
5. Confirm that authority, credentials and policy validity cover the session, and that a sign-out followed by sign-in preserves access to the same records.

The sample data file is a set of business inputs, not an installer, database restore or authorization override. Preserve existing records when populating a retained workspace. If a sample identifier already exists, compare it with the intended input and resolve differences before creating or changing anything.

## Help during a session

In the interactive examples, **Denied** and **Rejected** are expected results for the three access-boundary cases. If an allowed example reports an error, use the support details below; signing in is unnecessary.

For invited console access, first confirm the selected account and organization. If verification has expired, renew the existing session. Do not create a replacement authenticator, broader role or duplicate approval to work around the error.

Share the failing step, request reference, approximate time and a redacted screenshot through [support](../SUPPORT.md). Keep passwords, cookies, authenticator responses and private keys out of screenshots and issue reports.
