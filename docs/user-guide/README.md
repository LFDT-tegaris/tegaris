# Console guide

The console supports administration, independent review and investigation of governed application access. This guide follows a complete example workflow using synthetic organizations and contracts. Available actions depend on your identity, organization context, authority and the selected release.

## Before you begin

Confirm the environment URL, source/release revision and intended organization. Obtain your own account through the approved channel. Do not share one account between requester and reviewer.

Prepare a synthetic contract, its ABI, the intended network/runtime binding and a narrowly defined operation. Decide which actor should be allowed and which should be denied. If your evaluation uses real institutional infrastructure, agree its scope and access arrangements with its operator before connecting it.

## Find the right workspace

The primary navigation groups related work into Workspace, Policy management and Operations. The available records and actions are checked against the current account and context when you open a page.

| Area                                                  | Use it to                                                                               | Check before changing anything                                |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| **Account & workspace**                               | Inspect your account, register or verify an authenticator, and select a working context | Intended account, organization and workspace                  |
| **Organizations & access**                            | Manage organizations, users, roles, grants and access reviews                           | Requester, recipient, scope and validity period               |
| **Networks & providers**                              | Configure network connections, runtime targets and permission profiles                  | Network identity, endpoint and provider health                |
| **Contracts & ABI**                                   | Register contract definitions, ABIs and network bindings                                | Contract identity, method signatures and target network       |
| **Policies**                                          | Author and select policy versions                                                       | Policy set, immutable version and intended operation          |
| **Simulation**                                        | Inspect the decision for a proposed input                                               | Selected version, actor, resource and input values            |
| **Approvals & releases**                              | Review proposed changes and track publication and activation                            | Exact version, independent review and target activation state |
| **[Contract interactions](contract-interactions.md)** | Review interaction analyses, method grants and compiled-profile activation              | Runtime binding, method, workload and signed observation      |
| **Data & event privacy**                              | Inspect data and events available in the selected privacy context                       | Source, disclosure scope and relevant finality information    |
| **Evidence & operations**                             | Investigate decisions, request evidence exports, and access operational tasks           | Record scope, export purpose and required approvals           |

Use the **Account** control at the top of the page for **Account & security** or **Sign out**. Open **Account & security** to return to the dedicated account page. Press Escape to close the account menu and return focus to its control; clicking outside the menu also closes it.

Some forms include an **Enter workspace** link when you need to select a working context. In the current console, that link opens the account page. Complete verification there, then return to the task and check its selected records. Following the link does not itself grant access or submit the task.

### Sections, forms and keyboard use

Secondary tasks have labels that describe what will open. Some reference sections use a native disclosure with a heading and chevron. With keyboard focus on its heading, Enter or Space opens or closes it. Use Tab to reach the controls inside an expanded section. Expanding a section does not submit a request.

Other tasks open a labeled dialog. Activate its button to open it, then use Tab and Shift+Tab to move through its available controls. Use the close control or Escape to return to the opening button. Check the dialog heading before entering information. Opening or closing the dialog does not submit its form.

Read the section heading before entering identifiers or uploading a file. A collapsed section may contain advanced options, diagnostic references or a separate operation. Required review, confirmation and authorization still apply when those controls are expanded.

Wait for a pending request to finish before submitting again. A disabled control can also indicate a missing prerequisite or insufficient access. Check the nearby guidance and the current workspace rather than treating a disabled control as a completed action.

### Understand page and request states

| What you see                                  | What it means                                                                  | What to do                                                                                  |
| --------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| **Checking your session…**                    | The console is confirming the account and workspace before displaying controls | Let the check finish                                                                        |
| **Updating your session…**                    | A sign-in or workspace transition is in progress                               | Complete any open browser authentication prompt and wait for the confirmed workspace        |
| **Your session could not be verified.**       | The console could not establish the current session                            | Use **Retry session check**; investigate the connection or identity service if it repeats   |
| **No matching records**                       | The current authorized read returned no matching records                       | Review filters and scope; it does not establish global absence                              |
| **Page not available**                        | The requested page is unavailable to the current workspace                     | Check account and workspace access with your administrator                                  |
| **Access unavailable**                        | The action or information is not available under the current authority         | Review the required role, grant and selected context                                        |
| **Service unavailable** or **Request failed** | The requested read or operation could not be completed as reported             | Follow the page's recovery guidance; a read retry is different from resubmitting a mutation |
| **Outcome not confirmed**                     | A submitted change may have reached its owner, but its result is unresolved    | Read the original operation and reconcile its outcome before submitting another change      |

Where available, expand **Support reference** to obtain the code and request reference for a report. Include the page, time and a synthetic reproduction. Keep credentials, session cookies, private keys and private institutional records out of public issues. See [troubleshooting](troubleshooting.md) for recovery steps.

Choose **Copy** beside the request reference to copy its complete value. The button shows **Copied** when the clipboard request succeeds. If copying is unavailable, the reference stays visible for manual selection; follow [copying a reference](troubleshooting.md#copying-a-reference).

## 1. Sign in and select context

1. Open the console's sign-in page and follow the configured identity-provider flow.
2. Complete authenticator registration or authentication when prompted.
3. Select the organization you intend to administer.
4. Confirm the selected context before opening records or starting a mutation.

A successful identity-provider login does not automatically grant every administrative action. Membership, role, current grants, step-up requirements and resource scope are evaluated separately.

If the expected organization or action is unavailable, inspect your effective access with an authorized administrator. Do not borrow another person's session or change identifiers in a request to obtain access.

## Account security and working context

Open **Account & workspace**. The dedicated account page shows **Security & workspace** directly. The **Account references** section displays the complete account, organization and workspace references in separate fields. Use these values when your workspace administrator needs to identify the account or context you are using.

### Register or use an authenticator

Use **Register authenticator** for first-time enrollment or an approved replacement. Follow the browser's enrollment flow and the deployment's authenticator requirements. Keep any enrollment reference private and use **Check registration status** to reconcile an interrupted enrollment when that reference is available.

Use **Verify and enter workspace** when the account already has a registered authenticator. This action requests an assertion from that credential; it does not enroll another one. Follow the browser or device prompt and complete the requested user verification yourself.

If a credential is lost, complete the approved recovery process before registering its replacement. Follow any institutional hardware-attestation requirement; changing the enrollment options is not a way to bypass that policy.

### Enter an organization workspace

1. In **Organization workspace**, select an available context for your account.
2. Choose **Verify and enter workspace**.
3. Approve the current request using the registered authenticator.
4. After the console reloads, confirm that the intended context is active before opening records or submitting an action.

The list reflects contexts available to the account. Selecting an identifier does not grant access. Verification and current authority must both satisfy the context-selection checks.

An unanswered authenticator request expires and returns the account controls. Start a new verification when ready; an expired prompt cannot complete the earlier request. Do not register another authenticator merely because verification timed out. See [authenticator troubleshooting](troubleshooting.md#authenticator-and-workspace-selection).

### Verify an active workspace again

When a Participant workspace is already active, **Verify and renew session** requests a fresh assertion using the registered authenticator for that workspace. Complete the browser prompt and confirm the resulting context after the reload. The action remains subject to current account and workspace authority.

The workspace card identifies the active context as **Current workspace**. Renewal is available for that context whenever you want a new verified session; the action's presence does not indicate that the session expired or that an earlier verification failed. Selecting another workspace changes the action to **Verify and enter workspace**. Opening the account page or choosing an option does not start an authenticator request.

### Refresh a session

**Refresh session** replaces the current administrative session while retaining its selected context and existing authority. The original maximum sign-in expiry still applies. Confirm the resulting context after the console reloads. If the response is interrupted, read the current account state before retrying a separate business action.

Session refresh does not grant a new role, replace an authenticator or renew an application's workload certificate. Operators responsible for workload credentials should use the [certificate and workload identity guide](../operations/certificates.md).

## 2. Inspect existing configuration

Use the relevant directory to look for an existing organization, workload, contract or policy before creating another. Inspect the record's identity, state, revision and scope, rather than relying on its display name alone.

Search and filters help locate records you may access. An empty result does not establish that no record exists globally. Reset a filter deliberately if you need a broader authorized view; do not present that broader view as the original filtered result.

## 3. Prepare identities and grants

For an application workload, verify its organization membership, credential binding, wallet association where applicable and the authority required for the intended operation. Credential registration and permission grants have separate lifecycles.

Before submitting an access change, review the actor, resource, operation, validity period and any delegation limits. Use a second test actor to verify that the new grant does not broaden another actor's access.

Changes that require approval or stronger authentication must complete that workflow. A form being editable does not mean the change is already authorized.

### Workspace details in access workflows

Role, principal and grant pages show your current maker or checker role above the task. Open **Workspace details** to inspect the Participant, privacy domain and context generation used for that page. Close the dialog to return to the same task. Those identifiers describe the current context; permission and approval checks still apply to each change.

Use **Copy** beside the Participant or privacy domain reference when you need its exact value. Pages that include the principal reference offer the same control. Long references wrap across lines in narrow views; the copy action includes the whole value. After changing accounts or workspaces, reopen **Workspace details** and take the reference from the current view.

Use **Find role**, **Find principal** or **Find grant** to read an existing record by its identifier. Reading a record does not create or approve a change. Review headings describe the proposed action; an **Approved** request still needs its separate commit step before the changed record takes effect.

### Request an organization authority envelope

Open **Organizations & access → Authority requests**. The context card identifies the current organization workspace and shows your maker or checker role. **Workspace details** opens the identifiers in a separate dialog; opening or closing it preserves the draft and submits no change.

An authority envelope defines a bounded set of administrative permissions. This page prepares, reviews and creates a draft envelope. Creation does not activate the envelope, assign it to an application or make a policy effective.

Before starting, confirm that the maker and independent checker have their own accounts and the required access to this organization and privacy domain. Use the deployment's approved account and authority setup. Another account's authenticator cannot approve a request on your behalf.

#### Maker: prepare and submit

1. In **Request an authority envelope**, enter **Purpose**, **Valid until** and **Reason**. The purpose accepts 3–80 characters; the reason accepts 10–1,024. The date control uses your browser's local time. The service checks the allowed validity period.
2. Choose **Review request**. Inspect the proposed purpose, risk, expiry and candidate digest. The review describes the exact request; it does not create an active permission.
3. Choose **Send to checker**. Complete any authentication required for the action. Keep the original request reference and wait for its recorded approval state.
4. If an input needs changing after review, preserve the original request and resolve it through the authorized reconciliation or administrative process before preparing another. This page does not provide an edit or reset control for a retained immutable review. Changed business inputs are a new intent, not a retry of the original.

#### Checker: review independently

1. Sign in with the checker account and enter the intended organization workspace using that account's authenticator.
2. Open **Authority requests** and inspect the **Checker inbox**. Match the candidate digest and request state to the proposal being reviewed.
3. Use **Review and approve with security key** for the intended request. Approval requires the checker's own authentication and current authority; the maker cannot substitute their approval.
4. Confirm the resulting state. An authenticator prompt alone is not confirmation that approval was recorded.

#### Maker: create and verify the draft

Return to the original request and refresh its state. Once its recorded approval is **Approved**, choose **Create approved envelope** and complete the required authentication. Inspect the returned envelope state, operation reference and effect reference.

The created envelope is **Draft**. This page does not provide a general activation control. Complete the deployment's supported activation and assignment procedures before testing effective access; use the [interface reference](../reference/interfaces.md) to identify the relevant contract. A draft envelope or an approved request must not be reported as active access.

#### Interrupted or uncertain requests

Use **Check original request** when the page retains an earlier submission whose outcome needs checking. The console preserves its original review and operation information. A later sign-in may permit read-only investigation without permitting execution to resume.

Keep the original request and its business inputs intact. If the recorded result is unavailable or unconfirmed, investigate that result before preparing another request. Do not clear saved request information, change accounts or create a new proposal key to make the uncertainty disappear.

### Review administrative access

In **Organizations & access**, open **Review administrative access** and enter the principal reference to investigate. Select **Review current access**. Confirm the principal, its state and the observation timestamp before interpreting the assignments and delegations below it.

Each entry identifies its assignment or delegation, whether its constraints are current, the governing envelope and validity period, and its approval and authentication requirements. Read any reason shown for an entry that is no longer current. A current grant is one input to authorization; every action still requires a live platform policy, identity, privacy and context decision.

Choose **Administrative actions, resources and authority path** on an entry to inspect its action identifiers, resources, risk classes and ancestry in a separate dialog. Close the dialog to return to the same entry. Inspection sends no access change. Where available, **Review revocation of this assignment** or **Review revocation of this delegation** opens the corresponding grant workflow; following the link does not itself revoke access.

If the review has more results, use **Next authority paths** to inspect the next page. A context change clears the previous review. An empty authorized page means there are no matching paths for that principal in the selected privacy context; it does not establish that the principal has no access elsewhere.

### Reserve a workflow reference

Use **Reserve a workflow reference** when an approval request or policy activation needs a resource reference before access can be assigned. Select the reference purpose and enter the exact business action, resource and expected revision. If the operation requires an independent checker, provide that principal's identifier. A reservation creates a reference; it grants no permission and does not create the approval request or activate a policy.

After submission, review the returned business action, resource, expected revision and expiry. Use **Reserved resource for access grants** when preparing the corresponding finite grants. Use **Operation reference for creation** when creating the business operation. Keep these two references distinct. Creation still checks current authority, and the reservation's validity is bounded by the issuing authority and session.

For an expired, unused reservation whose business inputs are unchanged, choose **Renew an unused reservation**. Enter the previous reservation's operation identifier, then close the dialog and complete the main form. Opening or closing the dialog sends no reservation request; the entered identifier remains in the form until submission. Renewal retains the original reference and requires current authority. A consumed reservation cannot be renewed. If a submission fails or its response is lost, inspect the original operation before starting another request.

## Confirm modules and application readiness

Before authoring a policy, use [module setup and activation](../operations/modules.md) to confirm that the required releases and their dependency closure are active in the intended privacy workspace. A registered release still needs installation and activation. Keep the release manifest and configuration identities with the application's setup record.

For Participant RPC access, the console may ask you to **Verify Participant authenticator and load RPC access**. Complete that action with your existing authenticator. It authorizes the protected read; it does not create a workload or grant application permissions.

In **Compose role-bound RPC policy**, check **Enabled module bindings** and resolve the named missing modules before creating a version. In **RPC access by workload**, select the intended **Workload** and **Policy set**, then use **Read current RPC access** to inspect the effective method and capability requirements. A workload must have a current credential to appear in the selector; its role assignments and authority envelope are evaluated separately.

| Observation                                   | Next step                                                                                                                                 |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Missing enabled module bindings               | Check registration, installation, activation and current configuration in this workspace with the module operator.                        |
| No selectable workload                        | Check the workload principal and its current runtime credential with the identity owner. Signing in again does not renew that credential. |
| A workload is selectable but access is denied | Inspect its role assignment, envelope, capability and scope through the supported access workflows.                                       |
| A protected read is unavailable               | Check the selected workspace and any required authenticator verification. Preserve the safe error; unavailable is not an empty result.    |

Use the [integration guide](../development/integration.md) for workload requests and the [troubleshooting guide](troubleshooting.md) for access failures. Continue only after the required configuration is confirmed through its authoritative readback.

## 4. Register a contract and ABI

### Browse the contract library

In **Contracts & ABI**, the **Library** view separates **Contracts**, **Network bindings**, **Methods** and **ABI artifacts**. Select a category, enter its search prefix and choose **Search catalogue**. Prefix matching is case-sensitive. **Previous page** and **Next page** use the returned catalogue continuation; **Refresh catalogue** starts again at the first page with the current filter.

**Contract library unavailable** means the read did not complete. Refresh the catalogue to try again, and contact your administrator if it continues to fail. **Catalogue access unavailable** means the current account or workspace cannot browse that catalogue. A method the account is individually permitted to use may still be inspected by its reference through the corresponding method workflow. These messages do not establish that matching records are absent.

When **Request reference** is available, choose it to inspect the diagnostic identifier in a separate dialog. Opening or closing the dialog sends no catalogue or access change. Include that reference and the time when reporting the issue, and keep credentials and confidential contract inputs out of the report.

### Register a contract

Register the named contract asset before importing its ABI and binding a deployment. These are separate governed changes. None of them alone grants an application permission to call the contract.

#### Maker: prepare the contract

1. In **Contracts & ABI**, inspect **Library** to check whether the contract already exists in the selected workspace.
2. Choose **New contract**. Enter **Logical contract name**, **Display name** and **Reason**. Use a stable logical identifier and a display name that reviewers can recognize.
3. Choose **Review request**. Check the contract name, identifier and business reason in the review summary. Use **Edit request** to correct the inputs before asking for approval.
4. Choose **Choose checker** and select an independent active account. The maker cannot check their own change. **Checker account type** defaults to **Participant user**; select **Platform operator** only when that is the intended reviewer’s existing account type. An empty result for one account type does not establish that no reviewer exists.
5. Choose **Request approval** and retain the request reference. The request appears in **Activity** as **Awaiting approval**. A submitted request has not created the contract asset.

#### Checker: inspect and approve

Use a separate browser profile or browser so the maker remains signed in. Enter the same organization workspace with the checker account and its own authenticator. Open **Contracts & ABI**, select **Activity** and load the original request.

Compare the stored contract name, identifier and reason with the intended change. Check the maker, selected checker and approval state. Choose **Approve with security key** only for that exact request and complete the required authenticator verification. Do not approve a different request simply because its display name is similar.

#### Maker: execute and read back

Return to the maker’s original session, open the original request in **Activity** and refresh its approval state. Once the approval is usable, choose **Execute approved request** and complete any required authenticator verification. Read the recorded outcome, then refresh **Library** and inspect the resulting contract asset.

Keep the same request and operation references if the result is uncertain. Signing out or replacing the maker’s session can prevent execution, even after checker approval. Use the original request’s supported continuation when available; do not create a replacement transaction to bypass the session check.

#### Expired requests and authenticator prompts

The request and its authenticator prompt have separate deadlines. Workspace verification does not replace the verification required for an approval decision or execution. Complete the displayed authenticator prompt while it is open; if it closes without a confirmed result, read the original approval before trying again.

When a request expires, open its original record and use **Request fresh approval** if that control is available. The new attempt stays linked to the same intent and preserves the earlier history. The checker must review the new approval reference. Keep the maker's session open, and start the fresh attempt when both participants are available. Do not create another transaction to work around an expired request.

#### Continue with the ABI and deployment

Import the ABI that describes the intended deployed contract, inspect its parsed methods and arguments, then establish the test-network deployment and runtime binding through their corresponding governed requests. Verify the resulting contract, chain, address, ABI and method together.

An address alone is insufficient to distinguish deployments across networks. An ABI from another deployment is not a substitute. Retain the created record references for policy authoring and later troubleshooting.

### Review method argument restrictions

Argument rules restrict the values a method may accept. Check the runtime binding, ABI, canonical function signature, input position, operand type and allowed values together. For example, an address rule for `balanceOf(address)` can limit the account whose balance may be read.

An independent checker should review the exact proposed rule version before the maker completes its creation. Proposal and approval alone do not activate the method. Keep the created rule reference with the method policy and confirm the selected policy version and runtime activation separately. The [contract administration reference](../reference/interfaces.md#contract-administration-and-review) explains the fields and review sequence for developers integrating this flow.

## 5. Define a policy

Start with one operation and the minimum identities and resources needed to evaluate it. Record any method, argument, relationship, state or external-decision constraints supported by the selected workflow.

Review disclosure separately from execution. Specify the information the caller may receive rather than assuming that permission to invoke a method authorizes its entire result or all related events.

Before saving or submitting, inspect the selected organization, contract binding, actor/role, policy version and intended effect. If the form reports stale state, refresh the authoritative record and reconsider the change rather than repeatedly submitting the same stale form.

### Prepare an immutable policy version

1. In **Policies**, select **Policy set for this version**. If an existing set does not fit the work, choose **Create a policy set** to open the side panel, enter its name and reason, and choose **Create policy set draft**. Wait for its readback before selecting it. Creating a set does not activate a policy.
2. Enter **Semantic version**, for example `1.0.0`. Keep the version and policy contents together in your change record.
3. Choose **Policy file** to load a policy document and inspect **Policy draft review**. Check its scope, rule counts and disclosure settings against the intended change. Loading a file does not admit its dependencies or publish its rules.
4. If the artifact has already been admitted, choose **Compiled artifact (advanced)** instead. The **Artifact references** group exposes both required fields: **Normalized policy digest** and **Dependency closure digest**. Each uses `sha256:` followed by 64 lowercase hexadecimal characters. Take the two values from the same admitted artifact; do not substitute the hash of an unrelated file or an earlier dependency set.
5. Choose **Create immutable version** when the current workspace, policy-set selection and source inputs are ready. Read the returned result. An accepted immutable version still needs simulation and the separate release process before runtime use.

If the response is lost and the console reports that the original version result is unknown, retain the original inputs and use **Reconcile original version** when available. Changing the version or issuing a new request does not resolve the first attempt. If reconciliation is unavailable, preserve the original request information for your administrator and follow the [uncertain-outcome guidance](troubleshooting.md).

## 6. Simulate both permitted and rejected cases

Prepare a small scenario set before running simulation:

| Scenario                                 | What to observe                                   |
| ---------------------------------------- | ------------------------------------------------- |
| Intended actor and permitted input       | The expected decision and authorized output       |
| Same actor with an out-of-scope argument | A rejection without the protected effect          |
| Actor from another organization          | Isolation of both action and disclosure           |
| Missing or stale required input          | A constrained, truthful unavailable/denied result |
| Changed resource or policy version       | No silent reuse of an earlier decision            |

For a contract-method simulation:

1. Open **Simulation**, choose the policy set and review the intended version. Check the version reference and its recorded state before entering a request.
2. Choose the **Workload** and **Role assignment** to evaluate. The names describe the selected records; the submitted workload and assignment references determine which authority is evaluated. If several assignments are eligible, select one explicitly.
3. Use **Access references** to inspect or copy the complete workload, assignment and role references. Short reference suffixes in the selectors distinguish records that share a name. Changing the workspace clears the earlier choices.
4. Choose **Browse method library** to open the method chooser. Find the intended function and choose **Use method**. The chooser closes and fills **Contract method policy ID**. You can also enter a known complete method reference directly.
5. Use **Inspect configured method** to review its binding, signature, argument rules and configured approval requirements. Confirm the contract and network before using its method in the request.
6. Choose **RPC method** and enter **Encoded call data** using the selected ABI. Keep the selector and argument encoding together with the test case.
7. Choose **Run simulation** and read **Outcome**. **Permitted** means the selected policy allowed that simulated input. **Denied** is a policy rejection. **Not determined** needs investigation of unavailable or incomplete inputs; it does not establish permission.
8. Run a valid case outside the intended grant and confirm its rejection. Keep both results, their inputs and the exact version references for independent review.

The result is marked **Policy preview**. Live access is unchanged. The method chooser supports keyboard navigation; **Escape** closes it and returns focus to its opening button. A method selection also closes the chooser. Opening the library or the reference panel submits no policy change.

Record the inputs and selected version with the result. A simulation is evidence about that simulation's inputs; it does not publish a policy or prove runtime activation.

## 7. Submit and review the exact version

Open **Approvals & releases** and select **Releases & approvals**. Prepare the intended policy version and enter the independent checker's principal ID from an authorized identity record. The console leaves this field blank. An account identifier is not evidence that its owner is eligible to check the change; the service validates the selected checker and required authority.

The requester submits the intended change for review. The reviewer uses a separate identity and checks:

- The problem and requested scope.
- The selected policy version and affected identities/resources.
- Allowed and denied simulation results.
- Changes to disclosure or authority.
- Compatibility, recovery and expiry implications.

The reviewer must complete any required authentication and possess the relevant authority. If the request has expired, changed or become stale, use the supported workflow to resolve it. Do not treat an earlier approval as approval of a later version.

## 8. Publish and verify activation

Publish the approved selection through the release workflow. Retain the release and operation references, then inspect the intended runtime target's activation state.

For renewal of an existing published policy, select **Activation renewal** on the same page. Review the current authority epoch, successful simulation and exact target predecessors before requesting independent approval. Renewal activates the existing compiled policy without changing its semantics. The original release approval remains historical evidence. Changing between these tasks does not submit either form; resolve any pending original request before creating a replacement intent.

| State or observation       | What it establishes                                    |
| -------------------------- | ------------------------------------------------------ |
| Draft saved                | A proposed configuration exists                        |
| Simulation returned        | The selected simulation produced an outcome            |
| Review approved            | The selected review requirements were satisfied        |
| Publication accepted       | A publication operation was admitted                   |
| Target activation observed | The named target reports the selected activation state |
| Governed request verified  | The tested request behaved as observed at that target  |

These descriptions are conceptual; use the actual record's contract for its state enum. If activation is incomplete or unavailable, investigate it before attributing requests to the new policy.

## 9. Investigate activity and uncertain outcomes

Start with the original operation, request or transaction reference. Inspect the selected organization, policy version, target and relevant inputs. Distinguish the state of the administrative operation from the state of the downstream transaction.

For a timed-out write, read the original outcome before retrying. A new request or idempotency key can represent a second business intent. Do not create another operation just to discover whether the first completed.

Evidence and exports remain subject to authorization and disclosure rules. Review screenshots and exported records for sensitive information before sharing them.

## 10. Review evidence retention and preservation

Open **Evidence & operations** and select the retention or preservation task. Check the data class and scope before entering a duration or selecting an affected record. Retention, preservation holds and deletion have separate workflows and approvals.

Retention forms display readable data-class and deletion-mode names. API clients continue to use the corresponding contract values:

| Console deletion mode | Contract value      |
| --------------------- | ------------------- |
| Delete record         | `ROW_DELETE`        |
| Delete projection     | `PROJECTION_DELETE` |
| Identifier aliasing   | `IDENTIFIER_ALIAS`  |
| Cryptographic erasure | `CRYPTO_SHRED`      |

The service validates the combination of data class, deletion mode and current policy. Selecting a mode or approving a policy does not establish that a particular object has been deleted. Inspect the original deletion operation and its signed result to confirm its outcome.

For a retention policy, review the retention period, local grace period and required durable sink acknowledgements. Duration fields identify their units in their labels; preserve those units when copying a policy from an integration. **Require independent deletion approval** records whether that policy requires a separate checker. **Not required by this policy** does not waive other applicable approval, authentication or authorization checks.

For a preservation hold, choose **Legal**, **Regulatory** or **Incident**, then select the matching scope. An entire privacy domain, a sequence range, an exact digest, a projection, a Fact type and key, a block range and a generation target different sets of records. Review the fields for the selected scope and any open-ended upper bound before submitting. A Participant-wide hold uses its separate task and requires the corresponding authority in the Participant root context.

Read back the exact approved hold or policy version after completion. Releasing a hold does not delete evidence or remove another active hold. If the result is uncertain, reconcile the original operation before submitting a replacement.

## Read governed data and events

Open **Data & event privacy** after entering the intended organization workspace. Obtain the registered profile reference from its approved registration. The profile supplies the permitted field identifiers, filter conditions, data classes and page-size limit. Loading a profile does not grant access to its underlying data; each read checks current authority.

### Select the profile and prepare a read

1. Enter the **Registered profile reference** and select **Load profile**. Confirm that the returned profile is `REGISTERED`. If the reference cannot be loaded, resolve that result before preparing a read.
2. Open **Workspace details** if you need to inspect the Participant and privacy domain associated with the loaded view. Close the dialog to return to the task.
3. Enter a specific **Purpose** that explains why you need this data. The form accepts at most 256 characters. The service determines whether that purpose is authorized.
4. Choose a **Data class** from the loaded profile and select only the **Requested fields** needed for that purpose. A field being listed does not establish that the current request will be allowed to read it.
5. Set **Maximum records** within the displayed limit. The console caps this value at the smaller of the profile limit and 1,000. This is a page limit, not an indication of the total number of visible records.
6. Add filters where needed. Select a field from the requested fields and a condition offered by the profile. Enter the filter value as a JSON scalar: a quoted string such as `"SETTLED"`, an integer such as `100`, `true`, `false` or `null`. Arrays and objects are not accepted in this field. The profile and service determine which field, condition and value combinations are valid.
7. Select **Read projection** once. The console records an occurrence reference for the request. If the connection is interrupted, use that reference to investigate the original read.

### Interpret the returned page

The result displays the returned outcome and records, with values beside their field identifiers. It contains the fields released for this request. Do not infer access to omitted fields, other organizations or a broader data set from one successful read.

Use **Read next page** only when the console makes it available. Continuation remains bound to the request inputs. Changing the purpose, data class, requested fields, filters or page limit clears the previous result and continuation. Prepare the changed intent before making another read.

An authorized query that completes with no visible records is distinct from a failed request or a partial result. Use the displayed outcome and any error to determine which occurred. A page limit and a partial response do not establish that all matching records have been returned.

Leaving the page or changing window focus can clear released data. Returning focus refreshes the profile view. Reload the intended profile when needed and check the current context before continuing; an earlier result does not establish current authorization.

### Investigate an interrupted read

Open **Check an earlier request**, enter the original **Occurrence ID**, and select **Read occurrence status**. This reads metadata for that occurrence rather than repeating the projection request.

| Status field       | How to use it                                                                                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Durable state      | Read the service's recorded state for the original occurrence.                                                                                                                   |
| Client receipt     | Check the recorded receipt state separately from release authorization. Authorization alone does not establish that the client received the data.                                |
| Evidence reference | Use the returned reference for authorized evidence inspection. **No sealed evidence** means no sealed reference was returned; it does not establish that the read had no effect. |

Keep the original occurrence reference when reporting an uncertain result. A new read creates a new occurrence and undergoes a new authorization check. It cannot resolve the durable state of the earlier request. Follow the organization's handling rules before sharing returned records, screenshots or evidence.

## Keyboard and session checks

During an evaluation, complete the main journey with the keyboard: reach controls, inspect focus, open dialogs, resolve validation errors and return from details to the directory. Check narrow-screen layout, long identifiers, empty lists and failed requests.

After changing organization or ending a session, verify that stale records and pending actions are cleared. Sign out when finished. Follow [troubleshooting](troubleshooting.md) for unexpected behavior and [SUPPORT.md](../../SUPPORT.md) for a useful report.
