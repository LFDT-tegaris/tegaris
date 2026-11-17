# Troubleshooting

Start with the exact action, time, environment and safe error shown by the console or command. Preserve the original operation reference when a request may have changed state. Investigate the first failed prerequisite before changing downstream configuration.

## Collect a minimal diagnostic record

Record the source revision, operating system, pinned tool versions, command or console task, selected organization, expected result, actual result and any safe request/operation identifier. Keep credentials and private deployment details in the environment's approved private channel.

For a development workspace:

```sh
git rev-parse HEAD
bash scripts/operations/policy-testing.sh check
bash scripts/operations/policy-testing.sh qa-status --data-dir "$HOME/tegaris-dev"
```

The prerequisite check validates the local execution environment. Status reports the retained fixture; neither proves that a specific business operation completed.

## Setup and resource failures

| Symptom                              | Inspect                                             | Corrective action                                                               |
| ------------------------------------ | --------------------------------------------------- | ------------------------------------------------------------------------------- |
| Missing tool or wrong version        | The first prerequisite error and pinned versions    | Install the required tool/version, then repeat the check                        |
| No systemd user session              | The Linux login/session configuration               | Establish a working user service manager before allocating workloads            |
| Docker access denied                 | Local socket access and selected context            | Repair the intended account's access; do not expose a remote daemon             |
| Unsafe data directory                | Ownership, mode, canonical path and symlinks        | Select a new private directory outside the checkout                             |
| Inherited scenario variable rejected | Environment variables from previous tasks           | Remove unrelated selectors; keep only options documented for this command       |
| Resource admission fails             | Free disk, memory caps and retained workspaces      | Add capacity or resolve positively owned disposable work; preserve unknown data |
| Dependency metadata mismatch         | Install location, toolchain and pnpm execution mode | Restore a consistent frozen installation in the intended location               |

Do not solve capacity errors by deleting database volumes, source archives, unknown caches or another environment's images. Retained failures may contain the only evidence needed to recover a partially completed operation.

## Initialization and migration failures

A quiet migration is not necessarily stalled. Inspect the active process, database activity and durable migration records through the supported tooling before deciding it has stopped. A timeout does not prove that no migration was applied.

If initialization fails after durable writes, preserve the same data root and reconcile the completed phases. Do not rerun account seeding or repeat an initialization command blindly against a populated root. Preserve applied migration bytes and digests.

If you cannot establish which phase completed, stop dependent mutation work and report the uncertainty. A new data directory may be appropriate for an independent test, but it is not recovery of the original failed environment.

## Sign-in failures

| Observation                                  | Check                                                                                                                                                              |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Console cannot start sign-in                 | Identity-service health, configured issuer and authorization endpoint                                                                                              |
| **Sign-in unsuccessful**                     | Select **Back to sign in**, start a fresh attempt and check the account details supplied by your administrator. An expired sign-in request requires a new attempt. |
| Provider page opens but callback fails       | Exact callback URI, issuer response, cookie handling and provider token/JWKS reachability                                                                          |
| Browser works but server-side exchange fails | Service-to-provider DNS, network path and certificate validation                                                                                                   |
| Wrong organization or missing actions        | Membership, selected context, effective role/grants and required authentication                                                                                    |
| Hosted demo fails after changing hostname    | Configured origin, callback and account issuer bindings; preserve an existing workspace and its recovery records                                                   |

Keep issuer and endpoint protocols consistent. Preserve the exact registered callback. Do not bypass TLS warnings, loosen issuer checks or rewrite credential rows to force a login. See [hosted setup](../development/hosted-demo.md).

## Repeated session checks when changing pages

The console checks the session when a page first opens, when the browser restores a page, and after an account or workspace transition. Navigation within an unchanged, confirmed workspace rechecks the session in the background. A change to the account or workspace can require a page reload before controls are shown again.

If **Checking your session…** interrupts every menu change:

1. Record the starting page and destination. Note whether the problem occurs with the console's navigation, the browser's Back button or a full page reload.
2. Open **Account & workspace** and confirm the account, organization and selected workspace. Keep this tab open while investigating.
3. If **Your session could not be verified.** appears, use **Retry session check** and retain the result. An operator should check the identity service and the connection to it if verification keeps failing.
4. Report the environment, release/source revision, browser version, observation time and affected pages through [SUPPORT.md](../../SUPPORT.md). Include the safe request reference when one is shown.

Keep the original operation reference if a change was pending when the page stopped responding. Follow [timeouts, retries and recovery](#timeouts-retries-and-recovery) before submitting that change again. Session verification does not require enrolling a replacement authenticator.

### Session unavailable or signed out

| Result                                                             | Meaning                                                                                                                                                  | What to do                                                                                                                                             |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Session unavailable** or **Your session could not be verified.** | The console could not establish the current session state. A service failure, timeout or unreadable response does not establish that your session ended. | Keep the tab open and choose **Retry session check** when the connection is restored. Protected controls remain concealed until verification succeeds. |
| The current session check returns you to sign-in                   | The service confirmed that the session cannot be used, or there is no valid browser session.                                                             | Sign in through the configured identity provider and select an authorized workspace.                                                                   |
| The account is signed in but an action is denied                   | Session authentication succeeded; the requested action has additional authority or verification requirements.                                            | Check the selected workspace, required role, scope and authenticator freshness. Follow the action's safe error and retain its request reference.       |

A successful retry may restore access using the same browser session; it does not renew an expired session or change permissions. If a write was pending, inspect its original operation before submitting it again. Do not clear browser storage or create a new request solely because session verification was temporarily unavailable.

## Authenticator and workspace selection

**Register authenticator** enrolls a credential. **Verify and enter workspace** uses an existing credential to authenticate a context change. Repeated verification failures do not, by themselves, mean that another credential should be registered.

Start in **Account & workspace → Security & workspace**. Check the selected **Organization workspace** and use your own account. The identity-provider sign-in, authenticator verification and selection of an authorized workspace are separate steps. A completed sign-in does not establish that the later steps succeeded.

If the card says **Current workspace**, that context is already selected. **Verify and renew session** remains available to start a new verified session. It is an available action, rather than an error or an expiry indicator. Use the result of the requested operation and any specific session message to decide whether verification must be repeated.

### A protected read is unavailable while the account is signed in

A valid session and permission to read a resource are separate checks. Some governed assignments require recent authenticator verification even for a read. The service also checks the selected workspace, requested action, resource scope and current authority. Being signed in does not establish that those conditions still hold.

If the operation requires fresh verification, open **Account & workspace → Security & workspace** and choose **Verify and renew session** with the existing authenticator. Confirm the resulting workspace, then repeat the read. Renewal does not add a role, extend a grant or establish permission for a different action. Sensitive operations may still require their own verification.

If the read remains unavailable, retain the safe error code, time and resource reference for the administrator. Check membership, assignment and envelope validity, action/resource scope and service availability. An unavailable response alone does not identify which check failed or prove that the record is absent. Do not bypass the governed endpoint or broaden permissions to make the page load.

If a write was already submitted, preserve its original request reference and follow [timeouts, retries and recovery](#timeouts-retries-and-recovery). Renewing a session does not prove that the earlier write failed or authorize a replacement request.

### No authenticator prompt appears

1. Keep the console tab open and check for a browser or operating-system authentication dialog. A prompt can be behind another window.
2. Confirm that you opened the intended console hostname and account. An authenticator registered for another relying-party identity or account may not be offered.
3. Use a browser and authenticator supported by the deployment. Check whether your organization requires a physical security key, device unlock or another approved verification method.
4. Let the current request finish, cancel it through the browser, or wait for its timeout. Start one new verification attempt after the account controls return.
5. If the problem repeats, retain the browser/OS versions, the visible message, the time and the selected environment for support.

Do not work around a missing prompt by disabling user verification, editing a credential identifier or registering a replacement outside the account-recovery process. Never send a passkey, recovery secret or authentication QR code with a support report.

### Verification times out or is cancelled

The console bounds the authenticator wait using the issued challenge deadline and the browser request timeout. An unanswered request returns the account controls with this message:

> Authenticator verification timed out. Try again and approve your browser’s prompt.

The expired request cannot be completed by approving its old prompt later. When ready, select the intended context and begin a new verification. Use the authenticator already registered to that account. The console still verifies the returned assertion and the selected context; a late browser response is not permission to enter a workspace.

This timeout concerns the authentication step. If a separate business operation was submitted and its response was lost, follow [timeouts, retries and recovery](#timeouts-retries-and-recovery) before submitting that operation again.

### Verification succeeds but the expected workspace is unavailable

Inspect the context shown after the page reloads. A successful authenticator response does not grant membership, a role or access to another organization. Ask an authorized administrator to check the account's current membership and effective authority for the intended Participant/privacy context.

A session change in another tab can invalidate a pending attempt. Recheck the current account and context before starting another action. If the result of a context-selection request is unclear, reload the account page to read the current session; do not assume the selection succeeded from the authenticator dialog alone.

### An authenticator is lost or cannot be used

Use the deployment's approved account-recovery process. Register a replacement only after the required recovery and fresh sign-in steps. Changing accounts, editing records or using a colleague's authenticator does not establish authority to recover the original account.

See the [console guide](README.md#account-security-and-working-context) for the normal sequence and [private security reporting](../../SECURITY.md) if the problem indicates an authentication or isolation defect.

## Review, publication and runtime failures

An unavailable approval may reflect the wrong reviewer, expired authority, stale request or missing step-up authentication. Inspect those conditions independently. The requester must not substitute their own approval for the required reviewer.

For an approved policy that appears ineffective, inspect the release and target activation state. Confirm the request reached the intended governed endpoint and the target/version being investigated. Do not attribute a request to a policy merely because its review was approved.

For a denied or unavailable read, inspect identity, scope, disclosure policy and required decision-input validity. Do not route around the governed endpoint to obtain the missing result.

## Copying a reference

Workspace and request references remain readable when automatic copying is unavailable.

1. Open **Workspace details**, or expand **Support reference** on the affected page.
2. Check that the reference belongs to the intended environment and current workspace.
3. Choose **Copy** beside the value. **Copied** confirms that the complete value reached the clipboard.
4. If the console says **Could not copy. Select and copy the reference.**, select the displayed value and use your normal copy command. Include every line of a wrapped reference.
5. For a support report, include the request reference, error code, page and time. Follow [SUPPORT.md](../../SUPPORT.md) for the remaining report details.

Use the dialog's close control or Escape to return to the task. If the workspace changes, reopen its details before using another reference.

## Timeouts, retries and recovery

A timeout can occur before admission, during execution or after a durable effect whose response was lost. Preserve the original idempotency key, intent and operation reference. Query the recorded outcome before retrying a write.

Do not treat a new key as a harmless retry. Do not infer failure from an unavailable status read. If state remains uncertain, retain the uncertainty and use the supported reconciliation path.

After restart, confirm service identities, selected data root, database state and relevant operation readback. Health checks establish service readiness, not business-effect correctness. See [operations](../operations/README.md).

### Expired permission-profile binding requests

In **Networks & providers**, open the original request from **Activity** and read its approval and result. When **Request fresh approval** is available, it continues that original binding intent; it does not create a second binding or extend the organization's authority.

Continuation requires an unexecuted request, the same target revision, an unactivated target, and no existing binding for the target or profile name. The maker needs current authority, the independent checker must approve again, and the maker must execute the newly approved request. The original request and its expired approval remain in the record.

If the target revision changed, review the current target before deciding on a new binding intent. Do not change the reason or request key merely to evade a rejected retry. If organizational authority or an access grant expired, an administrator must resolve that expiry through the deployment's supported process; signing in again or requesting fresh approval does not renew it.

## Reporting and escalation

Open a public bug report only after removing passwords, session cookies, authorization codes, personal data, confidential contract inputs and private infrastructure details. A small synthetic reproduction is more useful than an unreviewed log archive.

Include completed and unrun checks explicitly. If the issue could violate identity, authorization, disclosure or evidence integrity, use [private security reporting](../../SECURITY.md). See [SUPPORT.md](../../SUPPORT.md) for the report structure.
