# Host a development demo

The local workspace can use an HTTPS hostname for console sign-in. It uses synthetic accounts and a development identity provider. Use it for evaluation with test data. A production deployment needs its own identity provider, operational configuration and qualification.

Start with the [Linux setup prerequisites](../getting-started.md). Keep the workspace on a separate machine or VM with its own data directory.

## Plan the evaluation environment

Assign an operator, an identity/configuration owner and a reviewer. Record the source revision, intended audience and who may receive the private account file. Use synthetic business data.

Reserve a hostname and route it only to the intended proxy. Confirm DNS from networks used by browsers and services. If the hostname previously pointed elsewhere, verify removal of old address records before relying on it for identity callbacks.

Keep the data directory outside the checkout with private permissions. The hostname is a deployment setting; do not commit real infrastructure addresses or account details into public source.

## Set the public origin before initialization

Configure DNS and a reverse proxy with a valid certificate for your hostname. Use one HTTPS origin for the console and development identity provider:

```sh
OPENPC_QA_PUBLIC_ORIGIN=https://demo.example.org \
  bash scripts/operations/policy-testing.sh qa-start \
  --local-qa-fixture --data-dir "$HOME/tegaris-demo"
```

The origin must contain only the scheme and hostname, plus a port if needed. Omit a trailing slash, path, query and credentials. The helper saves the origin in the workspace configuration and binds new development accounts to that issuer.

Use a new data directory when changing the issuer. Do not rewrite credential rows in an existing workspace to make a different issuer match. Preserve the previous workspace until its data is no longer needed.

## Route the hostname

The reverse proxy needs these routes on the same hostname:

| Public path                         | Local destination                                  |
| ----------------------------------- | -------------------------------------------------- |
| `/authorize`                        | Development identity provider on `127.0.0.1:53006` |
| `/.well-known/openid-configuration` | Development identity provider on `127.0.0.1:53006` |
| `/jwks`                             | Development identity provider on `127.0.0.1:53006` |
| `/token`                            | Development identity provider on `127.0.0.1:53006` |
| All other paths                     | Console gateway on `127.0.0.1:8080`                |

Preserve the original host and forward the HTTPS scheme. The callback path is `/api/v1/ui/oidc-session/callback`; it goes to the console gateway. Keep the local service ports private. Configure access logs to omit query strings so authorization codes are not recorded.

The identity service must be able to reach the public discovery, token and signing-key endpoints and validate their certificate. A browser reaching the sign-in page alone does not prove this server-to-server path works.

## Verify discovery and routing

From a network path representative of the identity service:

```sh
curl --fail --show-error --silent \
  https://demo.example.org/.well-known/openid-configuration
```

Inspect `issuer`, `authorization_endpoint`, `token_endpoint` and `jwks_uri`. They must identify the intended HTTPS origin and provider routes. A generic proxy success page is not a discovery response.

Verify the public certificate chain and hostname with normal validation enabled. Preserve the host and forwarded scheme through each proxy hop. Confirm the callback reaches the console, while `/token` and `/jwks` reach the provider.

Keep proxy logs useful without recording authorization codes, cookies or form passwords. Avoid query-string logging on sign-in and callback paths.

## Check sign-in

1. Open the console's `/signin` page and choose **Sign in**.
2. Confirm that the development provider opens on the same HTTPS hostname.
3. Use an account from the workspace's private accounts file.
4. Select the intended organization workspace. On a first visit, complete the approved authenticator registration. On later visits, verify with the existing authenticator; do not register a replacement to resolve an access failure.
5. Confirm that the expected workspace and role are shown, then open a protected page.
6. Sign out and verify that a new sign-in returns to the same workspace using the existing authenticator.

Keep passwords, session cookies, authorization codes and authenticator material out of issues and screenshots. Report the failing step and a redacted error instead.

## Rehearse the demonstration

Choose a specific business workflow and its expected outcomes before inviting users. Identify the maker and independent reviewer, the organization workspace, required roles, contract or ABI references, and network/provider configuration. Use synthetic records and a test network. Confirm prerequisites through their normal owner workflows; a page that is unavailable or denies access does not prove that its records are absent.

### Confirm the environment you will demonstrate

Check the public hostname from the presenter’s browser and identify the service instance, workspace and source revision that serve it. Keep build and qualification environments distinct from the served workspace. Records or passing tests in a separate environment do not establish that the public demo contains those records.

Inspect the contract library, registered providers and policy versions using the actual demonstration accounts. Record an empty catalogue separately from an unavailable or unauthorized read. If records appear to be missing, confirm the selected workspace and the serving instance before creating replacements.

### Keep the two review sessions open

Use separate browser profiles or separate browsers for the maker and checker. Separate tabs in the same profile share sign-in state and cannot reliably keep the two accounts independent. Verify each account in the intended workspace before starting the first request.

Keep the maker’s original session active until the approved request has executed and its result has been read back. Signing out, replacing that session or changing workspace can make its approval unusable for execution. Preserve the original request and use its supported continuation when available; do not submit a duplicate to work around that restriction.

### Check the workflow prerequisites

Before starting the walkthrough, confirm the following through authorized readback:

- The deployment's authority permits the intended runtime operation and remains valid for the whole walkthrough. Check its current scope and expiry separately from the presenter's administrative role. A working contract-registration or approval screen does not establish that application access is usable.
- The modules required by the chosen workflow and their dependencies have current enabled bindings in the intended privacy workspace. Follow [module setup and activation](../operations/modules.md) if registration, installation or activation is incomplete.
- The application workload has a current credential, and its role assignments, authority envelope and capability permissions cover the intended operation. Record the credential's expiry and allow enough time to complete the demonstration. Successful human sign-in does not renew application credentials.
- The contract definition, ABI, test-network deployment and runtime binding refer to the same synthetic application.
- The requester and independent reviewer can access the intended records with their own accounts and existing authenticators.
- If recovery is included in the demonstration, the named recovery operator has the effective recovery action and scope for that scenario. Check the assignment, role and issuing envelope; a workspace administrator label or ordinary target-update permission is insufficient. See [recovery authority](../operations/README.md#verify-recovery-authority-before-an-incident). If an ordinary activation stops unexpectedly, retain the original operation and investigate it before continuing.

For Participant RPC access, inspect **Enabled module bindings** in **Compose role-bound RPC policy** and the available **Workload** choices. Resolve missing bindings or an empty workload selector before the meeting; neither state is repaired by creating another policy draft. See [application readiness](../user-guide/README.md#confirm-modules-and-application-readiness).

### Check authority deadlines

Record these deadlines for the served environment before preparing a release:

| Dependency           | What to verify                                                                                                       |
| -------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Deployment authority | The current admitted scope covers the runtime resource and operation, and its validity extends beyond the rehearsal. |
| Workload identity    | The application's admitted credential and required signing identities are current.                                   |
| Application access   | Assignments and issuing authority cover the intended workload, capability and workspace for the required interval.   |
| Runtime policy       | The installed policy package and its required inputs remain valid through the planned requests.                      |

Human sign-in and approval requests have their own deadlines. Renewing a browser session, importing an ABI or registering a provider does not extend any of the dependencies above. The shortest applicable validity window limits when an application request can succeed.

The default QA initialization creates deployment authority valid for eight hours. That window starts when the authority is created, so setup and configuration consume part of it. Resuming the same workspace with `qa-start`, restarting services or signing in again does not restart the clock. Record the actual expiry before scheduling a rehearsal.

Runtime policy has a separate, shorter lifetime. The default local runtime snapshot lasts 60 seconds. An activation can therefore be recorded successfully while its installed package has already expired by the time an application sends a request. Check the installed package's expiry as well as the activation record and current target health.

For an explicitly selected manual QA installation, `OPENPC_LOCAL_RUNTIME_QA_SNAPSHOT_TTL_MS` accepts values from `60000` to `3600000` milliseconds. Set the required rehearsal window before initialization; one hour is the maximum for this setting under the ordinary local QA profile. The snapshot remains bounded by its source authority and credential validity. This setting does not extend deployment authority, grants or existing signed packages, and it is not a production credential policy.

Each application request still needs a fresh workload authentication assertion, whose lifetime is at most 60 seconds. A longer QA snapshot does not extend that assertion. Obtain it immediately before the request and keep it out of logs and screenshots.

If a package has expired, use the supported governed activation workflow for the same policy and its current predecessor. Preserve the original approval, activation and request evidence. A configuration change or service restart cannot make the expired signed package valid again. Complete both the permitted and denied application requests before reporting the demonstration as ready.

For a retained hosted environment, qualify the supported renewal or recovery path before that authority expires. If it has already expired and no qualified transition is available, record the runtime demonstration as blocked. Preserve the workspace and original records; rerunning initial setup, editing stored validity or creating another draft does not renew its authority. See the [operations guide](../operations/README.md) and [certificate and workload identity lifecycle](../operations/certificates.md).

Follow the [console user guide](../user-guide/README.md) with the accounts and inputs intended for the demonstration:

1. Create or select a policy set and prepare an immutable version. Review the document and workspace references. A saved draft or version does not change active permissions.
2. Simulate representative allowed and denied requests. Check the decision, scope and evidence for each case; one expected denial does not verify the allowed path.
3. Complete the required independent approval and release steps. Verify the resulting active version through its normal readback.
4. Exercise the permitted operation and the corresponding denied operation against the intended test system. Inspect the recorded operation and evidence, rather than treating a submitted request as a completed effect.

Preserve the original request reference when an outcome is uncertain. Read back that request before retrying; do not repeat it with a new key to bypass an unresolved result. See [troubleshooting](../user-guide/troubleshooting.md).

Record which workflows passed, the accounts and workspace used, source/artifact versions and any access or operating limits in the private environment record. Keep the public demonstration description within that verified scope. A functional evaluation does not establish production readiness.

## Keep the demo available

The QA helper is not a hosting supervisor. Before treating the demo as continuously available, verify startup after a machine restart, certificate renewal and service health. Internal development certificates also expire; renewing the public HTTPS certificate does not renew them. Preserve the data directory when stopping or resuming the workspace.

See [troubleshooting](../user-guide/troubleshooting.md) for startup and access failures.

Configure the operating-system service manager to start the retained workspace after its dependencies. Test a real restart and verify the same data root and recorded services before repeating sign-in. Allow normal dependency startup to complete before classifying an early unavailable response as a failure.

Maintain separate expiry records for public HTTPS, internal TLS and signing-provider trust. Unattended internal renewal is not qualified for every fixture relationship; see [operations](../operations/README.md). Do not extend retained validity records or bypass trust checks.

Follow the [certificate lifecycle procedure](../operations/certificates.md) to inventory consumers, inspect the complete chain and distinguish file renewal from governed workload rotation. A persistent demo must qualify both paths before the relevant material expires. Runtime policy packages also have independent deadlines. Use [runtime policy validity and refresh](../operations/README.md#runtime-policy-validity-and-refresh) to record the installed package, current dependencies and supported renewal procedure. A healthy console, renewed HTTPS certificate or new application assertion does not extend runtime policy validity.

## Completion record

Record effective issuer, route checks, source/artifact versions, sign-in, restart and unresolved operating limits in the environment's private record. Distinguish an authenticated session from completed authenticator enrollment and a full console workflow. A working sign-in page alone does not establish either.
