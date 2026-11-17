# Tegaris administration CLI (experimental)

The administration CLI is an incomplete development interface. It is excluded from the initial supported release, runtime image contexts and default release acceptance. Use the [console guide](../../docs/user-guide/README.md) for the supported human workflow. A successful CLI command or focused test does not establish qualification of the full administration surface.

## Development checks

The CLI checks are explicit opt-ins:

```sh
pnpm run test:r1.1:cli
pnpm run lint:r1.1:cli
pnpm run format:r1.1:cli
```

`test:r1.1:cli:transactions` and `test:r1.1:cli:cigl` exercise the selected runtime paths and require the configured external scratch directory and admitted resources. Read the root package scripts before running them. Shared browser and API code remains covered by ordinary repository checks even though the experimental CLI's own checks are opt-in.

## Run the development entry point

Run the repository CLI with the installed pinned toolchain and bounded execution:

`bash apps/admin-cli/openpc.sh --help` selects and verifies the installed pins without changing your shell defaults. From an already pinned shell, `pnpm --silent openpc:r1.1` uses the same opt-in development entrypoint.

```sh
pnpm --silent openpc:r1.1 --help
pnpm --silent openpc:r1.1 --config /secure/openpc/client.json session
pnpm --silent openpc:r1.1 --config /secure/openpc/client.json runtime-target RESOURCE_UUID
pnpm --silent openpc:r1.1 --config /secure/openpc/client.json operation OPERATION_UUID --wait-seconds 60
```

## Human authentication

For human authentication, configure `apiUrl`, `participantId`, `privacyDomainId` and `browserProfile` (a private directory relative to the configuration file). Optional `loginHint` selects the intended identity at your IdP. Run `login` to open the existing Workbench OIDC Code with PKCE flow, authenticate at the IdP and verify your security key to enter the explicit Participant/privacy context. Chromium must be installed for Playwright and a graphical display available. The CLI retains browser-managed HttpOnly cookies in the private profile; no manual cookie extraction is needed. Use distinct private profiles for independent makers and checkers. `session` validates current authority, `refresh` rotates the session and `logout` revokes it through the supported session owner. Expired or revoked sessions require a new login.

## Mutations and independent review

Human profiles support `read KIND RESOURCE_UUID`, `transaction KIND --input FILE --request-key UUID`, `review APPROVAL_UUID`, `approve APPROVAL_UUID`, `execute REQUEST_UUID` and `result APPROVAL_UUID [--wait-seconds N]`. Request kinds are `deployment-policy`, `deployment-intent`, `deployment-submission`, `native-value`, `cigl-analysis`, `cigl-observation`, `cigl-review`, `cigl-grant`, `cigl-grant-status`, `cigl-settings` and `cigl-activation`. Fields use the shared Workbench contracts, including optional submission predecessor references and approved policy renewal on CIGL activation. `read` uses the same kind to select its resource owner; for example, `read cigl-activation TARGET_UUID` reads a runtime target. An independent checker's approval access does not grant access to the maker's operation or business result.

The input file contains `{ "fields": { ... }, "reason": "...", "checkerId": "..." }`. It must be a private regular file owned by the current user. The CLI validates it against the owning public command schema and stores an atomic private draft before dispatch. Retain the same request UUID and profile after interruption; repeating that request recovers its original approval, and `execute` reads an already consumed candidate without submitting again. Changing the input under an existing UUID is rejected. The checker reviews the projected candidate using their own profile and runs `approve`; the maker then runs `execute` with the original request UUID. Each action uses the existing browser security-key ceremony bound to the actual approval or command. Never share profiles, drafts or security keys between actors.

## Read outcomes and resume interrupted work

`result` reads the original approval, operation and business effect separately. Pending polling exits 6 and never submits a command. Fresh sessions can recover a draft for the same maker and exact context; the public owners still enforce current authority, candidate expiry and stale-state checks. A terminal or uncertain business outcome is not permission to create a new request or replacement.

## Session-file readback mode

Existing session-file profiles support typed readback of operations, runtime targets, deployment intents/submissions, Native Value authorizations, CIGL analyses, grants and settings. They reuse the owning public response schemas and require a live authenticated session with the configured context already selected.

For this readback-only mode, configure `sessionFile` instead of `browserProfile`. Its path is relative to the configuration file. Its JSON object contains `origin` and `sessionToken`; provision it through your trusted authentication integration without printing the token or passing it on a command line. The file must be owned by the current user, have no group/other permissions, and be a regular file with one link. Symlinks are rejected. Session files, browser profiles and drafts must stay outside source control and diagnostic artifacts. The CLI never prints session tokens or refresh/session identifiers.

## Endpoint and transport requirements

Use an HTTPS origin with no path, query, credentials or fragment. The session file's origin must match exactly. Explicit `localDevelopment: true` permits HTTP only on a loopback hostname for the local synthetic environment. Redirects are rejected; there is no option to disable TLS verification or override authority settings.

## Output and exit codes

Output is JSON. Polling revalidates current identity/context and reads the original operation without resubmitting a command. `--wait-seconds` is supported for `operation` and `result`, from 0 to 300. Exit codes: 0 for a successful read or accepted command; 2 for invalid input; 3 for authentication, context or access denial; 4 for a transport/response failure, stale command or terminal failed operation; 6 when polling ends with the operation still pending or execution has not been confirmed. Keep the same operation ID to resume later. An accepted command may still have a pending operation; operation completion and business effect remain separate fields in the authoritative output.

## Remaining work

Workload certificate authentication, bootstrap, import/export, evidence and diagnostics commands remain incomplete administration work. Per-command qualification, packaging and full release acceptance are also outstanding. Browser-assisted transactions cover only their selected workflows.

When reporting a CLI issue, include the revision, command kind, safe error code and expected result. Exclude session files, browser profiles, passwords, security-key material and unredacted drafts. See [contributing](../../CONTRIBUTING.md) and [testing](../../docs/development/testing.md).
