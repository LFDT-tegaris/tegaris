# Tegaris console development

The console provides browser workflows for organization access, policy authoring,
review and release, contract interaction, privacy and operational evidence. It is
a Next.js application with React components and same-origin API routes. Those API
routes adapt browser requests to service owners; they do not replace backend
identity, authorization, approval or persistence checks.

Use the repository's [setup guide](../../docs/getting-started.md) and pinned
Node, pnpm and Rust versions before running these commands. The supported local
runtime requires Linux, Docker and systemd. A console process alone is insufficient
for authenticated application journeys.

## Find the owner of a change

| Path               | Responsibility                                                |
| ------------------ | ------------------------------------------------------------- |
| `app/[...path]/`   | Application route entry and workbench rendering               |
| `app/api/v1/ui/`   | Browser API adapters, request validation and service calls    |
| `components/`      | Forms, selection, session boundaries and task workflows       |
| `lib/`             | Shared browser-side validation and workflow helpers           |
| `app/globals.css`  | Styling and shared design tokens                              |
| `test/setup.ts`    | Component test environment                                    |
| `vitest.config.ts` | Separate Node server-contract and DOM component test projects |

Read the relevant backend owner before changing an API adapter. For example,
Identity owns session creation and context changes; a successful browser response
must agree with its durable session state. Keep organization, Participant, privacy
domain, resource and operation references bound to the selected context.

## Develop against a local evaluation

Follow the setup guide to start your own synthetic evaluation. Keep its data
directory outside the checkout and separate from automated test data. Use the
configured gateway origin to exercise authenticated behavior; direct `pnpm dev`
is useful for frontend development only when the required service configuration
and proxy routing are already supplied.

From the repository root, the console package commands are:

```sh
pnpm --filter @openpc/admin-web dev
pnpm --filter @openpc/admin-web check

bash scripts/maintenance/run-bounded.sh --profile focused -- \
  pnpm --filter @openpc/admin-web test --maxWorkers=2 \
  components/local-session.test.tsx
```

The focused reservation must account for any retained containers. Read the
[resource and testing guidance](../../docs/development/testing.md) before starting
a build or a second runtime on a shared machine. Do not assume that an available
port establishes adequate CPU, memory or disk capacity.

## Build and inspect the production package

Use the pinned Linux toolchain and a frozen dependency installation. Run from
the repository root in a clean task environment. Keep runtime credentials and
`.env` files outside the build source.

```sh
bash scripts/maintenance/run-bounded.sh --profile focused -- \
  pnpm --filter @openpc/admin-web build
```

This runs the Next.js production compiler, TypeScript validation, page generation
and dependency tracing. The supported container-build path also runs the shared
BFF contract gate before building the console image. Keep the affected component,
BFF and browser checks with the change; compilation covers a different boundary.

The build produces two parts used by the console image:

| Output                            | Purpose                                                             |
| --------------------------------- | ------------------------------------------------------------------- |
| `apps/admin-web/.next/standalone` | Traced Node server, runtime dependencies and compiled server routes |
| `apps/admin-web/.next/static`     | Compiled JavaScript, CSS and other static build assets              |

The server entry point in the standalone tree is
`apps/admin-web/server.js`. The static directory must accompany it at
`apps/admin-web/.next/static` inside the packaged tree. See the
[Dockerfile](Dockerfile) for the maintained image layout and pinned base image.

To inspect a fresh standalone package without connecting a backend, copy both
parts into a new directory outside the checkout:

```sh
review_root=$(mktemp -d "$HOME/tegaris-console.XXXXXXXX")
cp -R apps/admin-web/.next/standalone/. "$review_root/"
mkdir -p "$review_root/apps/admin-web/.next/static"
cp -R apps/admin-web/.next/static/. "$review_root/apps/admin-web/.next/static/"

OPENPC_LOCAL_RUNTIME=0 OPENPC_EVALUATION_UI=1 \
  HOSTNAME=127.0.0.1 PORT=3109 NEXT_TELEMETRY_DISABLED=1 \
  bash scripts/maintenance/run-bounded.sh --profile focused -- \
  node "$review_root/apps/admin-web/server.js"
```

Keep the server bound to loopback. The wrapper holds the shared resource lock
while this process runs; stop it with Ctrl+C before another bounded build or test.
Use a fresh output directory for each package inspection and retain failed
artifacts until the failure is understood.

In this deliberately unconfigured mode, verify:

| Request                                                        | Expected result                                                                |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `GET /signin`                                                  | HTTP 200, **Sign in to Tegaris**, and title **Tegaris \| Application Privacy** |
| A JavaScript URL under `/_next/static/` referenced by the page | HTTP 200 with the matching compiled asset bytes                                |
| `GET /home/session` or `GET /configure/policies`               | HTTP 307 to sign-in, preserving the requested return path                      |
| `GET /api/v1/ui/local-session`                                 | HTTP 200, `{ "enabled": false }`, and a no-store cache policy                  |

The configured response headers include `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`.

This inspection checks package relocation, startup, static assets and the stated
unconfigured routes. Use the supported runtime and browser journey below for
configured identities and governed operations. An image built for Alpine also
needs validation in that image; a host Node process is a separate environment.

## Run the first-policy browser journey

The package's `test:e2e` command delegates to the supported runtime CLI. It builds
or selects the required images, starts an isolated environment and runs the
first-policy browser/runtime journey. It is not a frontend-only development-server
check and does not require a private source package.

```sh
pnpm --filter @openpc/admin-web test:e2e \
  --data-dir "$HOME/tegaris-console-e2e"
```

Use a new or previously owned mode-0700 directory outside the repository. Its
path must be absolute, canonical and free of symlinks. Paths with spaces are
supported when quoted. The default is `$HOME/.local/share/openpc-policy-testing`
if `--data-dir` is omitted. Never select the data directory of a running manual
evaluation.

The runner retains private logs and diagnostic data and stops its diagnostic
services afterward, including after failure. Inspect the original failure before
retrying. A nonzero journey result remains nonzero through log capture and the
package command. Inherited scenario selectors and unknown options are rejected
before runtime allocation.

This journey establishes only its selected first-policy scenarios. The broader
public CI runtime command is `pnpm test:integration:runtime`; inspect its scenario
selection and resource requirements before running it. Existing scenario helpers
under `tests/integration/local-runtime/` cover additional browser tasks and
accessibility checks. Neither command is evidence of unexecuted institutional
onboarding, deployment, recovery or production scenarios.

## Reuse the console interaction patterns

### Workspace entry

Use [`WorkspaceEntry`](components/workspace-entry.tsx) when an operation needs a
selected organization workspace. In centrally signed-in deployments it directs
the user to **Account & workspace**, where authenticator verification and context
selection are performed. Pass the owning workflow's busy state so entry is not
offered as an active control during an in-flight change.

The component accepts the existing inline entry control as its child for supported
configurations that use inline selection. It chooses the presentation path; it does
not grant access, select a resource on the user's behalf or replace Identity's
session and context checks. A workflow must still bind each request and response
to the current authenticated actor.

### Loading, empty and error states

[`WorkspaceStatus`](components/workspace-status.tsx) displays the outcome supplied
by the owning response. Keep these distinctions intact:

| Owner outcome              | User-facing treatment                                                                                           |
| -------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Loading                    | Explain which workspace information is being read. Do not show an empty result while the read is pending.       |
| Authorized empty           | Show an empty state only when the owner confirms that the authorized result contains no records.                |
| Denied or hidden/not found | Preserve existence-hiding behavior. An opaque 404 uses neutral wording such as “Page not available.”            |
| Unavailable                | Explain that the read could not be completed; do not describe the user as signed out without evidence.          |
| Ambiguous write            | Explain that the outcome is unconfirmed and direct the user to read the original operation before resubmitting. |

A support disclosure may contain the code and request reference from a validated
public problem response. Keep them out of the primary heading and introductory
copy. Do not pass exception stacks, credential values, deployment addresses or raw
service response bodies into the component.

Only offer a retry when the owning response permits it, or when retrying a failed
read is explicitly supported. Use the existing request owner and show its pending
state. A retry control must not silently create a new business intent or replace an
unresolved original operation.

### Disclosures and inspection panels

Keep the selected task and its main action visible. Use a native `details`/`summary`
disclosure for optional reference data. Reserve
[`SecondaryPanel`](components/secondary-panel.tsx) for a separate inspection or
supporting form, with a specific trigger label that describes what opens.

Opening, closing or dismissing an inspection panel must not submit an operation,
clear a draft or change the selected actor. Preserve keyboard dismissal, focus
return and the existing first-invalid-field behavior. Test nested panels and a
closed panel containing an invalid required field when a change affects those
paths.

Use [`AccountMenu`](components/account-menu.tsx) for the account disclosure. It
supports Escape dismissal with focus return, closes after link activation or
when focus or a pointer moves outside, and resets its open state when the owning session controls are concealed.
Keep its children mounted so dismissing the menu does not discard local state.

### Visual consistency

Use the theme variables in [`app/globals.css`](app/globals.css) for surfaces,
text, borders, actions and focus. Keep a clear page heading, a short task
introduction and a distinct primary action. Use task names in controls rather than
implementation terms such as authenticated request or authoritative state.

Preserve visible disabled states, labels and focus indicators. Check light and
dark palettes, reduced motion, narrow screens and long identifiers. Do not rely
on color alone to communicate success, denial or pending work. Changing a shared
selector requires inspection of the affected forms, menus, tables and dialogs,
not only the page on which the change was first noticed.

## Verify a UI change

Test the actor, context, request and durable result together. Include loading,
empty, invalid, denied, unavailable and stale-response states. For a mutation,
verify the original operation after a lost response before submitting again.

Use keyboard interaction and inspect narrow screens, long resource identifiers,
labels, validation messages and focus recovery. Automated accessibility checks
complement rendered inspection and assistive-technology testing; a passing
primitive-button test does not establish complete application accessibility.

For session changes, conceal obsolete context promptly, abort superseded reads
and restore useful controls after cancellation or expiry. Never display an old
organization's data while a new session is being verified. See the
[testing matrix](../../docs/development/testing.md#minimum-behavioral-matrix) and
[contribution guidance](../../CONTRIBUTING.md).

Keep public examples synthetic. Do not commit real account credentials, session
cookies, authenticator material, operational addresses or customer data.
