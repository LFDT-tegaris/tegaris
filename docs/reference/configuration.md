# Development configuration reference

This reference covers the supported convenience entry point and the hosted development origin. It is not a complete production configuration specification. Component schemas and deployment assets in the selected revision remain authoritative for their own settings.

## Installation sources

The [installation configuration source guide](../operations/installation-source.md) covers `PUBLIC_OPERATIONS_SOURCE_V1`, its distributed schema/profiles, signed site values and installation-owner requirements. These are separate from the development lifecycle convenience commands below.

## Convenience commands

Run `bash scripts/operations/policy-testing.sh --help` to inspect the current command contract.

| Command     | Behavior                                                  | Important distinction                                 |
| ----------- | --------------------------------------------------------- | ----------------------------------------------------- |
| `check`     | Validates tools, Docker access and systemd session        | Does not initialize a workspace                       |
| `install`   | Installs locked language dependencies and pinned Chromium | Does not install all OS/browser system libraries      |
| `build`     | Builds selected development images                        | Does not run the acceptance journey                   |
| `run`       | Tests initial policy activation and withdrawal            | Leaves its diagnostic environment stopped             |
| `qa-start`  | Initializes or resumes a retained manual fixture          | Requires `--local-qa-fixture`                         |
| `qa-status` | Reads the retained fixture's status                       | Health is not proof of a business operation's outcome |
| `qa-stop`   | Stops recorded services and preserves data/keys           | Does not delete the workspace                         |

## Data directory

Use `--data-dir ABSOLUTE_PATH`. The helper's default is `$HOME/.local/share/openpc-policy-testing`; explicit per-workspace paths are easier to track.

The path must be outside the source checkout, canonical and not a symlink. An existing directory must belong to the executing account and have mode `0700`. The helper maintains private `logs` and `runtime` children and refuses unsafe pre-existing child links or permissions.

For a manual fixture, `qa-start` with the same data directory resumes its recorded workspace. The `run` command creates a fresh test environment under its data directory on every invocation; it does not resume a previous run. Keep automated tests and a manual fixture in separate directories. Changing the directory does not reconcile an interrupted operation in the original environment.

See [automated policy checks](../development/testing.md#automated-policy-activation-and-withdrawal) for their scope, expected output and retained diagnostics.

## Toolchain and process environment

| Setting                        | Use                                                                                            |
| ------------------------------ | ---------------------------------------------------------------------------------------------- |
| `CI=true`                      | Makes the chosen pnpm execution mode explicit; keep installation and later commands consistent |
| `OPENPC_QA_PUBLIC_ORIGIN`      | Optional HTTPS origin used by `qa-start` for a hosted development workspace                    |
| Docker context / `DOCKER_HOST` | Must resolve to the supported server-local Unix socket for this helper                         |

The helper rejects unrelated inherited `OPENPC_*` selectors. Avoid a shell environment accumulated from previous scenarios. Advanced runner and fault-injection settings are not ordinary application configuration.

Pinned Node.js, pnpm and Rust versions are recorded in the root package and toolchain files. Resource profiles are implemented by the maintenance runner. Do not silently replace either with local defaults.

## Console selection

The convenience helper defaults `OPENPC_EVALUATION_UI` to `1`, selecting the current Tegaris console for a new workspace and its browser journey. An explicit `0` selects the earlier shell for compatibility checks; an explicit `1` keeps the current console. Other values, including an empty value, are rejected before allocating a workspace.

When invoking the Compose runtime directly, set `OPENPC_EVALUATION_UI=1` in the environment shared by the runtime and browser driver. The Compose template retains its own default; the convenience helper supplies the current-console selection.

Resuming an existing workspace preserves its recorded configuration and images. Console selection is not an upgrade command. Follow the deployed revision's supported image-update and verification procedure for an existing installation.

## Organization context for sign-in

### Invitations and organization links

After an invitation is accepted, its **Continue to sign in** link carries the invitation's organization into sign-in. Keep this context when directing a newly activated member to the console. An organization-specific entry link has this form:

```text
/signin?returnTo=%2Fhome%2Fsession&participantId=<existing-participant-uuid>
```

The console validates the organization identifier and sends it to the existing sign-in API. Malformed or repeated organization parameters block sign-in instead of falling back to a different organization. A session for another organization does not satisfy the requested sign-in, and changing the organization cancels an outstanding authorization request.

The organization in a link is routing information, not an access grant. Identity still checks the exact provider account and active membership. Acceptance, activation, initial authenticator registration and workspace access remain separate steps.

### Single-organization default

For a console serving one organization, configure its existing Participant ID on the `admin-web` service:

```yaml
services:
  admin-web:
    environment:
      OPENPC_OIDC_PARTICIPANT_ID: '<existing-participant-uuid>'
```

This selects the organization when the console starts an OpenID Connect sign-in. Identity still resolves the provider's issuer, subject and audience against the organization's existing credential binding. The setting creates no membership, credential, role assignment or workspace permission. Normal authenticator verification and independent approval still apply.

Set this in the console's deployment configuration, validate the rendered configuration, then follow the installation's controlled service-update procedure. Setting a variable in an operator's shell does not update a running container. The retained fixture's convenience commands preserve their recorded configuration; they do not apply a new setting automatically.

After the update, check sign-in with an invited, active member whose provider returns an external account identity. Confirm that another organization's identity cannot enter the selected organization. Do not add internal principal identifiers to provider tokens to work around a missing organization context. Leave the default unset for a console used by several organizations and distribute organization-specific entry links.

## Hosted origin

Example:

```sh
OPENPC_QA_PUBLIC_ORIGIN=https://demo.example.org \
  bash scripts/operations/policy-testing.sh qa-start \
  --local-qa-fixture --data-dir "$HOME/tegaris-demo"
```

The setting accepts an HTTPS origin with an optional explicit non-default port. It rejects credentials, a path, query, fragment and trailing slash. The saved configuration aligns the identity issuer, callback and public authorization endpoint. New synthetic accounts are bound to that issuer.

Set it before initializing a new workspace. Resuming a retained workspace preserves its saved configuration; an environment variable is not a migration mechanism for its identities. See [hosted setup](../development/hosted-demo.md).

## Development endpoints

The local console gateway is normally reached at `http://localhost:8080`. Hosted development uses a reverse proxy with a valid public HTTPS origin. Its identity routes must reach the development provider, while the callback reaches the console gateway.

Keep database, provider and service ports private to the selected topology. A public console hostname does not justify exposing every mapped development port. Document actual endpoint identities and network controls in the environment's private configuration record.

## Secret and certificate handling

The accounts file, database credentials, session material, private keys and retained manifests belong outside source control. Use private filesystem permissions and the environment's approved access process.

Public HTTPS, internal service TLS and signing-provider trust have different lifecycles. Renewal of one does not renew the others. The local fixture creates short-lived internal certificates; inspect their real expiry and use supported renewal/recovery procedures. Do not alter retained trust records or validity timestamps to extend a test.

## Configuration-change verification

For each change, record the old and intended values privately, identify the affected services, validate the configuration and inspect the effective running state. Check the relevant user journey after restart. A successful configuration parse is not proof that traffic uses the intended endpoint or identity.
