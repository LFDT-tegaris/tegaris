# Set up a local development workspace

This guide creates an isolated workspace for evaluating the console and developing integrations. It uses synthetic organizations, accounts and initial identity trust. It does not demonstrate production installation, institutional onboarding or production key custody.

Read the [release scope](releases/README.md) and [privacy model](security/privacy-model.md) before selecting a revision. The instructions below describe the Linux development setup and its required tools. Keep the source revision and command outputs with your test results so another engineer can reproduce the setup.

## 1. Prepare the machine

Use a dedicated Linux machine or VM with systemd, Docker Engine, the Compose plugin and Buildx. The helper requires a server-local Docker socket and a working systemd user session. Docker Desktop on macOS or Windows is not a supported full-stack setup for this helper.

| Requirement      | What to verify                                                                                                      |
| ---------------- | ------------------------------------------------------------------------------------------------------------------- |
| Source           | A complete Git checkout of the selected revision; this entry point requires Git metadata                            |
| Node.js and pnpm | Exact versions in [package.json](../package.json)                                                                   |
| Rust             | Toolchain in [rust-toolchain.toml](../rust-toolchain.toml)                                                          |
| System tools     | Git, Python 3, OpenSSL, curl, ripgrep (`rg`), GNU coreutils, util-linux, systemd and Bash                           |
| Docker           | Engine access from your account, Compose and Buildx available, and a local Unix socket                              |
| Browser support  | The pinned Playwright browser and its operating-system libraries for browser tests                                  |
| Storage          | A private data directory outside the checkout, plus space for dependencies, images, databases and retained failures |

The source currently pins Node.js 24.19.0, pnpm 11.20.0 and Rust 1.98.0. Recheck the files when switching revisions. Do not update a lockfile to accommodate a different local tool version.

Use a dedicated VM with at least 24 GiB RAM; 32 GiB provides more headroom. The image-build command below admits an 8 GiB host command and an 8 GiB builder. Allow at least 130 GiB of free disk for that command: 80 GiB of estimated build space and a 50 GiB reserve. These are admission budgets, not guarantees of actual use. The runtime-target profile reserves 2 GiB for the host command and 9 GiB for containers. Retained containers and other workloads need additional capacity.

Do not expose the Docker socket over a network. Use an environment containing no production workloads or customer records.

## 2. Select the source and execution environment

The public repository is [LFDT-tegaris/tegaris](https://github.com/LFDT-tegaris/tegaris). Clone it into a new directory:

```sh
git clone https://github.com/LFDT-tegaris/tegaris.git tegaris
cd tegaris
git tag --list
```

Select a published release tag and use its matching documentation. For example, **after v0.9.0 is published**:

```sh
git switch --detach v0.9.0
```

A release marked “in preparation” has no published tag yet. Do not treat a missing tag as an installation failure or substitute an unrelated revision. The full-stack helper requires Git metadata, so use a checkout rather than an extracted source archive.

For contributor work, create a branch from the selected revision before editing. Record the source and tool versions:

```sh
git rev-parse HEAD
git status --short
node --version
pnpm --version
rustup run 1.98.0 rustc --version
docker compose version
docker buildx version
```

Run subsequent commands from the repository root. Use a Linux login session with a working user service manager. Repair a missing systemd user bus before starting a workload.

Use a consistent pnpm execution mode during installation and later commands. On a dedicated development machine, make that choice explicit:

```sh
export CI=true
```

The helper rejects most inherited `OPENPC_*` variables because scenario and fault selectors can change its behavior. Start from a clean task environment. Do not copy environment variables from an unrelated test session.

## 3. Check prerequisites

```sh
bash scripts/operations/policy-testing.sh check
```

A successful check reports that prerequisites passed without building images or starting services. Resolve the first reported prerequisite before repeating the check. Do not bypass local-Docker, toolchain or resource checks.

## 4. Install locked dependencies

Choose a new, absolute data path outside the checkout:

```sh
bash scripts/operations/policy-testing.sh install --data-dir "$HOME/tegaris-dev"
```

This installs locked JavaScript dependencies, fetches locked Rust dependencies and installs pinned Chromium. Operating-system packages and Chromium system libraries must already be available. Package lifecycle scripts are disabled by the dependency-install command.

Private logs are created under the data directory. An existing directory must be owned by your account, have mode `0700`, resolve to its canonical path and not be a symlink. Choose another path if those conditions do not describe the intended directory; do not recursively change permissions on unrelated data.

## 5. Initialize the workspace

### Build the service images

Build all seven application images before the first workspace startup. The QA startup helper rebuilds Identity when needed and expects the remaining application images to be available locally. Dependency installation alone does not create them.

Run this step before starting a workspace on the dedicated machine. Keep the build output outside the checkout and let the bounded runner enforce memory, CPU and disk admission:

```sh
bash scripts/maintenance/run-bounded.sh \
  --profile image-build --memory-gib 8 --external-memory-gib 8 \
  --peak-disk-gib 80 --reserve-disk-gib 50 -- \
  env OPENPC_EVALUATION_UI=1 OPENPC_LOCAL_RUNTIME=1 \
    OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 \
    OPENPC_LOCAL_RUNTIME_BUILD_ONLY=1 \
    OPENPC_LOCAL_RUNTIME_TMP_ROOT="$HOME/tegaris-dev/image-build" \
    bash tests/integration/local-runtime/run-compose-e2e.sh
```

The selected build must finish with `OPENPC_LOCAL_IMAGE_BUILD|PASS|runtime-acceptance=pending`. It prepares the owned images for Control worker, Fact, Policy, Identity, Participant, Control API and the console, then stops the builder. It does not initialize a workspace or prove a business workflow. Retain a failed build's log and diagnose its first error before another attempt; do not remove database volumes or lower resource checks to make admission pass.

### Start the services

```sh
bash scripts/operations/policy-testing.sh qa-start \
  --local-qa-fixture --data-dir "$HOME/tegaris-dev"

bash scripts/operations/policy-testing.sh qa-status \
  --data-dir "$HOME/tegaris-dev"
```

The helper selects the current Tegaris console for new workspaces (`OPENPC_EVALUATION_UI=1`). A retained workspace keeps its saved configuration; changing an environment variable does not upgrade its running services.

The fixture flag is required. Initial startup prepares the selected services, initializes databases and creates synthetic accounts. Cold migration can take several minutes. Let the supported runner report its result; a quiet interval alone does not prove migration has stopped.

Status reports the retained workspace, service states and private accounts-file location. Confirm expected services are running and healthy before testing the console. A completed migration container may be stopped with exit code zero; it is not a long-running service.

The retained workspace is test state. Keep databases, keys, manifests and the account file together. Never copy a live database directory to create another environment.

## 6. Sign in

Open **http://localhost:8080/signin** on the development machine. Obtain an account from the private file reported by `qa-status`; do not paste that file into an issue or chat channel.

Complete sign-in and register an authenticator when prompted. Select the organization you intend to administer. Use separate browser sessions for requester and reviewer so the workflow exercises distinct identities.

For a remote browser, follow the [hosted-demo guide](development/hosted-demo.md) to configure a valid HTTPS origin before initialization. Do not disable certificate checks or issuer validation.

## 7. Complete a first workflow

### Confirm application prerequisites

Before authoring a policy, verify the configuration needed by the selected application path. Workspace startup and human sign-in do not establish that modules, workload credentials or runtime permissions are ready.

| Prerequisite        | What to confirm                                                                                                                                     | If it is missing                                                                                                                                                   |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Modules             | The required releases and their dependencies are registered, installed and active, with current enabled bindings in the intended privacy workspace. | Follow [module setup and activation](operations/modules.md), starting with the publisher's exact release bundle and the deployment catalogue.                      |
| Workload identity   | The intended workload has a current, unexpired credential for the selected runtime.                                                                 | Use the supported workload and [certificate lifecycle](operations/certificates.md) process. Human authenticator verification does not renew a workload credential. |
| Workload authority  | Current role assignments and authority envelopes cover the intended capability and privacy workspace.                                               | Complete the governed access workflow; a selectable workload does not itself prove permission.                                                                     |
| Contract and target | The synthetic ABI, contract address, test network and runtime binding describe the same deployment.                                                 | Complete the contract and network configuration before using those references in a policy.                                                                         |
| Independent review  | Requester and reviewer have separate accounts and the required authority and authenticators.                                                        | Complete their supported account and access setup before submitting a change.                                                                                      |

For the Participant RPC workflow, load **Participant RPC access** using the existing authenticator when requested. In **Compose role-bound RPC policy**, inspect **Enabled module bindings** and the named missing modules. The **Workload** selector is populated from current workload credentials. If the selector is empty, check the workload credentials before continuing. Creating another policy set does not populate it.

Use the [console guide](user-guide/README.md) to inspect authorized records and complete setup. Retain the first failed step and its safe error reference. Do not seed module, approval or credential records directly in a database to make the workflow proceed.

### Run the policy journey

Follow the [console guide](user-guide/README.md):

1. Register a synthetic contract definition and ABI.
2. Associate it with the intended test network and runtime binding.
3. Define a policy for one narrowly scoped operation.
4. Simulate an allowed input and a deliberately denied input.
5. Submit the selected version for independent review.
6. Publish the approved version and inspect target activation.
7. Test the governed endpoint with the intended application identity.

Simulation, approval, release submission and runtime activation are different results. Record each separately. Do not use an unrestricted node endpoint to turn a denied governed request into a successful test.

## 8. Stop and resume

```sh
bash scripts/operations/policy-testing.sh qa-stop --data-dir "$HOME/tegaris-dev"
bash scripts/operations/policy-testing.sh qa-start \
  --local-qa-fixture --data-dir "$HOME/tegaris-dev"
```

The same directory resumes the existing workspace through its recorded service identities. It does not create new accounts or repeat business operations. Inspect status after resuming and reconcile interrupted operations through their original references.

The `run` command performs automated initial policy activation and withdrawal checks, including a renewal-expiry failure case, and leaves its diagnostic environment stopped. Each invocation creates a fresh test environment; it does not resume the manual workspace or run the complete governed-RPC suite. See [automated policy checks](development/testing.md#automated-policy-activation-and-withdrawal) for the command, expected output and failure handling.

## Completion criteria and failure handling

The setup exercise is complete when expected services are healthy, sign-in reaches the intended organization and the first allowed and denied workflows have recorded outcomes. Use those results as the starting point for the integration, security and operational checks in the [validation guide](evaluation/README.md).

### Verify each stage separately

| Stage                   | Evidence to retain                                                                            | Continue with                                                               |
| ----------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Prerequisites           | Successful `check` result and the pinned tool versions                                        | Locked dependency installation                                              |
| Dependency installation | Successful `install` result and its private log location                                      | Application image build                                                     |
| Application images      | Seven completed application builds, the image-build pass marker and stopped builder           | Workspace initialization and service startup                                |
| Workspace startup       | `qa-start` result and a fresh `qa-status` observation                                         | Console sign-in and organization selection                                  |
| Console access          | Successful sign-in, authenticator verification and the intended organization context          | Contract registration and the first policy workflow                         |
| First policy            | Reviewed policy version, release reference and observed target activation                     | A governed request from the intended application workload                   |
| Application outcome     | The workload's allowed result and the deliberately denied case                                | Disclosure, foreign-organization and recovery cases in the validation guide |
| Stop and resume         | Status after resuming the same data directory and authorized readback of the original records | Reconciliation of any interrupted operation before further changes          |

Record the operating system, source revision and any local modifications alongside these results. Include the selected network, contract and runtime binding so another engineer can identify the environment that produced the observations. Keep credentials, account files, private keys and confidential payloads out of the shared record.

For each command, record whether it completed successfully, failed or was interrupted. For a browser or application step, record the expected result, the actual permitted result and the observation time. Mark an unrun step as unrun; do not carry a passing result across a changed source revision or environment without checking compatibility.

### Recover an interrupted setup

If initialization fails, retain the private log and workspace. Inspect the last completed phase before retrying. Do not delete migration records, rerun identity seeding or remove volumes to hide a failure. See [troubleshooting](user-guide/troubleshooting.md) and [operations](operations/README.md).

Start with `qa-status` for the same data directory. Distinguish an unavailable status check from a confirmed stopped service. If the helper reports an ownership, manifest, identity or migration mismatch, preserve the evidence and investigate that mismatch before startup; selecting a new directory is not recovery of the original workspace.

If a policy or application request was already submitted, retain its original reference and use the supported readback before another mutation. A browser timeout or interrupted terminal does not establish that the server performed no work. Resume only after identifying the original outcome or keeping it explicitly unresolved for investigation.
