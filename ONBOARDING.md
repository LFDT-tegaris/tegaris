# Get started with Tegaris Application Layer Privacy

Tegaris brings application identity, scoped permissions, policy review and runtime controls into one administration environment for shared EVM networks. Start here to inspect the source and establish a workspace for an application or platform team.

The first public source release is being prepared as **v0.9.0**. Read its [release notes](docs/releases/v0.9.0.md) before selecting tests. The initial checks cover setup, workspace access, console inspection and selected component tests. The intended permitted RPC path remains unqualified; its current failure is recorded in the release notes.

## 1. Choose the test boundary

Use a dedicated Linux machine or VM with synthetic data. The full-stack helper requires systemd, a local Docker Engine, Compose and Buildx. Plan for 32 GiB RAM and at least 130 GiB free disk for the documented image build. Retained environments require additional capacity.

Select the reviewed source revision and keep it with your test record. Use the pinned Node.js, pnpm and Rust versions in the [setup guide](docs/getting-started.md). A cold setup includes dependencies, seven service-image builds and database initialization; no fixed setup duration is promised.

Tegaris governs configured application interfaces. Access to the underlying node or database must be considered separately. The [architecture guide](docs/architecture.md) explains the request path and trust boundaries.

## 2. Check the machine

From the repository root:

```sh
bash scripts/operations/policy-testing.sh check
```

**Expected result:** the prerequisite check passes without starting services. If it reports a missing tool, unsupported Docker connection or resource issue, resolve that specific requirement before continuing.

## 3. Build and start the workspace

Follow the [local setup guide](docs/getting-started.md) in order: locked dependency installation, service-image build, then workspace startup. Keep the private data directory outside the checkout. After the prerequisite, dependency and image-build stages pass, start and inspect the workspace:

```sh
bash scripts/operations/policy-testing.sh qa-start \
  --local-qa-fixture --data-dir "$HOME/tegaris-dev"

bash scripts/operations/policy-testing.sh qa-status \
  --data-dir "$HOME/tegaris-dev"
```

**Expected result:** the expected long-running services are healthy and status identifies the retained workspace and private accounts-file location. A completed migration job may be stopped with exit code zero. Keep the private account file out of shared logs and support reports.

Use [troubleshooting](docs/user-guide/troubleshooting.md) if startup fails. Retain the failed result and data directory rather than repeating initialization or deleting volumes.

## 4. Enter the console

Open **http://localhost:8080/signin** on the development machine. Use a generated synthetic account, register its authenticator when prompted and select the intended organization.

**Expected result:** the account and workspace are clear, and the console opens in that context. Authentication and authorization are part of workspace testing; a page loading successfully does not establish permission to execute an application request.

Use the [console guide](docs/user-guide/README.md) to inspect:

| Area                     | What to inspect                                                             |
| ------------------------ | --------------------------------------------------------------------------- |
| Account and organization | Selected account, workspace and available roles                             |
| Contracts and ABI        | Contract identity, method definitions and network binding                   |
| Policies                 | Drafts, immutable versions and their stated scope                           |
| Approvals and releases   | Requester, independent reviewer and distinct approval/release states        |
| Runtime and evidence     | Observed target state, operation references and available decision evidence |

Empty lists are valid in a new workspace. Record which resources were preconfigured and which you created during testing. Test keyboard navigation, invalid inputs and context changes alongside the normal screens.

## 5. Run a defined first test

Follow tests E01–E06 in the [getting-started checks](docs/releases/v0.9.0.md#getting-started-checks). The documentation check is a useful first source check:

```sh
python3 scripts/docs/check-docs.py
```

For application testing, define one synthetic contract method, an intended permitted caller and a caller that must be denied. Follow the [integration guide](docs/development/integration.md) and record both results independently. An approval or successful activation does not prove the permitted request succeeded. Do not treat the current known RPC failure as an expected pass.

The [interface reference](docs/reference/interfaces.md) links to OpenAPI, event contracts and owning schemas. It identifies incomplete API coverage so an integration does not assume an undocumented endpoint or authentication model.

## 6. Record the result and stop safely

Keep a short test record: revision, tool versions, selected test, input, expected outcome, observed outcome and passed/failed/not-run status. Include only synthetic, redacted reproductions in public reports.

Stop the workspace while preserving its data:

```sh
bash scripts/operations/policy-testing.sh qa-stop \
  --data-dir "$HOME/tegaris-dev"
```

Resume with `qa-start --local-qa-fixture` using that same directory, then inspect `qa-status`. A restart does not renew expired credentials or runtime authority. Consult the [hosted development guide](docs/development/hosted-demo.md) before keeping a workspace running for a scheduled demonstration.

## Continue according to your role

| Role                              | Next reference                                                                                                                |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Application developer             | [Integration](docs/development/integration.md) and [API contracts](docs/reference/interfaces.md)                              |
| Platform or operations engineer   | [Configuration](docs/reference/configuration.md) and [operations](docs/operations/README.md)                                  |
| Security or architecture reviewer | [Privacy model](docs/security/privacy-model.md) and [validation matrix](docs/evaluation/README.md)                            |
| Contributor                       | [Development](docs/development/README.md), [testing](docs/development/testing.md) and [contribution process](CONTRIBUTING.md) |

Use [SUPPORT.md](SUPPORT.md) for questions and reproducible issues. Report suspected vulnerabilities privately through [SECURITY.md](SECURITY.md).
