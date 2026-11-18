# Changelog

## v0.9.0 (in preparation)

The source and documentation are published in this repository; the v0.9.0 tag has not yet been published. See the [release notes](docs/releases/v0.9.0.md) for the getting-started checks, validation limits and known issues.

### Included source

- Application privacy and policy administration services, public configuration sources and machine-readable interfaces.
- An administration console for identity, contract, policy, approval, runtime and evidence workflows.
- A Linux development workspace using synthetic identities and isolated data.
- Contributor guidance, governance, security contacts, architecture and integration documentation.

### Console

- Avoid repeated “Checking your session…” screens when navigating within a verified workspace.
- Preserve the organization selected by an invitation when opening its sign-in page.
- Show loading while approvals and release details are being read, then display the workflow or the reported error.

### Runtime and interactive demo

- Match RPC read permissions to the operation and data classes requested by the application.
- Preserve runtime preparation during discovery reconnection and coordinate request validation with authority refresh.
- Add an account-free hosted demo with three permitted contract reads and three access-boundary examples.

### Documentation

- Expanded setup, architecture, integration, interface, security and console guidance.
- Added testing, configuration, operations, glossary and structured validation guides.
- Documented HTTPS development sign-in and its separate internal certificate requirements.
- Prepared code/documentation license declarations and contribution guidance.
- Replaced customer-specific console examples with neutral synthetic examples.

### Known limitations

- The separate synthetic balance-read workflow remains unqualified: its intended permitted request returned an authorization denial. The six hosted demo examples have their own verified scope.
- Persistent hosted operation, credential continuity, performance and production deployment require further validation.
- No supported upgrade path from unpublished development builds is provided.

These entries describe the source available for v0.9.0. Included source and passing component tests do not establish that every documented workflow is qualified.
