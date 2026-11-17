# Installation configuration sources

This guide explains how a new installation authenticates the configuration schema and named profiles distributed with Tegaris. It is for platform engineers preparing an installation, developers integrating the installation helpers, and reviewers assessing configuration provenance.

Use the source, documentation and migrations from the same release. Complete the [setup prerequisites](../getting-started.md), then read the [configuration reference](../reference/configuration.md) and [operations guide](README.md). Source authentication is one installation requirement; it does not establish that services are configured, authorized or ready to accept application traffic.

## Files supplied with the release

The public source profile is `PUBLIC_OPERATIONS_SOURCE_V1`. Its inventory pins the exact bytes of one schema and five named profiles:

| File                                                                                                           | Purpose                                          |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| [`config/schema/effective-configuration.schema.json`](../../config/schema/effective-configuration.schema.json) | Shape and constraints of effective configuration |
| [`config/profiles/local.yaml`](../../config/profiles/local.yaml)                                               | Local evaluation defaults and requirements       |
| [`config/profiles/development.yaml`](../../config/profiles/development.yaml)                                   | Development profile                              |
| [`config/profiles/test.yaml`](../../config/profiles/test.yaml)                                                 | Test profile                                     |
| [`config/profiles/staging.yaml`](../../config/profiles/staging.yaml)                                           | Staging profile                                  |
| [`config/profiles/production.yaml`](../../config/profiles/production.yaml)                                     | Production profile definition                    |

The inventory is [`config/source-authentication/public-operations-source-v1.json`](../../config/source-authentication/public-operations-source-v1.json). The verifier also pins the inventory itself. These inputs are available in the source checkout; a separate source package is not needed for public installation.

A profile's name selects its configuration requirements. Selecting `production` does not certify an installation for production or supply the institution's identity provider, PKI, secret custody, service topology or operating procedures. Qualify those dependencies for the intended deployment.

Keep all six input files together even when selecting only one profile. The loader authenticates every distributed input before returning the selected profile. A changed unselected profile therefore causes authentication to fail too.

## Understand the trust boundaries

| Boundary                     | What it establishes                                                                  | What remains to be checked                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| Release acquisition          | The source/artifact and revision obtained by the operator                            | Its authenticity under the institution's release verification procedure       |
| Public source authentication | The schema and profiles match the verifier's pinned public inventory                 | Site configuration, signature and installation authority                      |
| Signed site document         | The site content is signed by the pinned installation issuer within its validity     | Correct deployment values and required bindings                               |
| Installation record          | The selected sources and initial trust are durably bound to an environment and scope | Generation staging and activation prerequisites                               |
| Staged generation            | The generation was accepted for staging                                              | Qualifications, consumers, units, secrets and other reported missing bindings |
| Effective generation         | The generation has completed its owning commit requirements                          | Actual service behavior and complete deployment acceptance                    |

The inventory is not a signature over the entire repository or a replacement for release verification. Its digest identifies these configuration inputs. Installation and generation records have their own identity, scope and signed-content checks.

## Authenticate a selected profile

Run this read-only example from the release checkout, with its pinned Node.js and pnpm versions and locked dependencies installed:

```sh
pnpm exec node --import tsx --input-type=module <<'JS'
import { readPublicOperationsSources } from './scripts/operations/read-public-installation-sources.mjs';

const { identity } = await readPublicOperationsSources({
  sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
  profile: 'local',
});
console.log(JSON.stringify(identity, null, 2));
JS
```

Replace `local` with one of `development`, `test`, `staging` or `production` when appropriate. The loader uses the checkout containing its own module by default. A caller may provide `root` as an absolute path to a release tree containing the expected files; that tree must match the same pinned inventory.

The result contains two different objects:

- `identity` identifies the selected public source profile, inventory digest, named profile, schema digest and profile digest. It is suitable for a configuration-provenance record, subject to the institution's disclosure rules.
- `custody` contains the authenticated bytes needed by the installation owner. Treat it as private installation data. Do not return it from public status endpoints, paste it into issues or substitute it with an operator-written `verified: true` flag.

For this public profile, identity fields are `sourceProfile`, `inventoryDigest`, `profile`, `configurationSchemaDigest` and `namedProfileDigest`. They describe the public inventory actually checked. The public verifier does not claim that an installation came from a different delivery archive.

The loader requires regular input files and reads each within its pinned size bound. It rejects unknown profiles, unexpected input fields, mixed source formats, malformed content and changed bytes. It does not fall back to another source when authentication fails.

## Supply institution-specific configuration

Leave the distributed schema, inventory and named profiles unchanged. Put deployment-specific values into the supported signed site configuration and its approved secret references. The named profile and schema constrain those values; they are not templates to edit in place until verification passes.

The signed site document binds the environment, generation and base generation, selected profile, site digest, schema/profile digests, declared content digest, issuer identity/epoch and signature validity. Use the installation issuer and custody procedure selected for that deployment. Do not reuse synthetic test signer material.

The installation helpers are in [`scripts/operations/installation-generation-store.mjs`](../../scripts/operations/installation-generation-store.mjs). Their connected responsibilities are:

| Helper                                                             | Inputs and responsibility                                                                                                 |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `installInitialOperationsEnvironment(pool, scope, input)`          | Installs initial issuer/environment pins, base-generation identity, schema/profile bytes and authenticated source custody |
| `stageInitialOperationsGeneration(pool, scope, sources, signed)`   | Validates the site sources and actual signed document, then stages the generation through the owning database transaction |
| `readOperationsGeneration(pool, scope, environment, generationId)` | Reads authoritative generation state and missing bindings in the requested scope                                          |

Use the loader's `custody` as `sourceAuthentication` in the installation input. The `schemaBytes` and `profileBytes` supplied to the installation owner must be the same authenticated files, and the pins must identify that schema and selected profile. The signing and candidate helpers in [`installation-config-signature.mjs`](../../scripts/operations/installation-config-signature.mjs) retain their signature and content validation responsibilities.

An installation connection must be authorized to enter the installation owner's role. Running application connections must retain their normal restricted privileges. Do not grant an application database-owner membership merely to make installation succeed. The [database installation guidance](README.md#database-installation-and-upgrades) explains this separation.

## Read staging and activation results

After staging, read the generation through its owning helper. Preserve the environment, participant/privacy scope, generation identity and signed bytes used in the original operation.

A `STAGED` generation can be source-authenticated while remaining ineffective. Inspect `missingBindings` for outstanding qualifications, secret bindings, consumer readiness and unit readiness. Resolve each through its owning workflow. Source authentication must not remove an unrelated blocker or manufacture readiness from a caller-provided status value.

Read back the same generation after reconnecting. Installation bytes and their digest must remain unchanged. A foreign scope or a different generation identifier must not authenticate against another installation's source binding.

Keep credentials and custody out of the readback shown to application users. Public diagnostic output should identify the failed boundary without disclosing installation bytes, signing material or secret references.

## Offline and controlled environments

For an offline installation, transfer the reviewed release tree or approved artifacts, all six configuration files and their public inventory through the institution's existing artifact process. Obtain dependencies through its approved registry or prepared dependency cache. The source loader itself does not retrieve files from the network.

Verify the release before installation, then run the same source-authentication check inside the destination environment. Retain the release identity and selected public provenance fields in the private installation record. Avoid copying a live environment's database, authenticator material or installer credentials to demonstrate a fresh installation.

## Upgrades and retained installations

The source-authentication database functions are installed through the release's ordered migrations. Apply the supported installer for the selected release and verify its migration ledger. Previously applied SQL remains immutable; a source-verification change belongs in a new migration.

An existing installation retains the source custody and provenance originally admitted for it. Introducing the public profile does not rewrite earlier installation records, extend a certificate or replace a signed generation. The verifier retains explicit format handling for supported historical records; that compatibility is independent of the source format selected for a new installation.

Before an upgrade, retain the current migration identities/digests, installation bytes/digest and representative signed-operation readback. Afterward verify that the original records still authenticate and have unchanged bytes, then exercise the new public installation path separately. Follow the supported continuation for any unfinished operation rather than creating a replacement intent around a recorded effect.

## Diagnose source failures

| Observation                                            | Check                                                                                       | Supported response                                                                            |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `C17_SOURCE_AUTHENTICATION_FAILED`                     | Exact release tree, source-profile selection, inventory and all six input files             | Restore the reviewed release files and repeat the read-only verification                      |
| Selected profile exists but authentication fails       | Other distributed profiles and the inventory, including size/byte changes                   | Check the complete input set; selecting a different profile does not repair a changed release |
| Read-only loader succeeds but installation is rejected | Installation pins, scope, schema/profile bytes, supplied custody and installation authority | Preserve the failure and correct the specific mismatched input or authority                   |
| Source is accepted but staging rejects the site        | Site schema, signed content, issuer, signature and validity                                 | Prepare the correct signed document through its owning process                                |
| Generation is staged but ineffective                   | Authoritative `missingBindings`                                                             | Complete the named dependency; retain the source binding                                      |
| Retained installation fails after an upgrade           | Applied migration bytes, stored installation bytes and historical verifier compatibility    | Stop further mutations and investigate the original record; do not edit its custody or ledger |

Restore the configuration files and inventory from the selected release when verification fails. Do not change verifier constants or reduce validation to accept altered files.

## Contributor verification

Pure source checks run without a database:

```sh
bash scripts/maintenance/run-bounded.sh --profile focused -- \
  node --test scripts/operations/public-operations-source.test.mjs
```

The focused native fixture is [`postgres-public-operations-source.test.ts`](../../tests/integration/identity/postgres-public-operations-source.test.ts). It uses the integration runner's isolated admin/runtime database configuration, creates an installation-only restricted login, and exercises actual signed staging, rejection without effects, scope isolation, tamper handling and reconnect readback. Its private temporary material must remain outside the checkout. It is installation-owner acceptance; it does not demonstrate ordinary application authority or effective-generation readiness.

Use the standard [testing and resource guidance](../development/testing.md) when running it. A test skipped because database inputs are absent is not a native acceptance pass. Record the selected test names and actual results, including failed and unrun checks.
