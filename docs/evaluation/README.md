# Validation guide for application and platform teams

Use this guide to plan and record integration testing. It defines questions and evidence to collect; it is not a certification checklist or a claim that the current release satisfies every criterion.

For v0.9.0, begin with the [getting-started checks](../releases/v0.9.0.md#getting-started-checks) and its known issues. It covers source setup, workspace access, console inspection and selected component tests. The functional, privacy, recovery and operational scenarios below are a broader assessment plan, not a list of completed release checks.

## Establish scope and ownership

Select one application workflow and a source/release revision. Name the application, platform, security, identity/custody and operational owners. Agree on synthetic data, permitted infrastructure access and the handling of test evidence.

Write a short scope statement covering the actors, organizations, contracts, networks, operations and disclosed information. Identify direct node/database access that exists outside the proposed Tegaris boundary. Record excluded capabilities explicitly.

## Validation stages

| Stage                     | Work                                                                 | Exit evidence                                                              |
| ------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Architecture              | Review request paths, identity boundaries, custody and bypass routes | Agreed deployment boundary and unresolved design questions                 |
| Reproducibility           | Follow setup from the selected source in an isolated environment     | Revision, tool versions, commands, outcomes and required setup corrections |
| Functional journey        | Configure one contract/policy and complete review through activation | Selected versions, operations, target state and permitted result           |
| Privacy and authorization | Exercise unauthorized actors and withheld information                | Expected denials and absence of prohibited effects/disclosures             |
| Failure and recovery      | Interrupt services or responses within the agreed test scope         | Original-operation readback, preserved state and restart results           |
| Operations                | Assess certificates, backups, observability, upgrades and support    | Deployment-specific procedures and remaining qualification work            |
| Decision                  | Review results against the agreed workflow                           | Accepted evidence, failed/unrun checks, limits and next actions            |

## Scenario matrix

| Area               | Positive scenario                                              | Negative or recovery scenario                                        |
| ------------------ | -------------------------------------------------------------- | -------------------------------------------------------------------- |
| Identity           | Intended workload authenticates with current credentials       | Wrong issuer, expired credential, revoked grant                      |
| Organization scope | Authorized participant reads its permitted resource            | Another participant requests the same resource or collection         |
| Policy review      | Authorized independent reviewer approves the selected version  | Requester self-approval, stale version, expired request              |
| Activation         | Selected release is observed at the intended target            | Target unavailable, partial activation, earlier version still active |
| Disclosure         | Caller receives only permitted fields/records                  | Broader receipt, event, export or error-detail access is denied      |
| Decision inputs    | Valid, fresh source observation supports the decision          | Missing, stale, invalid-provenance or reorganized input              |
| Mutation           | One intended write produces its expected outcome               | Lost response, exact replay, conflicting replay, restart             |
| Client behavior    | Application distinguishes operation progress and final outcome | Timeout or unavailable status is incorrectly treated as failure      |
| Console            | User completes the task with clear context and feedback        | Context switch, stale response, validation failure, narrow screen    |

Select applicable scenarios from the actual release. Mark unsupported scenarios as outside scope rather than treating them as passed or silently omitting them.

## Evidence record

For each scenario, record:

1. Source revision and deployed artifact identifiers.
2. Actor, organization, resource and relevant policy/release versions.
3. Preconditions and synthetic inputs.
4. Expected decision, durable effect and permitted disclosure.
5. Exact command or user steps.
6. Observed response and authoritative state readback.
7. Result: passed, failed, not run or outside scope.
8. Limitations, owner and follow-up action.

Keep private environment details in the institution's evidence system. Public issues should contain a reduced synthetic reproduction, not exported test archives.

## Prepare a demonstration

Use one synthetic application workflow throughout the session. Prepare a permitted actor, an actor without the required permission and a reviewer who is independent of the requester. Keep each account separate. Agree which contract method and inputs will succeed, which will be rejected and what information each actor may receive.

Before inviting an audience, rehearse on the exact deployed revision. Confirm sign-in, existing-authenticator verification, organization selection and the authority needed by each actor. Check certificate and signing-credential validity for the session and its preparation period. Follow the [certificate lifecycle guide](../operations/certificates.md) if renewal is needed; a valid public HTTPS certificate alone does not establish internal signing continuity.

Prepare the contract, ABI, network binding and synthetic inputs through their supported workflows. Record any policy versions, approvals or activations created before the session. Explain that starting state to the audience so a prepared record is not mistaken for a change performed during the demonstration.

### Demonstration sequence

Use the [console guide](../user-guide/README.md) for the detailed controls and required permissions.

| Step                     | Presenter action                                                                                                                       | Observable result                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Enter the workspace      | Sign in, verify the existing authenticator and select the intended organization.                                                       | The account and working context are visible; no record from another context remains selected.                                |
| Establish the resource   | Open **Contracts & ABI** and inspect the prepared contract, network binding and method.                                                | The displayed contract, network and typed arguments match the agreed workflow.                                               |
| Inspect the policy       | Open **Policies** and select the immutable version being evaluated.                                                                    | Its scope and disclosure rules match the permitted actor and intended operation.                                             |
| Compare decisions        | In **Simulation**, run the permitted input and the agreed denied input against that version.                                           | Both results identify the selected version and can be compared with the expected decisions.                                  |
| Review independently     | In **Approvals & releases**, have the separate reviewer inspect and approve the exact proposed change, if this is part of the session. | The review identifies the correct requester, reviewer and version. Required authentication is completed.                     |
| Observe activation       | Publish through the supported release workflow and inspect the intended runtime target, or inspect the activation prepared earlier.    | The target's observed state identifies the selected version. An accepted publication is recorded separately from activation. |
| Exercise the application | In **Contract interactions**, or through the configured test application, submit the permitted request and its denied counterpart.     | The permitted request has its expected outcome. The denied request produces no protected effect or disclosure.               |
| Inspect the evidence     | In **Evidence & operations**, inspect the original operations and their available evidence.                                            | References connect the requests, selected policy and authoritative outcomes without exposing confidential inputs.            |

If an independent review or activation was prepared earlier, show its existing record and state that clearly. Do not describe a simulation as a runtime request or approval as activation. Mark unavailable or unsupported steps in the test record.

### Rehearsal and interruption checks

Complete the whole sequence with the actual presenter and reviewer accounts before the session. Check keyboard navigation, dialogs, long identifiers, loading, empty and error states, and the screen width used for presentation. Refresh or re-enter the workspace and verify that the selected records still reflect authoritative state.

If a write times out, retain its original reference and use supported readback to determine its outcome. Do not submit a replacement to keep the presentation moving. If a required actor, credential, approval or target becomes unavailable, stop the affected step and explain the limitation. Preserve completed records and return through the supported recovery process.

At the end, sign out, review captures before sharing them and store the results using the evidence record above. Leave credentials, account files, tokens and private infrastructure details out of public demonstration material. Perform any cleanup through the operator's agreed procedure, with completed effects and required evidence preserved.

## Performance and operational assessment

Do not infer throughput, latency, recovery time or availability from a successful demo. Define the intended load, request mix, policy complexity, dataset size, hardware, network conditions and failure model before measuring.

Measure permitted and denied requests separately where their paths differ. Include dependency unavailability, backpressure and recovery. Record warm/cold conditions and the exact build. A benchmark without these inputs is difficult to reproduce or compare.

Set recovery objectives with the deployment owner and test them against the chosen backup and restoration procedure. Do not invent numerical service objectives from development resource caps.

## Decision record

Summarize what the evidence supports for the selected workflow. Identify unresolved security, correctness and operational questions separately from usability improvements. Distinguish readiness for another validation stage from readiness to handle production activity.

The [release scope](../releases/README.md), [privacy model](../security/privacy-model.md) and [operations guide](../operations/README.md) should accompany the result so reviewers can see the assumptions and limits.
