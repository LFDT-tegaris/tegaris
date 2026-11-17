# Getting help

Start with the [setup guide](docs/getting-started.md) and [troubleshooting guide](docs/user-guide/troubleshooting.md).

For a reproducible bug, open an [issue](https://github.com/LFDT-tegaris/tegaris/issues). Include the version or commit, the steps you took, what you expected and what happened. Use synthetic examples and remove credentials, account details and private network addresses from logs.

Use an issue to discuss a feature or ask a product question. Describe the task you are trying to complete; a small example often helps more than a long list of proposed settings.

Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md). Do not include exploit details or sensitive records in a public issue.

This is a community project. There is no guaranteed response time or production support agreement. The [project contacts](MAINTAINERS.md) can help route contribution questions.

## Choose the right route

| Request                           | Route                     | Include                                                                       |
| --------------------------------- | ------------------------- | ----------------------------------------------------------------------------- |
| Setup or usage question           | Repository issue          | Task, selected version, attempted steps and the unclear guide section         |
| Reproducible defect               | Bug report                | Minimal synthetic reproduction, expected/actual behavior and safe diagnostics |
| Substantial feature/design change | Proposal issue            | Problem, scope, compatibility and acceptance criteria                         |
| Suspected security issue          | Private security contacts | Affected boundary and reproduction without public disclosure                  |

## Bug-report checklist

1. Source revision or release and relevant artifact identity.
2. Operating system and pinned tool versions.
3. Exact command or console task, including the relevant context without confidential identifiers.
4. Synthetic input and prerequisites sufficient to reproduce the issue.
5. Expected behavior and observed response/state.
6. Safe request, correlation or operation reference where useful.
7. Checks already performed, failures retained and checks not run.
8. Whether a mutation may have completed despite a lost response.

Avoid attaching an entire log directory by default. A concise redacted excerpt and a small reproduction are easier to review and safer to share. Preserve the full original evidence privately if it is needed for recovery.

## Follow-up and resolution

When asked for additional evidence, reproduce in the smallest suitable isolated environment. Do not rerun a possibly completed business operation merely to obtain a cleaner log. Reconcile its original outcome first.

When a correction is available, verify it against the affected scenario and record the tested revision. If the result changes, explain what passed and what remains unresolved. Closing an issue should reflect the agreed outcome, not just the existence of a pull request.
