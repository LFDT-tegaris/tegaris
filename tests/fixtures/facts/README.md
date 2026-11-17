# Fact admission fixtures

[The admission case catalogue](i05-gate3-admission-cases.json) lists deterministic local test cases for Fact admission. It contains case identifiers rather than business records.

The `positive` list covers signed admission, idempotent replay, finalization, replacement after invalidation, purpose-bound capabilities and concurrent duplicate submission. The `negative` list covers required rejections, including altered signatures, invalid encoding, stale observations, mismatched scope, unauthorized database access and changes to immutable evidence.

## Extending the catalogue

Keep existing case identifiers stable because test harnesses reference them. Add each new identifier to the appropriate list and implement an executable test that asserts:

- The expected response or rejection.
- The resulting database or runtime state.
- The absence of unauthorized writes or other forbidden effects.
- Replay or recovery behavior when the case involves either boundary.

A catalogue entry declares intended coverage. Passing evidence comes from the executable test and its asserted outcomes.

Use synthetic data only. Do not commit private keys, credentials, customer data or protected relationship members. Keep generated test artifacts in the fixture's owned temporary directory.

See the [testing guide](../../../docs/development/testing.md) for setup and test commands.
