import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

const source = (path) => readFileSync(path, 'utf8');

test('Explorer contract remains exact-profile and candidate-only', () => {
  const value = source('services/explorer-adapter/src/lib.rs');
  assert.match(value, /ExplorerAdapterContract/u);
  assert.match(value, /raw_fallback_forbidden/u);
  assert.match(value, /fact_store_write_forbidden/u);
  assert.match(value, /validate_explorer_profile/u);
});
test('The Graph contract requires manifest identity and rejects raw fallback', () => {
  const value = source('services/thegraph-adapter/src/lib.rs');
  assert.match(value, /TheGraphAdapterContract/u);
  assert.match(value, /exact_manifest_required/u);
  assert.match(value, /raw_fallback_forbidden/u);
  assert.match(value, /validate_thegraph_manifest/u);
});
test('SubQuery contract is client-only and managed lifecycle is future-absent', () => {
  const value = source('services/subquery-adapter/src/lib.rs');
  assert.match(value, /SubqueryAdapterContract/u);
  assert.match(value, /FutureAbsent/u);
  assert.match(value, /deployment_forbidden/u);
  assert.match(value, /validate_subquery_profile/u);
});
test('adapter contracts share non-authoritative candidate output only', () => {
  for (const path of [
    'services/explorer-adapter/src/lib.rs',
    'services/thegraph-adapter/src/lib.rs',
    'services/subquery-adapter/src/lib.rs',
  ]) {
    assert.match(source(path), /CandidateOutboxEnvelopeV1/u);
    assert.doesNotMatch(source(path), /reqwest|tokio|std::net|async fn/u);
  }
  for (const owner of ['shared', 'provider', 'indexer', 'explorer', 'thegraph', 'subquery']) {
    assert.equal(existsSync(`crates/pc-provider-api/src/validation/profile/${owner}.rs`), true);
  }
  for (const owner of [
    'provider',
    'indexer',
    'explorer',
    'thegraph',
    'subquery',
    'serde_closure',
  ]) {
    assert.equal(existsSync(`crates/pc-provider-api/src/validation/tests/${owner}.rs`), true);
  }
});
