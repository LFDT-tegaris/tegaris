import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');

test('I09 local OTel collector closes all signal contexts and emits a reviewable transformed sink', async () => {
  const [collector, unavailable, compose] = await Promise.all([
    readFile(resolve(root, 'containers/i09-local-otel-collector.yaml'), 'utf8'),
    readFile(resolve(root, 'containers/i09-local-otel-unavailable.yaml'), 'utf8'),
    readFile(resolve(root, 'deploy/compose/local/i09-observability.compose.yaml'), 'utf8'),
  ]);

  assert.match(collector, /transform\/closed_schema/);
  for (const context of ['resource', 'datapoint', 'log', 'span']) {
    assert.match(collector, new RegExp(`context: ${context}`));
  }
  assert.match(collector, /pipelines:\n {4}metrics:/);
  assert.match(collector, /\n {4}logs:/);
  assert.match(collector, /\n {4}traces:/);
  assert.match(collector, /debug\/retained/);
  assert.match(collector, /verbosity: detailed/);
  assert.match(collector, /memory_limiter/);
  assert.match(unavailable, /queue_size: 2/);
  assert.match(unavailable, /max_elapsed_time: 1s/);
  assert.match(
    compose,
    /otel\/opentelemetry-collector-contrib:0\.159\.0@sha256:1f2c54a30e713fac6b3ae77a1ec84010c2007e29ced8ec666214fc2f6739c1cc/,
  );
  assert.match(compose, /profiles: \[unavailable\]/);
  assert.match(compose, /read_only: true/);
  assert.match(compose, /no-new-privileges:true/);
});
