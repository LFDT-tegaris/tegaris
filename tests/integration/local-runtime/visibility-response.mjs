import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// Public projections of the two expected visibility failures.
// Availability and evidence failures are separate cases, never privacy passes.
export function assertVisibilityDenial(status, requestId, body, kind) {
  const expected = {
    'state-read': ['502', -32009, 'PC-RUNTIME-3009', 'FAILED', 'Response integrity invalid'],
    'response-family': ['403', -32001, 'PC-RUNTIME-3001', 'DENIED', 'Request denied'],
  }[kind];
  assert.ok(expected, 'a specific native visibility failure is required');
  assert.equal(status, expected[0], 'an outage is not an accepted visibility denial');
  assert.ok(Number.isSafeInteger(Number(requestId)));
  assert.equal(String(Number(requestId)), String(requestId));
  assert.deepEqual(Object.keys(body).sort(), ['error', 'id', 'jsonrpc']);
  assert.equal(body.jsonrpc, '2.0');
  assert.equal(body.id, Number(requestId), 'denial must belong to this exact request');
  assert.deepEqual(Object.keys(body.error).sort(), ['code', 'data', 'message']);
  assert.equal(body.error.code, expected[1]);
  assert.equal(body.error.message, expected[4]);
  const data = body.error.data;
  assert.deepEqual(Object.keys(data).sort(), [
    'attemptId',
    'pcCode',
    'retryable',
    'signedTransactionHash',
    'traceId',
    'truthState',
  ]);
  assert.equal(data.pcCode, expected[2]);
  assert.equal(data.truthState, expected[3]);
  assert.equal(data.retryable, false);
  assert.equal(data.attemptId, null);
  assert.equal(data.signedTransactionHash, null);
  assert.match(
    data.traceId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    'the native owner must provide its request-local trace',
  );
  return data.traceId;
}

export function recordedResponseStatus(headers) {
  const statuses = [
    ...headers.matchAll(/^HTTP\/(?:1\.[01]|2|3) ([2-5][0-9]{2})(?: [^\r\n]*)?\r?$/gmu),
  ];
  assert.equal(statuses.length, 1, 'one actual final native HTTP response is required');
  return statuses[0][1];
}

export function assertRequestEvidence(
  prior,
  current,
  { responseDigest, traceId, forwarded = false },
) {
  for (const [id, record] of Object.entries(prior.records)) {
    assert.deepEqual(current.records[id], record, 'earlier request evidence must remain unchanged');
  }
  const records = Object.entries(current.records)
    .filter(([id]) => !Object.hasOwn(prior.records, id))
    .map(([, record]) => record);
  if (responseDigest !== undefined) {
    assert.equal(records.length, 1, 'the current request must produce exactly one release');
    assert.equal(records[0].status.Released?.response_digest, responseDigest);
  } else {
    assert.equal(records.filter((record) => record.status.Released).length, 0);
    if (forwarded) {
      assert.equal(records.length, 1, 'the withheld request must retain its forwarding decision');
      assert.equal(records[0].status.Committed?.effect, 'ALLOW_FORWARD');
    }
  }
  if (traceId !== undefined) {
    for (const record of records) assert.equal(record.trace_id, traceId);
  }
}

async function main() {
  const [mode, status, requestId, root, requests, before] = process.argv.slice(2);
  const load = async (name) => JSON.parse(await readFile(join(root, name), 'utf8'));
  if (mode === 'restart-custody') {
    const prior = await load('decisions-event-allowed.json');
    const current = await load('decisions-restarted.json');
    assertRequestEvidence(prior, current, {});
    assert.ok(Object.values(prior.records).some((record) => record.status.Released));
  } else if (['transaction', 'receipt', 'event'].includes(mode)) {
    const variant = requests;
    const body = await load(`response-${mode}-${variant}.json`);
    if (variant === 'denied') {
      const traceId = assertVisibilityDenial(status, requestId, body, 'response-family');
      assertRequestEvidence(
        await load(`decisions-before-${mode}-${variant}.json`),
        await load(`decisions-${mode}-${variant}.json`),
        { traceId },
      );
    } else {
      assert.equal(status, '200', JSON.stringify(body));
      assert.equal(body.id, Number(requestId));
      if (mode === 'transaction') {
        assert.deepEqual(body.result, {
          from: `0x${'33'.repeat(20)}`,
          to: `0x${'11'.repeat(20)}`,
          value: '0x7',
        });
      } else {
        const logs = mode === 'receipt' ? body.result.logs : body.result;
        assert.equal(logs.length, 1);
        assert.equal(logs[0].data, `0x${'0'.repeat(63)}7`);
        assert.equal(logs[0].removed, false);
        if (mode === 'receipt') {
          assert.equal(body.result.logsBloom, `0x${'00'.repeat(256)}`);
          assert.equal(body.result.gasUsed, '0x5208');
          assert.equal(body.result.cumulativeGasUsed, '0x5208');
          assert.equal(body.result.contractAddress, null);
        }
      }
      const responseDigest = createHash('sha256')
        .update(await readFile(join(root, `response-${mode}-${variant}.json`)))
        .digest('hex');
      assertRequestEvidence(
        await load(`decisions-before-${mode}-${variant}.json`),
        await load(`decisions-${mode}-${variant}.json`),
        { responseDigest },
      );
    }
  } else if (mode === 'evidence') {
    const current = await load(`decisions-${status}.json`);
    const priorRequest = await load(`decisions-before-${status}.json`);
    if (status === 'denied') {
      const response = await load(`response-${status}.json`);
      const actualStatus = recordedResponseStatus(
        await readFile(join(root, `response-${status}.headers`), 'utf8'),
      );
      const traceId = assertVisibilityDenial(actualStatus, requestId, response, 'state-read');
      assertRequestEvidence(priorRequest, current, {
        forwarded: true,
        traceId,
      });
    } else {
      const response = await readFile(join(root, `response-${status}.json`));
      const digest = createHash('sha256').update(response).digest('hex');
      assertRequestEvidence(priorRequest, current, { responseDigest: digest });
      if (status === 'restarted') {
        const prior = await load('decisions-allowed.json');
        for (const [id, record] of Object.entries(prior.records)) {
          if (record.status.Released) assert.deepEqual(current.records[id], record);
        }
      }
    }
  } else {
    const calls = (await readFile(requests, 'utf8'))
      .trim()
      .split('\n')
      .slice(Number(before))
      .map(JSON.parse);
    assert.ok(
      calls.some((call) => call.method === 'eth_call'),
      'real provider call required',
    );
    const body = await load(`response-${mode}.json`);
    if (mode === 'denied') {
      assertVisibilityDenial(status, requestId, body, 'state-read');
    } else {
      assert.equal(status, '200', JSON.stringify(body));
      assert.deepEqual(body, {
        jsonrpc: '2.0',
        id: Number(requestId),
        result: `0x${'00'.repeat(30)}1234`,
      });
      assert.doesNotMatch(
        await readFile(join(root, `response-${mode}.headers`), 'utf8'),
        /^(set-cookie|x-provider-private|content-encoding):/imu,
      );
    }
  }
  process.stdout.write(`OPENPC_STATE_READ_RESPONSE|PASS|${mode}|${status}\n`);
}

if (import.meta.main) await main();
