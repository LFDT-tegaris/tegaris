import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { businessCborSql } from '../../../services/identity-service/src/db/business-cbor.mjs';
import { identityRuntimeCoseBindingSql } from '../../../services/identity-service/src/db/identity-runtime-cose-binding.mjs';

// Owned disposable PostgreSQL; this exercises the generated DB decoder, not a SQL mock.
test('business CBOR database decoder: canonical bytes, u64 precision and adversarial encodings', async () => {
  const scratch = process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT;
  assert.ok(scratch, 'OPENPC_LOCAL_RUNTIME_TMP_ROOT is required');
  const root = mkdtempSync(join(scratch, 'business-cbor-'));
  const container = `openpc-business-cbor-${process.pid}`;
  let created = false;
  const docker = (args, input) =>
    execFileSync('docker', args, { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  const sql = (input) =>
    docker(
      [
        'exec',
        '-i',
        container,
        'psql',
        '-X',
        '-qAt',
        '-v',
        'ON_ERROR_STOP=1',
        '-h',
        '127.0.0.1',
        '-U',
        'postgres',
        '-d',
        'postgres',
      ],
      input,
    ).trim();
  try {
    docker([
      'run',
      '-d',
      '--name',
      container,
      '--memory',
      '512m',
      '--cpus',
      '1',
      '--label',
      `io.openpc.test-owner=${root}`,
      '-e',
      'POSTGRES_HOST_AUTH_METHOD=trust',
      'docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7',
    ]);
    created = true;
    for (let attempts = 0; ; attempts++) {
      try {
        docker(['exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres']);
        break;
      } catch (error) {
        if (attempts >= 30) throw error;
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
    sql(`CREATE SCHEMA openpc;\n${businessCborSql}\n${identityRuntimeCoseBindingSql}`);
    for (const [hex, expected] of [
      ['1bffffffffffffffff', '18446744073709551615'],
      ['1b0020000000000001', '9007199254740993'],
      ['a300010141ff02826361626326', '{"0": 1, "1": {"bytes": "ff"}, "2": ["abc", -7]}'],
      ['a0', '{}'],
      ['80', '[]'],
      ['60', '""'],
      ['62c3a9', '"é"'],
      ['63efbbbf', '"﻿"'],
    ])
      assert.equal(sql(`select openpc.business_cbor(decode('${hex}','hex'));`), expected);
    for (const hex of [
      '',
      '1801',
      '190018',
      '1a00000100',
      '1b00000000ffffffff',
      '01ff',
      '9f01ff',
      'a201010102',
      'a202010102',
      'a1616101',
      'c101',
      'f4',
      'f6',
      'f93c00',
      '63',
      '61ff',
      '6365cc81',
      '9a00000101',
      '8381818181818181818100',
      '1bff',
      '5a00010001',
    ]) {
      assert.throws(
        () => sql(`select openpc.business_cbor(decode('${hex}','hex'));`),
        `accepted ${hex}`,
      );
    }
    // Independent CBOR construction tests database structure/cross-binding only.
    // These zero signatures are never passed off as cryptographic acceptance.
    const head = (major, value) =>
      value < 24
        ? Buffer.from([(major << 5) | value])
        : value < 256
          ? Buffer.from([(major << 5) | 24, value])
          : Buffer.from([(major << 5) | 25, value >> 8, value & 255]);
    const uint = (value) => (value < 0 ? head(1, -1 - value) : head(0, value));
    const bytes = (value) => Buffer.concat([head(2, value.length), value]);
    const text = (value) => Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)]);
    const array = (items) => Buffer.concat([head(4, items.length), ...items]);
    const map = (items) =>
      Buffer.concat([head(5, items.length), ...items.flatMap(([k, v]) => [uint(k), v])]);
    const keyId = 'sha256:' + 'ab'.repeat(32);
    const payload = map([[0, text('structural-evidence')]]);
    const envelope = map([
      [0, uint(1)],
      [1, uint(3002)],
      [2, uint(2)],
      [3, payload],
    ]);
    const header = [
      [1, uint(-8)],
      [2, array([100, 101, 102, 103].map(uint))],
      [3, text('application/pc+cbor')],
      [4, bytes(Buffer.from(keyId))],
      [100, uint(3002)],
      [101, uint(2)],
      [102, text('pc.cose.identity-runtime.v2')],
      [103, uint(2)],
    ];
    const cose = (fields = header, attached = envelope, signature = Buffer.alloc(64)) =>
      Buffer.concat([
        Buffer.from([0xd2]),
        array([bytes(map(fields)), map([]), bytes(attached), bytes(signature)]),
      ]);
    const admit = (wire, evidence = payload) =>
      sql(
        `select openpc.identity_runtime_cose_key_id(decode('${evidence.toString('hex')}','hex'),decode('${wire.toString('hex')}','hex'));`,
      );
    assert.equal(admit(cose()), keyId);
    assert.throws(() => admit(cose(), map([[0, text('substituted')]])));
    assert.throws(
      () => admit(cose(header, payload)),
      'bare payload must not substitute for the semantic envelope',
    );
    assert.throws(() => admit(cose(header, envelope, Buffer.alloc(63))));
    assert.throws(() => admit(Buffer.concat([cose(), Buffer.from([0])])));
    for (const [field, replacement] of [
      [1, uint(-7)],
      [4, bytes(Buffer.alloc(32))],
      [4, bytes(Buffer.from('sha256:' + 'AB'.repeat(32)))],
      [100, uint(3003)],
      [101, uint(1)],
      [102, uint(13)],
      [102, text('pc.cose.control-business-transition.v1')],
      [103, uint(1)],
    ])
      assert.throws(() => admit(cose(header.map(([k, v]) => [k, k === field ? replacement : v]))));
    for (const [field, replacement] of [
      [0, uint(2)],
      [1, uint(3003)],
      [2, uint(1)],
    ]) {
      const fields = [
        [0, uint(1)],
        [1, uint(3002)],
        [2, uint(2)],
        [3, payload],
      ];
      assert.throws(() =>
        admit(cose(header, map(fields.map(([k, v]) => [k, k === field ? replacement : v])))),
      );
    }
    assert.equal(
      sql("select openpc.business_uuid('01990000-0000-7000-8000-000000000001');"),
      '{"bytes": "01990000000070008000000000000001"}',
    );
  } finally {
    if (created) docker(['rm', '-fv', container]);
    rmSync(root, { recursive: true });
  }
});
