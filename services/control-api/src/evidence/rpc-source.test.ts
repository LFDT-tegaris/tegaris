import { expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';
import { parseRpcReaderResult } from './rpc-source.js';
import { EvidenceCustodyError } from './segment.js';

const batch = z.array(z.strictObject({ sequence: z.string() })).max(8);
const success = { status: 0, signal: null, stdout: '[]\n', stderr: '' } as const;
const unavailable = '{"version":1,"code":"UNAVAILABLE"}\n';
const failure = { ...success, status: 1, stdout: '', stderr: unavailable };

it('classifies an actual missing executable without assuming populated pipe fields', () => {
  const result = spawnSync(join(tmpdir(), `openpc-missing-reader-${randomUUID()}`), [], {
    encoding: 'utf8',
    input: '{}',
    timeout: 1000,
    maxBuffer: 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  expect(result.error).toMatchObject({ code: 'ENOENT' });
  expect(() => parseRpcReaderResult(result, batch)).toThrow(
    new EvidenceCustodyError('UNAVAILABLE'),
  );
  for (const contradictory of [
    { ...result, stdout: '[]' },
    { ...result, stderr: 'private diagnostic' },
  ])
    expect(() => parseRpcReaderResult(contradictory, batch)).toThrow(
      new EvidenceCustodyError('INTEGRITY'),
    );
});

it('accepts only schema-valid success with no contradictory diagnostics', () => {
  expect(parseRpcReaderResult(success, batch)).toEqual([]);
  expect(parseRpcReaderResult({ ...success, stdout: '[{"sequence":"1"}]\n' }, batch)).toEqual([
    { sequence: '1' },
  ]);
  for (const stdout of ['', 'null', '{}', '[{}]', '[{"sequence":1}]', '[]\n[]'])
    expect(() => parseRpcReaderResult({ ...success, stdout }, batch)).toThrow(
      new EvidenceCustodyError('INTEGRITY'),
    );
  expect(() => parseRpcReaderResult({ ...success, stderr: unavailable }, batch)).toThrow(
    new EvidenceCustodyError('INTEGRITY'),
  );
});

it('reports only strict versioned unavailability without returning an empty batch', () => {
  for (const stderr of [
    unavailable,
    '{"code":"UNAVAILABLE","version":1}',
    '{ "version" : 1, "code" : "UNAVAILABLE" }\n',
  ])
    expect(() => parseRpcReaderResult({ ...failure, stderr }, batch)).toThrow(
      new EvidenceCustodyError('UNAVAILABLE'),
    );
});

it.each([
  '',
  'runtime evidence source rejected\n',
  '{"version":1,"code":"REJECTED"}\n',
  '{"version":2,"code":"UNAVAILABLE"}',
  '{"version":"1","code":"UNAVAILABLE"}',
  '{"version":1,"code":"UNKNOWN"}',
  '{"version":1,"code":"UNAVAILABLE","path":"secret"}',
  '{"version":1,"code":"REJECTED","code":"UNAVAILABLE"}',
  '{"version":2,"version":1,"code":"UNAVAILABLE"}',
  `${unavailable}${unavailable}`,
  `${unavailable}\n`,
  `${' '.repeat(128)}${unavailable}`,
])('rejects unknown, ambiguous or unbounded reader diagnostics: case %#', (stderr) => {
  expect(() => parseRpcReaderResult({ ...failure, stderr }, batch)).toThrow(
    new EvidenceCustodyError('INTEGRITY'),
  );
});

it('rejects a diagnostic that contradicts output, exit status or a process error', () => {
  for (const result of [
    { ...failure, stdout: '[]' },
    { ...failure, stdout: ' ' },
    { ...failure, status: 2 },
    { ...failure, status: null },
    { ...failure, signal: 'SIGTERM' as const },
    { ...failure, error: Object.assign(new Error('hidden'), { code: 'ETIMEDOUT' }) },
  ])
    expect(() => parseRpcReaderResult(result, batch)).toThrow(
      new EvidenceCustodyError('INTEGRITY'),
    );
});

it('distinguishes observed process inability from unknown errors and truncated output', () => {
  for (const code of ['ENOENT', 'EACCES', 'EAGAIN', 'EMFILE', 'ENFILE', 'ENOMEM', 'ETIMEDOUT'])
    expect(() =>
      parseRpcReaderResult(
        {
          ...success,
          status: null,
          stdout: null,
          stderr: null,
          error: Object.assign(new Error('private command must not escape'), { code }),
        },
        batch,
      ),
    ).toThrow(new EvidenceCustodyError('UNAVAILABLE'));
  for (const result of [
    { ...success, status: null, error: new Error('unknown') },
    { ...success, status: null, error: Object.assign(new Error(), { code: 'ENOBUFS' }) },
    {
      ...success,
      status: null,
      stdout: '[',
      signal: 'SIGTERM' as const,
      error: Object.assign(new Error(), { code: 'ETIMEDOUT' }),
    },
    ...(['SIGTERM', 'SIGKILL', 'SIGINT'] as const).map((signal) => ({
      ...failure,
      status: null,
      stderr: '',
      signal,
    })),
  ])
    expect(() => parseRpcReaderResult(result, batch)).toThrow(
      new EvidenceCustodyError('INTEGRITY'),
    );
  expect(() =>
    parseRpcReaderResult(
      {
        ...failure,
        status: null,
        stderr: '',
        signal: 'SIGTERM',
        error: Object.assign(new Error(), { code: 'ETIMEDOUT' }),
      },
      batch,
    ),
  ).toThrow(new EvidenceCustodyError('UNAVAILABLE'));
});
