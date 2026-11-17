import { expect, it } from 'vitest';
import {
  createPinnedSigningTransport,
  PinnedSigningTransportError,
} from './pinned-signing-transport.js';
const digest = 'sha256:' + '01'.repeat(32);
it.each([
  'http://provider.invalid',
  'https://provider.invalid/path',
  'https://user:secret@provider.invalid',
  'https://provider.invalid?secret=yes',
  'https://provider.invalid#fragment',
])('rejects unsafe origin before reading certificates: %s', (providerOrigin) => {
  expect(() =>
    createPinnedSigningTransport(
      { certificate: Buffer.alloc(0), privateKey: Buffer.alloc(0), trustCa: Buffer.alloc(0) },
      { providerOrigin, providerTlsSpkiDigest: digest },
      digest,
    ),
  ).toThrow(PinnedSigningTransportError);
});
it.each([0, 49, 10001, NaN, Infinity])('rejects unsupported deadline %s', (timeoutMs) => {
  expect(() =>
    createPinnedSigningTransport(
      {
        certificate: Buffer.alloc(0),
        privateKey: Buffer.alloc(0),
        trustCa: Buffer.alloc(0),
        timeoutMs,
      },
      { providerOrigin: 'https://provider.invalid', providerTlsSpkiDigest: digest },
      digest,
    ),
  ).toThrow(PinnedSigningTransportError);
});
