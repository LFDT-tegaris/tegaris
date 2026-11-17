import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { signFixtureCertificate } from './fixture-certificate.mjs';

test('issuance in long paths stays inside its CA lifetime and preserves retained certificates', async (t) => {
  const parent = mkdtempSync(join(tmpdir(), 'openpc-fixture-certificate-'));
  const root = join(parent, ...Array.from({ length: 6 }, () => 'nested-checkout-'.repeat(4)));
  mkdirSync(root, { recursive: true });
  assert.ok(root.length > 400);
  let passed = false;
  t.after(() => {
    if (passed) rmSync(parent, { recursive: true });
  });
  const ca = join(root, 'ca.pem'),
    key = join(root, 'ca.key');
  const csr = join(root, 'workload.csr'),
    leaf = join(root, 'workload.pem');
  const participantId = '018f0000-0000-7000-8000-000000000101';
  const targetId = '018f0000-0000-7000-8000-000000000191';
  const openssl = (...args) => execFileSync('openssl', args, { stdio: 'pipe' });
  openssl(
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-sha256',
    '-days',
    '1',
    '-subj',
    '/CN=Fixture CA',
    '-keyout',
    key,
    '-out',
    ca,
  );
  const issuer = new X509Certificate(readFileSync(ca));
  openssl(
    'req',
    '-new',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-subj',
    '/CN=Fixture workload',
    '-addext',
    'extendedKeyUsage=clientAuth',
    '-addext',
    `subjectAltName=URI:urn:openpc:participant:${participantId}:workload:${targetId}`,
    '-keyout',
    join(root, 'workload.key'),
    '-out',
    csr,
  );
  while (Date.now() <= Date.parse(issuer.validFrom) + 1100) await delay(100);
  const invalid = join(root, 'outlives-ca.pem');
  openssl(
    'x509',
    '-req',
    '-sha256',
    '-days',
    '1',
    '-copy_extensions',
    'copy',
    '-in',
    csr,
    '-CA',
    ca,
    '-CAkey',
    key,
    '-set_serial',
    '1',
    '-out',
    invalid,
  );
  signFixtureCertificate(csr, ca, key, leaf);
  const certificate = new X509Certificate(readFileSync(leaf));
  assert.equal(certificate.validTo, issuer.validTo);
  assert.ok(certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey));
  const bytes = readFileSync(leaf);
  assert.throws(() => signFixtureCertificate(csr, ca, key, leaf), { code: 'EEXIST' });
  assert.deepEqual(readFileSync(leaf), bytes);
  const result = execFileSync(
    process.execPath,
    ['--import', 'tsx', '--input-type=module', '-', root, participantId, targetId],
    {
      encoding: 'utf8',
      input: `
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {X509Certificate} from 'node:crypto';
import {verifyIssuedWorkloadCertificate} from './services/identity-service/src/domain/workload-credential-issuer.ts';
const [root, participantId, targetId] = process.argv.slice(2);
const leaf = new X509Certificate(readFileSync(root + '/workload.pem'));
const request = {credentialId:'018f0000-0000-7000-8000-000000000192', participantId,
  principalId:'018f0000-0000-7000-8000-000000000190', workloadId:'urn:openpc:workload:' + targetId,
  publicKeySpkiDer:Buffer.from(leaf.publicKey.export({type:'spki',format:'der'}))};
assert.ok(verifyIssuedWorkloadCertificate(leaf.raw,readFileSync(root+'/ca.pem'),request));
const invalid = new X509Certificate(readFileSync(root+'/outlives-ca.pem'));
assert.equal(verifyIssuedWorkloadCertificate(invalid.raw,readFileSync(root+'/ca.pem'),request),undefined);
console.log('real-issuer-verifier-pass');
`,
    },
  );
  assert.match(result, /real-issuer-verifier-pass/u);
  passed = true;
});
