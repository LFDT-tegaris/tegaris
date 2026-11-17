import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import {
  constants,
  copyFileSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
  chmodSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// A certificate generated later than its CA must not extend the CA's lifetime.
// Sign only new fixture files; retained certificates and issuer manifests are immutable.
export function signFixtureCertificate(csrPath, caPath, caKeyPath, outputPath) {
  for (const path of [csrPath, caPath, caKeyPath, outputPath]) {
    assert.equal(resolve(path), path);
    assert.ok(!/[\r\n]/u.test(path));
  }
  const ca = new X509Certificate(readFileSync(caPath));
  const now = Date.now();
  const until = Math.min(Date.parse(ca.validTo), now + 24 * 60 * 60 * 1000);
  assert.ok(ca.ca && Date.parse(ca.validFrom) <= now && until > now + 60_000);
  const scratch = mkdtempSync(join(dirname(outputPath), '.certificate-'));
  chmodSync(scratch, 0o700);
  const quote = (value) => `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
  const index = join(scratch, 'index');
  const serial = join(scratch, 'serial');
  const config = join(scratch, 'openssl.cnf');
  writeFileSync(index, '', { mode: 0o600 });
  writeFileSync(serial, `${randomBytes(16).toString('hex')}\n`, { mode: 0o600 });
  writeFileSync(
    config,
    `[ca]
default_ca = fixture
[fixture]
database = index
new_certs_dir = .
serial = serial
certificate = ${quote(caPath)}
private_key = ${quote(caKeyPath)}
default_md = sha256
policy = fixture_subject
copy_extensions = copy
unique_subject = no
[fixture_subject]
commonName = supplied
`,
    { mode: 0o600 },
  );
  const draft = join(scratch, 'certificate.pem');
  const endDate =
    new Date(until).toISOString().replace(/[-:]/gu, '').replace(/T/u, '').slice(0, 14) + 'Z';
  execFileSync(
    'openssl',
    [
      'ca',
      '-batch',
      '-notext',
      '-config',
      'openssl.cnf',
      '-in',
      csrPath,
      '-out',
      'certificate.pem',
      '-enddate',
      endDate,
    ],
    // OpenSSL's CA archive path has a smaller limit than filesystem paths.
    { cwd: scratch, stdio: 'pipe' },
  );
  const certificate = new X509Certificate(readFileSync(draft));
  assert.ok(certificate.checkIssued(ca) && certificate.verify(ca.publicKey));
  assert.ok(Date.parse(certificate.validTo) <= Date.parse(ca.validTo));
  assert.ok(Date.parse(certificate.validTo) - Date.parse(certificate.validFrom) <= 86_400_000);
  copyFileSync(draft, outputPath, constants.COPYFILE_EXCL);
  chmodSync(outputPath, 0o444);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  assert.equal(process.argv.length, 6, 'Expected CSR, CA certificate, CA key and new output path');
  signFixtureCertificate(...process.argv.slice(2));
}
