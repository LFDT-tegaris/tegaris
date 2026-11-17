import { X509Certificate } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const [secretRoot, output] = process.argv.slice(2);
if (secretRoot === undefined || output === undefined) throw new Error('usage: secret-root output');

const participantId = '018f0000-0000-7000-8000-000000000101';
const principalId = '018f0000-0000-7000-8000-000000000190';
const workloadId = 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191';
const inputs = [
  ['018f0000-0000-7000-8000-000000000192', 'identity_mtls_client_cert.pem'],
  ['018f0000-0000-7000-8000-000000000193', 'identity_mtls_rotated_cert.pem'],
] as const;
const manifest = await Promise.all(
  inputs.map(async ([credentialId, filename]) => {
    const certificate = new X509Certificate(await readFile(join(secretRoot, filename)));
    return {
      credentialId,
      participantId,
      principalId,
      workloadId,
      publicKeySpkiDer: Buffer.from(
        certificate.publicKey.export({ format: 'der', type: 'spki' }),
      ).toString('base64'),
      certificateDer: certificate.raw.toString('base64'),
    };
  }),
);
await writeFile(output, `${JSON.stringify(manifest)}\n`, { mode: 0o400 });
