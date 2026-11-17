import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { request } from 'node:https';

export async function runtimeSnapshotTlsFixture(uriSan: string, serverDnsName?: string) {
  if (serverDnsName !== undefined && !/^[a-z][a-z0-9-]{0,62}$/u.test(serverDnsName))
    throw new Error('Invalid TLS fixture hostname');
  const parent =
    process.env.OPENPC_TEST_TMP_ROOT ?? process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT ?? tmpdir();
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'identity-snapshot-tls-'));
  const openssl = (...args: string[]) =>
    execFileSync('openssl', args, { cwd: root, stdio: 'pipe' });
  try {
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
      '/CN=OpenPC snapshot test CA',
      '-addext',
      'basicConstraints=critical,CA:true',
      '-keyout',
      'ca.key',
      '-out',
      'ca.pem',
    );
    for (const kind of ['client', 'server']) {
      await writeFile(
        join(root, `${kind}.cnf`),
        `basicConstraints=critical,CA:false\nextendedKeyUsage=${kind}Auth\nsubjectAltName=${kind === 'client' ? `URI:${uriSan}` : `IP:127.0.0.1${serverDnsName ? `,DNS:${serverDnsName}` : ''}`}\n`,
      );
      openssl(
        'req',
        '-new',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-subj',
        `/CN=OpenPC snapshot ${kind}`,
        '-keyout',
        `${kind}.key`,
        '-out',
        `${kind}.csr`,
      );
      openssl(
        'x509',
        '-req',
        '-sha256',
        '-days',
        '1',
        '-in',
        `${kind}.csr`,
        '-CA',
        'ca.pem',
        '-CAkey',
        'ca.key',
        '-CAcreateserial',
        '-extfile',
        `${kind}.cnf`,
        '-out',
        `${kind}.pem`,
      );
    }
    const ca = await readFile(join(root, 'ca.pem'));
    const certificate = await readFile(join(root, 'client.pem'));
    const key = await readFile(join(root, 'client.key'));
    const server = {
      ca,
      certificate: await readFile(join(root, 'server.pem')),
      privateKey: await readFile(join(root, 'server.key')),
    };
    return {
      certificate,
      privateKey: key,
      parsed: new X509Certificate(certificate),
      server,
      async post(
        url: string,
        body: unknown,
        client: { certificate: Buffer; privateKey: Buffer } | null = {
          certificate,
          privateKey: key,
        },
      ): Promise<{ status: number; body: unknown }> {
        return new Promise((resolve, reject) => {
          const call = request(
            url,
            {
              method: 'POST',
              ca,
              cert: client?.certificate,
              key: client?.privateKey,
              minVersion: 'TLSv1.3',
              maxVersion: 'TLSv1.3',
              headers: { 'content-type': 'application/json' },
            },
            (response) => {
              const chunks: Buffer[] = [];
              response.on('data', (chunk: Buffer) => chunks.push(chunk));
              response.on('error', reject);
              response.on('end', () => {
                try {
                  resolve({
                    status: response.statusCode ?? 0,
                    body: JSON.parse(Buffer.concat(chunks).toString()),
                  });
                } catch (error) {
                  reject(error);
                }
              });
            },
          );
          call.on('error', reject);
          call.setTimeout(10_000, () => call.destroy(new Error('Workload authentication timeout')));
          call.end(JSON.stringify(body));
        });
      },
      close: () => rm(root, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}
