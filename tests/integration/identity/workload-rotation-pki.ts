import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/** Independent test CA, prepared before public target creation and leaf issuance. */
export async function workloadRotationAuthority(root: string, participantId: string) {
  const file = (name: string) => join(root, name);
  const openssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
  const time = (value: number) =>
    new Date(value)
      .toISOString()
      .replace(/[-:T]/gu, '')
      .replace(/\.\d{3}Z$/u, 'Z');
  const now = Date.now();
  await writeFile(file('index'), '');
  await writeFile(file('serial'), '10\n');
  await writeFile(
    file('authority.cnf'),
    '[authority]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n',
  );
  await writeFile(
    file('issuer.cnf'),
    `[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=${file('index')}\nserial=${file('serial')}\nnew_certs_dir=${root}\ncertificate=${file('seed-ca.pem')}\nprivate_key=${file('ca.key')}\ndefault_md=sha256\npolicy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n`,
  );
  openssl(
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-days',
    '2',
    '-subj',
    '/CN=Workload rotation fixture CA',
    '-keyout',
    file('ca.key'),
    '-out',
    file('seed-ca.pem'),
  );
  openssl(
    'req',
    '-new',
    '-key',
    file('ca.key'),
    '-subj',
    '/CN=Workload rotation fixture CA',
    '-out',
    file('ca.csr'),
  );
  openssl(
    'ca',
    '-batch',
    '-selfsign',
    '-notext',
    '-config',
    file('issuer.cnf'),
    '-in',
    file('ca.csr'),
    '-out',
    file('ca.pem'),
    '-startdate',
    time(now - 86400000),
    '-enddate',
    time(now + 172800000),
    '-extfile',
    file('authority.cnf'),
    '-extensions',
    'authority',
  );
  const ca = await readFile(file('ca.pem'));
  let bound = false;
  return {
    ca,
    async bindWorkload(
      workloadId: string,
      options: {
        initiallyCurrent?: boolean;
        runtimeTargetId?: string;
        /** Finite validity of newly signed isolated initial trust only. */
        initialCredentialLifetimeMs?: number;
      } = {},
    ) {
      if (bound) throw new Error('Workload authority was already bound');
      if (!/^urn:openpc:workload:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(workloadId))
        throw new Error('Canonical workload identity is required');
      if (
        options.runtimeTargetId !== undefined &&
        workloadId !== `urn:openpc:workload:${options.runtimeTargetId}`
      )
        throw new Error('Workload must match the exact public runtime target');
      const initialLifetimeMs = options.initialCredentialLifetimeMs ?? 10000;
      if (
        !Number.isSafeInteger(initialLifetimeMs) ||
        initialLifetimeMs < 1000 ||
        initialLifetimeMs > 180000 ||
        (options.initialCredentialLifetimeMs !== undefined && options.initiallyCurrent !== true)
      )
        throw new Error(
          'Initial credential validity must be an explicit finite current test issuance',
        );
      bound = true;
      const now = Date.now();
      await writeFile(
        file('client.cnf'),
        `[client]\nsubjectAltName=URI:urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}\nextendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n`,
      );
      const leaf = async (name: string, start: number, end: number, server = false) => {
        openssl(
          'req',
          '-new',
          '-newkey',
          'ec',
          '-pkeyopt',
          'ec_paramgen_curve:P-256',
          '-nodes',
          '-subj',
          `/CN=Workload rotation ${name}`,
          '-keyout',
          file(`${name}.key`),
          '-out',
          file(`${name}.csr`),
        );
        openssl(
          'ca',
          '-batch',
          '-notext',
          '-config',
          file('issuer.cnf'),
          '-cert',
          file('ca.pem'),
          '-in',
          file(`${name}.csr`),
          '-out',
          file(`${name}.pem`),
          '-startdate',
          time(start),
          '-enddate',
          time(end),
          '-extfile',
          file(server ? 'server.cnf' : 'client.cnf'),
          '-extensions',
          server ? 'server' : 'client',
        );
        const certificate = new X509Certificate(await readFile(file(`${name}.pem`)));
        return {
          certificate,
          publicKey: Buffer.from(certificate.publicKey.export({ format: 'der', type: 'spki' })),
          pem: await readFile(file(`${name}.pem`)),
          privateKey: await readFile(file(`${name}.key`)),
        };
      };
      await writeFile(
        file('server.cnf'),
        '[server]\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n',
      );
      let initialIssued = false;
      return {
        ca: await readFile(file('ca.pem')),
        predecessor: await leaf(
          'predecessor',
          now - 1800000,
          options.initiallyCurrent ? now + initialLifetimeMs : now - 60000,
        ),
        successor: await leaf('successor', now - 10000, now + 3600000),
        server: await leaf('provider-server', now - 10000, now + 3600000, true),
        async issueInitialPredecessor() {
          if (initialIssued) throw new Error('Initial predecessor was already issued');
          initialIssued = true;
          const issuedAt = Date.now();
          return leaf('enrolled-predecessor', issuedAt - 1000, issuedAt + initialLifetimeMs);
        },
      };
    },
  };
}

/** Preserve the existing standalone workload fixture contract. */
export async function workloadRotationCertificates(
  root: string,
  participantId: string,
  workloadId: string,
  initiallyCurrent = false,
) {
  const authority = await workloadRotationAuthority(root, participantId);
  return authority.bindWorkload(workloadId, { initiallyCurrent });
}
