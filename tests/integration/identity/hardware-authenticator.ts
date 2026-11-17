/** External authenticator emulator. Generated keys are disposable test trust, never device qualification. */
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  X509Certificate,
  type KeyObject,
} from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeAttestationObject, isoCBOR } from '@simplewebauthn/server/helpers';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';

export const emulatorAaguid = '018f0000-0000-7000-8000-000000000999';
export function attestHardwareRegistration(
  response: RegistrationResponseJSON,
  leaf: string,
  key: Buffer,
  aaguid = emulatorAaguid,
  flags?: number,
): RegistrationResponseJSON {
  const original = decodeAttestationObject(
    new Uint8Array(Buffer.from(response.response.attestationObject, 'base64url')),
  );
  const authData = Buffer.from(original.get('authData'));
  Buffer.from(aaguid.replaceAll('-', ''), 'hex').copy(authData, 37);
  if (flags !== undefined) authData[32] = flags;
  const signature = sign(
    'sha256',
    Buffer.concat([
      authData,
      createHash('sha256')
        .update(Buffer.from(response.response.clientDataJSON, 'base64url'))
        .digest(),
    ]),
    key,
  );
  const statement = new Map<string, number | Uint8Array | Uint8Array[]>([
    ['alg', -7],
    ['sig', new Uint8Array(signature)],
    ['x5c', [new Uint8Array(new X509Certificate(leaf).raw)]],
  ]);
  const encoded = isoCBOR.encode(
    new Map<string, Parameters<typeof isoCBOR.encode>[0]>([
      ['fmt', 'packed'],
      ['authData', new Uint8Array(authData)],
      ['attStmt', statement],
    ]),
  );
  return {
    ...response,
    response: {
      ...response.response,
      attestationObject: Buffer.from(encoded).toString('base64url'),
    },
  };
}

export function createHardwareAuthenticatorEmulator() {
  const directory = mkdtempSync(
    join(process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT ?? tmpdir(), 'hardware-authenticator-'),
  );
  const openssl = (...args: string[]) =>
    execFileSync('openssl', args, { cwd: directory, stdio: 'pipe' });
  openssl(
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'root.key',
    '-out',
    'root.pem',
    '-days',
    '2',
    '-subj',
    '/CN=OpenPC External Test Authenticator Root',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
  );
  openssl(
    'req',
    '-new',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'leaf.key',
    '-out',
    'leaf.csr',
    '-subj',
    '/C=US/O=OpenPC External Test/OU=Authenticator Attestation/CN=Disposable Test Authenticator',
  );
  writeFileSync(
    join(directory, 'leaf.ext'),
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n',
  );
  openssl(
    'x509',
    '-req',
    '-in',
    'leaf.csr',
    '-CA',
    'root.pem',
    '-CAkey',
    'root.key',
    '-CAcreateserial',
    '-out',
    'leaf.pem',
    '-days',
    '2',
    '-extfile',
    'leaf.ext',
  );
  const leaf = readFileSync(join(directory, 'leaf.pem'), 'utf8');
  const key = readFileSync(join(directory, 'leaf.key'));
  const root = readFileSync(join(directory, 'root.pem'), 'utf8');
  const attest = (response: RegistrationResponseJSON, aaguid = emulatorAaguid, flags?: number) =>
    attestHardwareRegistration(response, leaf, key, aaguid, flags);
  return {
    directory,
    root,
    profile: {
      profileId: 'openpc-external-authenticator-test',
      aaguids: [emulatorAaguid],
      rootCertificatesPem: [root],
    },
    attest,
    dispose: () => rmSync(directory, { recursive: true, force: true }),
  };
}

export function createUnattestedTestRegistration(
  challenge: string,
  origin: string,
  rpId: string,
  publicKey?: KeyObject,
): RegistrationResponseJSON {
  const key = (
    publicKey ?? generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey
  ).export({
    format: 'jwk',
  });
  const credentialId = randomBytes(32);
  const cose = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(Buffer.from(key.x!, 'base64url'))],
      [-3, new Uint8Array(Buffer.from(key.y!, 'base64url'))],
    ]),
  );
  const authData = Buffer.concat([
    createHash('sha256').update(rpId).digest(),
    Buffer.from([0x45, 0, 0, 0, 1]),
    Buffer.alloc(16),
    Buffer.from([0, credentialId.length]),
    credentialId,
    Buffer.from(cose),
  ]);
  return {
    id: credentialId.toString('base64url'),
    rawId: credentialId.toString('base64url'),
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: Buffer.from(
        JSON.stringify({
          type: 'webauthn.create',
          challenge: Buffer.from(challenge).toString('base64url'),
          origin,
          crossOrigin: false,
        }),
      ).toString('base64url'),
      attestationObject: Buffer.from(
        isoCBOR.encode(
          new Map<string, Parameters<typeof isoCBOR.encode>[0]>([
            ['fmt', 'none'],
            ['authData', new Uint8Array(authData)],
            ['attStmt', new Map<string, never>()],
          ]),
        ),
      ).toString('base64url'),
      transports: ['usb'],
    },
  };
}
