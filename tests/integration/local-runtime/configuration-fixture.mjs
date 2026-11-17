import { createECDH, createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { keccak_256 } from '@noble/hashes/sha3.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const identities = {
  operator: {
    principalId: '018f0000-0000-7000-8000-000000000111',
    credentialId: '018f0000-0000-7000-8000-000000000916',
    approvalRequestId: '018f0000-0000-7000-8000-000000000918',
  },
  checker: {
    principalId: '018f0000-0000-7000-8000-000000000112',
    credentialId: '018f0000-0000-7000-8000-000000000917',
    approvalRequestId: '018f0000-0000-7000-8000-000000000919',
  },
};

const sha256 = (value) => createHash('sha256').update(value).digest();

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`;
}

function uuidv7() {
  const bytes = randomBytes(16);
  let timestamp = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function contractAbiFixture(factory = false, visibility = false) {
  const abi = factory
    ? [
        {
          type: 'function',
          name: 'deploy',
          inputs: [{ name: 'init', type: 'bytes' }],
          outputs: [{ name: 'created', type: 'address' }],
          stateMutability: 'nonpayable',
        },
        {
          type: 'function',
          name: 'deploy2',
          inputs: [
            { name: 'init', type: 'bytes' },
            { name: 'salt', type: 'bytes32' },
          ],
          outputs: [{ name: 'created', type: 'address' }],
          stateMutability: 'nonpayable',
        },
        {
          type: 'function',
          name: 'deploy3',
          inputs: [
            { name: 'init', type: 'bytes' },
            { name: 'salt', type: 'bytes32' },
          ],
          outputs: [{ name: 'created', type: 'address' }],
          stateMutability: 'nonpayable',
        },
      ]
    : [
        {
          type: 'function',
          name: 'transfer',
          inputs: [
            { name: 'to', type: 'address' },
            { name: 'amount', type: 'uint256' },
          ],
          outputs: [{ name: '', type: 'bool' }],
          stateMutability: 'nonpayable',
        },
        {
          type: 'function',
          name: 'balanceOf',
          inputs: [{ name: 'account', type: 'address' }],
          outputs: [{ name: '', type: 'uint256' }],
          stateMutability: 'view',
        },
      ];
  if (visibility)
    abi.push({
      type: 'event',
      name: 'Changed',
      anonymous: false,
      inputs: [{ name: 'value', type: 'uint256', indexed: false }],
    });
  const sourceBytes = Buffer.from(canonicalJson(abi));
  const digest = `sha256:${sha256(sourceBytes).toString('hex')}`;
  process.stdout.write(
    JSON.stringify({
      abi,
      sourceDocument: sourceBytes.toString('base64'),
      sourceDigest: digest,
      abiDigest: digest,
      selector: `0x${Buffer.from(keccak_256(new TextEncoder().encode('transfer(address,uint256)')))
        .toString('hex')
        .slice(0, 8)}`,
    }),
  );
}

async function identityFixture(root) {
  const { encodeIdentityCredentialPayload, signIdentityCredentialCoseSign1Es256 } =
    await import('../../../packages/security-kernel/src/index.ts');
  const result = {};
  for (const [name, identity] of Object.entries(identities)) {
    const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privateKeyPkcs8Der = keys.privateKey.export({ format: 'der', type: 'pkcs8' });
    const publicKeySpkiDer = keys.publicKey.export({ format: 'der', type: 'spki' });
    const privateKeyPath = join(root, `${name}-webauthn.pk8`);
    await writeFile(privateKeyPath, privateKeyPkcs8Der, { flag: 'wx', mode: 0o400 });
    const evidenceCbor = encodeIdentityCredentialPayload({
      participantId: `urn:openpc:participant:${participantId}`,
      principalId: `urn:openpc:principal:${identity.principalId}`,
      authorityEpoch: '1',
      issuedAt: '2026-09-10T00:00:00.000000Z',
      expiresAt: '2036-09-10T00:00:00.000000Z',
    });
    const coseSign1 = signIdentityCredentialCoseSign1Es256(
      privateKeyPkcs8Der,
      publicKeySpkiDer,
      evidenceCbor,
    );
    const subjectDigest = sha256(evidenceCbor);
    result[name] = {
      ...identity,
      privateKeyPath,
      publicKeySpkiDerHex: publicKeySpkiDer.toString('hex'),
      publicKeyDigestHex: sha256(publicKeySpkiDer).toString('hex'),
      evidenceCborHex: evidenceCbor.toString('hex'),
      coseSign1Hex: coseSign1.toString('hex'),
      subjectDigestHex: subjectDigest.toString('hex'),
      decisionDigestHex: sha256(Buffer.concat([subjectDigest, evidenceCbor])).toString('hex'),
    };
  }
  process.stdout.write(JSON.stringify(result));
}

async function authorizationEvidence(fixturePath, identityName, sequenceText) {
  if (!Object.hasOwn(identities, identityName) || !/^[1-9][0-9]{0,5}$/.test(sequenceText)) {
    throw new Error('invalid authorization evidence input');
  }
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'))[identityName];
  if (
    fixture === undefined ||
    typeof fixture.privateKeyPath !== 'string' ||
    typeof fixture.publicKeySpkiDerHex !== 'string'
  ) {
    throw new Error('invalid identity fixture');
  }
  const identity = identities[identityName];
  const { encodeIdentityCredentialPayload, signIdentityCredentialCoseSign1Es256 } =
    await import('../../../packages/security-kernel/src/index.ts');
  const issuedAt = new Date(Date.UTC(2026, 8, 10, 0, 0, 0) + Number(sequenceText) * 1_000)
    .toISOString()
    .replace('Z', '000Z');
  const evidenceCbor = encodeIdentityCredentialPayload({
    participantId: `urn:openpc:participant:${participantId}`,
    principalId: `urn:openpc:principal:${identity.principalId}`,
    authorityEpoch: '1',
    issuedAt,
    expiresAt: '2036-09-10T00:00:00.000000Z',
  });
  const coseSign1 = signIdentityCredentialCoseSign1Es256(
    await readFile(fixture.privateKeyPath),
    Buffer.from(fixture.publicKeySpkiDerHex, 'hex'),
    evidenceCbor,
  );
  process.stdout.write(
    JSON.stringify({
      evidenceCborHex: evidenceCbor.toString('hex'),
      evidenceDigestHex: sha256(evidenceCbor).toString('hex'),
      coseSign1Hex: coseSign1.toString('hex'),
    }),
  );
}

async function webAuthnAssertion(args) {
  const [privateKeyPath, credentialId, challenge, origin, rpIdHashText, signCountText] = args;
  if (!/^sha256:[0-9a-f]{64}$/.test(rpIdHashText) || !/^[1-9][0-9]*$/.test(signCountText)) {
    throw new Error('invalid WebAuthn fixture input');
  }
  const clientDataJson = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
  const authenticatorData = Buffer.alloc(37);
  Buffer.from(rpIdHashText.slice(7), 'hex').copy(authenticatorData);
  authenticatorData[32] = 0x05;
  authenticatorData.writeUInt32BE(Number(signCountText), 33);
  const signature = sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJson)]), {
    key: await readFile(privateKeyPath),
    format: 'der',
    type: 'pkcs8',
  });
  process.stdout.write(
    JSON.stringify({
      credentialId,
      authenticatorData: authenticatorData.toString('base64url'),
      clientDataJson: clientDataJson.toString('base64url'),
      signature: signature.toString('base64url'),
    }),
  );
}

const [command, ...args] = process.argv.slice(2);
if (command === 'identity-fixture' && args.length === 1) {
  await identityFixture(args[0]);
} else if (command === 'fact-reader-trust' && args.length === 1) {
  const key = createECDH('prime256v1');
  key.setPrivateKey(
    Buffer.from((await readFile(join(args[0], 'fact_signing_secret.txt'), 'utf8')).trim(), 'hex'),
  );
  await writeFile(
    join(args[0], 'policy_fact_verify_key.sec1'),
    key.getPublicKey(undefined, 'compressed'),
    { mode: 0o444 },
  );
  await chmod(join(args[0], 'policy_fact_verify_key.sec1'), 0o444);
} else if (command === 'authorization-evidence' && args.length === 3) {
  await authorizationEvidence(args[0], args[1], args[2]);
} else if (command === 'assertion' && args.length === 6) {
  await webAuthnAssertion(args);
} else if (command === 'digest' && args.length === 1) {
  process.stdout.write(`sha256:${sha256(canonicalJson(JSON.parse(args[0]))).toString('hex')}`);
} else if (command === 'etag' && args.length === 2) {
  process.stdout.write(
    `"sha256:${sha256(canonicalJson({ resourceId: args[0], revision: args[1] })).toString('hex')}"`,
  );
} else if (command === 'uuidv7' && args.length === 0) {
  process.stdout.write(uuidv7());
} else if (command === 'contract-abi' && args.length === 0) {
  contractAbiFixture();
} else if (command === 'visibility-abi' && args.length === 0) {
  contractAbiFixture(false, true);
} else if (command === 'factory-abi' && args.length === 0) {
  contractAbiFixture(true);
} else if (command === 'sha256-text' && args.length === 1) {
  process.stdout.write(`sha256:${sha256(args[0]).toString('hex')}`);
} else if (command === 'decision-digest' && args.length === 2) {
  process.stdout.write(
    sha256(
      Buffer.concat([Buffer.from(args[0].slice(7), 'hex'), Buffer.from(args[1], 'hex')]),
    ).toString('hex'),
  );
} else {
  throw new Error('unknown configuration fixture command');
}
