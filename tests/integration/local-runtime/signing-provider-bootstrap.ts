import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { chmod, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { evidenceKeyId } from '../../../packages/security-kernel/src/business-transition/cose.js';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  type IdentityEnvelopeSigningTrust,
} from '../../../packages/security-kernel/src/index.js';
import {
  businessSigningPurpose,
  businessProviderDescriptorSchema,
  type BusinessProviderDescriptor,
} from '../../../services/identity-service/src/domain/business-signing-provider.js';
import { createFixtureSigningStore } from './signing-provider-fixture-store.js';
import { createEnvelopeFixtureStore } from './signing-provider-envelope-store.js';
import {
  identityEnvelopeProviderDescriptorSchema,
  type IdentityEnvelopeProviderDescriptor,
} from '../../../services/identity-service/src/domain/identity-envelope-signing-provider.js';
import {
  rpcRetirementSigningFamilies,
  rpcRetirementSigningWorkload,
} from './rpc-retirement-signing.js';

import {
  runtimeSourceSigningFamilies,
  runtimeSourceSigningName,
} from './runtime-source-disposition-signing.js';

const [secretRoot, providerRoot, mode, scopedPrivacy] = process.argv.slice(2);
if (!secretRoot || !providerRoot) throw new Error('Owned signing provider roots are required');
assert.ok(
  mode === undefined ||
    mode === '--deletion-scope' ||
    mode === '--rejection-deletion' ||
    mode === '--participant-hold' ||
    mode === '--source-hold' ||
    mode === '--raw-deletion' ||
    mode === '--projection-deletion' ||
    mode === '--rpc-retirement' ||
    mode === '--store-retirement' ||
    mode === '--work-item' ||
    mode === '--runtime-scope' ||
    mode === '--runtime-source-disposition',
);
if (
  mode === '--runtime-source-disposition' ||
  mode === '--runtime-scope' ||
  mode === '--source-hold' ||
  (mode === '--participant-hold' && scopedPrivacy !== undefined) ||
  mode === '--raw-deletion' ||
  mode === '--projection-deletion' ||
  mode === '--rpc-retirement' ||
  mode === '--store-retirement' ||
  mode === '--work-item'
) {
  assert.match(
    scopedPrivacy ?? '',
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  if (mode !== '--projection-deletion' && mode !== '--rpc-retirement')
    assert.notEqual(scopedPrivacy, '018f0000-0000-7000-8000-000000000201');
}
const participantId = '018f0000-0000-7000-8000-000000000101';
const rpcRetirement = mode === '--rpc-retirement';
const tlsRoot = rpcRetirement ? join(secretRoot, 'rpc-retirement-transport') : secretRoot;
let prepareTls = mode === undefined;
if (rpcRetirement) {
  const exists = await stat(tlsRoot).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!exists) {
    await mkdir(tlsRoot, { mode: 0o700 });
    prepareTls = true;
  } else {
    assert.ok(exists.isDirectory());
    const expected = [
      'business_provider_ca.pem',
      'business_provider_server_cert.pem',
      'business_provider_server_key.pem',
      'business_api_cert.pem',
      'business_api_key.pem',
    ];
    assert.deepEqual(
      (await readdir(tlsRoot)).sort(),
      expected.sort(),
      'Partial transport requires diagnosis, never overwrite',
    );
    for (const file of expected.filter((file) => file.endsWith('cert.pem'))) {
      const certificate = new X509Certificate(await readFile(join(tlsRoot, file)));
      assert.ok(
        Date.parse(certificate.validTo) > Date.now() + 120000,
        'Retained transport must remain current',
      );
    }
  }
}
if (prepareTls) {
  const openssl = (args: string[]) =>
    execFileSync('openssl', args, { cwd: tlsRoot, stdio: 'ignore' });
  openssl([
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-keyout',
    'business_provider_ca.key',
    '-out',
    'business_provider_ca.pem',
    '-days',
    '1',
    '-subj',
    '/CN=OpenPC-local-external-signing-provider',
  ]);
  for (const [name, san, serial, usage] of [
    [
      'business_provider_server',
      'DNS:signing-provider,DNS:localhost,IP:127.0.0.1',
      '1',
      'serverAuth',
    ],
    [
      'business_api',
      `URI:urn:openpc:participant:${participantId}:workload:${rpcRetirement ? rpcRetirementSigningWorkload.workloadId : '018f0000-0000-7000-8000-000000000196'}`,
      '2',
      'clientAuth',
    ],
    [
      'business_worker',
      `URI:urn:openpc:participant:${participantId}:workload:018f0000-0000-7000-8000-000000000199`,
      '3',
      'clientAuth',
    ],
  ] as const) {
    if (rpcRetirement && name === 'business_worker') continue;
    openssl([
      'req',
      '-new',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      `${name}_key.pem`,
      '-out',
      `${name}.csr`,
      '-subj',
      `/CN=${name}`,
    ]);
    await writeFile(
      join(tlsRoot, `${name}.ext`),
      `subjectAltName=${san}\nextendedKeyUsage=${usage}\nkeyUsage=digitalSignature\n`,
      { mode: 0o600 },
    );
    openssl([
      'x509',
      '-req',
      '-in',
      `${name}.csr`,
      '-CA',
      'business_provider_ca.pem',
      '-CAkey',
      'business_provider_ca.key',
      '-set_serial',
      serial!,
      '-days',
      '1',
      '-extfile',
      `${name}.ext`,
      '-out',
      `${name}_cert.pem`,
    ]);
    await chmod(join(tlsRoot, `${name}_key.pem`), 0o444);
    await chmod(join(tlsRoot, `${name}_cert.pem`), 0o444);
    await rm(join(tlsRoot, `${name}.csr`));
    await rm(join(tlsRoot, `${name}.ext`));
  }
  await rm(join(tlsRoot, 'business_provider_ca.key'));
  await chmod(join(tlsRoot, 'business_provider_ca.pem'), 0o444);
}
const initialKeys: { descriptor: BusinessProviderDescriptor; privateKeyPkcs8Der: Buffer }[] = [];
let envelopePrivateKey: Buffer | undefined;
try {
  const basePrivacy = '018f0000-0000-7000-8000-000000000201';
  const deletionPrivacy = '018f0000-0000-7000-8000-000000004201';
  const keyDefinitions =
    mode === '--runtime-source-disposition'
      ? runtimeSourceSigningFamilies.map(
          ({ family }) =>
            [
              runtimeSourceSigningName(scopedPrivacy!, family),
              `secret://local/control-runtime-source-${scopedPrivacy}-${family}-evidence#1`,
              scopedPrivacy!,
            ] as const,
        )
      : mode === '--rpc-retirement'
        ? rpcRetirementSigningFamilies.map(
            ({ family }) =>
              [
                `control_rpc_retirement_${scopedPrivacy}_${family}_signing`,
                `secret://local/control-rpc-retirement-${scopedPrivacy}-${family}-evidence#1`,
                scopedPrivacy!,
              ] as const,
          )
        : mode === '--work-item'
          ? [
              [
                `control_work_item_${scopedPrivacy}_signing`,
                `secret://local/control-work-item-${scopedPrivacy}-evidence#1`,
                scopedPrivacy!,
              ] as const,
            ]
          : mode === '--store-retirement'
            ? [
                [
                  `control_store_retirement_${scopedPrivacy}_signing`,
                  `secret://local/control-store-retirement-${scopedPrivacy}-evidence#1`,
                  scopedPrivacy!,
                ] as const,
                [
                  `control_store_retirement_${scopedPrivacy}_retention_signing`,
                  `secret://local/control-store-retirement-${scopedPrivacy}-retention-evidence#1`,
                  scopedPrivacy!,
                ] as const,
              ]
            : mode === '--projection-deletion'
              ? ['hold', 'retention', 'deletion-local', 'deletion-projection'].map(
                  (family) =>
                    [
                      `control_projection_deletion_${scopedPrivacy}_${family}_signing`,
                      `secret://local/control-projection-deletion-${scopedPrivacy}-${family}-evidence#1`,
                      scopedPrivacy!,
                    ] as const,
                )
              : mode === '--raw-deletion'
                ? ['hold', 'retention', 'deletion'].map(
                    (family) =>
                      [
                        `control_raw_deletion_${scopedPrivacy}_${family}_signing`,
                        `secret://local/control-raw-deletion-${scopedPrivacy}-${family}-evidence#1`,
                        scopedPrivacy!,
                      ] as const,
                  )
                : mode === '--participant-hold'
                  ? [
                      [
                        scopedPrivacy
                          ? `control_participant_hold_${scopedPrivacy}_signing`
                          : 'control_participant_hold_signing',
                        scopedPrivacy
                          ? `secret://local/control-participant-hold-${scopedPrivacy}-evidence#1`
                          : 'secret://local/control-participant-hold-evidence#1',
                        scopedPrivacy ?? basePrivacy,
                      ] as const,
                    ]
                  : mode === '--runtime-scope' || mode === '--source-hold'
                    ? [
                        [
                          `control_${mode === '--source-hold' ? 'source_hold' : 'runtime'}_scope_${scopedPrivacy}_signing`,
                          `secret://local/control-${mode === '--source-hold' ? 'source-hold' : 'runtime'}-${scopedPrivacy}-evidence#1`,
                          scopedPrivacy!,
                        ] as const,
                      ]
                    : [
                        [
                          'control_evidence_deletion_signing',
                          'secret://local/control-local-deletion-evidence#1',
                          basePrivacy,
                        ] as const,
                        ...(mode === undefined
                          ? [
                              [
                                'control_business_signing',
                                'secret://local/control-business-evidence#1',
                              ],
                              [
                                'control_lifecycle_signing',
                                'secret://local/control-lifecycle-evidence#1',
                              ],
                              ['control_hold_signing', 'secret://local/control-hold-evidence#1'],
                              [
                                'control_participant_hold_signing',
                                'secret://local/control-participant-hold-evidence#1',
                              ],
                              [
                                'control_retention_signing',
                                'secret://local/control-retention-evidence#1',
                              ],
                              [
                                'control_notification_signing',
                                'secret://local/control-notification-evidence#1',
                              ],
                              ...(process.env.OPENPC_LOCAL_RUNTIME_WORK_ITEM_BROWSER_ONLY === '1'
                                ? [
                                    [
                                      'control_work_item_signing',
                                      'secret://local/control-work-item-evidence#1',
                                    ],
                                  ]
                                : []),
                            ].map(([name, reference]) => [name!, reference!, basePrivacy] as const)
                          : []),
                        ...['hold', 'retention', 'deletion', 'deletion-batch'].map(
                          (family) =>
                            [
                              `control_deletion_scope_${family}_signing`,
                              `secret://local/control-deletion-scope-${family}-evidence#1`,
                              deletionPrivacy,
                            ] as const,
                        ),
                      ];
  for (const [name, reference, privacyDomainId] of keyDefinitions) {
    const fileId = createHash('sha256').update(reference).digest('hex');
    const optional = async (path: string) =>
      readFile(path).catch((error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
    const prior = await optional(join(providerRoot, 'public', fileId + '.json'));
    if (prior) {
      const descriptor = businessProviderDescriptorSchema.parse(
        JSON.parse(prior.toString()).descriptor,
      );
      assert.equal(descriptor.participantId, participantId);
      assert.equal(descriptor.privacyDomainId, privacyDomainId);
      assert.equal(descriptor.reference, reference);
      assert.equal(descriptor.state, 'ACTIVE');
      assert.ok(
        BigInt(descriptor.validUntilNs) > BigInt(Date.now() + 120000) * 1000000n,
        'Initial signing key must remain live',
      );
      const publicBytes = Buffer.from(descriptor.publicKeySpkiHex, 'hex');
      assert.equal(evidenceKeyId(publicBytes), descriptor.fingerprint);
      for (const [filename, bytes] of [
        [`${name}_public_key.der`, publicBytes],
        [`${name}_descriptor.json`, Buffer.from(JSON.stringify(descriptor))],
      ] as const) {
        const existing = await optional(join(secretRoot, filename));
        if (existing) assert.deepEqual(existing, bytes);
        else await writeFile(join(secretRoot, filename), bytes, { flag: 'wx', mode: 0o444 });
      }
      continue;
    }
    assert.equal(
      await stat(join(providerRoot, 'keys', fileId + '.der')).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === 'ENOENT') return null;
          throw error;
        },
      ),
      null,
      'Unresolved provider key requires diagnosis',
    );
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privateKeyPkcs8Der = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
    const publicBytes = pair.publicKey.export({ format: 'der', type: 'spki' });
    const now = BigInt(Date.now()) * 1000000n;
    const descriptor: BusinessProviderDescriptor = {
      participantId,
      privacyDomainId,
      workloadCredentialId: rpcRetirement
        ? rpcRetirementSigningWorkload.credentialId
        : '018f0000-0000-7000-8000-000000000195',
      environmentId: 'local',
      secretClass: 'SECRET-SIGNING-KEY',
      purpose: businessSigningPurpose,
      reference,
      version: '1',
      algorithm: 'ES256',
      publicKeySpkiHex: publicBytes.toString('hex'),
      fingerprint: evidenceKeyId(publicBytes),
      validFromNs: (now - 1000000000n).toString(),
      validUntilNs: (now + 86400000000000n).toString(),
      state: 'ACTIVE',
      revokedAtNs: null,
      retiredAtNs: null,
    };
    initialKeys.push({ descriptor, privateKeyPkcs8Der });
    await createFixtureSigningStore({
      root: providerRoot,
      initialKeys: [{ descriptor, privateKeyPkcs8Der }],
    });
    await writeFile(join(secretRoot, `${name}_public_key.der`), publicBytes, {
      mode: 0o444,
      flag: 'wx',
    });
    await writeFile(join(secretRoot, `${name}_descriptor.json`), JSON.stringify(descriptor), {
      mode: 0o444,
      flag: 'wx',
    });
  }
  if (mode === undefined) {
    const reference = 'secret://local/identity-envelope-activation#1';
    const fileId = createHash('sha256').update(reference).digest('hex');
    const publicPath = join(providerRoot, 'identity-envelope', 'public', fileId + '.json');
    const privatePath = join(providerRoot, 'identity-envelope', 'keys', fileId + '.der');
    const optional = async (path: string) =>
      readFile(path).catch((error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
    let descriptor: IdentityEnvelopeProviderDescriptor;
    const prior = await optional(publicPath);
    if (prior) {
      descriptor = identityEnvelopeProviderDescriptorSchema.parse(JSON.parse(prior.toString()));
      assert.equal(descriptor.participantId, participantId);
      assert.equal(descriptor.privacyDomainId, basePrivacy);
      assert.equal(descriptor.reference, reference);
      assert.ok(BigInt(descriptor.validUntilNs) > BigInt(Date.now() + 120000) * 1000000n);
    } else {
      const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      envelopePrivateKey = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
      const publicKeySpkiDer = pair.publicKey.export({ format: 'der', type: 'spki' });
      const now = BigInt(Date.now()) * 1000000n;
      const trust: IdentityEnvelopeSigningTrust = {
        participantId,
        privacyDomainId: basePrivacy,
        environmentId: 'local',
        signerId: evidenceKeyId(publicKeySpkiDer),
        publicKeySpkiDer,
        workloadCredentialId: '018f0000-0000-7000-8000-000000000195',
        workloadCredentialEpoch: 1n,
        workloadParticipantEpoch: 1n,
        workloadPrincipalEpoch: 1n,
        keyEpoch: 1n,
        validFromNs: now - 1000000000n,
        validUntilNs: now + 86400000000000n,
        admissionKind: 'BOOTSTRAP',
        admissionReference: 'local-qa-initial-envelope-signing-trust',
        admissionDigest: createHash('sha256')
          .update('local-qa-initial-envelope-signing-trust')
          .digest(),
        secretClass: 'SECRET-SIGNING-KEY',
        secretReference: reference,
        secretVersion: '1',
        purpose: 'pc.cose.identity-authority-envelope.v1',
        profileId: 'pc.identity.authority-envelope.v1',
        profileVersion: 1,
        profileDigest: identityEnvelopeSigningProfileDigest,
      };
      descriptor = identityEnvelopeProviderDescriptorSchema.parse({
        participantId,
        privacyDomainId: basePrivacy,
        environmentId: 'local',
        workloadCredentialId: trust.workloadCredentialId,
        workloadCredentialEpoch: '1',
        secretClass: trust.secretClass,
        reference,
        version: '1',
        purpose: trust.purpose,
        purposeCode: 371,
        schemaId: 24034,
        schemaVersion: 1,
        schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
        profileId: trust.profileId,
        profileVersion: 1,
        profileDigest: trust.profileDigest,
        trustContextDigest: identityEnvelopeSigningTrustDigest(trust),
        algorithm: 'ES256',
        publicKeySpkiHex: publicKeySpkiDer.toString('hex'),
        fingerprint: trust.signerId,
        validFromNs: String(trust.validFromNs),
        validUntilNs: String(trust.validUntilNs),
        state: 'ACTIVE',
      });
      await createEnvelopeFixtureStore(providerRoot, {
        clients: [],
        initialKeys: [{ descriptor, privateKeyPkcs8Der: envelopePrivateKey }],
      });
    }
    const publicKeySpkiDer = Buffer.from(descriptor.publicKeySpkiHex, 'hex');
    for (const [filename, bytes] of [
      ['identity_envelope_signing_public_key.der', publicKeySpkiDer],
      ['identity_envelope_signing_descriptor.json', Buffer.from(JSON.stringify(descriptor))],
    ] as const) {
      const existing = await optional(join(secretRoot, filename));
      if (existing) assert.deepEqual(existing, bytes);
      else await writeFile(join(secretRoot, filename), bytes, { flag: 'wx', mode: 0o444 });
    }
    assert.ok(await optional(privatePath), 'Envelope signing private key must be durable');
  }
} finally {
  for (const key of initialKeys) key.privateKeyPkcs8Der.fill(0);
  envelopePrivateKey?.fill(0);
}
