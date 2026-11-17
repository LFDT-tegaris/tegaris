import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  qualificationKeyDescriptorSchema,
  qualificationKeyPeerSchema,
} from '../../../services/identity-service/src/domain/qualification-key-provider.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  rpcRetirementSigningWorkload,
  rpcRetirementSigningFamilies,
  rpcRetirementSigningProfiles,
} from './rpc-retirement-signing.js';
import { businessTransitionProfiles } from '../../../packages/security-kernel/src/business-transition/profiles.generated.js';
import {
  createFixtureSigningProvider,
  type FixtureSigningClient,
} from './signing-provider-fixture.js';
import { identityEnvelopeProviderDescriptorSchema } from '../../../services/identity-service/src/domain/identity-envelope-signing-provider.js';

const secrets = process.env.OPENPC_SIGNING_PROVIDER_SECRET_ROOT ?? '/run/secrets';
const root = process.env.OPENPC_SIGNING_PROVIDER_STATE_ROOT;
if (!root) throw new Error('External signing provider state root is required');
const read = (name: string) => readFile(join(secrets, name));
const rpcRetirement = process.env.OPENPC_SIGNING_PROVIDER_RPC_RETIREMENT === '1';
assert.ok(process.env.OPENPC_SIGNING_PROVIDER_RPC_RETIREMENT === undefined || rpcRetirement);
const apiCredentialId = rpcRetirement
  ? rpcRetirementSigningWorkload.credentialId
  : '018f0000-0000-7000-8000-000000000195';
const scope = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  environmentId: 'local',
  managedKeyOwners: [apiCredentialId],
};
const runtimePrivacy = process.env.OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID;
if (runtimePrivacy !== undefined)
  assert.match(
    runtimePrivacy,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const clients: FixtureSigningClient[] = [
  {
    ...scope,
    credentialId: apiCredentialId,
    workloadId: rpcRetirement
      ? rpcRetirementSigningWorkload.workloadId
      : '018f0000-0000-7000-8000-000000000196',
    certificate: await read('business_api_cert'),
    methods: ['INSPECT', 'PROVE', 'SIGN_RECEIPT'],
    additionalPrivacyDomainIds: [
      ...new Set([
        '018f0000-0000-7000-8000-000000004201',
        // Isolated initial-trust scope owned by the retention-search browser.
        '018f0021-0000-7000-8000-000000000201',
        ...(runtimePrivacy ? [runtimePrivacy] : []),
      ]),
    ],
    signingProfiles: (rpcRetirement
      ? rpcRetirementSigningFamilies.flatMap(({ family }) => rpcRetirementSigningProfiles(family))
      : businessTransitionProfiles
    ).map(({ profileId, profileVersion, profileDigest }) => ({
      profileId,
      profileVersion,
      profileDigest,
    })),
  },
  ...(!rpcRetirement
    ? [
        {
          ...scope,
          credentialId: '018f0000-0000-7000-8000-000000000198',
          workloadId: '018f0000-0000-7000-8000-000000000199',
          certificate: await read('business_worker_cert'),
          methods: [
            'INSPECT',
            'PREPARE',
            'DISTRIBUTE',
            'REVOKE',
            'RETIRE',
          ] as FixtureSigningClient['methods'],
          signingProfiles: [],
        },
      ]
    : []),
];
// Explicit opt-in external fixture configuration, never production custody.
// Only file names under the already installed secret root are accepted.
const qualificationEnabled = process.env.OPENPC_SIGNING_PROVIDER_QUALIFICATION === '1';
assert.ok(process.env.OPENPC_SIGNING_PROVIDER_QUALIFICATION === undefined || qualificationEnabled);
const secretName = z.string().regex(/^[a-zA-Z0-9_-]{1,96}$/u);
const qualification = qualificationEnabled
  ? await (async () => {
      const config = z
        .strictObject({
          clients: z
            .array(
              z.strictObject({
                certificateFile: secretName,
                peer: qualificationKeyPeerSchema,
                participantId: z.uuidv7(),
                privacyDomainId: z.uuidv7(),
                environmentId: z.string(),
              }),
            )
            .min(1)
            .max(64),
          keys: z
            .array(
              z.strictObject({
                descriptor: qualificationKeyDescriptorSchema,
                privateKeyFile: secretName,
              }),
            )
            .min(1)
            .max(64),
        })
        .parse(JSON.parse((await read('qualification_key_provider_config')).toString('utf8')));
      return {
        clients: await Promise.all(
          config.clients.map(async ({ certificateFile, ...value }) => ({
            ...value,
            certificate: await read(certificateFile),
          })),
        ),
        initialKeys: await Promise.all(
          config.keys.map(async ({ privateKeyFile, descriptor }) => ({
            descriptor,
            privateKeyPkcs8Der: await read(privateKeyFile),
          })),
        ),
      };
    })()
  : undefined;
const envelope = rpcRetirement
  ? undefined
  : await (async () => {
      const envelopeReference = 'secret://local/identity-envelope-activation#1';
      const envelopeReferenceId = createHash('sha256').update(envelopeReference).digest('hex');
      const envelopeDescriptor = identityEnvelopeProviderDescriptorSchema.parse(
        JSON.parse(
          await readFile(
            join(root, 'identity-envelope', 'public', envelopeReferenceId + '.json'),
            'utf8',
          ),
        ),
      );
      return {
        clients: [
          {
            certificate: await read('business_api_cert'),
            credentialId: '018f0000-0000-7000-8000-000000000195',
            workloadId: '018f0000-0000-7000-8000-000000000196',
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            environmentId: scope.environmentId,
            keyOwnerCredentialId: envelopeDescriptor.workloadCredentialId,
            methods: ['SIGN_AUTHORITY_ENVELOPE', 'ORIGINAL_LOOKUP'] as const,
          },
        ],
        initialKeys: [
          {
            descriptor: envelopeDescriptor,
            privateKeyPkcs8Der: await readFile(
              join(root, 'identity-envelope', 'keys', envelopeReferenceId + '.der'),
            ),
          },
        ],
      };
    })();
const fixture = await createFixtureSigningProvider({
  root,
  clients,
  initialKeys: [],
  certificate: await read('business_provider_server_cert'),
  privateKey: await read('business_provider_server_key'),
  ca: await read('business_provider_ca'),
  // The separate retirement certificate has no envelope-signing authority.
  ...(rpcRetirement ? {} : { envelope }),
  ...(qualification ? { qualification } : {}),
});
const port = z.coerce
  .number()
  .int()
  .min(0)
  .max(65535)
  .parse(process.env.OPENPC_LOCAL_SIGNING_PROVIDER_PORT ?? 3007);
fixture.server.listen(port, port === 0 ? '127.0.0.1' : '0.0.0.0', () => {
  const address = fixture.server.address();
  assert.ok(address && typeof address === 'object');
  process.stdout.write(`OPENPC_SIGNING_PROVIDER|listening|port=${address.port}\n`);
});
process.once('SIGTERM', () => void fixture.close());
process.once('SIGINT', () => void fixture.close());
