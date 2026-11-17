/** Local external-system adapter. It retains the installed business and
 * qualification clients and adds exact purpose371 rotation on the same actual
 * mutually authenticated TLS socket. No control data or authority is seeded. */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import { businessTransitionProfiles } from '../../packages/security-kernel/src/business-transition/profiles.generated.js';
import { canonicalDefinitionJson } from '../../packages/security-kernel/src/business-transition/definition.js';
import {
  qualificationKeyDescriptorSchema,
  qualificationKeyPeerSchema,
} from '../../services/identity-service/src/domain/qualification-key-provider.js';
import { identityEnvelopeProviderDescriptorSchema } from '../../services/identity-service/src/domain/identity-envelope-signing-provider.js';
import {
  createFixtureSigningProvider,
  type FixtureSigningClient,
} from '../../tests/integration/local-runtime/signing-provider-fixture.js';
import {
  rpcRetirementSigningWorkload,
  rpcRetirementSigningFamilies,
  rpcRetirementSigningProfiles,
} from '../../tests/integration/local-runtime/rpc-retirement-signing.js';
import { createLocalIdentityEnvelopeRotationStore } from './local-identity-envelope-rotation-store.js';

const secretName = z.string().regex(/^[a-zA-Z0-9_-]{1,96}$/u);
const qualificationConfiguration = z.strictObject({
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
      z.strictObject({ descriptor: qualificationKeyDescriptorSchema, privateKeyFile: secretName }),
    )
    .min(1)
    .max(64),
});
function flag(value: string | undefined) {
  if (value !== undefined && value !== '1') throw Error('LOCAL_PROVIDER_CONFIGURATION_INVALID');
  return value === '1';
}

/** External local adapter trust only. A configured ID creates no control
 * credential: callers must first complete its normal verified issuance. Fixed
 * workload/tenant scope and certificate verification remain unchanged. */
export function localSigningProviderCredentialBindings(environment: NodeJS.ProcessEnv) {
  const retirement = flag(environment.OPENPC_SIGNING_PROVIDER_RPC_RETIREMENT);
  const api = environment.OPENPC_SIGNING_PROVIDER_API_CREDENTIAL_ID;
  const worker = environment.OPENPC_SIGNING_PROVIDER_WORKER_CREDENTIAL_ID;
  if ((api === undefined) !== (worker === undefined) || (retirement && api !== undefined))
    throw Error('LOCAL_PROVIDER_CONFIGURATION_INVALID');
  try {
    const apiCredentialId = retirement
      ? rpcRetirementSigningWorkload.credentialId
      : z.uuidv7().parse(api ?? '018f0000-0000-7000-8000-000000000195');
    const workerCredentialId = z.uuidv7().parse(worker ?? '018f0000-0000-7000-8000-000000000198');
    if (apiCredentialId === workerCredentialId) throw Error();
    return { apiCredentialId, workerCredentialId };
  } catch {
    throw Error('LOCAL_PROVIDER_CONFIGURATION_INVALID');
  }
}

/** Shared first-party transport for the installed envelope store. The store
 * owns the exact certificate/scope bindings; this adapter never grants control
 * authority or publishes a rotation phase. */
export function registerLocalIdentityEnvelopeProviderRoutes(
  server: Awaited<ReturnType<typeof createFixtureSigningProvider>>['server'],
  envelope: Awaited<ReturnType<typeof createLocalIdentityEnvelopeRotationStore>>,
) {
  const previous = server.listeners('request');
  server.removeAllListeners('request');
  const send = (response: ServerResponse, status: number, value: unknown) => {
    if (response.destroyed || response.headersSent) return;
    response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(canonicalDefinitionJson(value));
  };
  const handle = async (request: IncomingMessage, response: ServerResponse, url: URL) => {
    const socket = request.socket as TLSSocket;
    const raw = socket.getPeerCertificate(true).raw;
    const peer =
      raw === undefined ? '' : 'sha256:' + createHash('sha256').update(raw).digest('hex');
    const routes = [
      '/v1/identity-envelope-signing/perform',
      '/v1/identity-envelope-signing/lookup',
      '/v1/identity-envelope-signing/rotation/perform',
      '/v1/identity-envelope-signing/rotation/lookup',
    ];
    if (
      !socket.authorized ||
      socket.getProtocol() !== 'TLSv1.3' ||
      !envelope.hasClient(peer) ||
      request.method !== 'POST' ||
      url.search ||
      url.hash ||
      !routes.includes(url.pathname)
    ) {
      send(response, 403, { code: 'DENIED' });
      return;
    }
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of request) {
      const bytes = Buffer.from(chunk);
      length += bytes.length;
      if (length > 196608) {
        send(response, 413, { code: 'TOO_LARGE' });
        return;
      }
      chunks.push(bytes);
    }
    const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    const body: unknown = JSON.parse(text);
    if (canonicalDefinitionJson(body) !== text) {
      send(response, 400, { code: 'INVALID_REQUEST' });
      return;
    }
    let result: unknown;
    if (url.pathname.includes('/rotation/'))
      result = url.pathname.endsWith('/perform')
        ? await envelope.perform(body, peer)
        : await envelope.lookup(body, peer);
    else if (url.pathname.endsWith('/perform')) {
      const signed = await envelope.normalPerform(body, peer);
      if (signed.drop) {
        response.destroy();
        return;
      }
      result = signed.observation;
    } else result = await envelope.normalLookup(body, peer);
    send(response, 200, result);
  };
  server.on('request', (request, response) => {
    let url: URL;
    try {
      url = new URL(request.url ?? '/', 'https://local-provider.invalid');
    } catch {
      send(response, 400, { code: 'INVALID_REQUEST' });
      return;
    }
    if (!url.pathname.startsWith('/v1/identity-envelope-signing/')) {
      for (const listener of previous) listener.call(server, request, response);
      return;
    }
    void handle(request, response, url).catch(() => send(response, 403, { code: 'DENIED' }));
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
}

export async function startLocalSigningProviderRuntime(
  environment: NodeJS.ProcessEnv = process.env,
) {
  const root = environment.OPENPC_SIGNING_PROVIDER_STATE_ROOT;
  if (!root || !isAbsolute(root)) throw Error('LOCAL_PROVIDER_CONFIGURATION_INVALID');
  const secrets = environment.OPENPC_SIGNING_PROVIDER_SECRET_ROOT ?? '/run/secrets';
  if (!isAbsolute(secrets)) throw Error('LOCAL_PROVIDER_CONFIGURATION_INVALID');
  const read = (name: string) => readFile(join(secrets, name));
  const retirement = flag(environment.OPENPC_SIGNING_PROVIDER_RPC_RETIREMENT);
  const qualificationEnabled = flag(environment.OPENPC_SIGNING_PROVIDER_QUALIFICATION);
  const credentialBindings = localSigningProviderCredentialBindings(environment);
  const apiCredential = credentialBindings.apiCredentialId;
  const apiWorkload = retirement
    ? rpcRetirementSigningWorkload.workloadId
    : '018f0000-0000-7000-8000-000000000196';
  const scope = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    environmentId: 'local',
    managedKeyOwners: [apiCredential],
  };
  const runtimePrivacy = environment.OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID;
  if (runtimePrivacy !== undefined) z.uuidv7().parse(runtimePrivacy);
  const apiCertificate = await read('business_api_cert');
  const clients: FixtureSigningClient[] = [
    {
      ...scope,
      credentialId: apiCredential,
      workloadId: apiWorkload,
      certificate: apiCertificate,
      methods: ['INSPECT', 'PROVE', 'SIGN_RECEIPT'],
      additionalPrivacyDomainIds: [
        ...new Set([
          '018f0000-0000-7000-8000-000000004201',
          '018f0021-0000-7000-8000-000000000201',
          ...(runtimePrivacy ? [runtimePrivacy] : []),
        ]),
      ],
      signingProfiles: (retirement
        ? rpcRetirementSigningFamilies.flatMap(({ family }) => rpcRetirementSigningProfiles(family))
        : businessTransitionProfiles
      ).map(({ profileId, profileVersion, profileDigest }) => ({
        profileId,
        profileVersion,
        profileDigest,
      })),
    },
    ...(!retirement
      ? [
          {
            ...scope,
            credentialId: credentialBindings.workerCredentialId,
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
  const qualification = qualificationEnabled
    ? await (async () => {
        const configuration = qualificationConfiguration.parse(
          JSON.parse((await read('qualification_key_provider_config')).toString('utf8')),
        );
        return {
          clients: await Promise.all(
            configuration.clients.map(async ({ certificateFile, ...value }) => ({
              ...value,
              certificate: await read(certificateFile),
            })),
          ),
          initialKeys: await Promise.all(
            configuration.keys.map(async ({ privateKeyFile, descriptor }) => ({
              descriptor,
              privateKeyPkcs8Der: await read(privateKeyFile),
            })),
          ),
        };
      })()
    : undefined;
  const predecessorReference = 'secret://local/identity-envelope-activation#1';
  const legacy = identityEnvelopeProviderDescriptorSchema.parse(
    JSON.parse(
      await readFile(
        join(
          root,
          'identity-envelope',
          'public',
          createHash('sha256').update(predecessorReference).digest('hex') + '.json',
        ),
        'utf8',
      ),
    ),
  );
  const keyValidity = z.coerce
    .number()
    .int()
    .min(900)
    .max(86400)
    .parse(environment.OPENPC_SIGNING_PROVIDER_ENVELOPE_KEY_VALIDITY_SECONDS ?? '86400');
  const envelope = await createLocalIdentityEnvelopeRotationStore({
    root,
    predecessorReference,
    predecessorFingerprint: legacy.fingerprint,
    keyValiditySeconds: keyValidity,
    clients: [
      {
        certificate: apiCertificate,
        credentialId:
          environment.OPENPC_SIGNING_PROVIDER_API_CREDENTIAL_ID === undefined
            ? '018f0000-0000-7000-8000-000000000195'
            : apiCredential,
        workloadId: '018f0000-0000-7000-8000-000000000196',
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        environmentId: scope.environmentId,
        keyOwnerCredentialId:
          environment.OPENPC_SIGNING_PROVIDER_API_CREDENTIAL_ID === undefined
            ? legacy.workloadCredentialId
            : apiCredential,
        methods: ['SIGN_AUTHORITY_ENVELOPE', 'ORIGINAL_LOOKUP'],
      },
    ],
  });
  const fixture = await createFixtureSigningProvider({
    root,
    clients,
    initialKeys: [],
    certificate: await read('business_provider_server_cert'),
    privateKey: await read('business_provider_server_key'),
    ca: await read('business_provider_ca'),
    ...(qualification ? { qualification } : {}),
  });
  registerLocalIdentityEnvelopeProviderRoutes(fixture.server, envelope);
  await new Promise<void>((resolve, reject) => {
    fixture.server.once('error', reject);
    fixture.server.listen(3007, '0.0.0.0', () => {
      fixture.server.off('error', reject);
      resolve();
    });
  });
  let closing: Promise<void> | undefined;
  return {
    server: fixture.server,
    close: () =>
      (closing ??= (async () => {
        await envelope.close();
        await fixture.close();
      })()),
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const runtime = await startLocalSigningProviderRuntime();
  const close = () => {
    void runtime.close().catch(() => {
      process.exitCode = 1;
    });
  };
  process.once('SIGTERM', close);
  process.once('SIGINT', close);
}
