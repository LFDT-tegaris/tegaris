import { writeFile, mkdir, chmod } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runtimeSnapshotTlsFixture } from '../identity/runtime-snapshot-tls-fixture.js';
import { recoveryBrowserActors } from './recovery-browser-fixture.js';
export const directoryBrowserProfileId = '018f0000-0000-7000-8000-000000000141';
export const directoryBrowserPrincipalId = '018f0000-0000-7000-8000-000000000142';
export const directoryBrowserExternalId = 'provider-user-immutable-A';
export const directoryBrowserGroupId = 'provider-group-immutable-A';
export function directoryBrowserState(active = true, version = 1) {
  return {
    status: 200,
    groups: [
      {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        id: directoryBrowserGroupId,
        displayName: 'Provider access group',
        members: [{ value: directoryBrowserExternalId, type: 'User' }],
        meta: {
          resourceType: 'Group',
          version: `W/"${version}"`,
          lastModified: new Date().toISOString(),
        },
      },
    ],
    users: [
      {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        id: directoryBrowserExternalId,
        userName: 'directory-user',
        displayName: 'Directory colleague',
        active,
        meta: {
          resourceType: 'User',
          version: `W/"${version}"`,
          lastModified: new Date().toISOString(),
        },
      },
    ],
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [secretRoot, dataRoot] = process.argv.slice(2);
  if (!secretRoot || !dataRoot) throw new Error('Directory fixture arguments missing');
  const root = join(dataRoot, 'directory-browser');
  await mkdir(root, { mode: 0o755 });
  await chmod(root, 0o755);
  const tls = await runtimeSnapshotTlsFixture(
    `urn:openpc:directory-profile:${directoryBrowserProfileId}`,
    'directory-emulator',
  );
  try {
    for (const [name, bytes] of Object.entries({
      directory_ca: tls.server.ca,
      directory_server_cert: tls.server.certificate,
      directory_server_key: tls.server.privateKey,
      directory_client_cert: tls.certificate,
      directory_client_key: tls.privateKey,
    })) {
      await writeFile(join(secretRoot, name), bytes, { mode: 0o444 });
      await chmod(join(secretRoot, name), 0o444);
    }
    await writeFile(
      join(root, 'profiles.json'),
      JSON.stringify([
        {
          participantId: '018f0000-0000-7000-8000-000000000101',
          profileId: directoryBrowserProfileId,
          baseUrl: 'https://directory-emulator:3447/scim/v2',
          oidcIssuer: 'http://oidc-emulator:3006',
          oidcClientId: 'openpc-local-workbench',
          subjectMapping: 'SCIM_ID',
          certificateRef: 'secret://local/directory_client_cert#1',
          privateKeyRef: 'secret://local/directory_client_key#1',
          trustCaRef: 'secret://local/directory_ca#1',
        },
      ]),
      { mode: 0o444 },
    );
    await writeFile(join(root, 'state.json'), JSON.stringify(directoryBrowserState()), {
      mode: 0o644,
    });
    const mount = (source: string, target: string) => JSON.stringify(`${source}:${target}:ro`);
    await writeFile(
      join(root, 'compose.yaml'),
      `services:
  identity-service:
    environment:
      IDENTITY_DIRECTORY_PROFILES_FILE: /directory/profiles.json
    depends_on:
      directory-emulator: { condition: service_healthy }
    volumes:
      - ${mount(root, '/directory')}
      - ${mount(join(secretRoot, 'directory_ca'), '/run/secrets/directory_ca')}
      - ${mount(join(secretRoot, 'directory_client_cert'), '/run/secrets/directory_client_cert')}
      - ${mount(join(secretRoot, 'directory_client_key'), '/run/secrets/directory_client_key')}
  oidc-emulator:
    environment:
      OIDC_EMULATOR_EXTRA_ACCOUNTS: ${JSON.stringify(JSON.stringify({ ...recoveryBrowserActors, 'directory-user': directoryBrowserPrincipalId }))}
      OIDC_EMULATOR_SUBJECTS: ${JSON.stringify(JSON.stringify({ 'directory-user': directoryBrowserExternalId }))}
  directory-emulator:
    image: docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43
    user: "\${OPENPC_LOCAL_UID}:\${OPENPC_LOCAL_GID}"
    command: [node, /directory-emulator.mjs]
    read_only: true
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    cpus: 0.25
    mem_limit: 128m
    memswap_limit: 128m
    pids_limit: 64
    networks: [openpc-local]
    volumes:
      - ${mount(resolve('tests/integration/local-runtime/directory-emulator.mjs'), '/directory-emulator.mjs')}
      - ${mount(root, '/directory')}
      - ${mount(join(secretRoot, 'directory_ca'), '/run/secrets/directory_ca')}
      - ${mount(join(secretRoot, 'directory_server_cert'), '/run/secrets/directory_server_cert')}
      - ${mount(join(secretRoot, 'directory_server_key'), '/run/secrets/directory_server_key')}
      - ${mount(join(secretRoot, 'directory_client_cert'), '/run/secrets/directory_client_cert')}
      - ${mount(join(secretRoot, 'directory_client_key'), '/run/secrets/directory_client_key')}
    healthcheck:
      test: [CMD, node, /directory-emulator.mjs, health]
      interval: 2s
      timeout: 5s
      retries: 30
`,
    );
  } finally {
    await tls.close();
  }
}
