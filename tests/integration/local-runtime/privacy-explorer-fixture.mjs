import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { chmod, copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  createGate3ConformantEndpoint,
  gate3EndpointPaths,
} from '../../privacy/i07-gate3-conformant-endpoint.ts';
import { executionRegistry } from '../../../services/control-api/src/contracts/privacy-explorer-adapter.ts';
import { sha256CanonicalJson } from '../../../services/control-api/src/privacy-explorer/canonical.ts';
import { validateExplorerProfile } from '../../../services/control-api/src/privacy-explorer/profile-registration.ts';

const [root] = process.argv.slice(2);
assert.ok(root && root.startsWith(process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT + '/'));
await mkdir(root, { recursive: true, mode: 0o755 });
process.env.OPENPC_PNC_TMP_ROOT = process.env.OPENPC_LOCAL_RUNTIME_TMP_ROOT;
const endpoint = await createGate3ConformantEndpoint(
  Object.values(gate3EndpointPaths).map((path) => ({
    path,
    expectedBody: Buffer.from('{}'),
    statusCode: 200,
    contentType: 'application/json',
    body: Buffer.from('{}'),
    maximumCalls: 1,
  })),
);
try {
  for (const name of ['ca.crt', 'server.crt', 'server.key', 'client.crt', 'client.key']) {
    await copyFile(join(endpoint.privateMaterialRoot, name), join(root, name));
    // Ephemeral test material must be readable by the unprivileged container
    // user. The owned fixture mount is read-only and never enters an image.
    await chmod(join(root, name), 0o444);
  }
} finally {
  await endpoint.close();
}
const sourcePath = new URL('./privacy-explorer-endpoint.mjs', import.meta.url);
const buildDigest = `sha256:${createHash('sha256')
  .update(await readFile(sourcePath))
  .digest('hex')}`;
await copyFile(sourcePath, join(root, 'endpoint.mjs'));
const sourceBinding = {
  platformId: 'local-platform',
  workloadId: '018f0000-0000-7000-8000-000000000191',
  accessClassIds: ['ACCESS-AUDIT'],
  productId: 'OpenPC external acceptance fixture',
  instanceId: 'local-explorer',
  releaseVersion: '1.0.0',
  buildDigest,
  adapterVersion: '1.0.0',
  transportProfileId: 'openpc-local-explorer@v1',
  egressPolicyId: 'openpc-loopback@v1',
  trustAnchorId: 'openpc-local-explorer-ca@v1',
  clientIdentityId: 'openpc-local-explorer-client@v1',
};
const definition = {
  id: 'local-governed-explorer',
  version: '1.0.0',
  sourceBinding,
  operationVersions: executionRegistry.operationDefinitions
    .map(({ id }) => ({ operationId: id, version: '1.0.0', acceptedDataClassIds: ['CLASS-READ'] }))
    .sort((a, b) => a.operationId.localeCompare(b.operationId)),
  allowedFieldIds: ['PEF-A', 'PEF-B'],
  allowedFilterIds: ['PEFILTER-A'],
  maximumPageSize: 20,
  responseSchemaVersion: '1.0',
  maximumFreshnessAgeMilliseconds: 60_000,
  provenanceProfileDigest: sha256CanonicalJson({ buildDigest, protocol: 'bounded-projection-v1' }),
  privacyProjectionId: 'PROJECTION-LOCAL-1',
  redactionProfileId: 'REDACTION-LOCAL-1',
  evidenceClassId: 'EVIDENCE-LOCAL-1',
  maximumDeadlineAt: new Date(Date.now() + 86_400_000).toISOString(),
  maximumReadAttempts: 1,
  retryBackoffMilliseconds: [],
};
const profile = validateExplorerProfile({ ...definition, digest: sha256CanonicalJson(definition) });
const mount = '/app/privacy-explorer-fixture';
const {
  platformId: _platform,
  workloadId: _workload,
  accessClassIds: _access,
  ...transportBinding
} = sourceBinding;
void _platform;
void _workload;
void _access;
const transport = {
  ...transportBinding,
  origin: 'https://127.0.0.1:55443',
  trustAnchorFile: `${mount}/ca.crt`,
  clientCertificateFile: `${mount}/client.crt`,
  clientPrivateKeyFile: `${mount}/client.key`,
  continuationKeyFile: `${mount}/continuation.key`,
  requestByteLimit: 65_536,
  responseByteLimit: 1_048_576,
  maximumJsonDepth: 32,
};
await writeFile(join(root, 'continuation.key'), randomBytes(32).toString('hex'), { mode: 0o444 });
await writeFile(join(root, 'profile.json'), JSON.stringify(profile));
await writeFile(join(root, 'transport.json'), JSON.stringify(transport));
await writeFile(join(root, 'mode'), 'COMPLETE');
await writeFile(
  join(root, 'control.env'),
  `CONTROL_API_EXPLORER_TRANSPORT_FILE=${mount}/transport.json\n`,
);
