import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { installInitialOperationsEnvironment } from '../../../scripts/operations/installation-generation-store.mjs';
import { installInitialPlatformEnvelopeScope } from '../../../scripts/operations/installation-platform-authority.mjs';
import {
  decodeEnvelopeScope,
  encodeEnvelopeScope,
  platformEnvelopeScopePreimage,
} from '../../../packages/security-kernel/src/index.ts';
import { envelopeBrowserInstallationInputs } from './envelope-recovery-browser-fixture.ts';

export function factTrustScenario(generation) {
  assert.ok(
    generation === 2 || generation === 3,
    'Only the positive and quarantine scenarios have initial trust',
  );
  return generation === 2
    ? {
        envelopeId: '018f0000-0000-7000-8000-000000008383',
        platformContextId: '018f0000-0000-7000-8000-000000008384',
        baseGenerationId: '018f0000-0000-7000-8000-000000008385',
        environmentId: 'local-first-policy-fact',
        filename: 'runtime-fact-initial-trust.json',
      }
    : {
        envelopeId: '018f0000-0000-7000-8000-000000008393',
        platformContextId: '018f0000-0000-7000-8000-000000008394',
        baseGenerationId: '018f0000-0000-7000-8000-000000008395',
        environmentId: 'local-quarantine-fact',
        filename: 'runtime-fact-initial-trust-3.json',
      };
}
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000007201';
const lifetimeMs = 86400000;
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

export function factInitialScope(startMs, resourceId) {
  assert.ok(
    Number.isSafeInteger(startMs) && startMs > 0 && Number.isSafeInteger(startMs + lifetimeMs),
  );
  assert.match(
    resourceId,
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  return {
    administration: {
      participantIds: [participantId],
      privacyDomainIds: [privacyDomainId],
      resourceIds: [resourceId],
      actionIntentIds: ['ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: ['STANDARD'],
    },
    runtime: {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      capabilityIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [],
    },
    validFromNs: String(BigInt(startMs) * 1000000n),
    validUntilNs: String(BigInt(startMs + lifetimeMs) * 1000000n),
    makerCheckerRequired: false,
    stepUpRequired: false,
    onwardDelegationDepth: 0,
  };
}

// Initial grantability only. The public Participant owner must still create
// and independently approve the exact workload/candidate assignment.
export async function installRuntimeFactInitialTrust(
  client,
  evidenceRoot,
  participant,
  privacy,
  resourceId,
  generation = 2,
) {
  assert.equal(participant, participantId);
  assert.equal(privacy, privacyDomainId);
  factInitialScope(Date.now(), resourceId);
  const scenario = factTrustScenario(generation);
  const { envelopeId, platformContextId: factInitialRoot, environmentId } = scenario;
  // A new scenario cannot bypass a retained legacy grant path.
  if (generation === 3) {
    const legacy = (
      await client.query(
        'select platform_context_id from control.authority_envelope where authority_envelope_id=$1',
        [factTrustScenario(2).envelopeId],
      )
    ).rows;
    assert.ok(legacy.length <= 1);
    if (legacy.length)
      assert.equal(
        legacy[0].platform_context_id,
        factTrustScenario(2).platformContextId,
        'Retained legacy Fact trust cannot be rebound',
      );
  }
  const existing = (
    await client.query(
      'select platform_context_id from control.authority_envelope where authority_envelope_id=$1',
      [envelopeId],
    )
  ).rows;
  assert.ok(existing.length <= 1);
  if (existing.length)
    assert.equal(
      existing[0].platform_context_id,
      factInitialRoot,
      'Retained legacy Fact trust cannot be rebound; use a fresh evaluation environment',
    );
  const path = join(evidenceRoot, scenario.filename);
  let prepared;
  try {
    prepared = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    assert.equal(existing.length, 0, 'Existing trust requires its original installation inputs');
    assert.equal(
      (
        await client.query('select 1 from control.platform_context where platform_context_id=$1', [
          factInitialRoot,
        ])
      ).rowCount,
      0,
      'A committed root cannot be retrofitted',
    );
    assert.equal(
      (
        await client.query(
          `select 1 from (
            select a.participant_id,a.privacy_domain_ids,a.action_intent_ids,a.resource_ids
            from control.assignment a join control.principal p using(participant_id,principal_id) where p.kind='WORKLOAD'
            union all select participant_id,privacy_domain_ids,action_intent_ids,resource_ids
            from control.authority_envelope where platform_context_id is not null
          ) grants where participant_id=$1 and $2=any(privacy_domain_ids)
            and 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'=any(action_intent_ids)
            and resource_ids && $3::text[]`,
          [participantId, privacyDomainId, [resourceId, resourceId.slice(-36), '*']],
        )
      ).rowCount,
      0,
      'Initial trust cannot replace a workload grant',
    );
    const scopes = await client.query(
      'select scope_cbor from control.platform_envelope_scope where owner_participant_id=$1 and installation_privacy_domain_id=$2',
      [participantId, privacyDomainId],
    );
    for (const row of scopes.rows) {
      const admitted = decodeEnvelopeScope(row.scope_cbor).administration;
      assert.ok(
        !admitted.actionIntentIds.includes('ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1') ||
          !admitted.resourceIds.some((id) => [resourceId, resourceId.slice(-36), '*'].includes(id)),
        'Initial trust cannot replace an installed resource ceiling',
      );
    }
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    prepared = {
      startMs: Date.now(),
      resourceId,
      issuerSpkiHex: key.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
    };
    // Freeze public inputs before either installer commits. A resumed attempt
    // uses the same source, root and lifetime, including after a lost response.
    await writeFile(path, JSON.stringify(prepared), { mode: 0o400, flag: 'wx' });
  }
  assert.deepEqual(Object.keys(prepared).sort(), ['issuerSpkiHex', 'resourceId', 'startMs']);
  assert.match(prepared.issuerSpkiHex, /^[0-9a-f]{182}$/u);
  assert.equal(prepared.resourceId, resourceId, 'Initial Fact resource cannot change');
  const grantable = factInitialScope(prepared.startMs, prepared.resourceId);
  encodeEnvelopeScope(grantable);
  assert.ok(
    prepared.startMs <= Date.now() && prepared.startMs + lifetimeMs > Date.now() + 300000,
    'Initial Fact trust expired; its lifetime must not be extended',
  );
  const { schemaBytes, profileBytes, sourceAuthentication } =
    await envelopeBrowserInstallationInputs();
  const password = randomBytes(24).toString('hex');
  const role = `openpc_fact_installer_${randomBytes(8).toString('hex')}`;
  let created = false,
    installer;
  try {
    await client.query(
      `create role ${role} login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '${password}'`,
    );
    created = true;
    await client.query(`grant openpc_control_owner to ${role}`);
    await client.query(`grant connect on database openpc_control to ${role}`);
    installer = new Pool({
      host: client.connectionParameters.host,
      port: client.connectionParameters.port,
      database: client.connectionParameters.database,
      user: role,
      password,
      max: 1,
    });
    const installationDigest = await installInitialOperationsEnvironment(
      installer,
      { participantId, privacyDomainId },
      {
        schemaBytes,
        profileBytes,
        sourceAuthentication,
        initialBaseGenerationId: scenario.baseGenerationId,
        pins: {
          issuerSpkiHex: prepared.issuerSpkiHex,
          issuerEpoch: '1',
          issuerValidFromMs: prepared.startMs,
          issuerValidUntilMs: prepared.startMs + lifetimeMs,
          environmentId,
          profile: 'local',
          configurationSchemaDigest: sha(schemaBytes),
          namedProfileDigest: sha(profileBytes),
        },
      },
    );
    const expected = {
      platformContextId: factInitialRoot,
      ownerParticipantId: participantId,
      installationPrivacyDomainId: privacyDomainId,
      platformAuthorityEpoch: '1',
      environmentId,
      installationDigest,
      grantable,
    };
    const installed = await installInitialPlatformEnvelopeScope(installer, expected);
    const stored = (
      await client.query(
        `select s.scope_cbor,s.admission_preimage,s.admission_digest
      from control.platform_envelope_scope s join control.platform_context p using(platform_context_id)
      where s.platform_context_id=$1 and s.owner_participant_id=$2 and s.installation_privacy_domain_id=$3
        and s.environment_id=$4 and s.installation_digest=$5 and s.platform_authority_epoch=1
        and p.owner_participant_id=$2 and p.state='ACTIVE' and p.authority_epoch=1`,
        [factInitialRoot, participantId, privacyDomainId, environmentId, installationDigest],
      )
    ).rows;
    assert.equal(stored.length, 1);
    assert.deepEqual(stored[0].scope_cbor, encodeEnvelopeScope(grantable));
    assert.deepEqual(stored[0].admission_preimage, platformEnvelopeScopePreimage(expected));
    assert.equal(
      `sha256:${stored[0].admission_digest.toString('hex')}`,
      installed.platformAuthorityDigest,
    );
    return {
      ...installed,
      resourceId: prepared.resourceId,
      validFrom: new Date(prepared.startMs).toISOString(),
      validUntil: new Date(prepared.startMs + lifetimeMs).toISOString(),
    };
  } finally {
    try {
      if (created) await client.query(`alter role ${role} nologin`);
    } finally {
      await installer?.end();
    }
  }
}
