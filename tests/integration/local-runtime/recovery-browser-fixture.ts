import { readFile, writeFile, mkdir, chmod, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { Pool } from 'pg';
import { createHardwareAuthenticatorEmulator } from '../identity/hardware-authenticator.js';
import { installEnvelopeBrowserTrust } from './envelope-recovery-browser-fixture.js';

const scenario = process.env.OPENPC_RECOVERY_BROWSER_SCENARIO ?? '0';
if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(scenario))
  throw new Error('Invalid recovery browser scenario');
const actorId = (suffix: number) =>
  `018f0000-0000-7000-8000-${String(Number(scenario) * 1000 + suffix).padStart(12, '0')}`;
export const recoveryBrowserActors = {
  'recovery-maker': actorId(131),
  'recovery-checker': actorId(132),
  'recovery-executor': actorId(133),
  'recovery-subject': actorId(134),
};
const [mode, secretRoot, dataRoot] = process.argv.slice(2);
const direct =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (direct && mode === 'bootstrap') {
  const emulator = createHardwareAuthenticatorEmulator();
  try {
    await mkdir(join(dataRoot!, 'recovery-browser'));
    await chmod(join(dataRoot!, 'recovery-browser'), 0o755);
    await writeFile(
      join(secretRoot!, 'recovery-attestation-leaf.key'),
      await readFile(join(emulator.directory, 'leaf.key')),
      { mode: 0o400 },
    );
    await writeFile(
      join(secretRoot!, 'recovery-attestation-leaf.pem'),
      await readFile(join(emulator.directory, 'leaf.pem')),
      { mode: 0o400 },
    );
    await writeFile(
      join(dataRoot!, 'recovery-browser/profile.json'),
      JSON.stringify(emulator.profile),
      { mode: 0o444 },
    );
    await chmod(join(dataRoot!, 'recovery-browser/profile.json'), 0o444);
    await writeFile(
      join(dataRoot!, 'recovery-browser/active-accounts.json'),
      JSON.stringify(recoveryBrowserActors),
      { mode: 0o444 },
    );
    await writeFile(
      join(dataRoot!, 'recovery-browser/compose.yaml'),
      `services:
  identity-service:
    environment:
      IDENTITY_RECOVERY_ATTESTATION_PROFILE_FILE: /recovery-profile.json
    volumes:
      - ${JSON.stringify(`${dataRoot}/recovery-browser/profile.json:/recovery-profile.json:ro`)}
  oidc-emulator:
    environment:
      OIDC_EMULATOR_EXTRA_ACCOUNTS: ${JSON.stringify(JSON.stringify(recoveryBrowserActors))}
      OIDC_EMULATOR_SCENARIO_ACCOUNTS_FILE: /recovery-browser/active-accounts.json
    volumes:
      - ${JSON.stringify(`${dataRoot}/recovery-browser:/recovery-browser:ro`)}
`,
    );
  } finally {
    emulator.dispose();
  }
} else if (direct && mode === 'seed') {
  const database = new Pool({
    host: '127.0.0.1',
    port: 55432,
    user: 'openpc_control',
    database: 'openpc_control',
    password: (await readFile(join(secretRoot!, 'control_pg_password.txt'), 'utf8')).trim(),
  });
  const participantId = '018f0000-0000-7000-8000-000000000101',
    privacyDomainId = '018f0000-0000-7000-8000-000000000201';
  const actors = Object.values(recoveryBrowserActors);
  const intents = [
    'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    'ACT-PARTICIPANTS_READ_COLLECTION-V1',
    'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    'ACT-IDENTITY_CREATE_SESSION-V1',
    'ACT-IDENTITY_DELETE_SESSION-V1',
    'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    'ACT-POLICY_APPROVE_REQUEST-V1',
    'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
    'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
  ];
  const firstAdmin = process.env.OPENPC_FIRST_ADMINISTRATOR_BROWSER === '1';
  const envelopeRecovery = process.env.OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY === '1';
  if (firstAdmin)
    intents.push(
      'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
      'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
      'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    );
  const hash = (value: string) => createHash('sha256').update(value).digest();
  if (
    process.env.OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY === '1' ||
    process.env.OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY === '1'
  )
    intents.push('ACT-PARTICIPANT_CREATE_MEMBER-V1');
  try {
    const platformContextId = envelopeRecovery
      ? await installEnvelopeBrowserTrust(database, dataRoot!)
      : undefined;
    // Initial trust only. No WebAuthn credentials, qualifications, approvals or recovery states are seeded.
    for (const [name, principalId] of Object.entries(recoveryBrowserActors))
      await database.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values ($1,$2,$4,$3,'ACTIVE',1)`,
        [
          principalId,
          participantId,
          `${name} scenario ${scenario}`,
          (firstAdmin || envelopeRecovery) && ['recovery-maker', 'recovery-checker'].includes(name)
            ? 'PLATFORM_OPERATOR'
            : 'USER',
        ],
      );
    for (const principalId of actors) {
      await database.query('insert into control.identity_subject(identity_subject_id) values($1)', [
        principalId,
      ]);
      await database.query(
        'insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$1)',
        [principalId, participantId],
      );
      const ids = await database.query<{ envelope: string; assignment: string }>(
        'select uuidv7()::text envelope,uuidv7()::text assignment',
      );
      const { envelope, assignment } = ids.rows[0]!;
      const roleId = platformContextId ? assignment : undefined;
      if (roleId)
        await database.query(
          `insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,created_by_principal_id)
        values($1,$2,$3,'Envelope browser initial custodian',$4,$5)`,
          [roleId, participantId, `urn:openpc:role:${roleId}`, intents, principalId],
        );
      await database.query(
        `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
        values ($1,$2,$3,$3,$4,1,0,'ACTIVE',clock_timestamp()-interval '1 hour',$5,$6,$7,$8,$9,array['*'],array['LOW','HIGH'],true,true,0,$10,$11)`,
        [
          envelope,
          participantId,
          principalId,
          principalId === actors[1] ? actors[0] : actors[1],
          Buffer.from('initial-browser-test-trust'),
          hash(envelope),
          Buffer.alloc(0),
          [privacyDomainId],
          intents,
          platformContextId ?? null,
          platformContextId ? '1' : null,
        ],
      );
      await database.query(
        `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state,created_by_principal_id,role_id)
        values ($1,$2,$3,$4,0,$5,$6,$7,array['*'],array['LOW','HIGH'],true,true,0,tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '2 hours','[)'),'ACTIVE',$3,$8)`,
        [
          assignment,
          participantId,
          principalId,
          envelope,
          hash(assignment),
          [privacyDomainId],
          intents,
          roleId ? `urn:openpc:role:${roleId}` : null,
        ],
      );
      await database.query(
        `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from) values ($1,$2::uuid,'OIDC_SUBJECT','http://oidc-emulator:3006',$2::text,'openpc-local-workbench','ACTIVE',1,clock_timestamp()-interval '1 hour')`,
        [participantId, principalId],
      );
    }
    // Publish aliases only after initial trust exists. Existing authorization
    // codes retain their selected account; no intermediate business state resets.
    const accountsPath = join(dataRoot!, 'recovery-browser/active-accounts.json');
    await writeFile(`${accountsPath}.next`, JSON.stringify(recoveryBrowserActors), { mode: 0o444 });
    await rename(`${accountsPath}.next`, accountsPath);
  } finally {
    await database.end();
  }
}
