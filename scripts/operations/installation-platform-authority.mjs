import { encodeEnvelopeScope } from '../../packages/security-kernel/src/identity-envelope/codec.ts';
import {
  platformEnvelopeScopePreimage,
  platformEnvelopeScopeDigest,
} from '../../packages/security-kernel/src/identity-envelope/platform-scope.ts';
import { InstallationConfigError } from './installation-config-inputs.mjs';
import {
  withInstallationTransaction,
  lockInstallationEnvironment,
} from './installation-generation-store.mjs';

const unavailable = () => {
  throw new InstallationConfigError('PLATFORM_SCOPE_UNAVAILABLE');
};

/** Initial installation only. This creates no operator, assignment, envelope,
 * approval or configuration generation. The upper bound is not actor authority.
 * A committed legacy root cannot be retrofitted, even by this installer. */
export async function installInitialPlatformEnvelopeScope(pool, input) {
  const preimage = platformEnvelopeScopePreimage(input),
    digest = platformEnvelopeScopeDigest(input),
    scopeBytes = encodeEnvelopeScope(input.grantable);
  // Snapshot the validated primitive bindings before the first asynchronous I/O.
  input = { ...input };
  if (input.platformAuthorityEpoch !== '1') unavailable();
  return withInstallationTransaction(
    pool,
    {
      participantId: input.ownerParticipantId,
      privacyDomainId: input.installationPrivacyDomainId,
    },
    async (client, scope) => {
      const authority = await client.query(`select current_user='openpc_control_owner'
      and pg_has_role(session_user,'openpc_control_owner','MEMBER')
      and exists(select 1 from pg_roles where rolname=session_user and rolcanlogin and not rolsuper and not rolbypassrls) allowed`);
      if (authority.rows[0]?.allowed !== true) unavailable();
      // All Participant fences precede installation/Platform locks. Do not acquire
      // descendant locks when changing or checking a Platform root.
      const participant = await client.query(
        `select 1 from control.participant
      where participant_id=$1 and state='ACTIVE' for share`,
        [scope.participantId],
      );
      if (participant.rowCount !== 1) unavailable();
      if (
        (
          await client.query(
            `select 1 from control.privacy_domain where participant_id=$1
      and privacy_domain_id=$2 and state='ACTIVE' for share`,
            [scope.participantId, scope.privacyDomainId],
          )
        ).rowCount !== 1
      )
        unavailable();
      await lockInstallationEnvironment(client, input.environmentId);
      const installation = await client.query(
        `select 1 from control.operations_installation
      where environment_id=$1 and participant_id=$2 and privacy_domain_id=$3 and state='ACTIVE'
        and installation_digest=$4 and openpc.operations_source_authentication_valid(installation)
      for share`,
        [input.environmentId, scope.participantId, scope.privacyDomainId, input.installationDigest],
      );
      if (installation.rowCount !== 1) unavailable();
      const root = await client.query(
        `select state,authority_epoch::text,owner_participant_id
      from control.platform_context where platform_context_id=$1 for share`,
        [input.platformContextId],
      );
      if (root.rowCount === 1) {
        const row = root.rows[0];
        if (
          row.state !== 'ACTIVE' ||
          row.authority_epoch !== '1' ||
          row.owner_participant_id !== scope.participantId
        )
          unavailable();
        const existing = await client.query(
          `select admission_preimage,admission_digest from control.platform_envelope_scope
        where platform_context_id=$1 and owner_participant_id=$2 and installation_privacy_domain_id=$3`,
          [input.platformContextId, scope.participantId, scope.privacyDomainId],
        );
        if (
          existing.rowCount !== 1 ||
          !existing.rows[0].admission_preimage.equals(preimage) ||
          existing.rows[0].admission_digest.toString('hex') !== digest.slice(7)
        )
          unavailable();
        return {
          platformContextId: input.platformContextId,
          platformAuthorityEpoch: '1',
          platformAuthorityDigest: digest,
        };
      }
      if (
        (
          await client.query(
            'select 1 from control.operations_generation_commit where environment_id=$1',
            [input.environmentId],
          )
        ).rowCount !== 0
      )
        unavailable();
      await client.query(
        `insert into control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version)
      values($1,$2,'ACTIVE',1,1)`,
        [input.platformContextId, scope.participantId],
      );
      await client.query(
        `insert into control.platform_envelope_scope(platform_context_id,owner_participant_id,installation_privacy_domain_id,
      platform_authority_epoch,environment_id,installation_digest,scope_cbor,admission_preimage,admission_digest)
      values($1,$2,$3,1,$4,$5,$6,$7,$8)`,
        [
          input.platformContextId,
          scope.participantId,
          scope.privacyDomainId,
          input.environmentId,
          input.installationDigest,
          scopeBytes,
          preimage,
          Buffer.from(digest.slice(7), 'hex'),
        ],
      );
      const stored = await client.query(
        `select admission_preimage,admission_digest from control.platform_envelope_scope
      where platform_context_id=$1`,
        [input.platformContextId],
      );
      if (
        stored.rowCount !== 1 ||
        !stored.rows[0].admission_preimage.equals(preimage) ||
        stored.rows[0].admission_digest.toString('hex') !== digest.slice(7)
      )
        unavailable();
      return {
        platformContextId: input.platformContextId,
        platformAuthorityEpoch: '1',
        platformAuthorityDigest: digest,
      };
    },
  );
}
