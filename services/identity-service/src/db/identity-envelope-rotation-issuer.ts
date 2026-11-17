import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { lockAuthorityFence } from './authority-fence.js';

const epoch = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n && BigInt(value) % 1000n === 0n);
const issuerSchema = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  workloadCredentialId: z.uuidv7(),
  workloadPrincipalId: z.uuidv7(),
  workloadParticipantEpoch: epoch,
  workloadPrincipalEpoch: epoch,
  workloadCredentialEpoch: epoch,
  workloadPublicKeyDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  credentialValidFromNs: nanos,
  credentialValidUntilNs: nanos.nullable(),
});
export { issuerSchema as identityEnvelopeRotationIssuerSchema };
export type IdentityEnvelopeRotationIssuer = Readonly<z.infer<typeof issuerSchema>>;
export class IdentityEnvelopeRotationIssuerUnavailable extends Error {
  constructor() {
    super('Current identity envelope rotation issuer is unavailable');
  }
}

/** Capture under the caller's existing scoped transaction and identity lock
 * order. No provider I/O, elevated connection or actor authorization is implied.
 * Persist this snapshot in the governed candidate and recheck it before effects,
 * immutable trust admission and cutover; a later epoch is a different intent. */
export async function captureIdentityEnvelopeRotationIssuer(
  client: PoolClient,
  scope: {
    participantId: string;
    privacyDomainId: string;
    workloadCredentialId: string;
  },
) {
  await client.query('select openpc.assert_request_context(true)');
  const discovery = await client.query<{ principalId: string }>(
    `select principal_id::text as "principalId" from control.credential
     where participant_id=$1 and credential_id=$2`,
    [scope.participantId, scope.workloadCredentialId],
  );
  if (discovery.rowCount !== 1 || !z.uuidv7().safeParse(discovery.rows[0]?.principalId).success)
    throw new IdentityEnvelopeRotationIssuerUnavailable();
  const principalId = discovery.rows[0]!.principalId;
  await lockAuthorityFence(client, scope.participantId, {
    participant: [{ id: scope.participantId }],
    privacy_domain: [{ id: scope.privacyDomainId }],
    principal: [{ id: principalId }],
    credential: [{ id: scope.workloadCredentialId }],
  });
  const result = await client.query<IdentityEnvelopeRotationIssuer & { nowNs: string }>(
    `select participant.participant_id::text as "participantId",domain.privacy_domain_id::text as "privacyDomainId",
       credential.credential_id::text as "workloadCredentialId",principal.principal_id::text as "workloadPrincipalId",
       participant.authority_epoch::text as "workloadParticipantEpoch",principal.authority_epoch::text as "workloadPrincipalEpoch",
       credential.credential_epoch::text as "workloadCredentialEpoch",
       'sha256:'||encode(credential.public_key_digest,'hex') as "workloadPublicKeyDigest",
       (floor(extract(epoch from credential.valid_from)*1000000)*1000)::text as "credentialValidFromNs",
       (floor(extract(epoch from credential.valid_until)*1000000)*1000)::text as "credentialValidUntilNs",
       (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as "nowNs"
     from control.participant participant
     join control.privacy_domain domain on domain.participant_id=participant.participant_id
     join control.credential credential on credential.participant_id=participant.participant_id
     join control.principal principal on principal.participant_id=credential.participant_id
       and principal.principal_id=credential.principal_id
     where participant.participant_id=$1 and domain.privacy_domain_id=$2 and credential.credential_id=$3
       and participant.state='ACTIVE' and domain.state='ACTIVE' and principal.state='ACTIVE' and principal.kind='WORKLOAD'
       and credential.state='ACTIVE' and credential.kind='WORKLOAD_MTLS'
       and credential.valid_from<=clock_timestamp() and (credential.valid_until is null or credential.valid_until>clock_timestamp())
     `,
    [scope.participantId, scope.privacyDomainId, scope.workloadCredentialId],
  );
  try {
    if (result.rowCount !== 1) throw new Error();
    const { nowNs, ...raw } = result.rows[0]!;
    const issuer = issuerSchema.parse(raw);
    const now = BigInt(nanos.parse(nowNs));
    if (
      issuer.participantId !== scope.participantId ||
      issuer.privacyDomainId !== scope.privacyDomainId ||
      issuer.workloadCredentialId !== scope.workloadCredentialId ||
      issuer.workloadPrincipalId !== principalId ||
      BigInt(issuer.credentialValidFromNs) > now ||
      (issuer.credentialValidUntilNs !== null && BigInt(issuer.credentialValidUntilNs) <= now)
    )
      throw new Error();
    return { issuer: Object.freeze(issuer), recordedAtNs: now };
  } catch {
    throw new IdentityEnvelopeRotationIssuerUnavailable();
  }
}

/** Pure comparison supplements the authoritative capture; caller-supplied epochs
 * can never establish issuer readiness or replace a locked current DB read. */
export function assertIdentityEnvelopeRotationIssuerUnchanged(
  expected: IdentityEnvelopeRotationIssuer,
  current: IdentityEnvelopeRotationIssuer,
) {
  try {
    if (
      canonicalDefinitionJson(issuerSchema.parse(expected)) !==
      canonicalDefinitionJson(issuerSchema.parse(current))
    )
      throw new Error();
  } catch {
    throw new IdentityEnvelopeRotationIssuerUnavailable();
  }
}
