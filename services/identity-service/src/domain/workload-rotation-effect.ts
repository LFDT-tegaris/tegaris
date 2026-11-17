import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { IdentityKernelError } from './identity-errors.js';
import {
  WORKLOAD_CERTIFICATE_MAX_LIFETIME_MS,
  type WorkloadCredentialIssuer,
  type IssuedWorkloadCertificate,
} from './workload-credential-issuer.js';

const hash = (bytes: Buffer) => createHash('sha256').update(bytes).digest();
const unavailable = () => new IdentityKernelError('PC-IDENTITY-1006');

export interface WorkloadRotationEffectInput {
  readonly participantId: string;
  readonly replacedCredentialId: string;
  readonly credentialId: string;
  readonly principalId: string;
  readonly workloadId: string;
  readonly predecessorEpoch: string;
  readonly publicKeySpkiDer: Buffer;
}

/** Durable effect only: the caller owns authorization, approval, active workload
 * validation and the predecessor write fence for the entire transaction. No
 * authority or runtime readiness is inferred from this function's arguments. */
export async function rotateWorkloadCredentialEffect(
  client: PoolClient,
  input: WorkloadRotationEffectInput,
  issuer: WorkloadCredentialIssuer,
  now: () => Date,
) {
  const epoch = BigInt(input.predecessorEpoch);
  if (epoch < 0n || epoch >= 18446744073709551615n) throw unavailable();
  let issued;
  try {
    issued = await issuer.issue({
      credentialId: input.credentialId,
      participantId: input.participantId,
      principalId: input.principalId,
      workloadId: input.workloadId,
      publicKeySpkiDer: input.publicKeySpkiDer,
    });
  } catch {
    throw unavailable();
  }
  return applyObservedWorkloadCredentialEffect(client, input, issued, now);
}

/** The recovery caller supplies an observation independently verified by its
 * pinned issuer adapter. This owner never dispatches external I/O. */
export async function applyObservedWorkloadCredentialEffect(
  client: PoolClient,
  input: WorkloadRotationEffectInput,
  issued: IssuedWorkloadCertificate,
  now: () => Date,
) {
  const diagnostic = (stage: string) =>
    process.stdout.write(
      JSON.stringify({
        boundary: 'workload_rotation_commit',
        stage,
        participantId: input.participantId,
        replacedCredentialId: input.replacedCredentialId,
        credentialId: input.credentialId,
      }) + '\n',
    );
  const epoch = BigInt(input.predecessorEpoch);
  if (epoch < 0n || epoch >= 18446744073709551615n) throw unavailable();
  if (
    issued.credentialId !== input.credentialId ||
    issued.participantId !== input.participantId ||
    issued.principalId !== input.principalId ||
    issued.workloadId !== input.workloadId ||
    !issued.publicKeySpkiDer.equals(input.publicKeySpkiDer) ||
    !Buffer.isBuffer(issued.certificateDer) ||
    !hash(issued.certificateDer).equals(issued.certificateFingerprint) ||
    issued.uriSan !==
      `urn:openpc:participant:${input.participantId}:workload:${input.workloadId.split(':').at(-1) ?? ''}` ||
    issued.certificateFingerprint.length !== 32 ||
    !/^sha256:[0-9a-f]{64}$/u.test(issued.keyId) ||
    !hash(issued.publicKeySpkiDer).equals(Buffer.from(issued.keyId.slice(7), 'hex')) ||
    !Number.isFinite(issued.notBefore.getTime()) ||
    !Number.isFinite(issued.notAfter.getTime()) ||
    issued.notBefore > now() ||
    issued.notAfter <= now() ||
    issued.notAfter <= issued.notBefore ||
    issued.notAfter.getTime() - issued.notBefore.getTime() > WORKLOAD_CERTIFICATE_MAX_LIFETIME_MS
  )
    throw unavailable();
  diagnostic('issuer_response_verified');
  const nextCredentialEpoch = (epoch + 1n).toString();
  const revoked = await client.query(
    `update control.credential set state='REVOKED',credential_epoch=$3,
            row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and credential_id=$2 and state='ACTIVE'
        and kind='WORKLOAD_MTLS' and credential_epoch=$4`,
    [input.participantId, input.replacedCredentialId, nextCredentialEpoch, input.predecessorEpoch],
  );
  if (revoked.rowCount !== 1) throw unavailable();
  const inserted = await client.query(
    `insert into control.credential
      (credential_id,participant_id,principal_id,kind,issuer,subject,audience,
       public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,
       valid_from,valid_until,rotated_from_credential_id,certificate_der)
     values ($1,$2,$3,'WORKLOAD_MTLS',$4,$5,$6,$7,$8,$9,'ACTIVE',$10,$11,$12,$13,$14)
     returning credential_id`,
    [
      input.credentialId,
      input.participantId,
      input.principalId,
      issued.issuer,
      issued.uriSan,
      issued.workloadId,
      Buffer.from(issued.keyId.slice(7), 'hex'),
      issued.publicKeySpkiDer,
      issued.certificateFingerprint,
      nextCredentialEpoch,
      issued.notBefore,
      issued.notAfter,
      input.replacedCredentialId,
      issued.certificateDer,
    ],
  );
  if (inserted.rowCount !== 1) throw unavailable();
  diagnostic('credential_rows_written');
  return {
    credentialId: input.credentialId,
    replacedCredentialId: input.replacedCredentialId,
    principalId: input.principalId,
    participantId: input.participantId,
    workloadId: input.workloadId,
    state: 'ACTIVE' as const,
    workloadEpoch: nextCredentialEpoch,
    keyId: issued.keyId,
    uriSan: issued.uriSan,
    notBefore: issued.notBefore,
    notAfter: issued.notAfter,
    issuer: issued.issuer,
    certificateFingerprint: `sha256:${issued.certificateFingerprint.toString('hex')}`,
  };
}
