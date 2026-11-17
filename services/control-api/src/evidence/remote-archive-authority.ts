import { createPrivateKey, createPublicKey, createHmac, randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  archiveDigest,
  decodeArchiveSinkProfile,
  decodeArchiveSinkReceipt,
  decodeProtectedArchiveSinkProfile,
  decodeProtectedArchiveSinkReceipt,
  encodeProtectedArchiveSinkReceipt,
  encodeArchiveSinkReceipt,
  evidenceKeyId,
  signArchiveCose,
  verifyArchiveCose,
  type ArchiveSinkProfileClaims,
  type ArchiveSinkReceiptClaims,
  type ProtectedArchiveSinkProfileClaims,
  type ProtectedArchiveSinkReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { type EvidenceScope } from './segment.js';
import {
  RemoteArchiveError,
  remoteArchiveProfile,
  type RemoteArchiveProfile,
} from './remote-archive-contracts.js';

const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
export const signedArchiveProfile = z.strictObject({
  transport: remoteArchiveProfile,
  payloadHex: hex.max(131072),
  coseHex: hex.max(133120),
});
export const archiveHostTrust = z.strictObject({
  environmentId: z.string().min(1).max(160),
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  sinkId: z.string().min(1).max(160),
  issuerSpkiHex: hex.length(182),
});
export type SignedArchiveProfile = z.infer<typeof signedArchiveProfile>;
export type ArchiveHostTrust = z.infer<typeof archiveHostTrust>;
export interface SignedArchiveReceipt<
  Claims extends ArchiveSinkReceiptClaims | ProtectedArchiveSinkReceiptClaims =
    ArchiveSinkReceiptClaims,
> {
  payload: Buffer;
  cose: Buffer;
  receiptDigest: string;
  claims: Claims;
}
export type SignedProtectedArchiveReceipt = SignedArchiveReceipt<ProtectedArchiveSinkReceiptClaims>;

/** Historical readback authenticates the profile that actually signed the
 * receipt. Current key selection and credential freshness govern new effects,
 * not verification of immutable history. The caller supplies installed trust. */
export function verifyArchiveHistory(
  hostTrust: ArchiveHostTrust,
  signed: SignedArchiveProfile,
  payload: Buffer,
  cose: Buffer,
): SignedArchiveReceipt {
  try {
    const { claims: p, profileDigest, sourceKind } = verifyInstalledProfile(hostTrust, signed);
    if (sourceKind !== 'SEGMENT') throw new RemoteArchiveError('INTEGRITY');
    const claims = decodeArchiveSinkReceipt(payload);
    checkProfileReceipt(p, profileDigest, claims);
    if (
      !verifyArchiveCose(
        'EvidenceSinkReceiptV1',
        Buffer.from(p.receiptSignerSpki, 'hex'),
        payload,
        cose,
      )
    )
      throw new RemoteArchiveError('INTEGRITY');
    return {
      payload: Buffer.from(payload),
      cose: Buffer.from(cose),
      receiptDigest: archiveDigest(cose),
      claims,
    };
  } catch {
    throw new RemoteArchiveError('INTEGRITY');
  }
}

export function verifyProtectedArchiveHistory(
  hostTrust: ArchiveHostTrust,
  signed: SignedArchiveProfile,
  payload: Buffer,
  cose: Buffer,
): SignedProtectedArchiveReceipt {
  try {
    const installed = verifyInstalledProfile(hostTrust, signed);
    if (installed.sourceKind !== 'PROTECTED_PROOF') throw new RemoteArchiveError('INTEGRITY');
    const claims = decodeProtectedArchiveSinkReceipt(payload);
    checkProfileReceipt(installed.claims, installed.profileDigest, claims);
    if (
      !verifyArchiveCose(
        'EvidenceProtectedSinkReceiptV1',
        Buffer.from(installed.claims.receiptSignerSpki, 'hex'),
        payload,
        cose,
      )
    )
      throw new RemoteArchiveError('INTEGRITY');
    return {
      payload: Buffer.from(payload),
      cose: Buffer.from(cose),
      receiptDigest: archiveDigest(cose),
      claims,
    };
  } catch {
    throw new RemoteArchiveError('INTEGRITY');
  }
}

function verifyInstalledProfile(hostTrust: ArchiveHostTrust, signed: SignedArchiveProfile) {
  const trust = Object.freeze(archiveHostTrust.parse(structuredClone(hostTrust)));
  const document = signedArchiveProfile.parse(structuredClone(signed));
  const payload = Buffer.from(document.payloadHex, 'hex'),
    cose = Buffer.from(document.coseHex, 'hex');
  let claims: ArchiveSinkProfileClaims | ProtectedArchiveSinkProfileClaims;
  let sourceKind: 'SEGMENT' | 'PROTECTED_PROOF';
  try {
    claims = decodeArchiveSinkProfile(payload);
    sourceKind = 'SEGMENT';
  } catch {
    claims = decodeProtectedArchiveSinkProfile(payload);
    sourceKind = 'PROTECTED_PROOF';
  }
  const root = Buffer.from(trust.issuerSpkiHex, 'hex');
  if (
    !verifyArchiveCose(
      sourceKind === 'SEGMENT' ? 'EvidenceSinkProfileV1' : 'EvidenceProtectedSinkProfileV1',
      root,
      payload,
      cose,
    ) ||
    claims.issuerKeyId !== evidenceKeyId(root) ||
    claims.environmentId !== trust.environmentId ||
    claims.participantId !== trust.participantId ||
    claims.privacyDomainId !== trust.privacyDomainId ||
    claims.sinkId !== trust.sinkId ||
    claims.sinkId !== document.transport.sinkId ||
    claims.profileId !== document.transport.profileId ||
    claims.transportProfileDigest !== sha256(document.transport)
  )
    throw new RemoteArchiveError('INTEGRITY');
  return { trust, document, claims, sourceKind, profileDigest: archiveDigest(cose) };
}

function checkProfileReceipt(
  p: ArchiveSinkProfileClaims,
  profileDigest: string,
  claims: ArchiveSinkReceiptClaims | ProtectedArchiveSinkReceiptClaims,
) {
  if (
    claims.participantId !== p.participantId ||
    claims.privacyDomainId !== p.privacyDomainId ||
    !p.streamIds.includes(claims.streamId) ||
    claims.environmentId !== p.environmentId ||
    claims.signedProfileDigest !== profileDigest ||
    claims.signerKeyId !== evidenceKeyId(Buffer.from(p.receiptSignerSpki, 'hex')) ||
    BigInt(claims.recordedAtMicros) < BigInt(p.validFromMs) * 1000n ||
    BigInt(claims.recordedAtMicros) >= BigInt(p.validUntilMs) * 1000n
  )
    throw new RemoteArchiveError('INTEGRITY');
}

/** One host-installed profile/key pair. No request-supplied root or signer is
 * admitted. Cryptographic verification and SQL live authority are separate. */
export class RemoteArchiveAuthority {
  private readonly document: SignedArchiveProfile;
  private readonly profileClaims: ArchiveSinkProfileClaims;
  private readonly privateKey: Buffer;
  private readonly commitKey: Buffer;
  private closed = false;
  readonly sourceKind: 'SEGMENT' | 'PROTECTED_PROOF';
  readonly profileDigest: string;
  readonly trust: ArchiveHostTrust;

  constructor(
    hostTrust: ArchiveHostTrust,
    signed: SignedArchiveProfile,
    privateKeyPkcs8: Buffer,
    commitKey: Buffer,
  ) {
    try {
      const installed = verifyInstalledProfile(hostTrust, signed);
      this.sourceKind = installed.sourceKind;
      this.trust = installed.trust;
      this.document = installed.document;
      this.profileClaims = installed.claims;
      this.profileDigest = installed.profileDigest;
      const c = this.profileClaims;
      const key = createPrivateKey({ key: privateKeyPkcs8, format: 'der', type: 'pkcs8' });
      if (
        createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('hex') !==
        c.receiptSignerSpki
      )
        throw new RemoteArchiveError('INTEGRITY');
      if (commitKey.length !== 32) throw new RemoteArchiveError('INVALID');
      this.privateKey = Buffer.from(privateKeyPkcs8);
      this.commitKey = Buffer.from(commitKey);
    } catch {
      throw new RemoteArchiveError('INTEGRITY');
    }
  }
  get profile(): RemoteArchiveProfile {
    return structuredClone(this.document.transport);
  }
  get claims(): ArchiveSinkProfileClaims {
    return structuredClone(this.profileClaims);
  }
  get protectedPolicy(): ProtectedArchiveSinkProfileClaims | null {
    return this.sourceKind === 'PROTECTED_PROOF'
      ? structuredClone(this.profileClaims as ProtectedArchiveSinkProfileClaims)
      : null;
  }
  assertSourceKind(kind: 'SEGMENT' | 'PROTECTED_PROOF') {
    if (this.sourceKind !== kind) throw new RemoteArchiveError('INVALID');
  }
  get signedProfile(): SignedArchiveProfile {
    return structuredClone(this.document);
  }
  close() {
    this.closed = true;
    this.privateKey.fill(0);
    this.commitKey.fill(0);
  }

  assertScope(scope: EvidenceScope) {
    const c = this.profileClaims;
    if (
      scope.participantId !== c.participantId ||
      scope.privacyDomainId !== c.privacyDomainId ||
      !c.streamIds.includes(scope.streamId)
    )
      throw new RemoteArchiveError('INVALID');
  }
  /** Called under the shared lifecycle fence before dispatch and again in the
   * receipt/checkpoint transaction. SQL independently checks the login, complete
   * installed profile, credential/principal state, current revision and clock. */
  async admit(client: PoolClient, scope: EvidenceScope) {
    if (this.closed) throw new RemoteArchiveError('UNAVAILABLE');
    this.assertScope(scope);
    const selected = await client.query<{
      payload: Buffer;
      cose: Buffer;
      transport: RemoteArchiveProfile;
      issuerSpki: Buffer;
      nowMicros: string;
    }>(
      `select p.payload,p.cose,p.transport,t.issuer_spki as "issuerSpki",
        (floor(extract(epoch from clock_timestamp())*1000000))::text as "nowMicros"
       from openpc.require_archive_profile($1,$2) p join control.evidence_archive_trust t
        using(participant_id,privacy_domain_id,environment_id,sink_id,issuer_key_id)`,
      [this.profileDigest, scope.streamId],
    );
    const row = selected.rows[0];
    if (
      selected.rowCount !== 1 ||
      !row ||
      row.payload.toString('hex') !== this.document.payloadHex ||
      row.cose.toString('hex') !== this.document.coseHex ||
      row.issuerSpki.toString('hex') !== this.trust.issuerSpkiHex ||
      canonicalJson(row.transport) !== canonicalJson(this.document.transport)
    )
      throw new RemoteArchiveError('INTEGRITY');
    return row.nowMicros;
  }
  sign(claims: ArchiveSinkReceiptClaims): SignedArchiveReceipt {
    this.assertSourceKind('SEGMENT');
    if (this.closed) throw new RemoteArchiveError('UNAVAILABLE');
    this.checkReceiptClaims(claims);
    const payload = encodeArchiveSinkReceipt(claims);
    const cose = signArchiveCose(
      'EvidenceSinkReceiptV1',
      this.privateKey,
      Buffer.from(this.profileClaims.receiptSignerSpki, 'hex'),
      payload,
    );
    return { payload, cose, receiptDigest: archiveDigest(cose), claims: structuredClone(claims) };
  }
  verify(payload: Buffer, cose: Buffer): SignedArchiveReceipt {
    this.assertSourceKind('SEGMENT');
    const claims = decodeArchiveSinkReceipt(payload);
    this.checkReceiptClaims(claims);
    if (
      !verifyArchiveCose(
        'EvidenceSinkReceiptV1',
        Buffer.from(this.profileClaims.receiptSignerSpki, 'hex'),
        payload,
        cose,
      )
    )
      throw new RemoteArchiveError('INTEGRITY');
    return {
      payload: Buffer.from(payload),
      cose: Buffer.from(cose),
      receiptDigest: archiveDigest(cose),
      claims,
    };
  }
  signProtected(claims: ProtectedArchiveSinkReceiptClaims): SignedProtectedArchiveReceipt {
    this.assertSourceKind('PROTECTED_PROOF');
    if (this.closed) throw new RemoteArchiveError('UNAVAILABLE');
    this.checkReceiptClaims(claims);
    const payload = encodeProtectedArchiveSinkReceipt(claims);
    const cose = signArchiveCose(
      'EvidenceProtectedSinkReceiptV1',
      this.privateKey,
      Buffer.from(this.profileClaims.receiptSignerSpki, 'hex'),
      payload,
    );
    return { payload, cose, receiptDigest: archiveDigest(cose), claims: structuredClone(claims) };
  }
  verifyProtected(payload: Buffer, cose: Buffer): SignedProtectedArchiveReceipt {
    this.assertSourceKind('PROTECTED_PROOF');
    return verifyProtectedArchiveHistory(this.trust, this.document, payload, cose);
  }
  /** Exact one-use SQL commit proof, issued only after checking this receipt's
   * actual signature. SQL independently rechecks current authority/observations
   * and consumes it with the receipt and outbox, never in a separate commit. */
  commitCapability(value: SignedArchiveReceipt | SignedProtectedArchiveReceipt) {
    if (this.closed) throw new RemoteArchiveError('UNAVAILABLE');
    const verified =
      this.sourceKind === 'SEGMENT'
        ? this.verify(value.payload, value.cose)
        : this.verifyProtected(value.payload, value.cose);
    const c = verified.claims;
    const nonce = randomBytes(32);
    const mac = createHmac('sha256', this.commitKey)
      .update('OPENPC_REMOTE_ARCHIVE_CUSTODY_COMMIT_V1')
      .update(Buffer.from(c.participantId.replaceAll('-', ''), 'hex'))
      .update(Buffer.from(c.privacyDomainId.replaceAll('-', ''), 'hex'))
      .update(Buffer.from(verified.receiptDigest.slice(7), 'hex'))
      .update(Buffer.from(archiveDigest(value.payload).slice(7), 'hex'))
      .update(Buffer.from(c.signedProfileDigest.slice(7), 'hex'))
      .update(Buffer.from(c.attemptBindingDigest.slice(7), 'hex'))
      .update(nonce)
      .digest();
    return { nonce, mac };
  }
  private checkReceiptClaims(claims: ArchiveSinkReceiptClaims | ProtectedArchiveSinkReceiptClaims) {
    checkProfileReceipt(this.profileClaims, this.profileDigest, claims);
  }
}
