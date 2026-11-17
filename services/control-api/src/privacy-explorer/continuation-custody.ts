import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import { canonicalJson, sha256CanonicalJson } from './canonical.js';
import type { ExplorerCustodyScope } from './postgres-custody.js';

export type ExplorerContinuationBinding = Readonly<{
  queryDigest: string;
  profileDigest: string;
  authorityGeneration: string;
  factGeneration: string;
  identityGeneration: string;
}>;

const digest = /^sha256:[0-9a-f]{64}$/;
const unavailable = () => new Error('Privacy Explorer continuation unavailable');

/** Stable service key comes from secret-file configuration and survives process restart. */
export class ExplorerContinuationCustody {
  private readonly key: Buffer;
  private readonly bindingDigest: string;
  constructor(
    key: Uint8Array,
    private readonly scope: ExplorerCustodyScope,
    binding: ExplorerContinuationBinding,
  ) {
    if (key.byteLength !== 32 || Object.values(binding).some((value) => !digest.test(value)))
      throw unavailable();
    this.key = Buffer.from(key);
    this.bindingDigest = sha256CanonicalJson({
      domain: 'OPENPC-EXPLORER-CONTINUATION-1',
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      subject: scope.subject,
      ...binding,
    });
  }

  recordReference(externalId: string) {
    if (!externalId || externalId.length > 256) throw unavailable();
    return `per1.${createHmac('sha256', this.key)
      .update(
        canonicalJson({
          domain: 'OPENPC-EXPLORER-RECORD-1',
          binding: this.bindingDigest,
          id: externalId,
        }),
      )
      .digest('base64url')}`;
  }

  async retain(
    client: PoolClient,
    occurrenceId: string,
    externalCursor: string,
    expiresAt: string,
  ) {
    if (!externalCursor || externalCursor.length > 1024 || !Number.isFinite(Date.parse(expiresAt)))
      throw unavailable();
    const reference = `pec1.${randomBytes(32).toString('base64url')}`;
    const referenceDigest = this.referenceDigest(reference);
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce);
    cipher.setAAD(Buffer.from(`${referenceDigest}:${this.bindingDigest}`));
    const ciphertext = Buffer.concat([cipher.update(externalCursor, 'utf8'), cipher.final()]);
    const sealed = Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]);
    const inserted = await client.query(
      `insert into control.privacy_explorer_continuation
       (reference_digest,participant_id,privacy_domain_id,occurrence_id,binding_digest,sealed_cursor,expires_at)
       select $1,$2,$3,$4,$5,$6,least($7::timestamptz,clock_timestamp()+interval '5 minutes')
       from control.privacy_explorer_execution e where e.occurrence_id=$4 and e.participant_id=$2
       and e.privacy_domain_id=$3 and e.subject=$8 and e.disposition='OPEN'
       and e.deadline_at>clock_timestamp() and $7::timestamptz>clock_timestamp()
       returning reference_digest`,
      [
        referenceDigest,
        this.scope.participantId,
        this.scope.privacyDomainId,
        occurrenceId,
        this.bindingDigest,
        sealed,
        expiresAt,
        this.scope.subject,
      ],
    );
    if (inserted.rowCount !== 1) throw unavailable();
    return reference;
  }

  async consume(client: PoolClient, reference: string, occurrenceId: string) {
    const referenceDigest = this.referenceDigest(reference);
    const selected = await client.query<{ sealed_cursor: Buffer }>(
      `update control.privacy_explorer_continuation c set consumed_by=$1
       from control.privacy_explorer_execution e
       where c.reference_digest=$2 and c.participant_id=$3 and c.privacy_domain_id=$4
         and c.binding_digest=$5 and c.consumed_by is null and c.expires_at>clock_timestamp()
         and (e.participant_id,e.privacy_domain_id,e.occurrence_id)=
             (c.participant_id,c.privacy_domain_id,c.occurrence_id)
         and e.subject=$6 and e.disposition='RELEASE_AUTHORIZED' and e.occurrence_id<>$1
       returning c.sealed_cursor`,
      [
        occurrenceId,
        referenceDigest,
        this.scope.participantId,
        this.scope.privacyDomainId,
        this.bindingDigest,
        this.scope.subject,
      ],
    );
    const sealed = selected.rows[0]?.sealed_cursor;
    if (selected.rowCount !== 1 || !sealed || sealed.length < 29 || sealed.length > 4124)
      throw unavailable();
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.key, sealed.subarray(0, 12));
      decipher.setAAD(Buffer.from(`${referenceDigest}:${this.bindingDigest}`));
      decipher.setAuthTag(sealed.subarray(12, 28));
      const cursor = Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]);
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(cursor);
        if (!text || text.length > 1024) throw unavailable();
        return text;
      } finally {
        cursor.fill(0);
      }
    } catch {
      throw unavailable();
    }
  }

  private referenceDigest(reference: string) {
    if (!/^pec1\.[A-Za-z0-9_-]{43}$/.test(reference)) throw unavailable();
    return `sha256:${createHash('sha256').update(reference).digest('hex')}`;
  }
}
