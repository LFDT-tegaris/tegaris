import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import { parseStrictJsonBytes } from '../privacy-explorer/strict-json.js';
import {
  admitStoreRetirement,
  exactStoreRetirementSourceBinding,
} from './store-retirement-contracts.js';
import {
  readCandidateRetirementPreflight,
  readFactRetirementPreflight,
} from './store-retirement-preflight.js';
import {
  retirementAttempt,
  retirementAttemptDigest,
  retirementHost,
  retirementSelectionDigest,
  retirementWireBytes,
  type StoreRetirementHost,
} from './store-retirement-wire.js';

const unavailable = () => new ConfigurationRepositoryError('PC-DATA-6007');
const uuidBytes = (value: string) =>
  Buffer.from(z.uuidv7().parse(value).replaceAll('-', ''), 'hex');
const hash = (bytes: Buffer) => createHash('sha256').update(bytes).digest();

/** Installed source-verification owner only. Public inputs cannot supply its
 * host pins, verifier secret, native executable or database/signature trust. */
export class StoreRetirementAdmissionAuthority {
  readonly hostDigest: string;
  private readonly host: StoreRetirementHost;
  private readonly secret: Buffer;
  private closed = false;
  constructor(
    host: StoreRetirementHost,
    secret: Buffer,
    private readonly targetConfigurationFile?: string,
  ) {
    this.host = retirementHost.parse(structuredClone(host));
    uuidBytes(this.host.scope.participant_id);
    uuidBytes(this.host.scope.privacy_domain_id);
    if (
      secret.length !== 32 ||
      (this.host.store === 'openpc_candidate_index' && !targetConfigurationFile?.startsWith('/'))
    )
      throw unavailable();
    this.hostDigest = hash(retirementWireBytes(this.host)).toString('hex');
    this.secret = Buffer.from(secret);
  }
  close() {
    this.closed = true;
    this.secret.fill(0);
  }
  async insert(
    client: PoolClient,
    context: MutationContext,
    operationId: string,
    input: z.infer<typeof admitStoreRetirement>,
  ) {
    const scope = context.authorization;
    if (
      this.closed ||
      input.participantId !== `urn:openpc:participant:${scope.participantId}` ||
      input.hostDigest !== this.hostDigest ||
      scope.participantId !== this.host.scope.participant_id ||
      scope.privacyDomainId !== this.host.scope.privacy_domain_id ||
      !scope.approvalRequestId ||
      context.catalogOperationId !== 'CFG-OP-ADMIT-STORE-RETIREMENT' ||
      context.expectedRevision !== '0'
    )
      throw unavailable();
    const source = exactStoreRetirementSourceBinding(input.sourceBinding);
    const rows = await client.query(
      `select h.host_wire,substring(p.policy_digest from 8) policy_digest,
      encode(d.decision_digest,'hex') approval_digest,
      coalesce(previous.retirement_id,$5::uuid)::text retirement_id
      from control.store_retirement_host h join control.retention_policy p
       on p.participant_id=h.participant_id and p.privacy_domain_id=h.privacy_domain_id and p.retention_policy_id=$4 and p.active_until is null
      join control.approval_request a on a.participant_id=h.participant_id and a.privacy_domain_id=h.privacy_domain_id and a.approval_request_id=$6
      join control.approval_decision_record d on d.participant_id=a.participant_id and d.privacy_domain_id=a.privacy_domain_id and d.approval_request_id=a.approval_request_id
      left join control.store_retirement_admission previous on previous.participant_id=h.participant_id and previous.privacy_domain_id=h.privacy_domain_id and previous.attempt_id=$7
      where h.participant_id=$1 and h.privacy_domain_id=$2 and h.host_digest=$3 and a.state='APPROVED'
       and d.decision='APPROVE' and a.expires_at>clock_timestamp() and ($7::uuid is null or previous.attempt_id is not null)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        this.hostDigest,
        input.retentionPolicyId.slice(-36),
        context.resourceId,
        scope.approvalRequestId,
        input.previousAttemptId?.slice(-36) ?? null,
      ],
    );
    if (rows.rowCount !== 1) throw unavailable();
    const row = z
      .strictObject({
        host_wire: z.instanceof(Buffer),
        policy_digest: z.string().regex(/^[0-9a-f]{64}$/u),
        approval_digest: z.string().regex(/^[0-9a-f]{64}$/u),
        retirement_id: z.uuidv7(),
      })
      .parse(rows.rows[0]);
    if (!row.host_wire.equals(retirementWireBytes(this.host))) throw unavailable();
    const actual = await client.query(
      'select openpc.store_retirement_source_binding($1,$2,$3) value',
      [
        input.retentionPolicyId.slice(-36),
        Buffer.from(source.binding.selectionWireHex, 'hex'),
        JSON.stringify(source.binding.recordRefs),
      ],
    );
    if (actual.rowCount !== 1 || sha256(actual.rows[0].value) !== source.digest)
      throw unavailable();
    const attempt = retirementAttempt.parse({
      scope: this.host.scope,
      store: this.host.store,
      business_intent_id: row.retirement_id,
      attempt_id: context.resourceId,
      governance: {
        retention_policy_digest: row.policy_digest,
        archive_manifest_digest: source.binding.archiveManifestDigest,
        archive_acknowledgement_digest: source.binding.archiveAcknowledgementDigest,
        approval_digest: row.approval_digest,
        lifecycle_revision: BigInt(source.binding.lifecycleRevision),
        retention_not_before_ms: BigInt(source.binding.retentionNotBeforeMs),
      },
      selection: source.selection,
      selection_digest: retirementSelectionDigest(this.host.scope, source.selection),
    });
    // Native read-only observation checks actual source payload/signatures,
    // generations/checkpoints/readiness and references. It is not a target fence.
    const native =
      this.host.store === 'openpc_facts'
        ? await readFactRetirementPreflight(attempt)
        : await readCandidateRetirementPreflight(attempt, this.host, this.targetConfigurationFile!);
    if (native.result.state !== 'CLEAR') throw unavailable();
    const deadline = await client.query(
      'select (floor(extract(epoch from clock_timestamp())*1000)+60000)::text value',
    );
    const dispatchNotAfterMs = BigInt(
      z
        .string()
        .regex(/^[1-9][0-9]*$/u)
        .parse(deadline.rows[0]?.value),
    );
    const deadlineBytes = Buffer.alloc(8);
    deadlineBytes.writeBigInt64BE(dispatchNotAfterMs);
    const wire = retirementWireBytes(attempt),
      nonce = randomBytes(32);
    const binding = hash(
      Buffer.concat([
        wire,
        Buffer.from(source.digest),
        uuidBytes(operationId),
        uuidBytes(scope.approvalRequestId),
        deadlineBytes,
      ]),
    );
    const mac = createHmac('sha256', this.secret)
      .update(
        Buffer.concat([
          Buffer.from('OPENPC_STORE_RETIREMENT_SOURCE_COMMIT_V1'),
          uuidBytes(scope.participantId),
          uuidBytes(scope.privacyDomainId),
          Buffer.from(this.hostDigest, 'hex'),
          binding,
          nonce,
        ]),
      )
      .digest();
    await client.query(
      `insert into control.store_retirement_admission(participant_id,privacy_domain_id,retirement_id,attempt_id,previous_attempt_id,
      host_digest,retention_policy_id,approval_request_id,operation_id,attempt_wire,attempt_digest,selection_digest,source_binding,source_binding_digest,
      lifecycle_revision,dispatch_not_after_ms,verification_nonce,verification_mac)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        row.retirement_id,
        context.resourceId,
        input.previousAttemptId?.slice(-36) ?? null,
        this.hostDigest,
        input.retentionPolicyId.slice(-36),
        scope.approvalRequestId,
        operationId,
        wire,
        retirementAttemptDigest(attempt),
        attempt.selection_digest,
        source.binding,
        source.digest,
        source.binding.lifecycleRevision,
        dispatchNotAfterMs.toString(),
        nonce,
        mac,
      ],
    );
  }
}

export async function loadStoreRetirementAdmissionAuthorities(path: string) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let value: unknown;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > 65536) throw unavailable();
    value = parseStrictJsonBytes(await file.readFile(), { maximumDepth: 8 });
  } finally {
    await file.close();
  }
  const config = z
    .strictObject({
      hosts: z
        .array(
          z.strictObject({
            host: retirementHost,
            verifierKeyFile: z.string().startsWith('/'),
            targetConfigurationFile: z.string().startsWith('/').optional(),
          }),
        )
        .min(1)
        .max(16),
    })
    .parse(value);
  const authorities = new Map<string, StoreRetirementAdmissionAuthority>();
  try {
    for (const item of config.hosts) {
      const file = await open(item.verifierKeyFile, constants.O_RDONLY | constants.O_NOFOLLOW);
      let bytes: Buffer | undefined;
      try {
        const stat = await file.stat();
        if (!stat.isFile() || stat.size !== 32 || (stat.mode & 0o077) !== 0) throw unavailable();
        bytes = await file.readFile();
        const authority = new StoreRetirementAdmissionAuthority(
          item.host,
          bytes,
          item.targetConfigurationFile,
        );
        if (authorities.has(authority.hostDigest)) {
          authority.close();
          throw unavailable();
        }
        authorities.set(authority.hostDigest, authority);
      } finally {
        bytes?.fill(0);
        await file.close();
      }
    }
    return authorities as ReadonlyMap<string, StoreRetirementAdmissionAuthority>;
  } catch (error) {
    for (const authority of authorities.values()) authority.close();
    throw error;
  }
}
