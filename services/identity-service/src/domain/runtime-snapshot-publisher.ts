import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import {
  encodeIdentityAuthorityScope,
  encodeIdentityAuthorityVector,
  encodeIdentityAuthContextAssertionPayload,
  encodeIdentityRuntimeSnapshot,
  identityApplicableDenyScopeSetDigest,
  identitySemanticDigest,
  identityWorkloadRuntimeBindings,
  identityRuntimeContextBindings,
  type IdentityAuthorityEntry,
  type IdentityRuntimeAuthorityProfile,
  type IdentitySnapshotActor,
} from '@openpc/security-kernel';
import type { IdentityRuntimeCryptoAdapter } from './identity-runtime-crypto.js';
import { identityActorKeyDigest } from './identity-runtime-authorization.js';
import { localOperationId } from './local-operation-id.js';
import { lockAuthorityFence } from '../db/authority-fence.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import {
  readRuntimeAuthorityGraph,
  sourceBytes,
  sourceDigest,
  type SourceValue,
} from './runtime-authority-graph.js';

export interface RuntimePublicationContext {
  readonly privacyDomainId: string;
  readonly targetRuntimeId: string;
}
export interface RuntimeWorkloadSubject {
  readonly participantId: string;
  readonly principalId: string;
  readonly workloadId: string;
  readonly uriSan: string;
  readonly keyId: string;
  readonly certificateFingerprint: Buffer;
  readonly notAfter: Date;
}
export interface PublishedWorkloadRuntime {
  readonly snapshotId: string;
  readonly manifestDigest: string;
  readonly assertionPayload: string;
  readonly assertionCoseSign1: string;
  readonly expiresAtNs: string;
}
interface Content {
  readonly kind: 'SHARD' | 'ROLE_ASSIGNMENTS' | 'PARTICIPANT_ENVELOPES';
  readonly payload: Buffer;
  readonly digest: Buffer;
  readonly ordinal: number;
}
const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest();
const workloadMask = [1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1] as const;

/** Sole SQL publication owner. The signing configuration is service-owned;
 * request data selects a target/privacy context and cannot supply authority. */
export class RuntimeSnapshotPublisher {
  constructor(
    private readonly crypto: IdentityRuntimeCryptoAdapter,
    private readonly profile: IdentityRuntimeAuthorityProfile,
    private readonly providerTrust: {
      readonly scope: readonly [string, string, string];
      readonly state: SourceValue;
    },
    private readonly snapshotLifetimeMs = 60_000,
  ) {
    if (
      !Number.isInteger(snapshotLifetimeMs) ||
      snapshotLifetimeMs < 60_000 ||
      snapshotLifetimeMs > 3_600_000
    )
      throw new Error('Invalid runtime snapshot lifetime');
    if (
      profile.profileId !== 'pc.identity.r1.workload-mtls' ||
      profile.profileVersion !== 1n ||
      profile.applicability.length !== 12 ||
      profile.applicability.some((v, i) => v !== workloadMask[i])
    )
      throw new Error('Invalid workload runtime release profile');
  }

  private async version(
    client: PoolClient,
    participantId: string,
    domainCode: number,
    tuple: readonly (string | Buffer)[],
    state: SourceValue,
  ): Promise<IdentityAuthorityEntry> {
    const scope = encodeIdentityAuthorityScope(domainCode, tuple);
    const result = await client.query<{ version: string; scope_cbor: Buffer }>(
      `insert into control.identity_runtime_authority_scope
         (participant_id,domain_code,scope_digest,scope_cbor,source_state_digest,version)
       values ($1,$2,$3,$4,$5,1)
       on conflict (participant_id,domain_code,scope_digest) do update
         set source_state_digest=excluded.source_state_digest,
             version=case when identity_runtime_authority_scope.source_state_digest=excluded.source_state_digest
               then identity_runtime_authority_scope.version else identity_runtime_authority_scope.version+1 end,
             updated_at=clock_timestamp()
       returning version::text,scope_cbor`,
      [participantId, domainCode, scope.digest, scope.payload, sourceDigest(state)],
    );
    const row = result.rows[0];
    if (row === undefined || !row.scope_cbor.equals(scope.payload))
      throw new Error('Authority scope conflict');
    return {
      domainCode,
      applicability: 1,
      scopeDigest: scope.digest,
      version: BigInt(row.version),
    };
  }

  /** Runs inside the certificate-authentication transaction, after its root
   * UPDATE fence. No publication or assertion escapes a rolled-back transaction. */
  async publishForAuthenticatedWorkload(
    client: PoolClient,
    context: RuntimePublicationContext,
    subject: RuntimeWorkloadSubject,
  ): Promise<PublishedWorkloadRuntime> {
    const publication = await this.buildSnapshot(
      client,
      context,
      subject.participantId,
      BigInt(subject.notAfter.getTime()) * 1_000_000n,
    );
    const actor = publication.actors.find((a) =>
      a.projection.actorKeyDigest.equals(
        identityActorKeyDigest(subject.participantId, subject.principalId),
      ),
    );
    if (
      actor === undefined ||
      !publication.workloads.some(
        (a) => a.principalId === subject.principalId && a.workloadId === subject.workloadId,
      )
    )
      throw new Error('Authenticated workload missing from complete snapshot');
    const bindings = identityWorkloadRuntimeBindings({
      ...subject,
      ...context,
      publicKeyDigest: Buffer.from(subject.keyId.slice(7), 'hex'),
    });
    // The reusable snapshot may have a local QA lifetime. A request assertion
    // remains within PDS's 60-second limit and all shorter source bounds.
    const assertionExpiry = publication.issuedAtNs + 60_000_000_000n;
    const assertionExpiresAtNs =
      publication.expiresAtNs < assertionExpiry ? publication.expiresAtNs : assertionExpiry;
    const assertion = encodeIdentityAuthContextAssertionPayload({
      assertionId: localOperationId(),
      actorKeyDigest: actor.projection.actorKeyDigest,
      actorKind: 1,
      participantContextDigest: bindings.participantContextDigest,
      audienceDigest: bindings.targetScopeDigest,
      senderBindingKind: 2,
      assuranceProfileDigest: publication.profileDigest,
      authorityVectorDigest: actor.projection.authorityVectorDigest,
      issuedAtNs: publication.issuedAtNs,
      expiresAtNs: assertionExpiresAtNs,
      authenticationEvidenceDigest: bindings.authenticationEvidenceDigest,
      senderCredentialBindingDigest: subject.certificateFingerprint,
    });
    const signedAssertion = await this.crypto.signCanonicalAssertion(assertion);
    return {
      snapshotId: publication.snapshotId,
      manifestDigest: publication.manifestDigest,
      assertionPayload: assertion.toString('base64'),
      assertionCoseSign1: signedAssertion.coseSign1.toString('base64'),
      expiresAtNs: assertionExpiresAtNs.toString(),
    };
  }

  /** Source-owner refresh, including after a credential is revoked. This issues
   * no authentication assertion and runs in its own scoped transaction, so
   * unavailable signing/capacity can never roll back the original revocation. */
  async refreshTargetSnapshot(
    client: PoolClient,
    participantId: string,
    context: RuntimePublicationContext,
  ) {
    await lockAuthorityFence(client, participantId, {
      participant: [{ id: participantId, write: true }],
    });
    const result = await this.buildSnapshot(client, context, participantId);
    return {
      snapshotId: result.snapshotId,
      manifestDigest: result.manifestDigest,
      expiresAtNs: result.expiresAtNs.toString(),
    };
  }

  /** Bounded service-owned reconciliation of durable target heads. Targets are
   * selected from previously authenticated publication, never a caller list. */
  async refreshPublishedTargets(pool: Pool, participantId: string, privacyDomainId: string) {
    const scope = {
      participantId,
      privacyDomainId,
      actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    };
    const targets = await runScopedTransaction(pool, scope, localOperationId, async (client) => {
      const rows = await client.query<{ target_runtime_id: string }>(
        `select target_runtime_id from control.identity_runtime_snapshot_head
         where participant_id=$1 and privacy_domain_id=$2 order by target_runtime_id limit 257`,
        [participantId, privacyDomainId],
      );
      if (rows.rows.length > 256)
        throw new Error('Runtime snapshot reconciliation capacity exceeded');
      return rows.rows;
    });
    let failed = 0;
    for (const target of targets) {
      try {
        await runScopedTransaction(pool, scope, localOperationId, (client) =>
          this.refreshTargetSnapshot(client, participantId, {
            privacyDomainId,
            targetRuntimeId: target.target_runtime_id,
          }),
        );
      } catch {
        // One invalidated target cannot starve other targets. Failed heads keep
        // their original hard expiry; reconciliation never extends stale state.
        failed++;
      }
    }
    return { attempted: targets.length, failed };
  }

  private async buildSnapshot(
    client: PoolClient,
    context: RuntimePublicationContext,
    participantId: string,
    credentialExpiry?: bigint,
  ) {
    const target = await client.query(
      `select runtime_target_id from control.runtime_target
       where participant_id=$1 and privacy_domain_id=$2 and runtime_target_id=$3 for share`,
      [participantId, context.privacyDomainId, context.targetRuntimeId],
    );
    if (target.rowCount !== 1) throw new Error('Runtime target context unavailable');
    const graph = await readRuntimeAuthorityGraph(
      client,
      participantId,
      context.privacyDomainId,
      context.targetRuntimeId,
    );
    const signedProfile = await this.crypto.signAuthorityProfile(this.profile);
    const bindings = identityRuntimeContextBindings({
      participantId,
      ...context,
    });
    const encodedActors: IdentitySnapshotActor[] = [];
    const content: Content[] = [];
    for (const actor of graph.actors) {
      const sets = await client.query<{ domain_code: number; set_id: string }>(
        `insert into control.identity_runtime_authority_set
           (participant_id,privacy_domain_id,principal_id,domain_code)
         select $1,$2,$3,domain from unnest(array[4,6,7,9]::smallint[]) domain
         on conflict (participant_id,privacy_domain_id,principal_id,domain_code) do nothing`,
        [participantId, context.privacyDomainId, actor.principalId],
      );
      // Immutable sets intentionally use DO NOTHING; an UPDATE would trip their guard.
      void sets;
      const existing = await client.query<{ domain_code: number; set_id: string }>(
        `select domain_code,set_id from control.identity_runtime_authority_set
         where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3 order by domain_code`,
        [participantId, context.privacyDomainId, actor.principalId],
      );
      const ids = new Map(existing.rows.map((r) => [r.domain_code, r.set_id]));
      if (ids.size !== 4) throw new Error('Incomplete actor authority sets');
      const rolePayload = sourceBytes({
        participant_id: participantId,
        participant: graph.participant,
        privacy_domain_id: context.privacyDomainId,
        principal_id: actor.principalId,
        workload_id: actor.workloadId,
        principal: actor.principal,
        credentials: actor.credentials,
        paths: actor.paths,
        wallet_bindings: actor.walletBindings,
        runtime_target_profile: graph.runtimeTargetProfile,
        revocations: actor.revocations,
      });
      const envelopePayload = sourceBytes(actor.envelopes);
      if (rolePayload.length > 4_194_304 || envelopePayload.length > 4_194_304)
        throw new Error('Runtime authority content capacity exceeded');
      const roles = sha256(rolePayload);
      const envelopes = sha256(envelopePayload);
      content.push(
        { kind: 'ROLE_ASSIGNMENTS', payload: rolePayload, digest: roles, ordinal: 0 },
        { kind: 'PARTICIPANT_ENVELOPES', payload: envelopePayload, digest: envelopes, ordinal: 0 },
      );
      const entries: IdentityAuthorityEntry[] = workloadMask.map((_, i) => ({
        domainCode: i + 1,
        applicability: 0,
        scopeDigest: Buffer.alloc(32),
        version: 0n,
      }));
      const set = async (code: number, tuple: readonly (string | Buffer)[], state: SourceValue) => {
        entries[code - 1] = await this.version(client, participantId, code, tuple, state);
      };
      await set(1, this.providerTrust.scope, this.providerTrust.state);
      await set(2, ['WORKLOAD', actor.workloadId], actor.principal);
      await set(4, [ids.get(4)!, participantId], {
        participant: graph.participant,
        principal: actor.principal,
        privacy: graph.privacy,
        walletBindings: actor.walletBindings,
      });
      await set(6, [ids.get(6)!, participantId, actor.principalId], {
        paths: actor.paths,
        revocations: actor.revocations,
      });
      await set(7, [ids.get(7)!, participantId], actor.envelopes);
      await set(9, [ids.get(9)!, actor.workloadId, participantId], actor.credentials);
      const denyScopes = identityApplicableDenyScopeSetDigest([
        `urn:openpc:participant:${participantId}`,
        `urn:openpc:privacy-domain:${context.privacyDomainId}`,
        `urn:openpc:principal:${actor.principalId}`,
        actor.workloadId,
      ]);
      await set(12, [denyScopes], {
        revocations: actor.revocations,
        participant: graph.participant,
        principal: actor.principal,
      });
      const authorityVector = {
        profileId: this.profile.profileId,
        profileVersion: this.profile.profileVersion,
        profileSemanticDigest: signedProfile.semanticDigest,
        entries,
      };
      encodedActors.push({
        authorityVector,
        projection: {
          actorKeyDigest: identityActorKeyDigest(participantId, actor.principalId),
          actorKind: 1,
          participantContextDigest: bindings.participantContextDigest,
          roleAssignmentSetDigest: roles,
          participantEnvelopeDigest: envelopes,
          authorityVectorDigest: identitySemanticDigest(
            3001,
            encodeIdentityAuthorityVector(authorityVector),
          ),
        },
      });
    }
    const clock = await client.query<{ ns: string }>(
      `select (extract(epoch from clock_timestamp())*1000000000)::numeric(20,0)::text ns`,
    );
    const issuedAtNs = BigInt(clock.rows[0]!.ns);
    let expiresAtNs = issuedAtNs + BigInt(this.snapshotLifetimeMs) * 1_000_000n;
    if (graph.nextTransitionNs !== undefined && graph.nextTransitionNs < expiresAtNs)
      expiresAtNs = graph.nextTransitionNs;
    if (credentialExpiry !== undefined && credentialExpiry < expiresAtNs)
      expiresAtNs = credentialExpiry;
    if (expiresAtNs <= issuedAtNs) throw new Error('Authority changed during publication');
    const stateDigest = sourceDigest({
      participant: graph.participant,
      privacy: graph.privacy,
      actors: graph.actors.map((a) => ({ ...a })),
      runtimeTargetProfile: graph.runtimeTargetProfile,
      profile: signedProfile.semanticDigest.toString('hex'),
      providerTrust: this.providerTrust.state,
      snapshotLifetimeMs: this.snapshotLifetimeMs,
    });
    const head = await client.query<{
      snapshot_id: string;
      manifest_digest: Buffer;
      expires_at_ns: string;
    }>(
      `select s.snapshot_id,s.manifest_digest,s.expires_at_ns::text
         from control.identity_runtime_snapshot_head h join control.identity_runtime_snapshot s
           on s.snapshot_id=h.snapshot_id and s.participant_id=h.participant_id and s.privacy_domain_id=h.privacy_domain_id
          and s.target_runtime_id=h.target_runtime_id
        where h.participant_id=$1 and h.privacy_domain_id=$2 and h.target_runtime_id=$3
          and s.source_state_digest=$4 and s.profile_digest=$5 and s.expires_at_ns>$6`,
      [
        participantId,
        context.privacyDomainId,
        context.targetRuntimeId,
        stateDigest,
        signedProfile.semanticDigest,
        // Keep enough validity for Fleet preparation and confirmation between
        // source-owner refreshes. Shorter credential/authority bounds still win.
        (issuedAtNs + 45_000_000_000n).toString(),
      ],
    );
    let snapshotId: string;
    let manifestDigest: Buffer;
    if (head.rows.length === 1) {
      snapshotId = head.rows[0]!.snapshot_id;
      manifestDigest = head.rows[0]!.manifest_digest;
      if (BigInt(head.rows[0]!.expires_at_ns) < expiresAtNs)
        expiresAtNs = BigInt(head.rows[0]!.expires_at_ns);
    } else {
      snapshotId = localOperationId();
      const snapshot = encodeIdentityRuntimeSnapshot({
        snapshotId,
        targetScopeDigest: bindings.targetScopeDigest,
        releaseProfileRegistryDigest: signedProfile.semanticDigest,
        issuedAtNs,
        hardExpiryNs: expiresAtNs,
        signerId: this.profile.signerId,
        actors: encodedActors,
      });
      manifestDigest = snapshot.manifestSemanticDigest;
      const signed = await this.crypto.signCanonicalSnapshotManifest(snapshot.manifestPayload);
      await client.query(
        `insert into control.identity_runtime_snapshot
          (snapshot_id,participant_id,privacy_domain_id,target_runtime_id,source_state_digest,manifest_digest,
           manifest_payload,manifest_cose,profile_payload,profile_cose,profile_digest,issued_at_ns,expires_at_ns,actor_count,shard_count)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [
          snapshotId,
          participantId,
          context.privacyDomainId,
          context.targetRuntimeId,
          stateDigest,
          manifestDigest,
          snapshot.manifestPayload,
          signed.coseSign1,
          signedProfile.payload,
          signedProfile.coseSign1,
          signedProfile.semanticDigest,
          issuedAtNs.toString(),
          expiresAtNs.toString(),
          encodedActors.length,
          snapshot.shards.length,
        ],
      );
      content.push(
        ...snapshot.shards.map((s, ordinal) => ({
          kind: 'SHARD' as const,
          payload: s.payload,
          digest: sha256(s.payload),
          ordinal,
        })),
      );
      const seen = new Set<string>();
      for (const artifact of content) {
        const key = `${artifact.kind}/${artifact.digest.toString('hex')}`;
        if (seen.has(key)) continue;
        seen.add(key);
        await client.query(
          `insert into control.identity_runtime_snapshot_content
             (participant_id,privacy_domain_id,snapshot_id,content_digest,content_kind,ordinal,payload)
           values ($1,$2,$3,$4,$5,$6,$7)`,
          [
            participantId,
            context.privacyDomainId,
            snapshotId,
            artifact.digest,
            artifact.kind,
            artifact.ordinal,
            artifact.payload,
          ],
        );
      }
      await client.query(
        `insert into control.identity_runtime_snapshot_head (participant_id,privacy_domain_id,target_runtime_id,snapshot_id)
         values ($1,$2,$3,$4) on conflict (participant_id,privacy_domain_id,target_runtime_id)
         do update set snapshot_id=excluded.snapshot_id,updated_at=clock_timestamp()`,
        [participantId, context.privacyDomainId, context.targetRuntimeId, snapshotId],
      );
    }
    return {
      snapshotId,
      manifestDigest: `sha256:${manifestDigest.toString('hex')}`,
      issuedAtNs,
      expiresAtNs,
      actors: encodedActors,
      workloads: graph.actors.map((a) => ({
        principalId: a.principalId,
        workloadId: a.workloadId,
      })),
      profileDigest: signedProfile.semanticDigest,
    };
  }
}
