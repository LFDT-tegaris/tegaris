import { z } from 'zod';
import type { Pool, PoolClient } from 'pg';
import {
  fenceBoundAuthorities,
  type BoundAuthority,
} from '../../../identity-service/src/db/authority-fence.js';
import type { AuthorizedPolicyActor } from '../../../module-registry/src/policy-http.js';
import type { ExplorerProjectionRequestV1 } from '../contracts/privacy-explorer-adapter.js';
import type { ConfigurationAuthorizer } from '../configuration/authorization.js';
import { loadRegisteredExplorerProfile } from '../configuration/privacy-explorer/profile-repository.js';
import { bindLocalContext, type PrivacyExplorerLocalContext } from './context.js';
import { canonicalJson, sha256CanonicalJson } from './canonical.js';
import {
  disclosureGenerationIdentity,
  evaluateDisclosure,
  loadDisclosureGenerations,
} from './disclosure-policy.js';
import { PostgresExplorerCustody, type ExplorerCustodyScope } from './postgres-custody.js';
import {
  registerExplorerProfile,
  requireLiveExplorerProfile,
  type RegisteredExplorerProfile,
} from './profile-registration.js';

export const explorerProjectionAction = 'ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1';
export const explorerOccurrenceAction = 'ACT-PRIVACY_EXPLORER_READ_OCCURRENCE-V1';
const unavailable = () => new Error('Privacy Explorer disclosure authority unavailable');
export type DisclosureContextBinding = Readonly<{
  actor: AuthorizedPolicyActor;
  authority: BoundAuthority;
  scope: ExplorerCustodyScope;
  custody: PostgresExplorerCustody;
  profile: RegisteredExplorerProfile;
  registrationId: string;
  intent: ExplorerProjectionRequestV1;
  authorityGeneration: string;
  factGeneration: string;
  identityGeneration: string;
}>;
const bindings = new WeakMap<PrivacyExplorerLocalContext, DisclosureContextBinding>();
export const requireDisclosureContext = (context: PrivacyExplorerLocalContext) => {
  const binding = bindings.get(context);
  if (!binding) throw unavailable();
  return binding;
};

export async function fenceDisclosureContext(
  client: PoolClient,
  binding: DisclosureContextBinding,
) {
  await fenceBoundAuthorities(client, binding.scope.participantId, [binding.authority]);
  const current = await loadRegisteredExplorerProfile(
    client,
    binding.scope.participantId,
    binding.scope.privacyDomainId,
    binding.registrationId,
  );
  const { registrationId: _, ...profile } = current;
  void _;
  if (canonicalJson(profile) !== canonicalJson(binding.profile)) throw unavailable();
  const generations = await loadDisclosureGenerations(client, binding.actor, binding.intent);
  const identity = disclosureGenerationIdentity(generations);
  if (
    identity.authorityGeneration !== binding.authorityGeneration ||
    identity.factGeneration !== binding.factGeneration
  )
    throw unavailable();
  return generations;
}

/** Only this live Identity/Policy/Profile join can construct a production local context. */
export const createDisclosureContextResolver =
  (pool: Pool, authorizer: ConfigurationAuthorizer) =>
  async (session: string, intent: ExplorerProjectionRequestV1, signal: AbortSignal) => {
    if (!authorizer.propose || signal.aborted || intent.action !== 'read') throw unavailable();
    const participantId = z.uuid().parse(intent.scope.participantId);
    const privacyDomainId = z.uuid().parse(intent.scope.privacyDomainId);
    const registrationId = z.uuid().parse(intent.resource.replace(/^urn:openpc:resource:/, ''));
    if (intent.resource !== `urn:openpc:resource:${registrationId}`) throw unavailable();
    const proof = await authorizer.propose({
      sessionToken: session,
      participantId,
      privacyDomainId,
      actionIntentId: explorerProjectionAction,
      resourceId: registrationId,
      candidateDigest: sha256CanonicalJson(intent),
      makerCheckerRequired: false,
      stepUpRequired: false,
    });
    if (
      proof.participantId !== participantId ||
      proof.privacyDomainId !== privacyDomainId ||
      signal.aborted
    )
      throw unavailable();
    const subject = `urn:openpc:principal:${proof.principalId}`;
    if (intent.subject !== subject) throw unavailable();
    const authority: BoundAuthority = {
      ...proof,
      actionIntentId: explorerProjectionAction,
      resourceId: registrationId,
    };
    const scope = {
      participantId,
      privacyDomainId,
      subject,
      actionIntentId: explorerProjectionAction,
    };
    const custody = new PostgresExplorerCustody(pool, scope);
    return custody.transaction(async (client) => {
      await fenceBoundAuthorities(client, participantId, [authority]);
      const roles = await client.query<{ role_id: string | null }>(
        'select role_id from control.assignment where participant_id=$1 and assignment_id=$2',
        [participantId, proof.assignmentId],
      );
      if (roles.rowCount !== 1) throw unavailable();
      const actor: AuthorizedPolicyActor = {
        ...proof,
        roleIds: roles.rows[0]?.role_id ? [roles.rows[0].role_id] : [],
      };
      const registered = await loadRegisteredExplorerProfile(
        client,
        participantId,
        privacyDomainId,
        registrationId,
      );
      const profile = registerExplorerProfile(registered, {
        verify: (value) => (value === registered ? registered : undefined),
      });
      const source = requireLiveExplorerProfile(profile);
      if (
        canonicalJson(profile) !== canonicalJson(intent.exportProfile) ||
        intent.scope.platformId !== source.platformId ||
        intent.scope.workloadId !== source.workloadId
      )
        throw unavailable();
      const generations = await loadDisclosureGenerations(client, actor, intent);
      await evaluateDisclosure(client, actor, intent, generations);
      const identity = disclosureGenerationIdentity(generations);
      const identityGeneration = sha256CanonicalJson(authority);
      const deadlineAt = new Date(
        Math.min(Date.now() + 30_000, Date.parse(profile.maximumDeadlineAt)),
      ).toISOString();
      const sessionEpoch = Number(proof.sessionEpoch);
      if (!Number.isSafeInteger(sessionEpoch) || signal.aborted) throw unavailable();
      const facts = {
        authorizationDigest: sha256CanonicalJson({
          authority,
          identity,
          occurrence: intent.occurrence,
        }),
        authorizationContextId: proof.sessionId,
        authorizationContextEpoch: sessionEpoch,
        subject,
        resource: intent.resource,
        participantId,
        privacyDomainId,
        platformId: source.platformId,
        workloadId: source.workloadId,
        accessClassIds: source.accessClassIds,
        allowedPurposeActions: [{ purpose: intent.purpose, action: intent.action }],
        allowedFieldIds: intent.projectionFields,
        auditCorrelationId: intent.occurrence.correlationId,
        occurrenceId: intent.occurrence.requestId,
        deadlineAt,
      };
      const context = bindLocalContext(facts, {
        verify: (value) => (value === facts ? facts : undefined),
      });
      bindings.set(context, {
        actor,
        authority,
        scope,
        custody,
        profile,
        registrationId,
        intent,
        ...identity,
        identityGeneration,
      });
      return { context, profile, serverMaximumDeadlineAt: deadlineAt };
    });
  };
