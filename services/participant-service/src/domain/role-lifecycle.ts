import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalAuthorizationJson } from '../../../identity-service/src/contracts/authorization.js';
import { verifyStoredStepUpEvidence } from '../../../identity-service/src/db/verified-step-up-evidence.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import { ParticipantKernelError } from './participant-errors.js';

export interface RoleDefinition {
  readonly id: string;
  readonly participantId: string;
  readonly roleId: string;
  readonly displayName: string;
  readonly actionIntentIds: readonly string[];
  readonly state: 'ACTIVE' | 'ARCHIVED';
}
export interface RoleRecord extends RoleDefinition {
  readonly revision: string;
  readonly origin: 'GOVERNED' | 'MIGRATED_ASSIGNMENT' | 'BOOTSTRAP';
}
export interface RoleReadback {
  readonly effect: RoleRecord;
  readonly operationId: string | null;
}
export interface RoleArchiveResult {
  readonly effect: RoleRecord;
  readonly newEpoch: string;
  readonly revokedAssignments: number;
}
export interface RoleProposal {
  readonly candidateDigest: string;
  readonly resourceId: string;
  readonly mutation: 'CREATE' | 'ARCHIVE';
  readonly expectedRevision: string;
  readonly state: string;
  readonly expiresAt: string;
  readonly proposedRole: RoleDefinition;
  /** Original committed historical result; never current role/permission. */
  readonly consumption: Readonly<{ operationId: string; effect: RoleRecord }> | null;
}

const revision = z.string().regex(/^(0|[1-9][0-9]{0,19})$/u);
const definition = z
  .strictObject({
    id: z.uuid(),
    participantId: z.uuid(),
    roleId: z.string().max(256),
    displayName: z.string().min(1).max(160),
    actionIntentIds: z
      .array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u))
      .max(256)
      .refine((items) => new Set(items).size === items.length),
    state: z.enum(['ACTIVE', 'ARCHIVED']),
  })
  .refine((value) => value.roleId === `urn:openpc:role:${value.id}`);
const historicalRecord = definition.safeExtend({
  revision,
  origin: z.enum(['GOVERNED', 'MIGRATED_ASSIGNMENT', 'BOOTSTRAP']),
});
const historicalArchive = z.strictObject({
  effect: historicalRecord,
  newEpoch: revision,
  revokedAssignments: z.number().int().nonnegative(),
});
const archiveCandidate = z.strictObject({ roleId: z.uuid(), state: z.literal('ARCHIVED') });
function unknown(): never {
  throw new ParticipantKernelError('PC-IDENTITY-1008');
}
interface RoleConsumptionRow {
  operation_id: string;
  result_payload: unknown;
  result_digest: Buffer;
  result_revision: string;
  approval_request_id: string;
  checker_principal_id: string;
  signer_credential_id: string;
  public_key_spki_der: Buffer;
  public_key_digest: Buffer;
  evidence_cbor: Buffer;
  evidence_digest: Buffer;
  cose_sign1: Buffer;
  maker_binding_digest: Buffer | null;
  evidence_maker_binding_digest: Buffer | null;
  event_maker_binding_digest: Buffer | null;
}
async function readRoleConsumption(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  candidateDigest: string,
  resourceId: string,
  proposal: {
    catalog_operation_id: string;
    expected_revision: string;
    candidate_document: unknown;
    consumed_operation_id: string;
  },
  verifier: IdentityRuntimeVerifier | undefined,
): Promise<NonNullable<RoleProposal['consumption']>> {
  const selected = await client.query<RoleConsumptionRow>(
    `select receipt.operation_id::text,receipt.result_payload,receipt.result_digest,
            receipt.result_aggregate_version::text result_revision,
            evidence.approval_request_id::text,evidence.checker_principal_id::text,
            evidence.signer_credential_id::text,credential.public_key_spki_der,credential.public_key_digest,
            evidence.evidence_cbor,evidence.evidence_digest,evidence.cose_sign1,
            receipt.webauthn_assertion_binding_digest as maker_binding_digest,
            evidence.webauthn_assertion_binding_digest as evidence_maker_binding_digest,
            event.webauthn_assertion_binding_digest as event_maker_binding_digest
       from control.mutation_candidate candidate
       join control.idempotency_record receipt
         on receipt.participant_id=candidate.participant_id and receipt.privacy_domain_id=candidate.privacy_domain_id
        and receipt.operation_id=candidate.consumed_operation_id and receipt.principal_id=candidate.maker_principal_id
        and receipt.action_intent_id=candidate.action_intent_id and receipt.catalog_operation_id=candidate.catalog_operation_id
        and receipt.idempotency_key=candidate.idempotency_key and receipt.input_digest=candidate.candidate_digest
        and receipt.expected_aggregate_version=candidate.expected_revision and receipt.terminal_state='COMMITTED'
        and receipt.webauthn_assertion_binding_digest is not null and octet_length(receipt.webauthn_assertion_binding_digest)=32
       join control.approval_request approval
         on approval.participant_id=candidate.participant_id and approval.privacy_domain_id=candidate.privacy_domain_id
        and approval.subject_type='CONFIGURATION_CANDIDATE' and approval.subject_id=candidate.mutation_candidate_id
        and approval.subject_digest=candidate.candidate_digest and approval.subject_version=candidate.expected_revision
        and approval.action_intent_id=candidate.action_intent_id and approval.maker_principal_id=candidate.maker_principal_id
        and approval.state='APPROVED'
       join control.mutation_evidence evidence
         on evidence.participant_id=candidate.participant_id and evidence.privacy_domain_id=candidate.privacy_domain_id
        and evidence.operation_id=candidate.consumed_operation_id and evidence.principal_id=candidate.maker_principal_id
        and evidence.approval_request_id=approval.approval_request_id and evidence.candidate_digest=candidate.candidate_digest
        and evidence.catalog_operation_id=candidate.catalog_operation_id and evidence.action_intent_id=candidate.action_intent_id
        and evidence.aggregate_type='role' and evidence.aggregate_id=candidate.resource_id
        and evidence.aggregate_version=candidate.expected_revision and evidence.evidence_digest=sha256(evidence.evidence_cbor)
        and evidence.webauthn_assertion_binding_digest is not null
        and evidence.webauthn_assertion_binding_digest=receipt.webauthn_assertion_binding_digest
       join control.approval_decision_record decision
         on decision.participant_id=approval.participant_id and decision.privacy_domain_id=approval.privacy_domain_id
        and decision.approval_request_id=approval.approval_request_id and decision.decision='APPROVE'
        and decision.approver_principal_id=evidence.checker_principal_id and decision.approver_principal_id<>candidate.maker_principal_id
        and decision.signer_credential_id=evidence.signer_credential_id and decision.candidate_digest=candidate.candidate_digest
        and decision.aggregate_version=candidate.expected_revision and decision.evidence_cbor=evidence.evidence_cbor
        and decision.cose_sign1=evidence.cose_sign1 and decision.decided_at<=evidence.occurred_at
       join control.credential credential
         on credential.participant_id=evidence.participant_id and credential.credential_id=evidence.signer_credential_id
        and credential.principal_id=evidence.checker_principal_id and credential.kind='WEBAUTHN'
        and credential.valid_from<=decision.decided_at and credential.valid_from<=evidence.occurred_at
        and (credential.valid_until is null or credential.valid_until>evidence.occurred_at)
       join control.outbox_event event
         on event.participant_id=evidence.participant_id and event.privacy_domain_id=evidence.privacy_domain_id
        and event.aggregate_type=evidence.aggregate_type and event.aggregate_id=evidence.aggregate_id
        and event.event_type='openpc.role.mutation.committed.v1' and event.payload_cbor=evidence.evidence_cbor
        and event.payload_digest=evidence.evidence_digest and event.cose_sign1=evidence.cose_sign1
        and event.webauthn_assertion_binding_digest is not null
        and event.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
      where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.candidate_digest=$3
        and candidate.resource_id=$4 and candidate.catalog_operation_id=$5 and candidate.expected_revision=$6
        and candidate.state='CONSUMED' and candidate.consumed_operation_id=$7
        and candidate.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' limit 2`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(candidateDigest.slice(7), 'hex'),
      resourceId,
      proposal.catalog_operation_id,
      proposal.expected_revision,
      proposal.consumed_operation_id,
    ],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    selected.rows.length !== 1 ||
    !row ||
    !Buffer.isBuffer(row.maker_binding_digest) ||
    row.maker_binding_digest.length !== 32 ||
    !Buffer.isBuffer(row.evidence_maker_binding_digest) ||
    !Buffer.isBuffer(row.event_maker_binding_digest) ||
    !row.maker_binding_digest.equals(row.evidence_maker_binding_digest) ||
    !row.maker_binding_digest.equals(row.event_maker_binding_digest) ||
    row.operation_id !== proposal.consumed_operation_id ||
    !z.uuid().safeParse(row.operation_id).success ||
    [row.approval_request_id, row.checker_principal_id, row.signer_credential_id].some(
      (value) => !z.uuid().safeParse(value).success,
    )
  )
    unknown();
  const create = proposal.catalog_operation_id === 'ID-OP-ROLE-CREATE';
  const parsed = create
    ? historicalRecord.safeParse(row.result_payload)
    : historicalArchive.safeParse(row.result_payload);
  if (
    !parsed.success ||
    !revision.safeParse(row.result_revision).success ||
    !revision.safeParse(proposal.expected_revision).success
  )
    unknown();
  const effect = create
    ? (parsed.data as RoleRecord)
    : (parsed.data as z.infer<typeof historicalArchive>).effect;
  // Actual producers: CREATE inserts version1/default GOVERNED; ARCHIVE advances
  // row_version by1. Evidence binds the PRE-effect revision, receipt the POST.
  if (
    effect.id !== resourceId ||
    effect.participantId !== participantId ||
    effect.revision !== row.result_revision ||
    (create
      ? proposal.expected_revision !== '0' ||
        effect.revision !== '1' ||
        effect.origin !== 'GOVERNED' ||
        effect.state !== 'ACTIVE'
      : BigInt(effect.revision) !== BigInt(proposal.expected_revision) + 1n ||
        effect.state !== 'ARCHIVED')
  )
    unknown();
  const proposed = create
    ? definition.safeParse(proposal.candidate_document)
    : archiveCandidate.safeParse(proposal.candidate_document);
  if (
    !proposed.success ||
    (create
      ? canonicalAuthorizationJson(proposed.data) !==
        canonicalAuthorizationJson({
          id: effect.id,
          participantId: effect.participantId,
          roleId: effect.roleId,
          displayName: effect.displayName,
          actionIntentIds: effect.actionIntentIds,
          state: effect.state,
        })
      : (proposed.data as z.infer<typeof archiveCandidate>).roleId !== resourceId)
  )
    unknown();
  for (const value of [
    row.result_digest,
    row.public_key_spki_der,
    row.public_key_digest,
    row.evidence_cbor,
    row.evidence_digest,
    row.cose_sign1,
  ])
    if (!Buffer.isBuffer(value) || value.length === 0) unknown();
  if (
    !createHash('sha256')
      .update(canonicalAuthorizationJson(row.result_payload))
      .digest()
      .equals(row.result_digest) ||
    !createHash('sha256').update(row.public_key_spki_der).digest().equals(row.public_key_digest) ||
    !createHash('sha256').update(row.evidence_cbor).digest().equals(row.evidence_digest) ||
    !(await verifyStoredStepUpEvidence(
      client,
      {
        participantId,
        privacyDomainId,
        principalId: row.checker_principal_id,
        credentialId: row.signer_credential_id,
        approvalRequestId: row.approval_request_id,
        credentialPublicKey: row.public_key_spki_der,
        evidenceCbor: row.evidence_cbor,
        coseSign1: row.cose_sign1,
      },
      verifier,
    ))
  )
    unknown();
  return Object.freeze({
    operationId: row.operation_id,
    effect: Object.freeze({
      ...effect,
      actionIntentIds: Object.freeze([...effect.actionIntentIds]),
    }),
  });
}

/** Caller fences the exact resource resolved from this immutable candidate. */
export async function readRoleProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  candidateDigest: string,
  resourceId: string,
  verifier?: IdentityRuntimeVerifier,
): Promise<RoleProposal> {
  const proposal = await client.query<{
    catalog_operation_id: string;
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: RoleDefinition;
    consumed_operation_id: string | null;
  }>(
    `select catalog_operation_id,expected_revision::text,state,expires_at,candidate_document,consumed_operation_id::text
      from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2
       and candidate_digest=$3 and resource_id=$4
       and catalog_operation_id in ('ID-OP-ROLE-CREATE','ID-OP-ROLE-ARCHIVE') for share`,
    [participantId, privacyDomainId, Buffer.from(candidateDigest.slice(7), 'hex'), resourceId],
  );
  if (proposal.rowCount !== 1 || proposal.rows.length !== 1)
    throw new ParticipantKernelError('PC-IDENTITY-1008');
  const value = proposal.rows[0]!;
  if (
    !revision.safeParse(value.expected_revision).success ||
    `sha256:${createHash('sha256').update(canonicalAuthorizationJson(value.candidate_document)).digest('hex')}` !==
      candidateDigest
  )
    unknown();
  const document =
    value.catalog_operation_id === 'ID-OP-ROLE-CREATE'
      ? definition.safeParse(value.candidate_document)
      : archiveCandidate.safeParse(value.candidate_document);
  if (
    !document.success ||
    (value.catalog_operation_id === 'ID-OP-ROLE-CREATE'
      ? (document.data as RoleDefinition).id !== resourceId ||
        (document.data as RoleDefinition).participantId !== participantId ||
        (document.data as RoleDefinition).state !== 'ACTIVE' ||
        value.expected_revision !== '0'
      : (document.data as z.infer<typeof archiveCandidate>).roleId !== resourceId)
  )
    unknown();
  if ((value.state === 'CONSUMED') !== (value.consumed_operation_id !== null)) unknown();
  const consumption =
    value.consumed_operation_id === null
      ? null
      : await readRoleConsumption(
          client,
          participantId,
          privacyDomainId,
          candidateDigest,
          resourceId,
          { ...value, consumed_operation_id: value.consumed_operation_id },
          verifier,
        );
  const mutation = value.catalog_operation_id === 'ID-OP-ROLE-CREATE' ? 'CREATE' : 'ARCHIVE';
  const role =
    mutation === 'CREATE'
      ? value.candidate_document
      : (consumption?.effect ??
        (await readRole(client, participantId, privacyDomainId, resourceId)).effect);
  return {
    candidateDigest,
    resourceId,
    mutation,
    expectedRevision: value.expected_revision,
    state: value.state,
    expiresAt: value.expires_at.toISOString(),
    consumption,
    proposedRole: {
      id: role.id,
      participantId,
      roleId: role.roleId,
      displayName: role.displayName,
      actionIntentIds: role.actionIntentIds,
      state: mutation === 'CREATE' ? 'ACTIVE' : 'ARCHIVED',
    },
  };
}
interface RoleRow {
  authority_role_id: string;
  participant_id: string;
  role_id: string;
  display_name: string;
  action_intent_ids: string[];
  state: RoleRecord['state'];
  origin: RoleRecord['origin'];
  row_version: string;
}
function record(row: RoleRow | undefined): RoleRecord {
  if (row === undefined) throw new ParticipantKernelError('PC-IDENTITY-1008');
  return {
    id: row.authority_role_id,
    participantId: row.participant_id,
    roleId: row.role_id,
    displayName: row.display_name,
    actionIntentIds: row.action_intent_ids,
    state: row.state,
    origin: row.origin,
    revision: String(row.row_version),
  };
}

/** Caller owns the live authorization fence and scoped transaction. */
export async function readRole(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  roleId: string,
): Promise<RoleReadback> {
  const result = await client.query<RoleRow & { operation_id: string | null }>(
    `select role.*,candidate.consumed_operation_id::text operation_id from control.authority_role role
     left join lateral (
       select consumed_operation_id from control.mutation_candidate
        where participant_id=role.participant_id and privacy_domain_id=$3
         and resource_id=role.authority_role_id and state='CONSUMED'
         and catalog_operation_id in ('ID-OP-ROLE-CREATE','ID-OP-ROLE-ARCHIVE')
        order by expected_revision desc limit 1
     ) candidate on true where role.participant_id=$1 and role.authority_role_id=$2`,
    [participantId, roleId, privacyDomainId],
  );
  return { effect: record(result.rows[0]), operationId: result.rows[0]!.operation_id };
}

export async function createRole(
  client: PoolClient,
  principalId: string,
  envelopeId: string,
  value: RoleDefinition,
): Promise<RoleRecord> {
  const envelope = await client.query<{ action_intent_ids: string[] }>(
    `select action_intent_ids from control.authority_envelope
      where participant_id=$1 and authority_envelope_id=$2 and state='ACTIVE'`,
    [value.participantId, envelopeId],
  );
  if (
    value.state !== 'ACTIVE' ||
    value.roleId !== `urn:openpc:role:${value.id}` ||
    envelope.rowCount !== 1 ||
    !value.actionIntentIds.every((action) => envelope.rows[0]!.action_intent_ids.includes(action))
  ) {
    throw new ParticipantKernelError('PC-IDENTITY-1002');
  }
  const result = await client.query<RoleRow>(
    `insert into control.authority_role
      (authority_role_id,participant_id,role_id,display_name,action_intent_ids,created_by_principal_id)
     values ($1,$2,$3,$4,$5,$6) returning *`,
    [
      value.id,
      value.participantId,
      value.roleId,
      value.displayName,
      value.actionIntentIds,
      principalId,
    ],
  );
  return record(result.rows[0]);
}

/** Archive is deny-first: revoke grants and descendants, advance the root epoch, retain tombstones. */
export async function archiveRole(
  client: PoolClient,
  participantId: string,
  principalId: string,
  roleId: string,
  operationId: string,
): Promise<RoleArchiveResult> {
  const role = await client.query<RoleRow>(
    `select * from control.authority_role where participant_id=$1 and authority_role_id=$2 and state='ACTIVE' for update`,
    [participantId, roleId],
  );
  const value = record(role.rows[0]);
  const assignments = await client.query<{ assignment_id: string }>(
    `update control.assignment set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3
      where participant_id=$1 and role_id=$2 and state in ('ACTIVE','SUSPENDED') returning assignment_id`,
    [participantId, value.roleId, operationId],
  );
  await client.query(
    `with recursive descendants as (
      select delegation_id from control.delegation where participant_id=$1 and parent_assignment_id=any($2::uuid[])
      union select child.delegation_id from control.delegation child join descendants parent
        on child.parent_delegation_id=parent.delegation_id where child.participant_id=$1
    ) update control.delegation set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3
      where participant_id=$1 and delegation_id in (select delegation_id from descendants) and state in ('ACTIVE','SUSPENDED')`,
    [participantId, assignments.rows.map((row) => row.assignment_id), operationId],
  );
  const epoch = await client.query<{ authority_epoch: string }>(
    `update control.participant set authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 returning authority_epoch::text`,
    [participantId],
  );
  const newEpoch = epoch.rows[0]!.authority_epoch;
  for (const assignment of assignments.rows) {
    await client.query(
      `insert into control.revocation
        (participant_id,target_type,target_id,effective_at,reason_code,authority_epoch,receipt_digest,created_by_principal_id)
       values ($1,'assignment',$2,clock_timestamp(),'ROLE_ARCHIVED',$3,$4,$5)`,
      [
        participantId,
        assignment.assignment_id,
        newEpoch,
        createHash('sha256')
          .update(`role:${roleId}:assignment:${assignment.assignment_id}:${newEpoch}`)
          .digest(),
        principalId,
      ],
    );
  }
  const archived = await client.query<RoleRow>(
    `update control.authority_role set state='ARCHIVED',row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and authority_role_id=$2 and state='ACTIVE' returning *`,
    [participantId, roleId],
  );
  return {
    effect: record(archived.rows[0]),
    newEpoch,
    revokedAssignments: assignments.rowCount ?? 0,
  };
}
