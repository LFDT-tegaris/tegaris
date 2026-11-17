import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { decodeEnvelopeScope } from '../../../packages/security-kernel/src/identity-envelope/codec.ts';
import { encodeCbor } from '../../../packages/security-kernel/src/canonical-cbor.ts';

const participant = '018f0000-0000-7000-8000-000000000101';
const privacy = '018f0000-0000-7000-8000-000000000201';
const maker = '018f0000-0000-7000-8000-000000000111';
const checker = '018f0000-0000-7000-8000-000000000112';
const provider = '01a0f4e2-a2af-7371-8ca3-d63c500c4373';
const fingerprint = 'sha256:ac8de64682a9240cc57b047606819f4e000cf42ff30a745d3781d0b22f0c9b96';
const update = 'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1';
const approve = 'ACT-POLICY_APPROVE_REQUEST-V1';
const platform = '018f0000-0000-7000-8000-000000000401';
const ids = {
  maker: ['019a08d0-0001-7000-8000-000000000001', '019a08d0-0001-7000-8000-000000000002'],
  checker: ['019a08d0-0001-7000-8000-000000000003', '019a08d0-0001-7000-8000-000000000004'],
};

// Disposable initial trust only. These LEGACY bytes are deliberately synthetic;
// they are neither typed envelope signatures nor maker/checker business evidence.
export async function supplementProviderRenewalTrust(client, input) {
  assert.deepEqual(
    Object.keys(input).sort(),
    [
      ...(input.phase === 'checker' ? ['approvalId', 'phase', 'revision'] : ['phase', 'revision']),
      ...(input.expectedPlatformEpoch === undefined ? [] : ['expectedPlatformEpoch']),
    ].sort(),
  );
  assert.ok(Object.hasOwn(ids, input.phase));
  assert.match(input.revision, /^[1-9][0-9]*$/u);
  if (input.phase === 'checker')
    assert.match(
      input.approvalId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
  const epoch = input.expectedPlatformEpoch ?? '1';
  assert.match(epoch, /^[1-9][0-9]*$/u);
  assert.ok(BigInt(epoch) <= 18446744073709551615n);
  const principal = input.phase === 'maker' ? maker : checker;
  const actions = input.phase === 'maker' ? [update] : [update, approve];
  const resources = input.phase === 'maker' ? [provider] : [provider, input.approvalId];
  // A later authoritative provider revision is a new QA renewal intent.
  // Keep the original v8 IDs for exact replay; never extend an older grant.
  const grantIds =
    input.revision === '8' && epoch === '1'
      ? ids[input.phase]
      : ['envelope', 'assignment'].map((kind) => {
          const hash = createHash('sha256')
            .update(
              `SYNTHETIC_LOCAL_QA_PROVIDER_RENEWAL:${provider}:${input.revision}:${input.phase}:${kind}${epoch === '1' ? '' : `:epoch:${epoch}`}`,
            )
            .digest('hex');
          return `019a08d0-${hash.slice(0, 4)}-7${hash.slice(4, 7)}-8${hash.slice(7, 10)}-${hash.slice(10, 22)}`;
        });
  const [envelope, assignment] = grantIds;
  await client.query('begin isolation level serializable');
  try {
    await client.query(
      "select pg_advisory_xact_lock(hashtext('openpc-disposable-local-qa-fixture'))",
    );
    const source = await client.query(
      `select clock_timestamp() as now, least(clock_timestamp()+interval '1 hour',
         (select min(valid_until) from control.credential where participant_id=$1
           and principal_id=any($3::uuid[]) and kind in ('OIDC_SUBJECT','WEBAUTHN')
           and state='ACTIVE' and valid_from<=clock_timestamp()
           and (valid_until is null or valid_until>clock_timestamp()))) as bound
       from control.provider_profile p
       join control.participant tenant on tenant.participant_id=p.participant_id and tenant.state='ACTIVE'
       join control.privacy_domain d on d.participant_id=p.participant_id and d.privacy_domain_id=p.privacy_domain_id and d.state='ACTIVE'
       join control.platform_context platform on platform.platform_context_id=$4 and platform.state='ACTIVE' and platform.authority_epoch=$8::numeric
       where p.participant_id=$1 and p.privacy_domain_id=$2 and p.provider_profile_id=$5
         and p.revision=$6::bigint and p.state='QUALIFIED' and p.behavior_fingerprint=$7
         and not exists (select 1 from unnest($3::uuid[]) actor where not exists (
           select 1 from control.principal principal where principal.participant_id=$1
             and principal.principal_id=actor and principal.state='ACTIVE'
             and exists (select 1 from control.credential c where c.participant_id=$1 and c.principal_id=actor
               and c.kind='WEBAUTHN' and c.state='ACTIVE' and c.valid_from<=clock_timestamp()
               and (c.valid_until is null or c.valid_until>clock_timestamp()))
             and exists (select 1 from control.credential c where c.participant_id=$1 and c.principal_id=actor
               and c.kind='OIDC_SUBJECT' and c.state='ACTIVE' and c.valid_from<=clock_timestamp()
               and (c.valid_until is null or c.valid_until>clock_timestamp()))))
       for share of p,tenant,d,platform`,
      [
        participant,
        privacy,
        [maker, checker],
        platform,
        provider,
        input.revision,
        fingerprint,
        epoch,
      ],
    );
    assert.equal(source.rowCount, 1, 'Current retained provider and actor credentials required');
    const now = new Date(source.rows[0].now);
    let bound = new Date(source.rows[0].bound);
    if (epoch !== '1') {
      // A new epoch never inherits historical synthetic trust. Its installed,
      // independently governed terminal scope must explicitly admit every
      // action and exact provider/approval resource before any fixture write.
      const installed = await client.query(
        `select s.scope_cbor,s.admission_preimage,s.admission_digest from control.platform_envelope_scope_successor s
          join control.platform_scope_replacement r on r.replacement_id=s.replacement_id and r.state='COMMITTED'
          join control.platform_context p on p.platform_context_id=s.platform_context_id
            and p.authority_epoch=s.platform_authority_epoch and p.state='ACTIVE'
          where s.platform_context_id=$1 and s.platform_authority_epoch=$2::numeric
            and s.owner_participant_id=$3 and s.installation_privacy_domain_id=$4
          for share of s,r,p`,
        [platform, epoch, participant, privacy],
      );
      assert.equal(installed.rowCount, 1, 'Committed current terminal scope required');
      const row = installed.rows[0];
      assert.ok(
        createHash('sha256').update(row.admission_preimage).digest().equals(row.admission_digest),
      );
      const scope = decodeEnvelopeScope(row.scope_cbor);
      assert.ok(
        scope.administration.participantIds.includes(participant) &&
          scope.administration.privacyDomainIds.includes(privacy),
      );
      assert.ok(
        actions.every((action) => scope.administration.actionIntentIds.includes(action)),
        'Terminal action bound required',
      );
      assert.ok(
        resources.every((resource) => scope.administration.resourceIds.includes(resource)),
        'Terminal exact resource bound required',
      );
      assert.ok(scope.administration.riskClasses.includes('HIGH'));
      assert.ok(
        BigInt(scope.validFromNs) <= BigInt(+now) * 1000000n &&
          BigInt(scope.validUntilNs) > BigInt(+now) * 1000000n,
      );
      bound = new Date(Math.min(+bound, Number(BigInt(scope.validUntilNs) / 1000000n)));
    }
    assert.ok(Number.isFinite(+now) && +bound > +now && +bound - +now <= 3_600_001);
    if (input.phase === 'checker') {
      const request = await client.query(
        `select 1 from control.approval_request r join control.mutation_candidate c
          on c.mutation_candidate_id=r.subject_id and c.participant_id=r.participant_id
          and c.privacy_domain_id=r.privacy_domain_id and c.candidate_digest=r.subject_digest
          and c.expected_revision=r.subject_version and c.action_intent_id=r.action_intent_id
         where r.approval_request_id=$1 and r.participant_id=$2 and r.privacy_domain_id=$3
          and r.subject_type='CONFIGURATION_CANDIDATE' and r.state='OPEN' and r.expires_at>clock_timestamp()
          and r.maker_principal_id=$4 and r.checker_principal_id=$5
          and c.maker_principal_id=$4 and c.resource_id=$6 and c.action_intent_id=$7
          and c.catalog_operation_id='CFG-OP-UPDATE-PROVIDER-PROFILE' and c.expected_revision=$8
          and c.state='APPROVAL_REQUESTED' and c.consumed_operation_id is null and c.expires_at>clock_timestamp()
          and c.candidate_document->>'replacementDigest'=$9
          and c.predecessor_candidate_id is null
         for share of r,c`,
        [
          input.approvalId,
          participant,
          privacy,
          maker,
          checker,
          provider,
          update,
          input.revision,
          fingerprint,
        ],
      );
      assert.equal(request.rowCount, 1, 'Exact current unconsumed UI proposal required');
    }
    const read = async () =>
      (
        await client.query(
          `select e.principal_id::text principal,e.representation,e.state,e.valid_from as "validFrom",e.valid_until as "validUntil",
        e.semantic_cbor as semantic,e.semantic_digest as digest,e.cose_sign1 as cose,
        e.privacy_domain_ids as privacy,e.action_intent_ids as actions,e.resource_ids as resources,
        e.risk_classes as risks,e.runtime_capability_ids as capabilities,e.maker_checker_required as "makerChecker",
        e.step_up_required as "stepUp",e.onward_delegation_depth as depth,
        e.platform_context_id::text platform,e.platform_authority_epoch::text epoch,
        a.assignment_id::text assignment,a.principal_id::text as "assignedPrincipal",a.state as "assignmentState",
        a.role_id as role,a.scope_digest as "scopeDigest",lower(a.valid_during) as "assignmentFrom",upper(a.valid_during) as "assignmentUntil",
        a.privacy_domain_ids as "assignmentPrivacy",a.action_intent_ids as "assignmentActions",
        a.resource_ids as "assignmentResources",a.risk_classes as "assignmentRisks",
        a.runtime_capability_ids as "assignmentCapabilities",a.maker_checker_required as "assignmentMakerChecker",
        a.step_up_required as "assignmentStepUp",a.onward_delegation_depth as "assignmentDepth"
       from control.authority_envelope e left join control.assignment a on a.authority_envelope_id=e.authority_envelope_id
       where e.authority_envelope_id=$1 and e.participant_id=$2`,
          [envelope, participant],
        )
      ).rows;
    const prior = await read();
    assert.ok(prior.length <= 1);
    const validFrom = prior[0] ? new Date(prior[0].validFrom) : now;
    const validUntil = prior[0] ? new Date(prior[0].validUntil) : bound;
    assert.ok(
      +validFrom <= +now &&
        +validUntil > +now &&
        +validUntil <= +bound &&
        +validUntil - +validFrom <= 3_600_001,
      'Expired or widened trust must never be renewed by replay',
    );
    const semantic = encodeCbor([
      'SYNTHETIC_LOCAL_QA_PROVIDER_RENEWAL',
      input.phase,
      participant,
      privacy,
      principal,
      provider,
      input.revision,
      input.approvalId ?? '',
      ...(epoch === '1' ? [] : [platform, epoch]),
      actions,
      resources,
      validFrom.toISOString(),
      validUntil.toISOString(),
    ]);
    const digest = createHash('sha256').update(semantic).digest();
    const cose = Buffer.from('d28440a04040', 'hex');
    const expected = {
      principal,
      representation: 'LEGACY',
      state: 'ACTIVE',
      validFrom,
      validUntil,
      semantic,
      digest,
      cose,
      privacy: [privacy],
      actions,
      resources,
      risks: ['HIGH'],
      capabilities: [],
      makerChecker: true,
      stepUp: true,
      depth: 0,
      platform,
      epoch,
      assignment,
      assignedPrincipal: principal,
      assignmentState: 'ACTIVE',
      role: null,
      scopeDigest: digest,
      assignmentFrom: validFrom,
      assignmentUntil: validUntil,
      assignmentPrivacy: [privacy],
      assignmentActions: actions,
      assignmentResources: resources,
      assignmentRisks: ['HIGH'],
      assignmentCapabilities: [],
      assignmentMakerChecker: true,
      assignmentStepUp: true,
      assignmentDepth: 0,
    };
    if (prior.length === 0) {
      await client.query(
        `insert into control.authority_envelope (authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
          representation,authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,semantic_digest,cose_sign1,
          privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,
          platform_context_id,platform_authority_epoch)
         values($1,$2,$3,$4,$5,'LEGACY',1,0,'ACTIVE',$6,$7,$8,$9,$10,$11,$12,$13,ARRAY['HIGH'],true,true,0,$14,$15::numeric)`,
        [
          envelope,
          participant,
          principal,
          maker,
          checker,
          validFrom,
          validUntil,
          semantic,
          digest,
          cose,
          [privacy],
          actions,
          resources,
          platform,
          epoch,
        ],
      );
      await client.query(
        `insert into control.assignment (assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,
          valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
          maker_checker_required,step_up_required,onward_delegation_depth)
         values($1,$2,$3,$4,0,$5,tstzrange($6,$7,'[)'),'ACTIVE',$3,$8,$9,$10,ARRAY['HIGH'],true,true,0)`,
        [
          assignment,
          participant,
          principal,
          envelope,
          digest,
          validFrom,
          validUntil,
          [privacy],
          actions,
          resources,
        ],
      );
    }
    assert.deepEqual(await read(), [expected], 'Exact synthetic trust readback required');
    await client.query('commit');
    return {
      fixture: 'SYNTHETIC_LOCAL_QA_PROVIDER_RENEWAL',
      phase: input.phase,
      envelopeId: envelope,
      assignmentId: assignment,
      validUntil: validUntil.toISOString(),
      actions,
      resources,
      replay: prior.length === 1,
    };
  } catch (error) {
    await client.query('rollback');
    throw error;
  }
}
