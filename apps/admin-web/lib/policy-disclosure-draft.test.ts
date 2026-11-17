import { expect, it } from 'vitest';
import { changeDisclosureDraft, readDisclosureDraft } from './policy-disclosure-draft';

const scope = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
};
const disclosureDocument = {
  schemaVersion: '1.0.0',
  ...scope,
  moduleBindings: [
    {
      moduleId: 'pc.policy.ptv',
      semanticVersion: '1.0.0',
      manifestDigest: `sha256:${'a'.repeat(64)}`,
      configurationDigest: `sha256:${'b'.repeat(64)}`,
    },
  ],
  rpcPolicies: [],
  contractPolicies: [],
  requiredFacts: [],
  visibilityPolicies: [
    {
      policyId: '018f0000-0000-7000-8000-000000000901',
      selector: {
        kind: 'TRANSACTION',
        runtimeBindingId: '018f0000-0000-7000-8000-000000000902',
        bindingRevision: '1',
      },
      mode: 'STATIC',
      effect: 'ALLOW',
      subject: { kind: 'PRINCIPAL', principalId: '018f0000-0000-7000-8000-000000000111' },
      purpose: 'AUDIT',
      requiredRoles: ['reader'],
      dimensions: ['EXISTENCE', 'METADATA', 'PAYLOAD'],
      fields: ['from', 'to', 'value'],
      conditions: [],
    },
  ],
};
const id = disclosureDocument.visibilityPolicies[0]!.policyId,
  text = JSON.stringify(disclosureDocument);
const edit = (change: Parameters<typeof changeDisclosureDraft>[4], value = text) =>
  changeDisclosureDraft(value, text, scope, id, change);

it('narrows fields and preserves every resource, subject, role, condition and unrelated family', () => {
  const document = {
    ...disclosureDocument,
    requiredFacts: [{ candidateId: 'retained', generationId: 'retained', factDigest: 'retained' }],
    factConditions: [{ kind: 'EXTERNAL_OBSERVATION', condition: 'retained' }],
    indexerPolicies: [{ rpcPolicyDigest: 'retained-dependency' }],
  };
  const original = JSON.stringify(document),
    result = changeDisclosureDraft(original, original, scope, id, { fields: ['to'] });
  expect(result).toHaveProperty('value');
  if (!('value' in result)) return;
  expect(JSON.parse(result.value)).toEqual({
    ...document,
    visibilityPolicies: [{ ...document.visibilityPolicies[0], fields: ['to'] }],
  });
});
it('supports denial and restoring the imported dimensions and fields without deleting rule prerequisites', () => {
  const denied = edit({ effect: 'DENY' });
  if (!('value' in denied)) throw Error('Expected draft denial');
  const allowed = edit({ effect: 'ALLOW' }, denied.value);
  if (!('value' in allowed)) throw Error('Expected draft restoration');
  expect(JSON.parse(allowed.value)).toEqual(disclosureDocument);
});
it.each([{ fields: [] }, { dimensions: [] }, { dimensions: ['PAYLOAD'] as const, fields: [] }])(
  'rejects an incomplete allow rule %j',
  (change) => {
    expect(edit(change as Parameters<typeof edit>[0])).toHaveProperty('error');
  },
);
it.each([{ fields: ['secret'] }, { dimensions: ['EXPORT'] }, { fields: ['to', 'to'] }])(
  'rejects expansion or duplicate selection %j',
  (change) => {
    expect(edit(change as Parameters<typeof edit>[0])).toHaveProperty('error');
  },
);
it('accepts whole receipts without fabricating field projection', () => {
  const document = {
      ...disclosureDocument,
      visibilityPolicies: [
        {
          ...disclosureDocument.visibilityPolicies[0],
          selector: { ...disclosureDocument.visibilityPolicies[0]!.selector, kind: 'RECEIPT' },
          fields: [],
        },
      ],
    },
    original = JSON.stringify(document);
  expect(changeDisclosureDraft(original, original, scope, id, { effect: 'DENY' })).toHaveProperty(
    'value',
  );
  expect(changeDisclosureDraft(original, original, scope, id, { fields: ['from'] })).toHaveProperty(
    'error',
  );
});
it('does not edit ambiguous policy identities, malformed selectors, or foreign workspace documents', () => {
  expect(
    readDisclosureDraft(
      JSON.stringify({
        ...disclosureDocument,
        visibilityPolicies: [
          ...disclosureDocument.visibilityPolicies,
          ...disclosureDocument.visibilityPolicies,
        ],
      }),
      scope,
    ),
  ).toBeUndefined();
  expect(
    readDisclosureDraft(
      JSON.stringify({
        ...disclosureDocument,
        visibilityPolicies: [
          { ...disclosureDocument.visibilityPolicies[0], selector: { kind: 'EVENT' } },
        ],
      }),
      scope,
    ),
  ).toBeUndefined();
  expect(
    changeDisclosureDraft(text, text, { ...scope, privacyDomainId: 'foreign' }, id, {
      effect: 'DENY',
    }),
  ).toHaveProperty('error');
});
it('rejects an old editor baseline after changes to subject, roles, resource or conditions', () => {
  for (const update of [
    { subject: { kind: 'PRINCIPAL', principalId: '018f0000-0000-7000-8000-000000000199' } },
    { requiredRoles: ['other'] },
    { selector: { ...disclosureDocument.visibilityPolicies[0]!.selector, bindingRevision: '2' } },
    { conditions: [{ kind: 'RELATIONSHIP' }] },
  ]) {
    const changed = JSON.stringify({
      ...disclosureDocument,
      visibilityPolicies: [{ ...disclosureDocument.visibilityPolicies[0], ...update }],
    });
    expect(changeDisclosureDraft(changed, text, scope, id, { effect: 'DENY' })).toHaveProperty(
      'error',
    );
  }
});
it('bounds display and leaves unfamiliar rules to native validation and advanced editing', () => {
  expect(
    readDisclosureDraft(
      JSON.stringify({
        ...disclosureDocument,
        visibilityPolicies: [
          { ...disclosureDocument.visibilityPolicies[0], extra: 'unrecognized' },
        ],
      }),
      scope,
    ),
  ).toBeUndefined();
  expect(
    readDisclosureDraft(
      JSON.stringify({
        ...disclosureDocument,
        visibilityPolicies: Array.from(
          { length: 257 },
          () => disclosureDocument.visibilityPolicies[0],
        ),
      }),
      scope,
    ),
  ).toBeUndefined();
  expect(
    readDisclosureDraft(
      JSON.stringify({
        ...disclosureDocument,
        visibilityPolicies: [
          { ...disclosureDocument.visibilityPolicies[0], mode: 'DYNAMIC', conditions: [] },
        ],
      }),
      scope,
    ),
  ).toBeUndefined();
});

it.each(['not-a-revision', '18446744073709551616', '9'.repeat(1024)])(
  'rejects malformed or out-of-range revisions without crashing the draft editor: %s',
  (bindingRevision) => {
    const document = {
      ...disclosureDocument,
      visibilityPolicies: [
        {
          ...disclosureDocument.visibilityPolicies[0],
          selector: { ...disclosureDocument.visibilityPolicies[0]!.selector, bindingRevision },
        },
      ],
    };
    expect(() => readDisclosureDraft(JSON.stringify(document), scope)).not.toThrow();
    expect(readDisclosureDraft(JSON.stringify(document), scope)).toBeUndefined();
  },
);
