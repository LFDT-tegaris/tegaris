import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyInventory, classifyLicense } from './license-policy.mjs';

const policy = {
  allowLicenseIdentifiers: ['MIT', 'Apache-2.0', 'BSD-3-Clause'],
  reviewLicenseIdentifiers: ['MPL-2.0'],
  unqualifiedLicenseIdentifiers: ['BlueOak-1.0.0'],
};

for (const [expression, expected] of [
  ['MIT', 'ALLOW'],
  [' mit ', 'ALLOW'],
  ['MIT AND Apache-2.0', 'ALLOW'],
  ['MIT OR GPL-3.0-only', 'ALLOW'],
  ['((MIT))', 'ALLOW'],
  ['MIT OR(Apache-2.0)', 'ALLOW'],
  ['(MIT OR Apache-2.0) AND BSD-3-Clause', 'ALLOW'],
  ['(MIT OR Apache-2.0) AND GPL-3.0-only', 'DENY'],
  ['GPL-3.0-only AND (MIT OR Apache-2.0)', 'DENY'],
  ['MIT OR Apache-2.0 AND GPL-3.0-only', 'ALLOW'],
  ['MPL-2.0', 'REVIEW'],
  ['MIT AND MPL-2.0', 'REVIEW'],
  ['(MIT OR Apache-2.0) AND MPL-2.0', 'REVIEW'],
  ['MPL-2.0 AND GPL-3.0-only', 'DENY'],
  ['MPL-2.0 OR GPL-3.0-only', 'REVIEW'],
  ['BlueOak-1.0.0 AND MIT', 'UNQUALIFIED'],
  ['BlueOak-1.0.0 AND MPL-2.0', 'UNQUALIFIED'],
  ['BlueOak-1.0.0 OR MPL-2.0', 'REVIEW'],
  ['LicenseRef-Unknown', 'DENY'],
  ['DocumentRef-external:LicenseRef-Unknown', 'DENY'],
  ['Apache-2.0 WITH LLVM-exception', 'DENY'],
  ['Apache-2.0 WITH LLVM-exception OR MIT', 'ALLOW'],
]) {
  test(`license policy: ${expression} returns ${expected}`, () => {
    assert.equal(classifyLicense(expression, policy), expected);
  });
}

for (const expression of [
  '',
  ' ',
  'UNLICENSED',
  'NOASSERTION',
  'NONE',
  'UNKNOWN',
  'UNLICENSED OR MIT',
  'MIT OR NOASSERTION',
  'AND MIT',
  'OR MIT',
  'MIT AND',
  'MIT OR',
  'MIT OR OR Apache-2.0',
  'MIT Apache-2.0',
  '()',
  '(MIT',
  'MIT)',
  'MIT ()',
  '(MIT OR)',
  'MIT || Apache-2.0',
  'MIT & Apache-2.0',
  'MIT;Apache-2.0',
  'MIT\nOR Apache-2.0',
  'MIT\0',
  'MIT +',
  'MIT++',
  'MIT+AND Apache-2.0',
  '(MIT) WITH LLVM-exception',
  'MIT WITH',
  'MIT WITH (LLVM-exception)',
  'MIT WITH LLVM-exception WITH Other',
  'MIT WITH LicenseRef-exception',
  'MIT WITH DocumentRef-other:LicenseRef-exception',
  'LicenseRef-example+',
  'https://example.invalid/license',
]) {
  test(`license policy rejects malformed or missing declaration ${JSON.stringify(expression)}`, () => {
    assert.equal(classifyLicense(expression, policy), 'DENY');
  });
}

test('first-party metadata has no exemption from the declared-license policy', () => {
  assert.equal(classifyLicense('UNLICENSED', policy, { firstParty: true }), 'DENY');
  assert.equal(classifyLicense('NOASSERTION', policy, { firstParty: true }), 'DENY');
  assert.equal(classifyLicense('Apache-2.0', policy, { firstParty: true }), 'ALLOW');
  assert.equal(classifyLicense('UNLICENSED', { allowLicenseIdentifiers: ['UNLICENSED'] }), 'DENY');
});

test('a license exception requires the complete license and exception pair in policy', () => {
  const pair = 'Apache-2.0 WITH LLVM-exception';
  assert.equal(
    classifyLicense(pair, { allowLicenseIdentifiers: ['Apache-2.0', 'LLVM-exception'] }),
    'DENY',
  );
  assert.equal(classifyLicense(pair, { allowLicenseIdentifiers: [pair] }), 'ALLOW');
  assert.equal(
    classifyLicense('apache-2.0 WITH llvm-exception', { reviewLicenseIdentifiers: [pair] }),
    'REVIEW',
  );
  assert.equal(
    classifyLicense('GPL-2.0+ WITH Classpath-exception-2.0', {
      allowLicenseIdentifiers: ['GPL-2.0+ WITH Classpath-exception-2.0'],
    }),
    'ALLOW',
  );
  assert.equal(
    classifyLicense('MIT+AND Apache-2.0', { allowLicenseIdentifiers: ['MIT+', 'Apache-2.0'] }),
    'DENY',
  );
});

test('only explicitly requested simple legacy Cargo alternatives are normalized', () => {
  for (const value of ['MIT/Apache-2.0', 'Apache-2.0 / MIT', 'Unlicense/MIT']) {
    assert.equal(classifyLicense(value, policy), 'DENY');
    assert.equal(classifyLicense(value, policy, { legacySlash: true }), 'ALLOW');
    assert.equal(classifyLicense(value, policy, { legacySlash: 'true' }), 'DENY');
  }
  for (const value of ['MIT//Apache-2.0', '(MIT/Apache-2.0)', 'MIT/Apache-2.0 AND GPL-3.0-only']) {
    assert.equal(classifyLicense(value, policy, { legacySlash: true }), 'DENY');
  }
});

test('license input and policy bounds reject invalid values without accepting a partial parse', () => {
  for (const expression of [
    null,
    undefined,
    7,
    {},
    'MIT '.repeat(1025),
    '('.repeat(65) + 'MIT' + ')'.repeat(65),
  ]) {
    assert.equal(classifyLicense(expression, policy), 'DENY');
  }
  assert.equal(classifyLicense('('.repeat(64) + 'MIT' + ')'.repeat(64), policy), 'ALLOW');
  for (const invalid of [
    null,
    { allowLicenseIdentifiers: 'MIT' },
    { allowLicenseIdentifiers: [7] },
  ]) {
    assert.equal(classifyLicense('MIT', invalid), 'DENY');
  }
});

test('inventory distinguishes technical disposition from release eligibility', () => {
  const packages = [{ name: 'example', versions: ['1.0.0'] }];
  const reviewed = classifyInventory({ 'MPL-2.0': packages, 'MIT': packages }, policy);
  assert.equal(reviewed.localTechnicalStatus, 'PASS');
  assert.equal(reviewed.releaseQualification, 'NOT_PROVEN_OPEN');
  assert.deepEqual(reviewed.findings[0].components, ['example@1.0.0']);
  const denied = classifyInventory({ '(MIT OR Apache-2.0) AND GPL-3.0-only': packages }, policy);
  assert.equal(denied.localTechnicalStatus, 'FAIL');
  assert.equal(denied.releaseQualification, 'NOT_PROVEN_OPEN');
  assert.equal(
    classifyInventory({ MIT: packages }, policy).releaseQualification,
    'LOCALLY_LICENSE_ELIGIBLE',
  );
});

test('empty or incomplete inventories cannot establish license eligibility', () => {
  assert.deepEqual(classifyInventory({}, policy), {
    findings: [],
    localTechnicalStatus: 'FAIL',
    releaseQualification: 'NOT_PROVEN_OPEN',
  });
  for (const invalid of [
    null,
    [],
    'MIT',
    { MIT: [] },
    { MIT: [null] },
    { MIT: [{ name: 'example', versions: [] }] },
    { MIT: [{ name: '', versions: ['1.0.0'] }] },
    { MIT: [{ name: 'example', versions: [1] }] },
  ])
    assert.throws(() => classifyInventory(invalid, policy), TypeError);
});
