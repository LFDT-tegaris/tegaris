import assert from 'node:assert/strict';
import test from 'node:test';
import {
  localQaIssuer,
  qaPublicOrigin,
  qaPublicServices,
  qaIssuerFromCompose,
} from './qa-public-origin.mjs';

test('public demo identity settings share one HTTPS origin and retain duration settings', () => {
  const original = { 'identity-service': { mem_limit: '512m', environment: { TTL: '10' } } };
  const services = qaPublicServices('https://demo.example', original);
  assert.equal(services['identity-service'].mem_limit, '512m');
  assert.equal(services['identity-service'].environment.TTL, '10');
  assert.equal(qaIssuerFromCompose({ services }), 'https://demo.example');
  assert.deepEqual(original, {
    'identity-service': { mem_limit: '512m', environment: { TTL: '10' } },
  });
  assert.equal(qaPublicOrigin(undefined), undefined);
  assert.equal(qaIssuerFromCompose({ services: {} }), localQaIssuer);
});

test('public demo identity rejects ambiguous origins and inconsistent saved bindings', () => {
  for (const value of [
    '',
    'http://demo.example',
    'https://demo.example/',
    'https://demo.example/path',
    'https://user:pass@demo.example',
    'https://demo.example?x=1',
    'https://demo.example#x',
    'https://demo.example:443',
  ]) {
    assert.throws(() => qaPublicOrigin(value));
  }
  for (const service of ['identity-service', 'admin-web', 'oidc-emulator']) {
    const services = qaPublicServices('https://demo.example');
    const key = Object.keys(services[service].environment).at(-1);
    services[service].environment[key] = 'https://other.example';
    assert.throws(() => qaIssuerFromCompose({ services }));
  }
  const incomplete = qaPublicServices('https://demo.example');
  delete incomplete['oidc-emulator'].environment.OIDC_EMULATOR_ISSUER;
  assert.throws(() => qaIssuerFromCompose({ services: incomplete }));
});
