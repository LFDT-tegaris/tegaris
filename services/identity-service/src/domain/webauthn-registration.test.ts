import { createHash } from 'node:crypto';
import { createServer } from 'node:http';

import { chromium } from '@playwright/test';
import { afterEach, expect, it } from 'vitest';

import { localWebAuthnRegistrationAdapter } from './webauthn-registration.js';

const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => (error === undefined ? resolve() : reject(error))),
          ),
      ),
  );
});

it('verifies a real Chromium virtual-authenticator registration response', async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end('<!doctype html><title>OpenPC WebAuthn verifier</title>');
  });
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (address === null || typeof address === 'string')
    throw new Error('test server address missing');
  const origin = `http://localhost:${address.port}`;
  const challenge = 'initial-registration-challenge-000000000000000001';
  const options = await localWebAuthnRegistrationAdapter.options({
    challenge,
    rpId: 'localhost',
    principalId: '018f0000-0000-7000-8000-000000000111',
    displayLabel: 'Local operator',
    excludedCredentialIds: [],
  });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        ctap2Version: 'ctap2_1',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
      },
    });
    await page.goto(origin);
    const registration = await page.evaluate(async (source) => {
      const decode = (value: string) => {
        const base64 = value
          .replaceAll('-', '+')
          .replaceAll('_', '/')
          .padEnd(Math.ceil(value.length / 4) * 4, '=');
        return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
      };
      const encode = (value: ArrayBuffer) => {
        const bytes = new Uint8Array(value);
        let binary = '';
        for (const byte of bytes) binary += String.fromCharCode(byte);
        return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
      };
      const publicKey = source as PublicKeyCredentialCreationOptions;
      publicKey.challenge = decode(String(publicKey.challenge));
      publicKey.user.id = decode(String(publicKey.user.id));
      const created = await navigator.credentials.create({ publicKey });
      if (!(created instanceof PublicKeyCredential)) throw new Error('credential creation failed');
      if (!(created.response instanceof AuthenticatorAttestationResponse)) {
        throw new Error('attestation response required');
      }
      return {
        id: created.id,
        rawId: encode(created.rawId),
        type: created.type,
        response: {
          attestationObject: encode(created.response.attestationObject),
          clientDataJSON: encode(created.response.clientDataJSON),
          transports: created.response.getTransports(),
        },
        clientExtensionResults: created.getClientExtensionResults(),
        authenticatorAttachment: created.authenticatorAttachment,
      };
    }, options);

    await expect(
      localWebAuthnRegistrationAdapter.verify({
        response: registration,
        expectedChallengeDigest: createHash('sha256').update(challenge).digest(),
        expectedOrigin: origin,
        expectedRpId: 'localhost',
      }),
    ).resolves.toMatchObject({
      externalCredentialId: registration.id,
      signCount: expect.stringMatching(/^\d+$/u),
    });
    await cdp.detach();
    await context.close();
  } finally {
    await browser.close();
  }
}, 30_000);
