import { expect, it } from 'vitest';
import { createHttpQualificationSigningProvider } from './http-qualification-signing-provider.js';
import { QualificationSigningUnknown } from './qualification-signing-provider.js';
import type { QualificationKeyInstallation } from './qualification-key-provider.js';
it('rejects caller-selected generic capability and v1 subject-only trust before transport allocation', () => {
  for (const trust of [
    null,
    { schemaVersion: 1 },
    { schemaVersion: 2, purpose: 'SIGN_ANY', nonExportable: true },
    { providerOrigin: 'https://untrusted.example', ready: true },
  ])
    expect(() =>
      createHttpQualificationSigningProvider({
        trust: trust as unknown as QualificationKeyInstallation,
        certificate: Buffer.alloc(0),
        privateKey: Buffer.alloc(0),
        trustCa: Buffer.alloc(0),
      }),
    ).toThrow(QualificationSigningUnknown);
});

it('constructs with independent B only and rejects A, copied certificates and mismatched private keys without network I/O', async () => {
  const { runtimeSnapshotTlsFixture } =
    await import('../../../../tests/integration/identity/runtime-snapshot-tls-fixture.js');
  const { qualificationSigningWireFixture } =
    await import('../../../../tests/integration/local-runtime/qualification-signing-cases.js');
  const { qualificationDigest: hash } =
    await import('../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js');
  const f = qualificationSigningWireFixture();
  const a = await runtimeSnapshotTlsFixture(
    `urn:openpc:participant:${f.trust.participantId}:workload:subject`,
  );
  let b: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>> | undefined;
  try {
    b = await runtimeSnapshotTlsFixture(
      `urn:openpc:participant:${f.trust.participantId}:workload:observer`,
    );
    const bound = (actor: typeof a, peer: typeof f.trust.peer) => ({
      ...peer,
      keyDigest: hash(actor.parsed.publicKey.export({ type: 'spki', format: 'der' })),
      certificateDigest: hash(actor.parsed.raw),
    });
    const trust = {
      ...f.trust,
      peer: bound(a, f.trust.peer),
      observer: bound(b, f.trust.observer),
    };
    const config = {
      trust,
      certificate: b.certificate,
      privateKey: b.privateKey,
      trustCa: a.server.ca,
    };
    const transport = createHttpQualificationSigningProvider(config);
    transport.close();
    transport.close();
    for (const patch of [
      { certificate: a.certificate, privateKey: a.privateKey },
      { certificate: a.certificate },
      { privateKey: a.privateKey },
      {
        trust: {
          ...trust,
          observer: { ...trust.observer, certificateDigest: trust.peer.certificateDigest },
        },
      },
    ])
      expect(() => createHttpQualificationSigningProvider({ ...config, ...patch })).toThrow(
        QualificationSigningUnknown,
      );
  } finally {
    await a.close();
    await b?.close();
  }
});
