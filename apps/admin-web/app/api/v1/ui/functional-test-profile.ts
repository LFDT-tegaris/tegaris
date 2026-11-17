import { createHash, createPrivateKey, sign } from 'node:crypto';
import { open, readFile, unlink } from 'node:fs/promises';
import { z } from 'zod';

const absolutePath = z.string().startsWith('/').min(2);
const actorSchema = z.strictObject({
  sessionToken: z.string().regex(/^[0-9a-f-]{36}\.[0-9a-f-]{36}$/u),
  platformSessionToken: z
    .string()
    .regex(/^[0-9a-f-]{36}\.[0-9a-f-]{36}$/u)
    .optional(),
  principalId: z.uuid(),
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  credentialId: z.uuid(),
  assertionCredentialId: z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/u)
    .min(1)
    .max(1024),
  privateKeyFile: absolutePath,
  counterFile: absolutePath,
});
export const functionalTestProfileSchema = z
  .strictObject({
    version: z.literal(1),
    actors: z.strictObject({ operator: actorSchema, viewer: actorSchema }),
  })
  .refine(
    ({ actors }) =>
      actors.operator.principalId !== actors.viewer.principalId &&
      actors.operator.credentialId !== actors.viewer.credentialId &&
      actors.operator.counterFile !== actors.viewer.counterFile &&
      actors.operator.participantId === actors.viewer.participantId &&
      actors.operator.privacyDomainId === actors.viewer.privacyDomainId &&
      (actors.operator.platformSessionToken === undefined) ===
        (actors.viewer.platformSessionToken === undefined) &&
      (actors.operator.platformSessionToken === undefined ||
        new Set([
          actors.operator.sessionToken,
          actors.viewer.sessionToken,
          actors.operator.platformSessionToken,
          actors.viewer.platformSessionToken,
        ]).size === 4),
  );
export type FunctionalTestProfile = z.infer<typeof functionalTestProfileSchema>;
export const functionalActorCookie = 'openpc_functional_actor';
export const functionalContextCookie = 'openpc_functional_context';

export function functionalContext(value: string | undefined) {
  return value === undefined || value === 'PARTICIPANT'
    ? 'PARTICIPANT'
    : value === 'PLATFORM'
      ? 'PLATFORM'
      : undefined;
}

export async function readFunctionalTestProfile(
  environment: Readonly<Record<string, string | undefined>>,
) {
  const mode = environment.OPENPC_FUNCTIONAL_TEST;
  if (mode === undefined || mode === '0') return undefined;
  if (
    mode !== '1' ||
    environment.OPENPC_LOCAL_RUNTIME !== '1' ||
    environment.OPENPC_LOCAL_RUNTIME_QA_FIXTURE !== '1' ||
    !absolutePath.safeParse(environment.OPENPC_FUNCTIONAL_TEST_PROFILE_FILE).success
  )
    throw new Error('Functional testing requires an explicit local QA installation.');
  return functionalTestProfileSchema.parse(
    JSON.parse(await readFile(environment.OPENPC_FUNCTIONAL_TEST_PROFILE_FILE!, 'utf8')),
  );
}

export function functionalActor(value: string | undefined): 'operator' | 'viewer' | undefined {
  return value === undefined || value === 'operator'
    ? 'operator'
    : value === 'viewer'
      ? 'viewer'
      : undefined;
}

/** Synthetic QA authenticator only. Reserve its durable counter before signing;
 * keep the lock through native verification so concurrent assertions cannot reorder. */
export async function withFunctionalAssertion<T>(
  actor: FunctionalTestProfile['actors']['operator'],
  input: { readonly challenge: string; readonly origin: string },
  verify: (assertion: {
    credentialId: string;
    authenticatorData: string;
    clientDataJson: string;
    signature: string;
  }) => Promise<T>,
): Promise<T> {
  const lockPath = `${actor.counterFile}.lock`;
  const lock = await open(lockPath, 'wx', 0o600);
  try {
    const counter = (await readFile(actor.counterFile, 'utf8')).trim();
    if (!/^(?:0|[1-9][0-9]*)$/u.test(counter)) throw new Error('Invalid test counter.');
    const next = BigInt(counter) + 1n;
    if (next > 0xffff_ffffn) throw new Error('Test counter exhausted.');
    const key = createPrivateKey({
      key: await readFile(actor.privateKeyFile),
      format: 'der',
      type: 'pkcs8',
    });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
      throw new Error('Unsupported test authenticator.');
    const clientData = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: input.challenge,
        origin: input.origin,
        crossOrigin: false,
      }),
    );
    const authenticatorData = Buffer.alloc(37);
    createHash('sha256').update(new URL(input.origin).hostname).digest().copy(authenticatorData);
    authenticatorData[32] = 0x05;
    authenticatorData.writeUInt32BE(Number(next), 33);
    const counterHandle = await open(actor.counterFile, 'r+');
    try {
      await counterHandle.write(`${next}\n`, 0, 'utf8');
      await counterHandle.truncate(Buffer.byteLength(`${next}\n`));
      await counterHandle.sync();
    } finally {
      await counterHandle.close();
    }
    return await verify({
      credentialId: z.uuid().safeParse(actor.assertionCredentialId).success
        ? Buffer.from(actor.assertionCredentialId, 'utf8').toString('base64url')
        : actor.assertionCredentialId,
      authenticatorData: authenticatorData.toString('base64url'),
      clientDataJson: clientData.toString('base64url'),
      signature: sign(
        'sha256',
        Buffer.concat([authenticatorData, createHash('sha256').update(clientData).digest()]),
        key,
      ).toString('base64url'),
    });
  } finally {
    await lock.close();
    await unlink(lockPath);
  }
}
