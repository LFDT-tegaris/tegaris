import { connect } from 'node:net';
import { closeSync, openSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import type { PoolClient } from 'pg';
import { z } from 'zod';

const message = z.strictObject({
  wire: z.array(z.number().int().min(0).max(255)).min(1).max(16384),
  mac: z.array(z.number().int().min(0).max(255)).length(32),
});

/** The SQL verifier owns permission. The client only transports a challenge
 * bound to its actual transaction and the native owner's authenticated reply. */
export async function authorizeRuntimeArtifactRead(client: PoolClient, inputId: string) {
  const result = await client.query<{ challenge: unknown }>(
    'select openpc.runtime_artifact_materialization_challenge($1::uuid) challenge',
    [inputId],
  );
  if (result.rowCount !== 1) throw new Error('runtime source challenge unavailable');
  if (result.rows[0]!.challenge === null) return; // Historical compatibility, never non-use proof.
  const challenge = message.parse(result.rows[0]!.challenge);
  const response = await transportRuntimeArtifactChallenge(challenge);
  await client.query(
    `select set_config('openpc.runtime_source_read_permits',
      (coalesce(nullif(current_setting('openpc.runtime_source_read_permits',true),''),'{}')::jsonb
       || jsonb_build_object($1::text,jsonb_build_object('wire',$2::text,'mac',$3::text)))::text,true)`,
    [
      inputId,
      Buffer.from(response.wire).toString('hex'),
      Buffer.from(response.mac).toString('hex'),
    ],
  );
}

/** The installed private EvidenceCustody login and its SQL owner determine the
 * archive boundary. A generic reader cannot choose an archive purpose. */
export async function authorizeRuntimeArtifactArchiveRead(
  client: PoolClient,
  inputId: string,
  streamId: string,
) {
  const result = await client.query<{ challenge: unknown }>(
    'select openpc.runtime_artifact_archive_challenge($1::uuid,$2::text) challenge',
    [inputId, streamId],
  );
  if (result.rowCount !== 1) throw new Error('runtime archive challenge unavailable');
  const response = await transportRuntimeArtifactChallenge(
    message.parse(result.rows[0]!.challenge),
  );
  await client.query("select set_config('openpc.runtime_source_archive_permit',$1,true)", [
    JSON.stringify({
      wire: Buffer.from(response.wire).toString('hex'),
      mac: Buffer.from(response.mac).toString('hex'),
    }),
  ]);
}

async function transportRuntimeArtifactChallenge(challenge: z.infer<typeof message>) {
  const directory = process.env.OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY;
  if (!directory || !isAbsolute(directory))
    throw new Error('runtime source read endpoint unavailable');
  const document = z
    .object({
      binding: z.object({
        generation_id: z
          .string()
          .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u),
      }),
    })
    .parse(JSON.parse(Buffer.from(challenge.wire).toString('utf8')));
  const request = Buffer.from(JSON.stringify(challenge));
  if (request.length > 65536) throw new Error('runtime source challenge rejected');
  const frame = Buffer.alloc(4 + request.length);
  frame.writeUInt32BE(request.length);
  request.copy(frame, 4);
  const response = await new Promise<z.infer<typeof message>>((resolve, reject) => {
    // Keep the directory open until connect completes. The short Linux FD path
    // also works when the retained installation path exceeds sockaddr_un.
    let directoryFd: number | undefined = openSync(
      join(directory, document.binding.generation_id),
      'r',
    );
    const socket = connect({ path: `/proc/self/fd/${directoryFd}/read.sock` });
    const closeDirectory = () => {
      if (directoryFd !== undefined) {
        closeSync(directoryFd);
        directoryFd = undefined;
      }
    };
    const chunks: Buffer[] = [];
    let length = 0;
    let settled = false;
    const fail = () => {
      if (!settled) {
        settled = true;
        reject(new Error('runtime source read unavailable'));
      }
      socket.destroy();
    };
    const deadline = setTimeout(fail, 3000);
    socket.once('connect', () => {
      closeDirectory();
      socket.write(frame);
    });
    socket.on('data', (chunk: Buffer) => {
      length += chunk.length;
      if (length > 65540) {
        fail();
        return;
      }
      chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      if (bytes.length < 4) return;
      const size = bytes.readUInt32BE(0);
      if (size === 0 || size > 65536 || bytes.length > size + 4) {
        fail();
        return;
      }
      if (bytes.length === size + 4) {
        try {
          const parsed = message.parse(JSON.parse(bytes.subarray(4).toString('utf8')));
          settled = true;
          resolve(parsed);
          socket.destroy();
        } catch {
          fail();
        }
      }
    });
    socket.once('error', fail);
    socket.once('close', () => {
      closeDirectory();
      clearTimeout(deadline);
      if (!settled) fail();
    });
  });
  return response;
}
