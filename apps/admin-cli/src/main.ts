import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import {
  AdministrationClient,
  apiOrigin,
  CliError,
  configSchema,
  resources,
  sessionFileSchema,
  type ResourceKind,
} from './client.js';
import { readJson } from './files.js';
import type { BrowserRuntime } from './browser-session.js';

export async function run(
  args: string[],
  write: (value: unknown) => void,
  browserRuntime?: BrowserRuntime,
): Promise<number> {
  if (args.length === 1 && args[0] === '--help') {
    write({
      usage: 'openpc --config FILE session | RESOURCE ID [--wait-seconds N]',
      resources: Object.keys(resources),
      wait: 'Operation and browser result support polling, up to 300 seconds. Pending exits 6; no command is resubmitted.',
      authentication:
        'Configure browserProfile for browser-assisted OIDC login, explicit context and WebAuthn. Existing sessionFile profiles support readback only.',
      browserCommands: [
        'login',
        'session',
        'read KIND RESOURCE_UUID',
        'refresh',
        'logout',
        'transaction KIND --input FILE --request-key UUID',
        'review APPROVAL_UUID',
        'approve APPROVAL_UUID',
        'execute REQUEST_UUID',
        'result APPROVAL_UUID [--wait-seconds N]',
      ],
    });
    return 0;
  }
  if (args[0] !== '--config' || !args[1] || !args[2]) throw new CliError('INPUT');
  const callerDirectory = process.env.OPENPC_CLI_CWD ?? process.cwd();
  const configPath = resolve(callerDirectory, args[1]);
  const parsed = configSchema.safeParse(await readJson(configPath, false));
  if (!parsed.success) throw new CliError('INPUT');
  const config = parsed.data;
  if (config.browserProfile) {
    const { runBrowser } = await import('./browser-commands.js');
    const browserArgs = args.slice(2);
    if (browserArgs[0] === 'transaction' && browserArgs[2] === '--input' && browserArgs[3])
      browserArgs[3] = resolve(callerDirectory, browserArgs[3]);
    return runBrowser(
      browserArgs,
      config,
      resolve(dirname(configPath), config.browserProfile),
      write,
      browserRuntime,
    );
  }
  if (!config.sessionFile) throw new CliError('INPUT');
  const secret = sessionFileSchema.safeParse(
    await readJson(resolve(dirname(configPath), config.sessionFile), true),
  );
  if (!secret.success || secret.data.origin !== apiOrigin(config))
    throw new CliError('AUTHENTICATION');
  const client = new AdministrationClient(config, secret.data.sessionToken);
  if (args[2] === 'session' && args.length === 3) {
    write(await client.session());
    return 0;
  }
  if (!Object.hasOwn(resources, args[2]) || !args[3]) throw new CliError('INPUT');
  const kind = args[2] as ResourceKind;
  let seconds = 0;
  if (
    args.length === 6 &&
    kind === 'operation' &&
    args[4] === '--wait-seconds' &&
    /^\d{1,3}$/u.test(args[5]!)
  ) {
    seconds = Number(args[5]);
    if (seconds > 300) throw new CliError('INPUT');
  } else if (args.length !== 4) throw new CliError('INPUT');
  const deadline = Date.now() + seconds * 1000;
  while (true) {
    const result = await client.read(kind, args[3]);
    if (kind !== 'operation' || !seconds) {
      write(result);
      return 0;
    }
    const state = 'state' in result ? result.state : undefined;
    if (state === 'SUCCEEDED' || state === 'FAILED') {
      write(result);
      return state === 'SUCCEEDED' ? 0 : 4;
    }
    if (Date.now() >= deadline) {
      write(result);
      return 6;
    }
    await delay(Math.min(1000, deadline - Date.now()));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  run(process.argv.slice(2), (value) => process.stdout.write(`${JSON.stringify(value)}\n`))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      const code = error instanceof CliError ? error.code : 'RESPONSE';
      process.stderr.write(
        `${JSON.stringify({ error: code, ...(error instanceof CliError && error.problem ? { problem: error.problem } : {}) })}\n`,
      );
      process.exitCode =
        code === 'INPUT' ? 2 : ['AUTHENTICATION', 'CONTEXT', 'DENIED'].includes(code) ? 3 : 4;
    });
}
