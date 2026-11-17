import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readdir, readlink, realpath, rm } from 'node:fs/promises';
import { builtinModules } from 'node:module';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { promisify } from 'node:util';
import { z } from 'zod';
import {
  canonical,
  digest,
} from '../../../services/control-api/src/configuration/operations/notification-qualification-contract.ts';
import { parseStrictJsonBytes } from '../../../services/control-api/src/privacy-explorer/strict-json.ts';

const exec = promisify(execFile);
const maximum = 16777216;
const banner =
  'import { createRequire } from "node:module"; const require = createRequire(import.meta.url);';
const entries = Object.freeze({
  SUBJECT: 'services/control-api/src/local-runtime.ts',
  HARNESS: 'scripts/operations/notification-qualification-harness.mjs',
});
const bad = (reason) => new Error(`NOTIFICATION_BUILD_${reason}`);
const pathSchema = z
  .string()
  .min(1)
  .max(1024)
  .refine(
    (p) =>
      !isAbsolute(p) &&
      !p.includes('\\') &&
      !p.includes('\0') &&
      p.split('/').every((s) => s && s !== '.' && s !== '..'),
  );
const recipeSchema = z.strictObject({
  node: z.literal('24.19.0'),
  pnpm: z.literal('11.20.0'),
  esbuild: z.literal('0.28.2'),
  platform: z.literal('node'),
  format: z.literal('esm'),
  banner: z.literal(banner),
  entry: z.enum([entries.SUBJECT, entries.HARNESS]),
});
const packageSchema = z.strictObject({
  version: z.literal(1),
  kind: z.enum(['SUBJECT', 'HARNESS']),
  recipe: recipeSchema,
  // This is the retained source preimage, not a second package-integrity catalogue.
  // It includes bytes actually consumed plus resolver configuration; pnpm owns integrity.
  files: z
    .array(
      z.strictObject({
        path: pathSchema,
        bytes: z
          .string()
          .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u),
      }),
    )
    .min(1)
    .max(20000),
});
export function notificationBuildRecipe(kind) {
  if (typeof kind !== 'string' || !Object.hasOwn(entries, kind)) throw bad('KIND');
  return {
    node: '24.19.0',
    pnpm: '11.20.0',
    esbuild: '0.28.2',
    platform: 'node',
    format: 'esm',
    banner,
    entry: entries[kind],
  };
}
/** Pure decoding is never a build-verification result. */
export function parseNotificationBuildSource(bytes) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > maximum) throw bad('SIZE');
  const value = packageSchema.parse(parseStrictJsonBytes(bytes, { maximumDepth: 8 }));
  if (
    canonical(value.recipe) !== canonical(notificationBuildRecipe(value.kind)) ||
    canonical(value) !== bytes.toString('utf8')
  )
    throw bad('SOURCE');
  let previous = '';
  for (const file of value.files) {
    if (
      file.path <= previous ||
      Buffer.from(file.bytes, 'base64').toString('base64') !== file.bytes
    )
      throw bad('SOURCE');
    previous = file.path;
  }
  if (
    !value.files.some((f) => f.path === value.recipe.entry) ||
    !value.files.some((f) => f.path === 'pnpm-lock.yaml')
  )
    throw bad('SOURCE');
  return value;
}
async function regular(path, limit = maximum) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > limit) throw bad('FILE');
    const bytes = await file.readFile();
    if (bytes.length > limit) throw bad('SIZE');
    return bytes;
  } finally {
    await file.close();
  }
}
const inside = (root, path) =>
  path === root || (!relative(root, path).startsWith('../') && !isAbsolute(relative(root, path)));
async function command(file, args, cwd, timeout = 120000) {
  // Do not propagate Node loaders/options, package hooks or esbuild overrides.
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    LANG: 'C',
    LC_ALL: 'C',
    COREPACK_ENABLE_NETWORK: '0',
    COREPACK_ENABLE_DOWNLOAD_PROMPT: '0',
    COREPACK_ENABLE_AUTO_PIN: '0',
    GOMAXPROCS: '2',
  };
  try {
    return await exec(file, args, { cwd, env, timeout, killSignal: 'SIGKILL', maxBuffer: 65536 });
  } catch (error) {
    const status =
      typeof error.code === 'number'
        ? String(error.code)
        : error.code === 'ENOENT'
          ? 'MISSING'
          : error.killed
            ? 'LIMIT'
            : 'FAILED';
    throw bad('PROCESS_' + status);
  }
}
async function validateTree(root) {
  let count = 0,
    total = 0;
  async function walk(directory) {
    for (const name of await readdir(directory)) {
      if (++count > 500000) throw bad('TREE_BOUND');
      const path = join(directory, name),
        stat = await lstat(path);
      if (stat.isSymbolicLink()) {
        if (!relative(root, path).split('/').includes('node_modules')) throw bad('LINK');
        const target = await readlink(path);
        if (isAbsolute(target) || !inside(root, resolve(dirname(path), target))) throw bad('LINK');
        // pnpm's installed, relative dependency links are not submitted source entries.
        try {
          if (!inside(root, await realpath(path))) throw bad('LINK');
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
      } else if (stat.isDirectory()) await walk(path);
      else if (stat.isFile()) {
        total += stat.size;
        if (total > 4 * 1024 ** 3) throw bad('TREE_BOUND');
      } else throw bad('FILE');
    }
  }
  await walk(root);
}
const roots = [
  'package.json',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  '.npmrc',
  'tsconfig.base.json',
  'packages',
  'generated',
  'schemas',
  'services/control-api',
  'services/identity-service',
  'services/module-registry',
  'services/participant-service',
  'scripts/operations',
  'tests/integration/identity',
  'tests/integration/local-runtime',
  'node_modules',
];
export function assertNotificationBuildRecipe(docker, rootPackage, servicePackage) {
  if (
    rootPackage.engines?.node !== '24.19.0' ||
    rootPackage.packageManager !== 'pnpm@11.20.0' ||
    servicePackage.devDependencies?.esbuild !== '0.28.2'
  )
    throw bad('RECIPE');
  const recipeLine = [
    'RUN pnpm --filter @openpc/control-api exec esbuild src/local-runtime.ts --bundle --platform=node',
    `    --format=esm --banner:js='${banner}'`,
    '    --outfile=/openpc-control-api-runtime.mjs',
  ].join(' \\' + '\n');
  if (
    !docker.includes(recipeLine) ||
    !docker.includes(
      'COPY --from=build --chown=openpc:openpc /openpc-control-api-runtime.mjs /app/server.mjs',
    )
  )
    throw bad('RECIPE');
}
async function snapshot(repository, target) {
  for (const name of roots) {
    const from = join(repository, name),
      to = join(target, name);
    if ((await lstat(from)).isSymbolicLink()) throw bad('ROOT_LINK');
    await mkdir(dirname(to), { recursive: true, mode: 0o700 });
    await command('/bin/cp', ['-a', '--reflink=auto', '--', from, to], repository);
  }
  await validateTree(target);
  assertNotificationBuildRecipe(
    (await regular(join(target, 'services/control-api/Dockerfile'))).toString('utf8'),
    JSON.parse((await regular(join(target, 'package.json'))).toString('utf8')),
    JSON.parse((await regular(join(target, 'services/control-api/package.json'))).toString('utf8')),
  );

  if (
    !(await regular(join(target, 'pnpm-lock.yaml'))).equals(
      await regular(join(target, 'node_modules/.pnpm/lock.yaml')),
    )
  )
    throw bad('INSTALLED_LOCK');
}
async function bundle(root, kind, output) {
  const recipe = notificationBuildRecipe(kind);
  const compiler = join(root, 'services/control-api/node_modules/esbuild/bin/esbuild');
  if (!inside(root, await realpath(compiler))) throw bad('COMPILER');
  const version = await command(compiler, ['--version'], root, 10000);
  if (version.stdout.trim() !== recipe.esbuild) throw bad('COMPILER');
  const cwd = kind === 'SUBJECT' ? join(root, 'services/control-api') : root;
  const entry = kind === 'SUBJECT' ? 'src/local-runtime.ts' : recipe.entry;
  await command(
    compiler,
    [
      entry,
      '--bundle',
      '--platform=node',
      '--format=esm',
      '--banner:js=' + banner,
      '--outfile=' + output,
      '--metafile=' + output + '.meta',
      '--log-level=error',
    ],
    cwd,
  );
  const meta = JSON.parse((await regular(output + '.meta')).toString('utf8'));
  const builtins = new Set(
    builtinModules.flatMap((m) => [m, m.startsWith('node:') ? m : 'node:' + m]),
  );
  for (const record of [...Object.values(meta.inputs), ...Object.values(meta.outputs)])
    for (const item of record.imports ?? [])
      if (item.external && !builtins.has(item.path)) throw bad('EXTERNAL');
  const names = new Set(
    Object.keys(meta.inputs).map((name) => {
      const path = resolve(cwd, name);
      if (!inside(root, path)) throw bad('INPUT');
      return relative(root, path);
    }),
  );
  for (const name of names) pathSchema.parse(name);
  for (const name of [
    'package.json',
    'pnpm-lock.yaml',
    'pnpm-workspace.yaml',
    '.npmrc',
    'tsconfig.base.json',
    'services/control-api/Dockerfile',
  ])
    names.add(name);
  // Include every resolver package/tsconfig along the consumed paths. Missing
  // files are absent, never replaced by a fabricated configuration.
  for (const name of [...names]) {
    let directory = dirname(join(root, name));
    while (inside(root, directory)) {
      for (const config of ['package.json', 'tsconfig.json', 'jsconfig.json']) {
        const path = join(directory, config);
        try {
          if ((await lstat(path)).isFile()) names.add(relative(root, path));
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
      }
      if (directory === root) break;
      directory = dirname(directory);
    }
  }
  const files = [];
  for (const name of [...names].sort()) {
    const path = join(root, name);
    if (!inside(root, await realpath(path))) throw bad('INPUT');
    files.push({ path: name, bytes: (await regular(path)).toString('base64') });
  }
  const source = Buffer.from(canonical({ version: 1, kind, recipe, files }));
  parseNotificationBuildSource(source);
  return { source, build: await regular(output) };
}
/** Canonical heavy owner only. No caller commands, plugins, network/install or
 * submitted-code execution. Two actual fixed-recipe builds verify the captured
 * consumed closure before a server-origin nonce may be acquired. */
export async function prepareNotificationBuilds({ repositoryRoot, temporaryRoot }) {
  const repository = await realpath(repositoryRoot),
    parent = await realpath(temporaryRoot);
  if (
    repository !== repositoryRoot ||
    parent !== temporaryRoot ||
    inside(repository, parent) ||
    process.version !== 'v24.19.0'
  )
    throw bad('ROOT');
  // run-bounded validates the real inherited lock, cgroup, live margin and disk.
  // These inherited variables are used only by that owner, never as proof here.
  try {
    await exec(
      '/bin/bash',
      [
        join(repository, 'scripts/maintenance/run-bounded.sh'),
        '--reuse',
        '--memory-gib',
        '2',
        '--external-memory-gib',
        '0',
        '--peak-disk-gib',
        '10',
        '--',
        'true',
      ],
      { cwd: repository, timeout: 15000, maxBuffer: 65536 },
    );
  } catch {
    throw bad('ADMISSION');
  }
  const node = await command(process.execPath, ['--version'], repository, 10000);
  const pnpmPath = await realpath(join(dirname(process.execPath), 'pnpm'));
  const pnpm = await command(pnpmPath, ['--version'], repository, 15000);
  if (node.stdout.trim() !== 'v24.19.0' || pnpm.stdout.trim() !== '11.20.0') throw bad('TOOLCHAIN');
  // Use pnpm's existing integrity owner; never invent another registry catalogue.
  await command(
    pnpmPath,
    ['--offline', '--ignore-scripts', '--ignore-pnpmfile', 'store', 'status'],
    repository,
  );
  const work = await mkdtemp(join(parent, 'notification-build-'));
  try {
    const tree = join(work, 'tree');
    await mkdir(tree, { mode: 0o700 });
    await snapshot(repository, tree);
    const outputs = [];
    for (const kind of ['SUBJECT', 'HARNESS']) {
      const first = await bundle(tree, kind, join(work, kind + '-first.mjs'));
      const second = await bundle(tree, kind, join(work, kind + '-second.mjs'));
      if (!first.source.equals(second.source) || !first.build.equals(second.build))
        throw bad('UNSTABLE');
      outputs.push({
        kind,
        source: first.source,
        build: first.build,
        sourceDigest: digest(first.source),
        buildDigest: digest(first.build),
      });
    }
    return outputs;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
