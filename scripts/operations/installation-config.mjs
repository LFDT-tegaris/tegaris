import { pathToFileURL } from 'node:url';
import manifest from '../../package.json' with { type: 'json' };
import {
  InstallationConfigError,
  invalid,
  loadInstallationSources,
} from './installation-config-inputs.mjs';
import { prepareInstallationCandidate } from './installation-config-validation.mjs';

export {
  materializeInstallationCandidate,
  renderInstallationCandidate,
} from './installation-config-materialize.mjs';
export { prepareInstallationCandidate } from './installation-config-validation.mjs';

export function parseInstallationArguments(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (
      !['--config', '--profile', '--check-config', '--print-effective-digest'].includes(argument) ||
      Object.hasOwn(options, argument)
    )
      invalid('INSTALLER_ARGUMENT');
    if (argument === '--config' || argument === '--profile') {
      const value = args[++index];
      if (!value || value.startsWith('--')) invalid('INSTALLER_ARGUMENT');
      options[argument] = value;
    } else options[argument] = true;
  }
  if (
    !options['--config'] ||
    !options['--profile'] ||
    (!options['--check-config'] && !options['--print-effective-digest'])
  )
    invalid('INSTALLER_ARGUMENT');
  return options;
}

/**
 * Uses shipped schema and profile inputs; the qualification owner may supply the
 * external archive location through code. Neither input grants trust or accepts trust booleans.
 * Until canonical verification/consumer owners are connected, this entrypoint exits nonzero.
 */
export async function checkInstallationConfig(args, { c17Root, environment = process.env } = {}) {
  if (process.versions.node !== manifest.engines.node) invalid('TOOLCHAIN_MISMATCH');
  const options = parseInstallationArguments(args);
  const sources = await loadInstallationSources({
    c17Root,
    environment,
    profile: options['--profile'],
    sitePath: options['--config'],
  });
  const candidate = prepareInstallationCandidate(sources);
  return {
    exitCode: 2,
    result: {
      state: 'BLOCKED',
      startupAllowed: false,
      blockers: candidate.blockers,
      // No effective digest exists before signed generation admission and owner effectiveness.
      ...(options['--print-effective-digest'] ? { effectiveDigest: null } : {}),
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { exitCode, result } = await checkInstallationConfig(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = exitCode;
  } catch (error) {
    const safe =
      error instanceof InstallationConfigError
        ? error
        : new InstallationConfigError('INPUT_UNAVAILABLE');
    process.stderr.write(`${JSON.stringify({ code: safe.code, reason: safe.reason })}\n`);
    process.exitCode = 2;
  }
}
