import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseStrictJsonBytes } from '../../services/control-api/src/privacy-explorer/strict-json.ts';

export class InstallationConfigError extends Error {
  constructor(reason, code = 'OPS_CONFIG_INVALID') {
    super(`${code}: ${reason}`);
    this.name = 'InstallationConfigError';
    this.code = code;
    this.reason = reason;
  }
}

export const invalid = (reason) => {
  throw new InstallationConfigError(reason);
};

export const environmentTargets = Object.freeze({
  OPENPC_ENVIRONMENT_ID: ['environmentId'],
  OPENPC_PUBLIC_BASE_URL: ['publicBaseUrl'],
  OPENPC_OTLP_ENDPOINT: ['telemetry', 'otlpEndpoint'],
  OPENPC_CONTROL_DSN_REF: ['postgres', 'controlDsnSecretRef'],
  OPENPC_FACTS_DSN_REF: ['postgres', 'factsDsnSecretRef'],
  OPENPC_CANDIDATE_INDEX_DSN_REF: ['postgres', 'candidateIndexDsnSecretRef'],
  OPENPC_OIDC_CLIENT_SECRET_REF: ['identity', 'clientSecretRef'],
  OPENPC_TRUST_BUNDLE_REF: ['pki', 'trustBundleSecretRef'],
  OPENPC_SIGNING_KEY_REF: ['pki', 'signingKeySecretRef'],
});
for (const target of Object.values(environmentTargets)) Object.freeze(target);

export function assertUnicode(value) {
  if (typeof value === 'string') {
    if (
      !value.isWellFormed() ||
      value.normalize('NFC') !== value ||
      [...value].some(
        (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
      )
    )
      invalid('INVALID_UNICODE');
  } else if (Array.isArray(value)) {
    for (const item of value) assertUnicode(item);
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      assertUnicode(key);
      assertUnicode(item);
    }
  }
}

export function parseConfigurationJson(bytes, maximumBytes = 131072) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > maximumBytes)
    invalid('INPUT_SIZE');
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) invalid('JSON_BOM');
  let value;
  try {
    value = parseStrictJsonBytes(bytes, { maximumDepth: 16 });
  } catch {
    invalid('MALFORMED_JSON');
  }
  assertUnicode(value);
  if (value === null || Array.isArray(value) || typeof value !== 'object')
    invalid('OBJECT_REQUIRED');
  return value;
}

export async function readConfigurationBytes(path, maximumBytes = 131072) {
  if (typeof path !== 'string' || !isAbsolute(path) || path.length > 4096) invalid('INPUT_PATH');
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await file.stat();
    if (!stat.isFile() || stat.size === 0 || stat.size > maximumBytes) invalid('INPUT_SIZE');
    // Bound the read as well as stat: a concurrently extended file cannot allocate without limit.
    const bytes = Buffer.alloc(maximumBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await file.read(bytes, length, bytes.length - length, null);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length === 0 || length > maximumBytes) invalid('INPUT_SIZE');
    return bytes.subarray(0, length);
  } catch (error) {
    if (error instanceof InstallationConfigError) throw error;
    invalid('INPUT_UNAVAILABLE');
  } finally {
    await file?.close();
  }
}

// The five packaged profiles use block maps and single-line flow collections.
// Accept only that closed syntax, never YAML tags, aliases, merges or implicit types.
// Operator/site documents use the shared strict JSON owner above.
function profileFlow(source) {
  let offset = 0;
  const whitespace = () => {
    while (source[offset] === ' ') offset += 1;
  };
  const scalar = () => {
    whitespace();
    if (source[offset] === '"') {
      const start = offset++;
      while (offset < source.length) {
        if (source[offset++] === '"') {
          try {
            return JSON.parse(source.slice(start, offset));
          } catch {
            invalid('PROFILE_SYNTAX');
          }
        }
        if (source[offset - 1] === '\\') offset += 1;
      }
      invalid('PROFILE_SYNTAX');
    }
    const start = offset;
    while (offset < source.length && !',]}'.includes(source[offset])) offset += 1;
    const text = source.slice(start, offset).trim();
    if (!/^[A-Za-z0-9_./-]+$/u.test(text)) invalid('PROFILE_SYNTAX');
    if (text === 'true') return true;
    if (text === 'false') return false;
    return text;
  };
  const value = (depth = 0) => {
    if (depth > 8) invalid('PROFILE_DEPTH');
    whitespace();
    const opener = source[offset];
    if (opener !== '{' && opener !== '[') return scalar();
    offset += 1;
    const result = opener === '{' ? {} : [];
    const closer = opener === '{' ? '}' : ']';
    whitespace();
    if (source[offset] === closer) {
      offset += 1;
      return result;
    }
    while (offset < source.length) {
      whitespace();
      if (opener === '{') {
        const key = /^[A-Za-z][A-Za-z0-9_.-]*:(?= )/u.exec(source.slice(offset));
        if (!key) invalid('PROFILE_SYNTAX');
        offset += key[0].length;
        const name = key[0].slice(0, -1);
        if (['__proto__', 'constructor', 'prototype'].includes(name) || Object.hasOwn(result, name))
          invalid('PROFILE_DUPLICATE');
        result[name] = value(depth + 1);
      } else result.push(value(depth + 1));
      whitespace();
      if (source[offset++] === closer) return result;
      if (source[offset - 1] !== ',') invalid('PROFILE_SYNTAX');
    }
    invalid('PROFILE_SYNTAX');
  };
  const result = value();
  whitespace();
  if (offset !== source.length) invalid('PROFILE_SYNTAX');
  return result;
}

export function parseNamedProfile(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 65536)
    invalid('PROFILE_SIZE');
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    invalid('PROFILE_ENCODING');
  }
  const root = {};
  let child;
  for (const line of source.split('\n')) {
    if (line === '') continue;
    const match = /^( {0}| {2})([A-Za-z][A-Za-z0-9_.-]*):(?: (.+))?$/u.exec(line);
    if (!match) invalid('PROFILE_SYNTAX');
    const [, indent, key, text] = match;
    const target = indent === '' ? root : child;
    if (!target || ['constructor', 'prototype'].includes(key) || Object.hasOwn(target, key))
      invalid('PROFILE_DUPLICATE');
    if (text === undefined) {
      if (indent !== '') invalid('PROFILE_SYNTAX');
      child = {};
      target[key] = child;
    } else {
      target[key] = profileFlow(text);
      if (indent === '') child = undefined;
    }
  }
  assertUnicode(root);
  return root;
}

export function readEnvironment(environment) {
  if (!environment || typeof environment !== 'object' || Array.isArray(environment))
    invalid('ENVIRONMENT_REQUIRED');
  const result = {};
  for (const [name, value] of Object.entries(environment)) {
    if (!name.toUpperCase().startsWith('OPENPC_')) continue;
    if (!Object.hasOwn(environmentTargets, name) || typeof value !== 'string' || value === '')
      invalid('UNDECLARED_ENVIRONMENT');
    assertUnicode(value);
    const path = environmentTargets[name];
    if (path.length === 1) result[path[0]] = value;
    else (result[path[0]] ??= {})[path[1]] = value;
  }
  return result;
}

export async function loadInstallationSources({ c17Root, profile, sitePath, environment }) {
  if (!['local', 'development', 'test', 'staging', 'production'].includes(profile))
    invalid('UNKNOWN_PROFILE');
  if (c17Root !== undefined && (typeof c17Root !== 'string' || !isAbsolute(c17Root)))
    invalid('C17_INPUT_BINDING_MISSING');
  // Packaged inputs preserve the original archive bytes. Their presence alone
  // grants no archive, site, generation or deployment qualification.
  const installed = fileURLToPath(new URL('../../config/', import.meta.url));
  const operations =
    c17Root === undefined ? installed : join(c17Root, 'SPECIFICATIONS', 'OPERATIONS');
  const [schemaBytes, profileBytes, siteBytes] = await Promise.all([
    readConfigurationBytes(
      c17Root === undefined
        ? join(installed, 'schema', 'effective-configuration.schema.json')
        : join(operations, 'configuration.schema.json'),
    ),
    readConfigurationBytes(join(operations, 'profiles', `${profile}.yaml`), 65536),
    readConfigurationBytes(sitePath),
  ]);
  return {
    schema: parseConfigurationJson(schemaBytes),
    namedProfile: parseNamedProfile(profileBytes),
    site: parseConfigurationJson(siteBytes),
    environment: readEnvironment(environment),
    profile,
    // These digests are input identity, not archive/signature/qualification verification.
    schemaBytes,
    profileBytes,
    siteBytes,
  };
}
