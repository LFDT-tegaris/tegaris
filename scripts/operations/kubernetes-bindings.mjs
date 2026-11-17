import { createRequire } from 'node:module';
import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';
import { parseStrictJsonBytes } from '../../services/control-api/src/privacy-explorer/strict-json.ts';

// Vite already declares this exact locked peer. Do not load Vite or introduce a
// second YAML parser/version just for the offline packaging tool.
const require = createRequire(import.meta.url);
const yamlRequire = createRequire(require.resolve('vite/package.json'));
const yaml = yamlRequire('yaml');
export const yamlVersion = yamlRequire('yaml/package.json').version;
if (yamlVersion !== '2.9.0') throw new Error('OPS_KUBERNETES: YAML_TOOLCHAIN');

export { canonicalJson, sha256 };
export const templateNames = Object.freeze([
  'openpc-core.template.yaml',
  'otel-configmap.template.yaml',
  'protected-target.pod-template.yaml',
  'postgresql-and-valkey.template.yaml',
]);

export class KubernetesMaterializationError extends Error {
  constructor(reason) {
    super(`OPS_KUBERNETES: ${reason}`);
    this.name = 'KubernetesMaterializationError';
    this.reason = reason;
  }
}
export function invalid(reason) {
  throw new KubernetesMaterializationError(reason);
}

export function parseInput(bytes, maximumBytes = 2 ** 20) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > maximumBytes)
    invalid('INPUT_SIZE');
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) invalid('INPUT_BOM');
  try {
    const value = parseStrictJsonBytes(bytes, { maximumDepth: 24 });
    if (value === null || typeof value !== 'object' || Array.isArray(value))
      invalid('INPUT_OBJECT');
    return value;
  } catch (error) {
    if (error instanceof KubernetesMaterializationError) throw error;
    invalid('INPUT_JSON');
  }
}

export function utf8(bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 2 ** 20)
    invalid('TEMPLATE_SIZE');
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    invalid('TEMPLATE_ENCODING');
  }
  if (source.includes('\r') || source.includes('\0') || source.startsWith('\uFEFF'))
    invalid('TEMPLATE_ENCODING');
  return source;
}

/** No aliases, tags, merges, duplicate/complex keys or implicit YAML 1.1 types. */
export function parseYaml(source) {
  if (typeof source !== 'string' || Buffer.byteLength(source) > 2 ** 20) invalid('YAML_SIZE');
  const document = yaml.parseDocument(source, {
    version: '1.2',
    schema: 'core',
    strict: true,
    uniqueKeys: true,
    prettyErrors: false,
    merge: false,
  });
  if (document.errors.length || document.warnings.length) invalid('YAML_SYNTAX');
  let nodes = 0;
  function inspect(node, depth = 0) {
    if (++nodes > 50000 || depth > 40) invalid('YAML_LIMIT');
    if (!node) return;
    if (yaml.isAlias(node) || node.anchor || node.tag) invalid('YAML_INDIRECTION');
    if (yaml.isMap(node)) {
      for (const { key, value } of node.items) {
        if (
          !yaml.isScalar(key) ||
          typeof key.value !== 'string' ||
          ['__proto__', 'constructor', 'prototype', '<<'].includes(key.value)
        )
          invalid('YAML_KEY');
        inspect(key, depth + 1);
        inspect(value, depth + 1);
      }
    } else if (yaml.isSeq(node)) {
      for (const item of node.items) inspect(item, depth + 1);
    } else if (yaml.isScalar(node)) {
      if (typeof node.value === 'number' && !Number.isSafeInteger(node.value))
        invalid('YAML_NUMBER');
    } else invalid('YAML_NODE');
  }
  inspect(document.contents);
  return document.toJS({ maxAliasCount: 0 });
}

/** Sorted maps and explicit string scalars give stable bytes and no implicit typing. */
export function encodeYaml(value) {
  const document = new yaml.Document(JSON.parse(canonicalJson(value)));
  yaml.visit(document, {
    Scalar(_key, node) {
      if (typeof node.value === 'string')
        node.type = node.value.includes('\n') ? 'BLOCK_LITERAL' : 'QUOTE_DOUBLE';
    },
  });
  return document.toString({ lineWidth: 0, indent: 2 });
}

export function pointerValue(input, pointer, target) {
  if (typeof pointer !== 'string' || !/^(?:@)?\//u.test(pointer)) invalid('BINDING_POINTER');
  const local = pointer.startsWith('@');
  let value = local ? target : input;
  for (const encoded of pointer.slice(local ? 2 : 1).split('/')) {
    if (/~(?![01])/u.test(encoded)) invalid('BINDING_POINTER');
    const name = encoded.replace(/~1/gu, '/').replace(/~0/gu, '~');
    if (!value || typeof value !== 'object' || !Object.hasOwn(value, name))
      invalid('BINDING_POINTER');
    value = value[name];
  }
  return value;
}

export function expandBindings(rules) {
  const table = new Map();
  function add(token, binding) {
    if (!/^OPENPC_INPUT_[A-Z0-9_]+$/u.test(token) || table.has(token)) invalid('BINDING_AMBIGUOUS');
    table.set(token, binding);
  }
  for (const [token, binding] of Object.entries(rules.direct)) add(token, binding);
  for (const family of rules.families) {
    const pattern = new RegExp(family.pattern, 'u');
    const entries = family.symbolPointers
      ? Object.entries(family.symbolPointers).map(([symbol, pointer]) => [
          `OPENPC_INPUT_IMAGES_${symbol}`,
          pointer,
        ])
      : Object.entries(
          family.symbolBasePointers ?? { PROTECTED_TARGET: family.basePointer },
        ).flatMap(([symbol, base]) =>
          Object.entries(family.fieldSuffixPointers).map(([field, suffix]) => [
            `OPENPC_INPUT_RESOURCES_${symbol}_${field}`,
            `${base}${suffix}`,
          ]),
        );
    for (const [token, pointer] of entries) {
      if (!pattern.test(token)) invalid('BINDING_FAMILY');
      add(token, { pointer, serialization: family.serialization });
    }
  }
  // A direct binding must not also match a family, including one whose enumerated
  // symbol map omitted that token. Regex overlap is never resolved by precedence.
  for (const token of table.keys()) {
    const matches =
      Number(Object.hasOwn(rules.direct, token)) +
      rules.families.filter(({ pattern }) => new RegExp(pattern, 'u').test(token)).length;
    if (matches !== 1) invalid('BINDING_AMBIGUOUS');
  }
  return table;
}

export function templateTokens(value, tokens = new Set()) {
  if (typeof value === 'string' && value.includes('OPENPC_INPUT_')) {
    if (!/^OPENPC_INPUT_[A-Z0-9_]+$/u.test(value)) invalid('BINDING_EMBEDDED');
    tokens.add(value);
  } else if (Array.isArray(value)) {
    for (const item of value) templateTokens(item, tokens);
  } else if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (key.includes('OPENPC_INPUT_')) invalid('BINDING_KEY');
      templateTokens(item, tokens);
    }
  }
  return tokens;
}

export function bindTemplate(template, table, input, target, counts = new Map()) {
  if (typeof template === 'string' && template.startsWith('OPENPC_INPUT_')) {
    const binding = table.get(template);
    if (!binding) invalid('BINDING_UNKNOWN');
    const value = pointerValue(input, binding.pointer, target);
    switch (binding.serialization) {
      case 'YAML_STRING':
        if (typeof value !== 'string' || !value.isWellFormed() || /[\r\n\0]/u.test(value))
          invalid('BINDING_STRING');
        break;
      case 'YAML_INTEGER':
      case 'QUOTED_DECIMAL_BYTES':
        if (
          !Number.isSafeInteger(value) ||
          value < 0 ||
          (binding.serialization === 'QUOTED_DECIMAL_BYTES' && value === 0)
        )
          invalid('BINDING_INTEGER');
        break;
      case 'YAML_BLOCK_SCALAR_INDENT_4_UTF8_LF':
        if (
          typeof value !== 'string' ||
          !value.isWellFormed() ||
          /[\r\0]/u.test(value) ||
          value.endsWith('\n')
        )
          invalid('BINDING_BLOCK');
        break;
      default:
        invalid('BINDING_SERIALIZATION');
    }
    if (typeof value === 'string' && value.includes('OPENPC_INPUT_')) invalid('BINDING_RECURSIVE');
    counts.set(template, (counts.get(template) ?? 0) + 1);
    return binding.serialization === 'QUOTED_DECIMAL_BYTES' ? String(value) : value;
  }
  if (Array.isArray(template))
    return template.map((item) => bindTemplate(item, table, input, target, counts));
  if (template && typeof template === 'object')
    return Object.fromEntries(
      Object.entries(template).map(([key, item]) => [
        key,
        bindTemplate(item, table, input, target, counts),
      ]),
    );
  return template;
}

export function checkBindingCoverage(templates, table) {
  const tokens = new Set();
  for (const template of Object.values(templates)) templateTokens(template, tokens);
  for (const token of tokens) if (!table.has(token)) invalid('BINDING_UNKNOWN');
  for (const token of table.keys()) if (!tokens.has(token)) invalid('BINDING_UNUSED');
}

// OpenTelemetry Collector 0.159 configuration template.
// The separately packaged observability.yaml is the operational catalogue, not
// a Collector configuration. Retaining this exact literal ships the executable
// template within the reserved binding owner without an archive-path dependency.
export const collectorTemplate = String.raw`# OpenTelemetry Collector 0.159.0 configuration template. Required typed
# OPENPC_INPUT_* bindings come from the signed telemetry qualification profile.
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    path: /
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls:
          cert_file: /run/openpc/secrets/otel-server/tls.crt
          key_file: /run/openpc/secrets/otel-server/tls.key
          client_ca_file: /run/openpc/secrets/otel-server/ca.crt
      http:
        endpoint: 0.0.0.0:4318
        tls:
          cert_file: /run/openpc/secrets/otel-server/tls.crt
          key_file: /run/openpc/secrets/otel-server/tls.key
          client_ca_file: /run/openpc/secrets/otel-server/ca.crt
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: OPENPC_INPUT_OTEL_MEMORY_LIMIT_MIB
    spike_limit_mib: OPENPC_INPUT_OTEL_MEMORY_SPIKE_LIMIT_MIB
  filter/closed_schema:
    error_mode: propagate
    traces:
      span:
        - 'attributes["openpc.schema_version"] != "1.0"'
        - 'attributes["openpc.payload"] != nil'
        - 'attributes["http.request.body"] != nil'
        - 'attributes["http.response.body"] != nil'
        - 'attributes["db.statement"] != nil'
    logs:
      log_record:
        - 'attributes["openpc.schema_version"] != "1.0"'
        - 'attributes["openpc.payload"] != nil'
        - 'attributes["authorization"] != nil'
        - 'attributes["cookie"] != nil'
        - 'attributes["secret"] != nil'
    metrics:
      metric:
        - 'not IsMatch(name, "^openpc_[a-z0-9_]+$")'
  attributes/remove_sensitive:
    actions:
      - {key: http.request.header.authorization, action: delete}
      - {key: http.request.header.cookie, action: delete}
      - {key: http.response.header.set-cookie, action: delete}
      - {key: rpc.request.metadata.authorization, action: delete}
      - {key: db.statement, action: delete}
      - {key: url.query, action: delete}
      - {key: enduser.id, action: delete}
      - {key: openpc.participant_id, action: delete}
      - {key: openpc.privacy_domain_id, action: delete}
      - {key: openpc.subject_id, action: delete}
      - {key: openpc.secret_ref, action: delete}
      - {key: openpc.payload, action: delete}
  resource/closed_identity:
    attributes:
      - {key: telemetry.sdk.version, action: delete}
      - {key: host.id, action: delete}
      - {key: process.command_args, action: delete}
  batch:
    timeout: OPENPC_INPUT_OTEL_BATCH_TIMEOUT
    send_batch_size: OPENPC_INPUT_OTEL_SEND_BATCH_SIZE
    send_batch_max_size: OPENPC_INPUT_OTEL_SEND_BATCH_MAX_SIZE
exporters:
  otlp/approved_sink:
    endpoint: "OPENPC_INPUT_OTEL_APPROVED_SINK_ENDPOINT"
    tls:
      ca_file: /run/openpc/secrets/otel-export/ca.crt
      cert_file: /run/openpc/secrets/otel-export/tls.crt
      key_file: /run/openpc/secrets/otel-export/tls.key
      insecure: false
    compression: gzip
    sending_queue:
      enabled: true
      num_consumers: OPENPC_INPUT_OTEL_EXPORT_CONSUMERS
      queue_size: OPENPC_INPUT_OTEL_EXPORT_QUEUE_SIZE
    retry_on_failure:
      enabled: true
      initial_interval: OPENPC_INPUT_OTEL_RETRY_INITIAL_INTERVAL
      max_interval: OPENPC_INPUT_OTEL_RETRY_MAX_INTERVAL
      max_elapsed_time: OPENPC_INPUT_OTEL_RETRY_MAX_ELAPSED_TIME
  prometheus:
    endpoint: 0.0.0.0:8889
    namespace: openpc
    send_timestamps: true
    metric_expiration: OPENPC_INPUT_OTEL_METRIC_EXPIRATION
service:
  extensions: [health_check]
  telemetry:
    logs:
      level: warn
      encoding: json
    metrics:
      level: detailed
      readers:
        - pull:
            exporter:
              prometheus:
                host: 127.0.0.1
                port: 8888
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, filter/closed_schema, attributes/remove_sensitive, resource/closed_identity, batch]
      exporters: [otlp/approved_sink]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, filter/closed_schema, attributes/remove_sensitive, resource/closed_identity, batch]
      exporters: [otlp/approved_sink, prometheus]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, filter/closed_schema, attributes/remove_sensitive, resource/closed_identity, batch]
      exporters: [otlp/approved_sink]
`;
