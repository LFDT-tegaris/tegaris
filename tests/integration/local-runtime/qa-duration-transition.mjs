import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const sorted = (value) =>
  Array.isArray(value)
    ? value.map(sorted)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((key) => [key, sorted(value[key])]),
        )
      : value;
export const durationDigest = (value) =>
  createHash('sha256')
    .update(JSON.stringify(sorted(value)))
    .digest('hex');
const environment = (entries) =>
  Object.fromEntries(
    (entries ?? []).map((entry) => {
      const at = entry.indexOf('=');
      return [entry.slice(0, at), entry.slice(at + 1)];
    }),
  );
function nanoseconds(value) {
  if (typeof value === 'number') return value;
  const units = { ns: 1, us: 1e3, ms: 1e6, s: 1e9, m: 60e9, h: 3600e9 };
  const pieces = [...String(value).matchAll(/(\d+(?:\.\d+)?)(ns|us|ms|s|m|h)/gu)];
  assert.equal(pieces.map((p) => p[0]).join(''), value);
  const result = pieces.reduce((sum, p) => sum + Number(p[1]) * units[p[2]], 0);
  assert.ok(Number.isSafeInteger(result) && result >= 0);
  return result;
}
function expectedHealth(service, image) {
  const value = { ...(image.Config.Healthcheck ?? {}) };
  const health = service.healthcheck;
  if (!health) return value;
  if (health.disable) return { Test: ['NONE'] };
  if (health.test) value.Test = health.test.map((entry) => entry.replaceAll('$$', '$'));
  for (const [input, output] of Object.entries({
    interval: 'Interval',
    timeout: 'Timeout',
    start_period: 'StartPeriod',
    start_interval: 'StartInterval',
  }))
    if (health[input] !== undefined) value[output] = nanoseconds(health[input]);
  if (health.retries !== undefined) value.Retries = health.retries;
  return value;
}
export function durationContainerState(c) {
  return {
    image: c.Image,
    imageName: c.Config.Image,
    command: c.Config.Cmd ?? [],
    entrypoint: c.Config.Entrypoint ?? [],
    user: c.Config.User ?? '',
    workingDirectory: c.Config.WorkingDir ?? '',
    healthcheck: c.Config.Healthcheck ?? {},
    restartPolicy: c.HostConfig.RestartPolicy ?? { Name: 'no', MaximumRetryCount: 0 },
    environment: durationDigest(environment(c.Config.Env)),
    memory: c.HostConfig.Memory,
    swap: c.HostConfig.MemorySwap,
    cpus: c.HostConfig.NanoCpus,
    cpuPeriod: c.HostConfig.CpuPeriod,
    cpuQuota: c.HostConfig.CpuQuota,
    pids: c.HostConfig.PidsLimit,
    readonly: c.HostConfig.ReadonlyRootfs,
    privileged: c.HostConfig.Privileged,
    security: [...(c.HostConfig.SecurityOpt ?? [])].sort(),
    capAdd: [...(c.HostConfig.CapAdd ?? [])].sort(),
    capDrop: [...(c.HostConfig.CapDrop ?? [])].sort(),
    ports: c.HostConfig.PortBindings ?? {},
    networks: Object.fromEntries(
      Object.entries(c.NetworkSettings.Networks).map(([name, v]) => [name, v.NetworkID]),
    ),
    mounts: c.Mounts.map((m) => ({
      source: m.Source,
      target: m.Destination,
      type: m.Type,
      writable: m.RW,
    })).sort((a, b) => a.target.localeCompare(b.target)),
  };
}
export function durationExpectedState(configuration, name, image, networks, mounts) {
  const service = configuration.services[name];
  const env = environment(image.Config.Env);
  for (const [key, value] of Object.entries(service.environment ?? {})) {
    if (value === null) delete env[key];
    else env[key] = String(value);
  }
  const ports = {};
  for (const port of service.ports ?? []) {
    const key = `${port.target}/${port.protocol ?? 'tcp'}`;
    (ports[key] ??= []).push({ HostIp: port.host_ip ?? '', HostPort: String(port.published) });
  }
  return {
    image: image.Id,
    imageName: service.image,
    command: service.command ?? image.Config.Cmd ?? [],
    entrypoint: service.entrypoint ?? image.Config.Entrypoint ?? [],
    user: service.user ?? image.Config.User ?? '',
    workingDirectory: service.working_dir ?? image.Config.WorkingDir ?? '',
    healthcheck: expectedHealth(service, image),
    restartPolicy: {
      Name: (service.restart ?? 'no').split(':')[0],
      MaximumRetryCount: Number((service.restart ?? '').split(':')[1] ?? 0),
    },
    environment: durationDigest(env),
    memory: Number(service.mem_limit),
    swap: Number(service.memswap_limit ?? Number(service.mem_limit) * 2),
    cpus: Math.round(Number(service.cpus ?? 0) * 1e9),
    cpuPeriod: Number(service.cpu_period ?? 0),
    cpuQuota: Number(service.cpu_quota ?? 0),
    pids: Number(service.pids_limit ?? 0),
    readonly: service.read_only ?? false,
    privileged: service.privileged ?? false,
    security: [...(service.security_opt ?? [])].sort(),
    capAdd: [...(service.cap_add ?? [])].sort(),
    capDrop: [...(service.cap_drop ?? [])].sort(),
    ports,
    networks,
    mounts,
  };
}
export function durationTransitionPlan(pending, actual) {
  assert.equal(pending.version, 1);
  const names = pending.previous.map((c) => c.service);
  assert.equal(new Set(names).size, names.length);
  const running = actual.filter((c) => c.State.Running);
  assert.ok(
    running.every((c) => names.includes(c.Config.Labels['com.docker.compose.service'])),
    'Unexpected running service',
  );
  const remaining = [];
  for (const previous of pending.previous) {
    const matches = actual.filter(
      (c) => c.Config.Labels['com.docker.compose.service'] === previous.service,
    );
    assert.ok(matches.length <= 1, 'Duplicate transition service');
    if (!matches.length) {
      assert.ok(pending.changed.includes(previous.service), 'Missing protected service');
      remaining.push(previous.service);
      continue;
    }
    const c = matches[0];
    assert.equal(c.State.OOMKilled, false);
    assert.equal(c.Config.Labels['com.docker.compose.project'], pending.project);
    if (c.Id === previous.id) {
      assert.equal(
        durationDigest(durationContainerState(c)),
        previous.configuration,
        'Original process configuration drift',
      );
      assert.equal(c.State.StartedAt, previous.startedAt);
      if (pending.changed.includes(previous.service)) remaining.push(previous.service);
      else {
        assert.equal(c.State.Running, true);
        assert.equal(c.State.Health?.Status, 'healthy');
      }
    } else {
      assert.ok(pending.changed.includes(previous.service), 'Protected process replaced');
      assert.equal(
        durationDigest(durationContainerState(c)),
        pending.target[previous.service],
        'Successor configuration drift',
      );
      assert.equal(c.State.Running, true, 'Recorded successor is stopped; diagnose before retry');
      assert.equal(
        c.State.Health?.Status,
        'healthy',
        'Recorded successor is not ready; diagnose before retry',
      );
    }
  }
  return { remaining, complete: remaining.length === 0 };
}

/** Each retry first reads actual external state. Already completed services and
 * a lost final save never cause another recreation or a replacement intent. */
export async function completeDurationTransition(pending, ports) {
  for (;;) {
    const actual = await ports.read();
    await ports.authenticate(actual);
    const plan = durationTransitionPlan(pending, actual);
    if (plan.complete) {
      await ports.finish(actual);
      return;
    }
    await ports.recreate(plan.remaining[0]);
  }
}

/** Recover the exact initial intent after its private temporary save succeeded
 * but publication failed. Authentication must finish before preserving/publishing
 * that original intent; callers cannot allocate a replacement overlay. */
export async function reconcileInitialDurationSave(manifest, candidate, input, ports) {
  assert.equal(manifest.durationProfilePending, undefined);
  assert.deepEqual(input.command, manifest.command);
  const { durationProfilePending: pending, ...previous } = candidate;
  assert.ok(pending);
  assert.deepEqual(previous, manifest, 'Unrelated unpublished maintenance record');
  assert.equal(pending.mode, input.mode);
  assert.deepEqual(pending.previousCommand, input.command);
  await ports.authenticate(candidate);
  await ports.preserve();
  await ports.publish(candidate);
  return candidate;
}
