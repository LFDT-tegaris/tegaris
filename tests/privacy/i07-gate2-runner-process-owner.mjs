import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

const sha256Bytes = (bytes) => createHash('sha256').update(bytes).digest('hex');
const utcNow = () => new Date().toISOString();
const delay = (milliseconds) =>
  new Promise((resolveDelay) => {
    setTimeout(resolveDelay, milliseconds);
  });

export const classifyTerminalExecution = ({
  controllerDeadlineElapsed,
  executionPropertySnapshots,
}) => {
  const retained = executionPropertySnapshots.filter(Boolean);
  const last = retained.at(-1) ?? {};
  const systemdTimedOut = retained.some((snapshot) => snapshot.Result === 'timeout');
  const execMainStatus = Number(last.ExecMainStatus ?? Number.NaN);
  const execMainCode = last.ExecMainCode ?? '';
  return Object.freeze({
    controllerDeadlineElapsed,
    systemdTimedOut,
    timedOut: controllerDeadlineElapsed || systemdTimedOut,
    unitResult: last.Result ?? '',
    exitCode: execMainCode === '1' && Number.isSafeInteger(execMainStatus) ? execMainStatus : null,
    signal:
      ['2', '3'].includes(execMainCode) && Number.isSafeInteger(execMainStatus)
        ? execMainStatus
        : null,
  });
};

export const readBinaryPrefix = (path, limit) => {
  const size = Math.min(statSync(path).size, limit);
  const bytes = Buffer.alloc(size);
  if (size === 0) return bytes;
  const descriptor = openSync(path, 'r');
  try {
    let offset = 0;
    while (offset < size) {
      const count = readSync(descriptor, bytes, offset, size - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    if (offset !== size) throw new Error(`short binary prefix read: ${path}`);
  } finally {
    closeSync(descriptor);
  }
  return bytes;
};

export const collectBinaryFileIdentity = (path) => {
  const descriptor = openSync(path, 'r');
  const hash = createHash('sha256');
  const chunk = Buffer.alloc(64 * 1024);
  let byteLength = 0;
  try {
    for (;;) {
      const count = readSync(descriptor, chunk, 0, chunk.length, null);
      if (count === 0) break;
      hash.update(chunk.subarray(0, count));
      byteLength += count;
    }
    if (fstatSync(descriptor).size !== byteLength)
      throw new Error(`external file changed during identity collection: ${path}`);
  } finally {
    closeSync(descriptor);
  }
  return Object.freeze({ path, sha256: hash.digest('hex'), byteLength });
};

export const createProcessOwner = ({
  cwd,
  environment,
  environmentId,
  outputRoot,
  unitPrefix,
  maximumOutputBytes = 128 * 1024 * 1024,
  maximumClientOutputBytes = maximumOutputBytes,
  terminationGraceMilliseconds = 1_000,
  killGraceMilliseconds = 2_000,
}) => {
  const observeWithin = (promise, maximumWaitMilliseconds) =>
    new Promise((resolveObservation) => {
      const timer = setTimeout(
        () => resolveObservation(Object.freeze({ observed: false, value: null })),
        maximumWaitMilliseconds,
      );
      promise.then((value) => {
        clearTimeout(timer);
        resolveObservation(Object.freeze({ observed: true, value }));
      });
    });
  const processGroupExists = (processGroupId) => {
    try {
      process.kill(-processGroupId, 0);
      return true;
    } catch (error) {
      if (error?.code === 'ESRCH') return false;
      if (error?.code === 'EPERM') return true;
      throw error;
    }
  };
  const signalProcessGroup = (processGroupId, signal) => {
    try {
      process.kill(-processGroupId, signal);
      return true;
    } catch (error) {
      if (error?.code === 'ESRCH') return false;
      throw error;
    }
  };
  const waitForProcessGroupEmpty = async (processGroupId, maximumWaitMilliseconds) => {
    const deadline = Date.now() + maximumWaitMilliseconds;
    while (processGroupExists(processGroupId) && Date.now() < deadline) await delay(25);
    return !processGroupExists(processGroupId);
  };
  const terminateProcessGroup = async (processGroupId) => {
    const termSent = signalProcessGroup(processGroupId, 'SIGTERM');
    if (await waitForProcessGroupEmpty(processGroupId, terminationGraceMilliseconds))
      return { termSent, killSent: false, processGroupEmpty: true };
    const killSent = signalProcessGroup(processGroupId, 'SIGKILL');
    return {
      termSent,
      killSent,
      processGroupEmpty: await waitForProcessGroupEmpty(processGroupId, killGraceMilliseconds),
    };
  };
  const runClientCommand = async (
    command,
    argv,
    { commandCwd = cwd, commandEnvironment = environment, timeoutMilliseconds = 30_000 } = {},
  ) => {
    const startedAt = utcNow();
    const child = spawn(command, argv, {
      cwd: commandCwd,
      env: { ...commandEnvironment },
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    let capturedBytes = 0;
    let outputLimitExceeded = false;
    let resolveOutputLimit;
    const outputLimit = new Promise((resolveLimit) => {
      resolveOutputLimit = resolveLimit;
    });
    const capture = (target, chunk) => {
      const bytes = Buffer.from(chunk);
      const remaining = Math.max(0, maximumClientOutputBytes - capturedBytes);
      if (remaining > 0) target.push(bytes.subarray(0, remaining));
      capturedBytes += bytes.length;
      if (capturedBytes > maximumClientOutputBytes && !outputLimitExceeded) {
        outputLimitExceeded = true;
        resolveOutputLimit('OUTPUT_LIMIT');
      }
    };
    child.stdout.on('data', (chunk) => capture(stdout, chunk));
    child.stderr.on('data', (chunk) => capture(stderr, chunk));
    let exitObserved = false;
    let closeObserved = false;
    let exitRecord = null;
    const exited = new Promise((resolveExit) => {
      child.once('exit', (exitCode, signal) => {
        exitObserved = true;
        exitRecord = Object.freeze({ exitCode, signal });
        resolveExit(exitRecord);
      });
    });
    const closed = new Promise((resolveClose) =>
      child.once('close', (exitCode, signal) => {
        closeObserved = true;
        resolveClose(Object.freeze({ exitCode, signal }));
      }),
    );
    const spawnFailed = new Promise((resolveFailure) =>
      child.once('error', (error) => resolveFailure({ kind: 'SPAWN_ERROR', error })),
    );
    let timeout;
    const timed = new Promise((resolveTimeout) => {
      timeout = setTimeout(() => resolveTimeout('TIMEOUT'), timeoutMilliseconds);
    });
    const first = await Promise.race([
      exited.then((result) => ({ kind: 'EXIT', result })),
      spawnFailed,
      timed.then((kind) => ({ kind })),
      outputLimit.then((kind) => ({ kind })),
    ]);
    clearTimeout(timeout);
    if (first.kind === 'SPAWN_ERROR')
      return {
        argv: [command, ...argv],
        cwd: commandCwd,
        startedAt,
        endedAt: utcNow(),
        processGroupId: null,
        detachedProcessGroup: false,
        timeoutMilliseconds,
        exitCode: null,
        signal: null,
        timedOut: false,
        outputLimitExceeded,
        exitObserved,
        closeObserved,
        exitWaitTimedOut: false,
        closeWaitTimedOut: false,
        residualDescendantDetected: false,
        termSent: false,
        killSent: false,
        processGroupEmpty: true,
        spawnError: String(first.error),
        stdout: '',
        stderr: '',
      };
    const processGroupId = child.pid;
    if (!processGroupId) throw new Error('owned process group has no leader');
    const timedOut = first.kind === 'TIMEOUT';
    let cleanup = { termSent: false, killSent: false, processGroupEmpty: true };
    if (timedOut || first.kind === 'OUTPUT_LIMIT')
      cleanup = await terminateProcessGroup(processGroupId);
    if (first.kind === 'EXIT') exitRecord = first.result;
    if (!exitObserved) await observeWithin(exited, killGraceMilliseconds);
    if (!closeObserved) await observeWithin(closed, killGraceMilliseconds);
    if (!closeObserved) {
      cleanup = await terminateProcessGroup(processGroupId);
      await observeWithin(exited, killGraceMilliseconds);
      await observeWithin(closed, killGraceMilliseconds);
    }
    const exitWaitTimedOut = !exitObserved;
    const closeWaitTimedOut = !closeObserved;
    const naturallyEmptyAfterClose =
      closeObserved &&
      (await waitForProcessGroupEmpty(processGroupId, terminationGraceMilliseconds));
    const residualDescendantDetected = closeObserved && !naturallyEmptyAfterClose;
    if (residualDescendantDetected) cleanup = await terminateProcessGroup(processGroupId);
    const processGroupEmpty = !processGroupExists(processGroupId);
    return {
      argv: [command, ...argv],
      cwd: commandCwd,
      startedAt,
      endedAt: utcNow(),
      processGroupId,
      detachedProcessGroup: true,
      timeoutMilliseconds,
      exitCode: exitRecord?.exitCode ?? null,
      signal: exitRecord?.signal ?? null,
      timedOut,
      outputLimitExceeded,
      exitObserved,
      closeObserved,
      exitWaitTimedOut,
      closeWaitTimedOut,
      residualDescendantDetected,
      termSent: cleanup.termSent,
      killSent: cleanup.killSent,
      processGroupEmpty: cleanup.processGroupEmpty && processGroupEmpty,
      spawnError: null,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8'),
    };
  };
  const clientCommandFailed = (result) =>
    result.spawnError !== null ||
    result.timedOut ||
    result.outputLimitExceeded ||
    !result.exitObserved ||
    !result.closeObserved ||
    result.exitWaitTimedOut ||
    result.closeWaitTimedOut ||
    result.exitCode !== 0 ||
    result.signal !== null ||
    result.residualDescendantDetected ||
    !result.processGroupEmpty;
  const compactClientExecution = (result) => ({
    argv: result.argv,
    cwd: result.cwd,
    environmentId,
    startedAt: result.startedAt,
    endedAt: result.endedAt,
    processGroupId: result.processGroupId,
    detachedProcessGroup: result.detachedProcessGroup,
    timeoutMilliseconds: result.timeoutMilliseconds,
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    outputLimitExceeded: result.outputLimitExceeded,
    exitObserved: result.exitObserved,
    closeObserved: result.closeObserved,
    exitWaitTimedOut: result.exitWaitTimedOut,
    closeWaitTimedOut: result.closeWaitTimedOut,
    residualDescendantDetected: result.residualDescendantDetected,
    termSent: result.termSent,
    killSent: result.killSent,
    processGroupEmpty: result.processGroupEmpty,
    spawnError: result.spawnError,
    stdoutSha256: sha256Bytes(result.stdout),
    stdoutByteLength: Buffer.byteLength(result.stdout),
    stderrSha256: sha256Bytes(result.stderr),
    stderrByteLength: Buffer.byteLength(result.stderr),
  });
  const runManagementCommand = async (command, argv, timeoutMilliseconds = 30_000) => {
    const result = await runClientCommand(command, argv, { timeoutMilliseconds });
    if (clientCommandFailed(result))
      throw new Error(`${command} ${argv.join(' ')} failed: ${result.stderr}`);
    return result.stdout;
  };
  const systemctl = (...argv) => runManagementCommand('systemctl', ['--user', ...argv]);
  const parseProperties = (value) =>
    Object.fromEntries(
      value
        .split('\n')
        .filter(Boolean)
        .map((line) => {
          const separator = line.indexOf('=');
          return [line.slice(0, separator), line.slice(separator + 1)];
        }),
    );
  const inspectUnit = async (unitName) =>
    parseProperties(
      await systemctl(
        'show',
        unitName,
        '--no-pager',
        '--property=LoadState',
        '--property=ActiveState',
        '--property=SubState',
        '--property=Result',
        '--property=ExecMainCode',
        '--property=ExecMainStatus',
        '--property=ControlGroup',
        '--property=InvocationID',
        '--property=MemoryCurrent',
        '--property=MemoryPeak',
        '--property=MemorySwapCurrent',
        '--property=MemorySwapPeak',
        '--property=TasksCurrent',
      ),
    );
  const readCgroupPids = (controlGroup) => {
    if (!controlGroup || controlGroup === '/') return [];
    try {
      return readFileSync(join('/sys/fs/cgroup', controlGroup, 'cgroup.procs'), 'utf8')
        .split('\n')
        .filter(Boolean)
        .map(Number)
        .sort((left, right) => left - right);
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw error;
    }
  };
  const fileByteLength = (path) => {
    try {
      return statSync(path).size;
    } catch (error) {
      if (error?.code === 'ENOENT') return 0;
      throw error;
    }
  };
  const describePreview = (path, limit, fullFile) => {
    const bytes = readBinaryPrefix(path, limit);
    return Object.freeze({
      sha256: sha256Bytes(bytes),
      byteLength: bytes.length,
      limit,
      truncated: fullFile.byteLength > bytes.length,
    });
  };
  const normalizedProperties = (properties) =>
    Object.freeze({
      LoadState: properties.LoadState ?? '',
      ActiveState: properties.ActiveState ?? '',
      SubState: properties.SubState ?? '',
      Result: properties.Result ?? '',
      ExecMainCode: properties.ExecMainCode ?? '',
      ExecMainStatus: properties.ExecMainStatus ?? '',
      ControlGroup: properties.ControlGroup ?? '',
      InvocationID: properties.InvocationID ?? '',
      MemoryCurrent: properties.MemoryCurrent ?? '',
      MemoryPeak: properties.MemoryPeak ?? '',
      MemorySwapCurrent: properties.MemorySwapCurrent ?? '',
      MemorySwapPeak: properties.MemorySwapPeak ?? '',
      TasksCurrent: properties.TasksCurrent ?? '',
    });
  const executionSignature = (properties) =>
    JSON.stringify({
      ActiveState: properties.ActiveState,
      SubState: properties.SubState,
      Result: properties.Result,
      ExecMainCode: properties.ExecMainCode,
      ExecMainStatus: properties.ExecMainStatus,
      ControlGroup: properties.ControlGroup,
      InvocationID: properties.InvocationID,
    });
  const freezeArray = (values) => Object.freeze(values.map((value) => Object.freeze(value)));
  const scopedSnapshotFailed = (snapshot) =>
    snapshot.ownerError !== null ||
    snapshot.cleanupErrors.length !== 0 ||
    snapshot.timedOut ||
    snapshot.outputLimitExceeded ||
    snapshot.exitCode !== 0 ||
    snapshot.signal !== null ||
    snapshot.residualDescendantDetected ||
    !snapshot.cgroupEmptyAfterCleanup ||
    !snapshot.unitAbsentAfterCleanup;
  const unitIsAbsent = async (unitName) =>
    (await systemctl('list-units', unitName, '--all', '--no-legend', '--plain')).trim() === '';
  let unitSequence = 0;
  const runScopedCommand = async (
    command,
    argv,
    timeoutMilliseconds,
    purpose,
    faultInjection = 'NONE',
  ) => {
    if (!['NONE', 'AFTER_LAUNCH'].includes(faultInjection))
      throw new Error('unknown process-owner fault injection');
    unitSequence += 1;
    const unitName = `${unitPrefix}-${process.pid}-${unitSequence}.service`;
    const unitStem = unitName.slice(0, -'.service'.length);
    const stdoutPath = join(outputRoot, `${unitStem}.stdout.log`);
    const stderrPath = join(outputRoot, `${unitStem}.stderr.log`);
    writeFileSync(stdoutPath, '', { encoding: 'utf8', flag: 'wx' });
    writeFileSync(stderrPath, '', { encoding: 'utf8', flag: 'wx' });
    const startedAt = utcNow();
    const runtimeSeconds = Math.max(1, Math.ceil(timeoutMilliseconds / 1_000));
    let properties = {};
    let controlGroup = '';
    let observedControlGroup = '';
    let finalCleanupProperties = Object.freeze({});
    let controllerDeadlineElapsed = false;
    let liveOutputLimitDetected = false;
    let residualDescendantDetected = false;
    let residualPidsBeforeCleanup = [];
    let residualPidsAfterCleanup = [];
    let killSent = false;
    let ownerError = null;
    const cleanupErrors = [];
    const logProgress = [];
    const resourceSamples = [];
    const executionPropertySnapshots = [];
    let lastExecutionSignature = '';
    let lastObservedExecutionProperties = null;
    let lastLogByteLength = -1;
    let launchAttempted = false;
    let launchSucceeded = false;
    let unitAbsentAfterCleanup = false;
    const retainExecutionProperties = (observed) => {
      const normalized = normalizedProperties(observed);
      lastObservedExecutionProperties = normalized;
      if (normalized.ControlGroup) observedControlGroup = normalized.ControlGroup;
      const signature = executionSignature(normalized);
      if (signature !== lastExecutionSignature) {
        executionPropertySnapshots.push(Object.freeze({ observedAt: utcNow(), ...normalized }));
        lastExecutionSignature = signature;
      }
      resourceSamples.push(
        Object.freeze({
          observedAt: utcNow(),
          controlGroup: normalized.ControlGroup,
          memoryCurrent: normalized.MemoryCurrent,
          memoryPeak: normalized.MemoryPeak,
          memorySwapCurrent: normalized.MemorySwapCurrent,
          memorySwapPeak: normalized.MemorySwapPeak,
          tasksCurrent: normalized.TasksCurrent,
        }),
      );
    };
    try {
      launchAttempted = true;
      await runManagementCommand('systemd-run', [
        '--user',
        '--unit',
        unitStem,
        '--property=Type=exec',
        '--property=KillMode=control-group',
        '--property=RemainAfterExit=yes',
        '--property=MemoryAccounting=yes',
        '--property=TasksAccounting=yes',
        `--property=RuntimeMaxSec=${runtimeSeconds}s`,
        '--property=TimeoutStopSec=1s',
        `--working-directory=${cwd}`,
        `--property=StandardOutput=append:${stdoutPath}`,
        `--property=StandardError=append:${stderrPath}`,
        ...Object.entries(environment).map(([key, value]) => `--setenv=${key}=${value}`),
        command,
        ...argv,
      ]);
      launchSucceeded = true;
      if (faultInjection === 'AFTER_LAUNCH')
        throw new Error('PROCESS_OWNER_SELF_TEST_FAILURE_AFTER_LAUNCH');
      const deadline = Date.now() + timeoutMilliseconds;
      properties = await inspectUnit(unitName);
      retainExecutionProperties(properties);
      while (!['exited', 'failed', 'dead'].includes(properties.SubState) && Date.now() < deadline) {
        await delay(Math.min(100, Math.max(0, deadline - Date.now())));
        properties = await inspectUnit(unitName);
        retainExecutionProperties(properties);
        const logByteLength = fileByteLength(stdoutPath) + fileByteLength(stderrPath);
        if (logByteLength !== lastLogByteLength) {
          logProgress.push({ observedAt: utcNow(), byteLength: logByteLength });
          lastLogByteLength = logByteLength;
        }
        if (logByteLength > maximumOutputBytes) {
          liveOutputLimitDetected = true;
          break;
        }
      }
      const finalObservedLogByteLength = fileByteLength(stdoutPath) + fileByteLength(stderrPath);
      if (finalObservedLogByteLength !== lastLogByteLength)
        logProgress.push({ observedAt: utcNow(), byteLength: finalObservedLogByteLength });
      controllerDeadlineElapsed =
        !liveOutputLimitDetected &&
        !['exited', 'failed', 'dead'].includes(properties.SubState) &&
        Date.now() >= deadline;
      controlGroup = observedControlGroup || properties.ControlGroup || '';
    } catch (error) {
      ownerError = String(error);
    } finally {
      if (launchSucceeded)
        try {
          const preCleanupProperties = await inspectUnit(unitName);
          retainExecutionProperties(preCleanupProperties);
          controlGroup = observedControlGroup || preCleanupProperties.ControlGroup || controlGroup;
        } catch (error) {
          cleanupErrors.push(`inspect-before-cleanup: ${String(error)}`);
        }
      residualPidsBeforeCleanup = readCgroupPids(controlGroup);
      residualDescendantDetected =
        ['exited', 'failed', 'dead'].includes(lastObservedExecutionProperties?.SubState ?? '') &&
        residualPidsBeforeCleanup.length > 0;
      if (launchAttempted)
        try {
          await systemctl('stop', unitName);
        } catch (error) {
          if (launchSucceeded) cleanupErrors.push(`stop: ${String(error)}`);
        }
      const cleanupDeadline = Date.now() + killGraceMilliseconds;
      while (readCgroupPids(controlGroup).length > 0 && Date.now() < cleanupDeadline)
        await delay(25);
      residualPidsAfterCleanup = readCgroupPids(controlGroup);
      if (residualPidsAfterCleanup.length > 0) {
        killSent = true;
        try {
          await systemctl('kill', '--kill-who=all', '--signal=SIGKILL', unitName);
          await systemctl('stop', unitName);
        } catch (error) {
          cleanupErrors.push(`kill: ${String(error)}`);
        }
        const killDeadline = Date.now() + killGraceMilliseconds;
        while (readCgroupPids(controlGroup).length > 0 && Date.now() < killDeadline)
          await delay(25);
        residualPidsAfterCleanup = readCgroupPids(controlGroup);
      }
      if (launchAttempted)
        try {
          finalCleanupProperties = normalizedProperties(await inspectUnit(unitName));
        } catch (error) {
          if (launchSucceeded) cleanupErrors.push(`inspect-after-cleanup: ${String(error)}`);
        }
      await systemctl('reset-failed', unitName).catch(() => undefined);
      try {
        unitAbsentAfterCleanup = await unitIsAbsent(unitName);
      } catch (error) {
        cleanupErrors.push(`unit-inventory-after-cleanup: ${String(error)}`);
      }
    }
    const stdoutFullFile = collectBinaryFileIdentity(stdoutPath);
    const stderrFullFile = collectBinaryFileIdentity(stderrPath);
    const actualCombinedOutputByteLength = stdoutFullFile.byteLength + stderrFullFile.byteLength;
    const outputLimitExceeded =
      liveOutputLimitDetected || actualCombinedOutputByteLength > maximumOutputBytes;
    const stdoutPreviewLimit = Math.min(maximumOutputBytes, stdoutFullFile.byteLength);
    const stderrPreviewLimit = Math.max(0, maximumOutputBytes - stdoutPreviewLimit);
    const stdoutPreview = describePreview(stdoutPath, stdoutPreviewLimit, stdoutFullFile);
    const stderrPreview = describePreview(stderrPath, stderrPreviewLimit, stderrFullFile);
    const terminal = classifyTerminalExecution({
      controllerDeadlineElapsed,
      executionPropertySnapshots,
    });
    const snapshot = {
      purpose,
      argv: [command, ...argv],
      cwd,
      environmentId,
      startedAt,
      endedAt: utcNow(),
      timeoutMilliseconds,
      controllerDeadlineElapsed: terminal.controllerDeadlineElapsed,
      systemdTimedOut: terminal.systemdTimedOut,
      timedOut: terminal.timedOut,
      liveOutputLimitDetected,
      outputLimitExceeded,
      actualCombinedOutputByteLength,
      maximumOutputBytes,
      maximumClientOutputBytes,
      unitName,
      invocationId:
        lastObservedExecutionProperties?.InvocationID ?? finalCleanupProperties.InvocationID ?? '',
      controlGroup,
      cgroupVersion: 2,
      killMode: 'control-group',
      accounting: 'MEMORY_AND_TASKS',
      memoryCurrent: lastObservedExecutionProperties?.MemoryCurrent ?? '',
      memoryPeak: lastObservedExecutionProperties?.MemoryPeak ?? '',
      memorySwapCurrent: lastObservedExecutionProperties?.MemorySwapCurrent ?? '',
      memorySwapPeak: lastObservedExecutionProperties?.MemorySwapPeak ?? '',
      tasksCurrent: lastObservedExecutionProperties?.TasksCurrent ?? '',
      unitResult: terminal.unitResult,
      exitCode: terminal.exitCode,
      signal: terminal.signal,
      executionPropertySnapshots: freezeArray(executionPropertySnapshots),
      lastObservedExecutionProperties,
      finalCleanupProperties,
      residualDescendantDetected,
      residualPidsBeforeCleanup: Object.freeze([...residualPidsBeforeCleanup]),
      residualPidsAfterCleanup: Object.freeze([...residualPidsAfterCleanup]),
      killSent,
      cgroupEmptyAfterCleanup: residualPidsAfterCleanup.length === 0,
      unitAbsentAfterCleanup,
      ownerError,
      cleanupErrors: Object.freeze([...cleanupErrors]),
      logProgress: freezeArray(logProgress),
      resourceSamples: freezeArray(resourceSamples),
      stdout: Object.freeze({ fullFile: stdoutFullFile, preview: stdoutPreview }),
      stderr: Object.freeze({ fullFile: stderrFullFile, preview: stderrPreview }),
    };
    return Object.freeze({ ...snapshot, failed: scopedSnapshotFailed(snapshot) });
  };
  const scopedCommandFailed = (snapshot) => snapshot.failed;
  const compactScopedExecution = (snapshot) => snapshot;
  const listOwnedUnits = async () =>
    (await systemctl('list-units', `${unitPrefix}-*.service`, '--all', '--no-legend', '--plain'))
      .split('\n')
      .map((line) => line.trim().split(/\s+/)[0])
      .filter(Boolean)
      .sort();

  return Object.freeze({
    runClientCommand,
    clientCommandFailed,
    compactClientExecution,
    runScopedCommand,
    scopedCommandFailed,
    compactScopedExecution,
    listOwnedUnits,
    contract: Object.freeze({
      kind: 'SYSTEMD_USER_TRANSIENT_SERVICE_CGROUP_V2',
      unitPrefix,
      outputRoot,
      maximumOutputBytes,
      maximumClientOutputBytes,
      type: 'exec',
      killMode: 'control-group',
      remainAfterExitForInspection: true,
      accounting: 'MEMORY_AND_TASKS_WITHOUT_SPECULATIVE_LIMITS',
      terminationGraceMilliseconds,
      killGraceMilliseconds,
    }),
  });
};
