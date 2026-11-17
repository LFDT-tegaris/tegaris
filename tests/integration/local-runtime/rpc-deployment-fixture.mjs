// Controlled external chain behavior. Internal approval, custody, policy,
// journaling and reconciliation remain real. Test controls affect only this RPC.
import assert from 'node:assert/strict';
import { readFile, appendFile } from 'node:fs/promises';

const create3HelperInit = '0x67363d3d37363d34f03d5260086018f3';
const create3HelperRuntime = '0x363d3d37363d34f0';

export async function deploymentResponse(root, input) {
  let scenario;
  try {
    scenario = JSON.parse(await readFile(`${root}/deployment-scenario.json`, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  }
  const { phase: chainPhase = 'pending', loseResponse = false } = scenario;
  let submissions;
  try {
    submissions = (await readFile(`${root}/deployment-submissions.jsonl`, 'utf8'))
      .trim()
      .split('\n')
      .filter(Boolean)
      .map(JSON.parse);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    submissions = [];
  }
  const replacementSent =
    scenario.replacement &&
    submissions.some((entry) => entry.transactionHash === scenario.replacement.transactionHash);
  const chainWallet = replacementSent ? scenario.replacement : scenario.wallet;
  const wallets = [scenario.wallet, ...(scenario.replacement ? [scenario.replacement] : [])];
  // Both exact hashes remain queryable in one external chain. The replacement
  // is selected by submitted bytes/hash or the fee fields of a simulation.
  const wallet = wallets.find((candidate) =>
    ['eth_getTransactionReceipt', 'eth_getTransactionByHash', 'debug_traceTransaction'].includes(
      input.method,
    )
      ? candidate.transactionHash === input.params[0]
      : input.method === 'eth_sendRawTransaction'
        ? candidate.signedTransaction === input.params[0]
        : input.method === 'debug_traceCall'
          ? `0x${BigInt(candidate.feePerGas ?? '2').toString(16)}` === input.params[0].maxFeePerGas
          : candidate === chainWallet,
  );
  assert.ok(wallet, 'unregistered deployment transaction');
  const factory = wallet.mechanism !== 'TRANSACTION_CREATE';
  const create3 = wallet.mechanism === 'CREATE3';
  const destination = factory ? wallet.factoryAddress : null;
  const nonce = `0x${wallet.nonce.toString(16)}`;
  const abandonedPreflight =
    scenario.abandonPreflight === true &&
    input.method === 'debug_traceCall' &&
    input.params[2]?.tracer === 'callTracer';
  const phase = replacementSent && wallet === scenario.wallet ? 'replaced' : chainPhase;
  await appendFile(
    `${root}/deployment-observations.jsonl`,
    JSON.stringify({
      phase,
      method: input.method,
      ...(input.method === 'eth_getCode' ? { address: input.params[0] } : {}),
      transactionHash: wallet.transactionHash,
      abandonedPreflight,
    }) + '\n',
    { mode: 0o600 },
  );
  // Give the test controller a deterministic window to interrupt the real
  // submitting worker while this external RPC is pending. Target/PDS/Broker
  // still execute normally and own any subsequent no-send journal transition.
  if (abandonedPreflight) await new Promise((resolve) => setTimeout(resolve, 2000));
  const hash = (byte) => `0x${byte.repeat(32)}`;
  const sent = submissions.some((entry) => entry.transactionHash === wallet.transactionHash);
  const postFinal = [
    'finalized',
    'invalidated-code',
    'invalidated-reorg',
    'invalidated-helper',
  ].includes(chainPhase);
  const included =
    sent &&
    [
      'included',
      'safe',
      'finalized',
      'wrong-code',
      'wrong-address',
      'wrong-helper',
      'invalidated-code',
      'invalidated-helper',
    ].includes(phase);
  const chainIncluded =
    submissions.some((entry) => entry.transactionHash === chainWallet.transactionHash) &&
    [
      'included',
      'safe',
      'finalized',
      'wrong-code',
      'wrong-address',
      'wrong-helper',
      'invalidated-code',
      'invalidated-helper',
    ].includes(chainPhase);
  const minedHash = ['reorg', 'invalidated-reorg'].includes(chainPhase) ? hash('bb') : hash('aa');
  const header = (number, blockHash) => ({
    number,
    hash: blockHash,
    stateRoot: hash('33'),
    gasLimit: '0x1000000',
    baseFeePerGas: '0x1',
    transactions: chainIncluded ? [chainWallet.transactionHash] : [],
  });
  const selected = { blockHash: hash('22'), requireCanonical: true };
  switch (input.method) {
    case 'eth_sendRawTransaction':
      assert.deepEqual(input.params, [wallet.signedTransaction]);
      await appendFile(
        `${root}/deployment-submissions.jsonl`,
        JSON.stringify({ transactionHash: wallet.transactionHash, raw: wallet.signedTransaction }) +
          '\n',
        { mode: 0o600 },
      );
      return { result: wallet.transactionHash, loseResponse };
    case 'eth_getBlockByNumber': {
      const [selector, full] = input.params;
      assert.equal(full, false);
      if (selector === '0x0') return { result: { number: '0x0', hash: hash('11') } };
      if (selector === 'latest')
        return { result: postFinal ? header('0xc', hash('cc')) : header('0xa', hash('22')) };
      if (selector === '0xc' && postFinal) return { result: header('0xc', hash('cc')) };
      if (selector === '0xb') return { result: header('0xb', minedHash) };
      if (selector === 'safe')
        return {
          result:
            chainPhase === 'safe' || chainPhase === 'finalized' ? header('0xb', minedHash) : null,
        };
      if (selector === 'finalized')
        return { result: chainPhase === 'finalized' ? header('0xb', minedHash) : null };
      throw Error('Unregistered block selector');
    }
    case 'eth_getTransactionReceipt':
      assert.deepEqual(input.params, [wallet.transactionHash]);
      return {
        result: included
          ? {
              transactionHash: wallet.transactionHash,
              from: wallet.sender,
              to: destination,
              blockNumber: '0xb',
              blockHash: minedHash,
              transactionIndex: '0x0',
              status: '0x1',
              contractAddress: factory
                ? null
                : phase === 'wrong-address'
                  ? `0x${'01'.repeat(20)}`
                  : wallet.expectedAddress,
              logs: [{ private: 'must not be disclosed' }],
            }
          : null,
      };
    case 'eth_getTransactionByHash':
      assert.deepEqual(input.params, [wallet.transactionHash]);
      return {
        result:
          sent && !['reorg', 'replaced'].includes(phase)
            ? {
                hash: wallet.transactionHash,
                from: wallet.sender,
                to: destination,
                nonce,
                chainId: '0x7a69',
                blockHash: included ? minedHash : null,
                blockNumber: included ? '0xb' : null,
              }
            : null,
      };
    case 'eth_getCode':
    case 'eth_getTransactionCount':
    case 'eth_getBalance': {
      const [address, anchor] = input.params;
      assert.ok(
        [
          wallet.sender,
          wallet.expectedAddress,
          ...(factory ? [wallet.factoryAddress] : []),
          ...(create3 ? [wallet.helperAddress] : []),
        ].includes(address),
      );
      if (
        input.method === 'eth_getCode' &&
        postFinal &&
        anchor.blockHash === hash('cc') &&
        anchor.requireCanonical === true
      ) {
        if (create3 && address === wallet.helperAddress)
          return { result: phase === 'invalidated-helper' ? '0x' : create3HelperRuntime };
        assert.equal(address, wallet.expectedAddress);
        return { result: phase === 'invalidated-code' ? '0x01' : '0x00' };
      }
      if (
        input.method === 'eth_getCode' &&
        anchor.blockHash === minedHash &&
        anchor.requireCanonical === true
      ) {
        if (create3 && address === wallet.helperAddress)
          return { result: phase === 'wrong-helper' ? '0x00' : create3HelperRuntime };
        assert.equal(address, wallet.expectedAddress);
        assert.ok(included);
        return { result: phase === 'wrong-code' ? '0x01' : '0x00' };
      }
      assert.deepEqual(anchor, selected);
      if (input.method === 'eth_getCode')
        return { result: address === destination ? wallet.factoryCode : '0x' };
      if (input.method === 'eth_getTransactionCount')
        return {
          result: address === wallet.sender ? nonce : address === destination ? '0x7' : '0x0',
        };
      return { result: address === wallet.sender ? '0xffffff' : '0x0' };
    }
    case 'debug_traceCall':
    case 'debug_traceTransaction': {
      if (input.method === 'debug_traceTransaction') {
        assert.equal(input.params[0], wallet.transactionHash);
        assert.ok(included);
        if (input.params[1].tracer === 'prestateTracer') {
          assert.ok(factory);
          assert.deepEqual(input.params[1], {
            tracer: 'prestateTracer',
            timeout: '5s',
            tracerConfig: { diffMode: false, disableCode: false, disableStorage: true },
          });
          return {
            result: {
              [wallet.factoryAddress]: { balance: '0x0', nonce: 7, code: wallet.factoryCode },
            },
          };
        }
        return { result: creationTrace(wallet, input.params[1], phase) };
      }
      const [call, anchor, options] = input.params;
      assert.deepEqual(anchor, selected);
      assert.equal(call.from, wallet.sender);
      assert.equal(call.data, wallet.calldata);
      assert.equal(call.chainId, '0x7a69');
      assert.equal(call.nonce, nonce);
      assert.equal(call.gas, '0x186a0');
      assert.equal(call.maxFeePerGas, `0x${BigInt(wallet.feePerGas ?? '2').toString(16)}`);
      assert.equal(call.maxPriorityFeePerGas, `0x${BigInt(wallet.tipPerGas ?? '1').toString(16)}`);
      assert.equal(call.value, `0x${BigInt(wallet.valueWei ?? '0').toString(16)}`);
      if (factory) assert.equal(call.to, destination);
      else assert.equal('to' in call, false);
      assert.deepEqual(call.accessList, []);
      return { result: creationTrace(wallet, options, phase) };
    }
    default:
      return undefined;
  }
}

function creationTrace(wallet, options, phase) {
  const factory = wallet.mechanism !== 'TRANSACTION_CREATE';
  const create3 = wallet.mechanism === 'CREATE3';
  const address = phase === 'wrong-address' ? `0x${'01'.repeat(20)}` : wallet.expectedAddress;
  if (options.tracer === 'callTracer') {
    assert.deepEqual(options, {
      tracer: 'callTracer',
      timeout: '5s',
      tracerConfig: { onlyTopCall: false, withLog: false },
    });
    const creation = {
      type: wallet.mechanism === 'CREATE2' ? 'CREATE2' : 'CREATE',
      from: factory ? wallet.factoryAddress : wallet.sender,
      to: address,
      value: factory ? '0x0' : `0x${BigInt(wallet.valueWei ?? '0').toString(16)}`,
      gas: '0x186a0',
      gasUsed: '0xcf08',
      input: wallet.initCode,
      output: '0x00',
    };
    if (create3) {
      creation.from = wallet.helperAddress;
      return {
        ...creation,
        type: 'CALL',
        from: wallet.sender,
        to: wallet.factoryAddress,
        input: wallet.calldata,
        output: `0x${'00'.repeat(12)}${address.slice(2)}`,
        calls: [
          {
            ...creation,
            type: 'CREATE2',
            from: wallet.factoryAddress,
            to: wallet.helperAddress,
            input: create3HelperInit,
            output: create3HelperRuntime,
          },
          {
            ...creation,
            type: 'CALL',
            from: wallet.factoryAddress,
            to: wallet.helperAddress,
            output: '0x',
            calls: [creation],
          },
        ],
      };
    }
    return factory
      ? {
          type: 'CALL',
          from: wallet.sender,
          to: wallet.factoryAddress,
          value: '0x0',
          gas: '0x186a0',
          gasUsed: '0xcf08',
          input: wallet.calldata,
          output: address,
          calls: [creation],
        }
      : creation;
  }
  assert.deepEqual(options, {
    timeout: '5s',
    enableMemory: false,
    disableStack: true,
    disableStorage: true,
    enableReturnData: false,
    limit: 0,
  });
  return {
    gas: 53000,
    failed: false,
    returnValue: create3
      ? `${'00'.repeat(12)}${address.slice(2)}`
      : factory
        ? address.slice(2)
        : '00',
    structLogs: [
      ...(create3
        ? [
            [0, 'CREATE2', 1],
            [0, 'PUSH8', 2],
            [9, 'RETURNDATASIZE', 2],
            [10, 'MSTORE', 2],
            [11, 'PUSH1', 2],
            [13, 'PUSH1', 2],
            [15, 'RETURN', 2],
            [1, 'CALL', 1],
            [0, 'CALLDATASIZE', 2],
            [1, 'RETURNDATASIZE', 2],
            [2, 'RETURNDATASIZE', 2],
            [3, 'CALLDATACOPY', 2],
            [4, 'CALLDATASIZE', 2],
            [5, 'RETURNDATASIZE', 2],
            [6, 'CALLVALUE', 2],
            [7, 'CREATE', 2],
          ].map(([pc, op, depth]) => ({ pc, op, depth, gas: 90000, gasCost: 3 }))
        : factory
          ? [{ pc: 0, op: wallet.mechanism, gas: 90000, gasCost: 32000, depth: 1 }]
          : []),
      ...[
        [0, 'PUSH1'],
        [2, 'PUSH1'],
        [4, 'PUSH1'],
        [6, 'CODECOPY'],
        [7, 'PUSH1'],
        [9, 'PUSH1'],
        [11, 'RETURN'],
      ].map(([pc, op]) => ({
        pc,
        op,
        gas: 50000,
        gasCost: 3,
        depth: create3 ? 3 : factory ? 2 : 1,
      })),
      ...(factory ? [{ pc: create3 ? 2 : 1, op: 'RETURN', gas: 20000, gasCost: 0, depth: 1 }] : []),
    ],
  };
}
