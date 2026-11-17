// External chain observations only. All identity, approval, publication and
// runtime permission decisions belong to the real internal services.
import assert from 'node:assert/strict';
import { readFile, appendFile } from 'node:fs/promises';

export async function ciglResponse(root, input) {
  let wallet;
  try {
    wallet = JSON.parse(await readFile(`${root}/cigl-wallet.json`, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  }
  const knownHashes = [wallet.transactionHash];
  const wallets = [wallet];
  try {
    const renewed = JSON.parse(await readFile(`${root}/cigl-renewed-wallet.json`, 'utf8'));
    assert.equal(renewed.sender, wallet.sender);
    assert.equal(renewed.destination, wallet.destination);
    assert.equal(renewed.calldata, wallet.calldata);
    assert.equal(renewed.nonce, wallet.nonce + 1);
    assert.notEqual(renewed.transactionHash, wallet.transactionHash);
    wallet = renewed;
    knownHashes.push(wallet.transactionHash);
    wallets.push(wallet);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const hash = (byte) => `0x${byte.repeat(32)}`;
  let mined;
  try {
    mined = JSON.parse(await readFile(`${root}/cigl-mined.json`, 'utf8'));
    assert.ok(knownHashes.includes(mined.transactionHash));
    assert.equal(typeof mined.diverged, 'boolean');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const advanced = knownHashes.length === 2 || Boolean(mined);
  const anchor = { blockHash: hash(advanced ? '44' : '22'), requireCanonical: true };
  const nested = `0x${'22'.repeat(20)}`;
  switch (input.method) {
    case 'eth_getBlockByNumber':
      if (mined && ['0xa', '0xb', 'safe', 'finalized'].includes(input.params[0])) {
        assert.equal(input.params[1], false);
        const original = input.params[0] === '0xa';
        return {
          result: {
            number: original ? '0xa' : '0xb',
            hash: hash(original ? '22' : '44'),
            transactions: original ? [] : [mined.transactionHash],
          },
        };
      }
      if (input.params[0] !== 'latest') return undefined;
      assert.deepEqual(input.params, ['latest', false]);
      return {
        result: {
          number: advanced ? '0xb' : '0xa',
          hash: anchor.blockHash,
          stateRoot: hash(advanced ? '55' : '33'),
          gasLimit: '0x1000000',
          baseFeePerGas: '0x1',
          ...(mined ? { transactions: [mined.transactionHash] } : {}),
        },
      };
    case 'eth_getBlockByHash': {
      const [selected, full] = input.params;
      assert.equal(full, false);
      assert.ok(selected === hash('22') || (advanced && selected === hash('44')));
      const isAdvanced = selected === hash('44');
      return {
        result: {
          number: isAdvanced ? '0xb' : '0xa',
          hash: selected,
          stateRoot: hash(isAdvanced ? '55' : '33'),
        },
      };
    }
    case 'eth_getCode': {
      assert.deepEqual(input.params[1], anchor);
      const [address] = input.params;
      const source =
        address === wallet.destination
          ? 'local-contract-code'
          : address === nested
            ? 'local-contract-code-b'
            : '';
      return { result: `0x${Buffer.from(source).toString('hex')}` };
    }
    case 'eth_getBalance':
    case 'eth_getTransactionCount':
      assert.deepEqual(input.params, [wallet.sender, anchor]);
      return {
        result:
          input.method === 'eth_getBalance'
            ? `0x${'f'.repeat(64)}`
            : `0x${(wallet.nonce + (mined ? 1 : 0)).toString(16)}`,
      };
    case 'debug_traceTransaction': {
      assert.ok(mined);
      assert.equal(input.params[0], mined.transactionHash);
      const selected = wallets.find((value) => value.transactionHash === mined.transactionHash);
      const response = await ciglResponse(root, {
        method: 'debug_traceCall',
        params: [
          {
            from: selected.sender,
            to: selected.destination,
            data: selected.calldata,
            value: '0x0',
            gas: `0x${BigInt(selected.gasLimit).toString(16)}`,
          },
          anchor,
          input.params[1],
        ],
      });
      if (mined.diverged && input.params[1].tracer === 'callTracer')
        response.result.calls[0].to = `0x${'33'.repeat(20)}`;
      return response;
    }
    case 'debug_traceCall': {
      const [call, selected, options] = input.params;
      assert.deepEqual(selected, anchor);
      assert.equal(call.from, wallet.sender);
      assert.equal(call.to, wallet.destination);
      assert.equal(call.data, wallet.calldata);
      assert.equal('stateOverrides' in options, false);
      if (options.tracer === 'callTracer')
        return {
          result: {
            type: 'CALL',
            from: call.from,
            to: call.to,
            input: call.data,
            value: call.value,
            gas: call.gas,
            gasUsed: '0x1000',
            calls: [
              {
                type: 'STATICCALL',
                from: call.to,
                to: nested,
                input: `0x70a08231${'00'.repeat(12)}${'22'.repeat(20)}`,
                gas: '0x3e8',
                gasUsed: '0x1',
              },
            ],
          },
        };
      return {
        result: {
          failed: false,
          gas: 4096,
          returnValue: '',
          structLogs: [
            { pc: 0, op: 'STATICCALL', gas: 10000, gasCost: 100, depth: 1 },
            { pc: 0, op: 'STOP', gas: 999, gasCost: 0, depth: 2 },
            { pc: 1, op: 'STOP', gas: 9000, gasCost: 0, depth: 1 },
          ],
        },
      };
    }
    case 'eth_sendRawTransaction':
      assert.deepEqual(input.params, [wallet.signedTransaction]);
      await appendFile(
        `${root}/cigl-submissions.jsonl`,
        JSON.stringify({ transactionHash: wallet.transactionHash }) + '\n',
      );
      return { result: wallet.transactionHash };
    case 'eth_getTransactionByHash':
    case 'eth_getTransactionReceipt':
      assert.equal(input.params.length, 1);
      assert.ok(knownHashes.includes(input.params[0]), 'unrelated transaction observation');
      if (mined?.transactionHash === input.params[0]) {
        const selected = wallets.find((value) => value.transactionHash === mined.transactionHash);
        return {
          result:
            input.method === 'eth_getTransactionReceipt'
              ? {
                  transactionHash: selected.transactionHash,
                  from: selected.sender,
                  to: selected.destination,
                  blockHash: hash('44'),
                  blockNumber: '0xb',
                  transactionIndex: '0x0',
                  status: '0x1',
                  contractAddress: null,
                  logs: [],
                }
              : {
                  hash: selected.transactionHash,
                  from: selected.sender,
                  to: selected.destination,
                  nonce: `0x${selected.nonce.toString(16)}`,
                  chainId: '0x7a69',
                  blockHash: hash('44'),
                  blockNumber: '0xb',
                },
        };
      }
      return { result: null };
    default:
      return undefined;
  }
}
