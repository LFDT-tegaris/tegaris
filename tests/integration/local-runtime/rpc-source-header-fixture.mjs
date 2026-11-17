// Controlled external chain data for source acquisition and finality tests.
export function sourceBlockHeader(number, branch = null) {
  if (!Number.isSafeInteger(number) || number < 10 || number > 22) return null;
  const hash = (byte) => `0x${byte.toString(16).padStart(2, '0').repeat(32)}`;
  return {
    number: `0x${number.toString(16)}`,
    hash: hash(number + 24 + (branch && number >= branch.forkHeight ? branch.hashOffset : 0)),
    parentHash: hash(
      number + 23 + (branch && number - 1 >= branch.forkHeight ? branch.hashOffset : 0),
    ),
    nonce: null,
    sha3Uncles: hash(0),
    logsBloom: null,
    transactionsRoot: hash(0),
    stateRoot: hash(0x33),
    receiptsRoot: hash(0),
    miner: `0x${'11'.repeat(20)}`,
    difficulty: '0x0',
    totalDifficulty: null,
    extraData: '0x',
    size: '0x1',
    gasLimit: '0x1',
    gasUsed: '0x0',
    timestamp: `0x${number.toString(16)}`,
    transactions: [],
    uncles: [],
    baseFeePerGas: null,
    withdrawalsRoot: null,
    blobGasUsed: null,
    excessBlobGas: null,
    parentBeaconBlockRoot: null,
    requestsHash: null,
  };
}

// The provider qualification corpus and later acquisition observe these same
// externally owned logs. This function supplies no internal admission state.
export function relationshipSourceLogs(owned, branch = null) {
  if (!Array.isArray(owned.relationshipEvents) || owned.relationshipEvents.length > 64)
    throw new Error('bad controlled relationship events');
  const signature = '0xb1fad1cf1959b1f2ff99e75268b8f16a068328466f001adc4e591b68e642baf3';
  const contract = owned.relationshipContractAddress ?? `0x${'11'.repeat(20)}`;
  if (!/^0x[0-9a-f]{40}$/u.test(contract)) throw new Error('bad relationship contract');
  const word = (value) => BigInt(value).toString(16).padStart(64, '0');
  return owned.relationshipEvents.map((event, index) => {
    const header = sourceBlockHeader(event.block, branch);
    if (
      !header ||
      ![0, 1, 2].includes(event.transition) ||
      !/^0x[0-9a-f]{64}$/u.test(event.entityTopic) ||
      !/^0x[0-9a-f]{64}$/u.test(event.subjectTopic) ||
      !Number.isSafeInteger(event.logIndex ?? index) ||
      (event.logIndex ?? index) < 0
    )
      throw new Error('bad controlled relationship event');
    return {
      address: contract,
      blockNumber: header.number,
      blockHash: header.hash,
      transactionHash: `0x${word(1000 + event.block)}`,
      transactionIndex: '0x0',
      logIndex: `0x${(event.logIndex ?? index).toString(16)}`,
      removed: false,
      topics: [signature, event.entityTopic, event.subjectTopic],
      data: `0x${word(event.transition)}${word(event.from)}${word(event.through ?? '18446744073709551615')}`,
    };
  });
}

// Faults alter only the controlled external response, never admitted state.
export function relationshipSourceFault(logs, fault) {
  if (fault === undefined || fault === null) return logs;
  if (!logs.length) throw new Error('relationship fault requires an occurrence');
  const first = structuredClone(logs[0]);
  if (fault === 'duplicate') return [first, structuredClone(first), ...logs.slice(1)];
  if (fault === 'conflict')
    return [
      first,
      { ...first, data: `0x${'0'.repeat(63)}1${first.data.slice(66)}` },
      ...logs.slice(1),
    ];
  if (fault === 'decode') return [{ ...first, data: '0x00' }, ...logs.slice(1)];
  throw new Error('unknown relationship source fault');
}
