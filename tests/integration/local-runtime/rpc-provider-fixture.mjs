// Controlled external JSON-RPC provider. No internal authority or business
// state is simulated here. All requests arrive through real mutual TLS.
import { createServer } from 'node:https';
import { readFile, appendFile, writeFile } from 'node:fs/promises';
import { createHash, X509Certificate } from 'node:crypto';
import { deploymentResponse } from './rpc-deployment-fixture.mjs';
import { ciglResponse } from './rpc-cigl-fixture.mjs';
import {
  relationshipSourceFault,
  relationshipSourceLogs,
  sourceBlockHeader,
} from './rpc-source-header-fixture.mjs';
const root = process.env.OPENPC_RPC_PROVIDER_ROOT;
if (!root) throw new Error('Owned RPC provider root required');
const readContractAddress = process.env.OPENPC_RPC_READ_CONTRACT_ADDRESS ?? `0x${'11'.repeat(20)}`;
if (!/^0x[0-9a-f]{40}$/u.test(readContractAddress))
  throw new Error('Invalid controlled read contract');
const read = (name) => readFile(`${root}/${name}`);
async function holdResponse(kind, maximumMs) {
  const hold = await read(`${kind}-hold`).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (hold?.toString() !== 'hold') return;
  const contactedAt = Date.now();
  await writeFile(`${root}/${kind}-contact`, String(contactedAt), { mode: 0o600 });
  while ((await read(`${kind}-hold`)).toString() !== 'release') {
    if (Date.now() - contactedAt >= maximumMs) throw new Error('external hold expired');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
const server = createServer(
  {
    key: await read('server.key'),
    cert: await read('server.pem'),
    ca: await read('ca.pem'),
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
  },
  async (req, res) => {
    try {
      if (!req.socket.authorized || req.url !== '/rpc' || req.method !== 'POST') {
        res.writeHead(403).end();
        return;
      }
      const client = new X509Certificate(await read('client.pem'));
      if (!req.socket.getPeerCertificate().raw.equals(client.raw)) {
        res.writeHead(403).end();
        return;
      }
      let body = Buffer.alloc(0);
      for await (const chunk of req) {
        body = Buffer.concat([body, chunk]);
        if (body.length > 65536) {
          res.writeHead(413).end();
          return;
        }
      }
      const input = JSON.parse(body);
      await appendFile(
        `${root}/requests.jsonl`,
        JSON.stringify({
          method: input.method,
          digest: createHash('sha256').update(body).digest('hex'),
        }) + '\n',
        { mode: 0o600 },
      );
      // Only fixture-owner files determine external business observations.
      // Persist exact occurrences so acquisition and independent admission see
      // the same external result, including across provider process restarts.
      if (input.method === 'acquireObservation') {
        const owned = JSON.parse(await read('fact-inputs.json'));
        const request = input.request;
        const context = input.context;
        if (
          typeof owned.externalSatisfied !== 'boolean' ||
          !Number.isSafeInteger(owned.maximumAgeMs) ||
          owned.maximumAgeMs < 1 ||
          owned.maximumAgeMs > 120000 ||
          !request ||
          !context ||
          !/^[0-9a-f]{64}$/u.test(context.idempotencyDigest) ||
          Date.parse(context.deadlineAt) <= Date.now() ||
          context.profileDigest !== request.providerConfigurationDigest ||
          context.cancellation?.mode !== 'NO_NEW_EFFECT_AFTER_CANCELLATION' ||
          context.reconciliation?.mode !== 'EXACT_OCCURRENCE'
        )
          throw new Error('bad external adapter request');
        const hashJson = (value) =>
          createHash('sha256').update(JSON.stringify(value)).digest('hex');
        const ordered = {
          participantId: request.participantId,
          privacyDomainId: request.privacyDomainId,
          providerId: request.providerId,
          providerVersion: request.providerVersion,
          providerConfigurationDigest: request.providerConfigurationDigest,
          sourceOccurrence: request.sourceOccurrence,
          condition: request.condition,
          inputDigest: request.inputDigest,
        };
        if (Object.keys(request).sort().join(',') !== Object.keys(ordered).sort().join(','))
          throw new Error('bad external request shape');
        const requestDigest = hashJson(['openpc:external-decision-request:v1', ordered]);
        if (
          context.idempotencyDigest !==
          hashJson([
            'openpc:external-decision-idempotency:v1',
            requestDigest,
            request.sourceOccurrence,
          ])
        )
          throw new Error('bad external occurrence');
        const path = `${root}/observation-${context.idempotencyDigest}.json`;
        const observedAtMs = Date.now();
        const observation = {
          requestDigest,
          sourceOccurrence: request.sourceOccurrence,
          participantId: request.participantId,
          privacyDomainId: request.privacyDomainId,
          providerId: request.providerId,
          providerVersion: request.providerVersion,
          providerConfigurationDigest: request.providerConfigurationDigest,
          condition: request.condition,
          satisfied: owned.externalSatisfied,
          observedAtMs,
          expiresAtMs: observedAtMs + owned.maximumAgeMs,
        };
        observation.responseDigest = hashJson([
          'openpc:external-decision-observation:v1',
          observation.requestDigest,
          observation.sourceOccurrence,
          observation.participantId,
          observation.privacyDomainId,
          observation.providerId,
          observation.providerVersion,
          observation.providerConfigurationDigest,
          observation.condition,
          observation.satisfied,
          observation.observedAtMs,
          observation.expiresAtMs,
        ]);
        await writeFile(path, JSON.stringify(observation), { flag: 'wx', mode: 0o600 }).catch(
          (error) => {
            if (error.code !== 'EEXIST') throw error;
          },
        );
        const bytes = await readFile(path);
        res
          .writeHead(200, { 'content-type': 'application/json', 'content-length': bytes.length })
          .end(bytes);
        return;
      }
      const reply = { jsonrpc: '2.0', id: input.id };
      const hash = (byte) => `0x${byte.repeat(32)}`;
      // The governed visibility journey owns this separate external record.
      // Its complete transaction/receipt and exact ABI event are independent
      // of the relationship source acquisition corpus below.
      const eventTopic = '0x938d2ee5be9cfb0f7270ee2eff90507e94b37625d9d2b3a61c97d30a4560b829';
      const visibilityRead =
        (['eth_getTransactionByHash', 'eth_getTransactionReceipt'].includes(input.method) &&
          input.params[0] === hash('44')) ||
        (input.method === 'eth_getLogs' && input.params[0]?.topics?.[0] === eventTopic);
      if (visibilityRead) {
        const mode = await read('visibility-mode').then(
          (bytes) => bytes.toString().trim(),
          (error) => {
            if (error.code === 'ENOENT') return 'COMPLETE';
            throw error;
          },
        );
        const log = {
          address: `0x${'11'.repeat(20)}`,
          blockHash: hash('22'),
          blockNumber: '0xa',
          transactionHash: hash('44'),
          transactionIndex: '0x0',
          logIndex: '0x0',
          removed: false,
          topics: [eventTopic],
          data: `0x${'0'.repeat(63)}7`,
        };
        if (mode === 'WRONG_HASH') log.blockHash = hash('55');
        if (mode === 'REMOVED') log.removed = true;
        if (input.method === 'eth_getTransactionByHash') {
          reply.result = {
            hash: mode === 'WRONG_HASH' ? hash('55') : hash('44'),
            blockHash: hash('22'),
            blockNumber: '0xa',
            transactionIndex: '0x0',
            from: `0x${'33'.repeat(20)}`,
            to: `0x${'11'.repeat(20)}`,
            gas: '0x5208',
            input: '0x',
            nonce: '0x1',
            value: '0x7',
          };
        } else if (input.method === 'eth_getTransactionReceipt') {
          reply.result = {
            transactionHash: hash('44'),
            transactionIndex: '0x0',
            blockHash: log.blockHash,
            blockNumber: '0xa',
            from: `0x${'33'.repeat(20)}`,
            to: log.address,
            cumulativeGasUsed: '0x5208',
            gasUsed: '0x5208',
            contractAddress: null,
            logs: [log],
            logsBloom: `0x${'00'.repeat(256)}`,
            status: '0x1',
          };
        } else {
          const filter = input.params[0];
          if (
            filter.address !== log.address ||
            filter.blockHash !== hash('22') ||
            JSON.stringify(filter.topics) !== JSON.stringify([eventTopic])
          )
            throw new Error('bad visibility log query');
          if (
            ['ORDERED_RELATIONSHIP', 'AFTER_RELATIONSHIP', 'CLOSED_RELATIONSHIP'].includes(mode)
          ) {
            // The separately acquired opening occurs at log 1. Protected logs
            // before it and at the same occurrence cannot borrow its grant.
            const indexes =
              mode === 'AFTER_RELATIONSHIP'
                ? [2]
                : mode === 'CLOSED_RELATIONSHIP'
                  ? [1, 3, 4]
                  : [0, 1, 2];
            reply.result = indexes.map((index) => ({
              ...log,
              logIndex: `0x${index.toString(16)}`,
              data: `0x${(index === (mode === 'CLOSED_RELATIONSHIP' ? 1 : 2) ? 7 : 999).toString(16).padStart(64, '0')}`,
            }));
          } else reply.result = mode === 'EMPTY' ? [] : [log];
        }
        const bytes = Buffer.from(JSON.stringify(reply));
        // Hold only the controlled protected response. Header/source reads
        // remain available so the real acquisition owner can observe a fork.
        await holdResponse('visibility', 2_000);
        res
          .writeHead(200, { 'content-type': 'application/json', 'content-length': bytes.length })
          .end(bytes);
        return;
      }
      // Only the external fixture owner can change this chain. Requests cannot
      // supply a fork or alter internal admission/qualification/business state.
      const branch = await read('source-chain.json').then(
        (bytes) => JSON.parse(bytes),
        (error) => {
          if (error.code === 'ENOENT') return null;
          throw error;
        },
      );
      if (
        branch &&
        (Object.keys(branch).sort().join(',') !== 'forkHeight,hashOffset' ||
          !Number.isSafeInteger(branch.forkHeight) ||
          branch.forkHeight < 10 ||
          branch.forkHeight > 22 ||
          !Number.isSafeInteger(branch.hashOffset) ||
          branch.hashOffset < 1 ||
          branch.hashOffset > 128)
      )
        throw new Error('bad controlled chain branch');
      const deployment =
        (await ciglResponse(root, input)) ?? (await deploymentResponse(root, input));
      if (deployment?.loseResponse) {
        req.socket.destroy();
        return;
      }
      if (deployment) reply.result = deployment.result;
      else
        switch (input.method) {
          case 'eth_chainId':
            reply.result = '0x7a69';
            break;
          case 'eth_getBlockByNumber':
            if (
              input.params.length !== 2 ||
              input.params[1] !== false ||
              !/^0x(?:0|[1-9a-f][0-9a-f]*)$/u.test(input.params[0])
            )
              throw new Error('bad header query');
            reply.result =
              input.params[0] === '0x0'
                ? { hash: hash('11'), number: '0x0' }
                : sourceBlockHeader(Number.parseInt(input.params[0].slice(2), 16), branch);
            break;
          case 'eth_getLogs':
          case 'eth_getTransactionReceipt': {
            const owned = JSON.parse(await read('fact-inputs.json'));
            const signature = '0xb1fad1cf1959b1f2ff99e75268b8f16a068328466f001adc4e591b68e642baf3';
            const contract = owned.relationshipContractAddress ?? `0x${'11'.repeat(20)}`;
            const logs = relationshipSourceLogs(owned, branch);
            if (input.method === 'eth_getLogs') {
              const [filter] = input.params;
              if (
                input.params.length !== 1 ||
                filter.address !== contract ||
                JSON.stringify(filter.topics) !== JSON.stringify([signature])
              )
                throw new Error('bad pinned relationship query');
              if (filter.blockHash === hash('44')) {
                reply.error = { code: -32000, message: 'unknown block' };
                break;
              }
              if (
                !Array.from(
                  { length: 13 },
                  (_, index) => sourceBlockHeader(10 + index, branch).hash,
                ).includes(filter.blockHash)
              )
                throw new Error('bad pinned relationship query');
              reply.result = relationshipSourceFault(
                logs.filter((log) => log.blockHash === filter.blockHash),
                owned.relationshipFault,
              );
            } else {
              const log = logs.find((item) => item.transactionHash === input.params[0]);
              if (input.params.length !== 1 || !log)
                throw new Error('unknown relationship receipt');
              reply.result = {
                transactionHash: log.transactionHash,
                transactionIndex: log.transactionIndex,
                blockHash: log.blockHash,
                blockNumber: log.blockNumber,
                status: '0x1',
                logs: logs.filter((item) => item.transactionHash === log.transactionHash),
              };
            }
            break;
          }
          case 'eth_getBlockByHash':
            if (JSON.stringify(input.params) !== JSON.stringify([hash('22'), false]))
              throw new Error('bad anchor query');
            reply.result = { hash: hash('22'), number: '0xa', stateRoot: hash('33') };
            break;
          case 'web3_clientVersion':
            reply.result = 'controlled-provider/v1';
            break;
          case 'eth_getCode': {
            const [address, anchor] = input.params;
            const knownAddress =
              address === readContractAddress ||
              address === JSON.parse(await read('fact-inputs.json')).relationshipContractAddress;
            if (
              input.params.length !== 2 ||
              !knownAddress ||
              !Array.from({ length: 13 }, (_, index) => sourceBlockHeader(10 + index, branch)).some(
                (header) =>
                  JSON.stringify(anchor) ===
                  JSON.stringify({ blockHash: header.hash, requireCanonical: true }),
              )
            )
              throw new Error('bad hash-pinned source code query');
            reply.result = `0x${Buffer.from('local-contract-code').toString('hex')}`;
            break;
          }
          case 'eth_call': {
            const [call, anchor] = input.params;
            const probeTarget =
              call.to === `0x${'77'.repeat(20)}` ||
              (call.from === `0x${'66'.repeat(20)}` &&
                call.data === '0x01020304' &&
                call.to === JSON.parse(await read('fact-inputs.json')).relationshipContractAddress);
            const probeCall =
              call.from === `0x${'66'.repeat(20)}` && probeTarget && call.data === '0x01020304';
            const governedCall =
              !('from' in call) &&
              call.to === readContractAddress &&
              call.data === `0x70a08231${'0'.repeat(24)}${'1'.repeat(40)}`;
            if ((!probeCall && !governedCall) || anchor.requireCanonical !== true)
              throw new Error('bad hash-pinned call');
            if (
              (probeCall && !branch && anchor.blockHash === hash('22')) ||
              (governedCall &&
                Array.from(
                  { length: 13 },
                  (_, index) => sourceBlockHeader(10 + index, branch).hash,
                ).includes(anchor.blockHash))
            )
              reply.result = governedCall ? `0x${'00'.repeat(30)}1234` : '0x1234';
            else if (anchor.blockHash === hash('44'))
              reply.error = { code: -32000, message: 'unknown block' };
            else if (anchor.blockHash === hash('55'))
              reply.error = { code: -32001, message: 'noncanonical block' };
            else throw new Error('unregistered block');
            break;
          }
          default:
            reply.error = { code: -32601, message: 'method not found' };
        }
      // Final independent header read for this two-confirmation reorg. Source
      // acquisition has already finished; no internal verifier is bypassed.
      if (input.method === 'eth_getBlockByNumber' && /^fact-reorg:[0-9a-f]{64}:5$/u.test(input.id))
        await holdResponse('reorg-observation', 10_000);
      const bytes = JSON.stringify(reply);
      res
        .writeHead(200, {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(bytes),
        })
        .end(bytes);
    } catch {
      res.writeHead(400).end();
    }
  },
);
server.listen(3008, '0.0.0.0');
process.once('SIGTERM', () => server.close());
