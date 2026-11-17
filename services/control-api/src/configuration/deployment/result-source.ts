import { readFileSync } from 'node:fs';
import type { PoolClient } from 'pg';

let source: string | undefined;
export interface DeploymentResultSource {
  deployment_intent_id: string;
  command_id: string;
  attempt_id: string;
  target_runtime_id: string;
  chain_id: string;
  genesis_digest: string;
  transaction_hash: string;
  intent_digest: string;
  preparation_digest: string;
  preparation_bytes: Buffer;
  publication_bytes: Buffer;
  execution_principal_id: string;
  execution_workload_id: string;
  actor_principal_id: string;
  sequence: string | null;
  signed_bytes: Buffer | null;
  result_digest: string | null;
  result_created_at: string | null;
  association_bytes: Buffer | null;
  activation_bytes: Buffer | null;
  activation_sequence: string | null;
  association_sequence: string | null;
  participant_epoch: string | null;
  association_current: boolean | null;
  successor_command_id: string | null;
}

export function selectDeploymentResultSource(
  client: Pick<PoolClient, 'query'>,
  command: string,
  participant: string,
  privacy: string,
) {
  source ??= readFileSync(new URL('./result-source.sql', import.meta.url), 'utf8');
  return client.query<DeploymentResultSource>(source, [command, participant, privacy]);
}
