import { executionRegistry } from '../contracts/privacy-explorer-adapter.js';

type Application =
  | (typeof executionRegistry.lifecycleApplications)[number]
  | (typeof executionRegistry.conditionApplications)[number]
  | (typeof executionRegistry.cancellationApplications)[number]
  | (typeof executionRegistry.contributionApplications)[number];

export type ReducerInput = Readonly<{
  state: string;
  operationId: string;
  eventId: string;
  guardId: string;
  conditionDefinitionId?: string;
}>;
export type ReducedTransition = Readonly<{
  state: string;
  rawStateEffectId: string;
  deliveryEffectId: string;
  adapterEffectId: string;
  retainedFactId: string;
  disposition: Application['disposition'];
}>;

const applications = [
  ...executionRegistry.lifecycleApplications,
  ...executionRegistry.conditionApplications,
  ...executionRegistry.cancellationApplications,
  ...executionRegistry.contributionApplications,
] as const;

export const initialPrivacyExplorerState = executionRegistry.states[0];

export const reducePrivacyExplorerTransition = (input: ReducerInput): ReducedTransition => {
  const matches = applications.filter((row) => {
    if (
      row.fromStateId !== input.state ||
      row.operationId !== input.operationId ||
      row.eventId !== input.eventId ||
      row.guardId !== input.guardId
    )
      return false;
    const disposition = row.disposition as Record<string, unknown>;
    return input.conditionDefinitionId === undefined
      ? disposition.kind !== 'CONDITION'
      : disposition.kind === 'CONDITION' &&
          disposition.conditionDefinitionId === input.conditionDefinitionId;
  });
  if (matches.length !== 1) throw new Error('undeclared or ambiguous Privacy Explorer transition');
  const row = matches[0] as Application;
  return Object.freeze({
    state: row.toStateId,
    rawStateEffectId: row.rawStateEffectId,
    deliveryEffectId: row.deliveryEffectId,
    adapterEffectId: row.adapterEffectId,
    retainedFactId: row.retainedFactId,
    disposition: row.disposition,
  });
};
