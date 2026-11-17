import { executionRegistry } from '../contracts/privacy-explorer-adapter.js';

export type PrivacyExplorerOutcome = 'COMPLETE' | 'PARTIAL' | 'UNKNOWN' | 'UNAVAILABLE';
export type OutcomeClassification = Readonly<{
  outcome: PrivacyExplorerOutcome;
  truthState: string;
  recordsAllowed: boolean;
  cursorLawId: string;
}>;

export const classifyOutcome = (outcome: PrivacyExplorerOutcome): OutcomeClassification => {
  const definition = executionRegistry.resultDefinitions.find((entry) => entry.outcome === outcome);
  if (!definition || definition.authorityEffectId !== 'NO_AUTHORITY')
    throw new Error('unknown non-authoritative outcome');
  return Object.freeze({
    outcome,
    truthState: definition.truthState,
    recordsAllowed: definition.recordLawId === 'RECORDS_ALLOWED',
    cursorLawId: definition.cursorLawId,
  });
};

export const rejectEmptySuccess = (outcome: PrivacyExplorerOutcome, recordCount: number) => {
  if (!Number.isInteger(recordCount) || recordCount < 0) throw new Error('invalid record count');
  const classification = classifyOutcome(outcome);
  if (outcome === 'COMPLETE' && recordCount === 0)
    throw new Error('absence cannot be represented as COMPLETE');
  if (!classification.recordsAllowed && recordCount !== 0)
    throw new Error('non-complete outcome cannot expose records');
  return classification;
};
