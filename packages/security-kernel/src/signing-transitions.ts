import { signingRotationActions } from './signing-operations.js';

export const signingRotationStates = [
  'REQUESTED',
  'APPROVED',
  'PREPARED',
  'DISTRIBUTED',
  'VERIFIED',
  'CUTOVER_FENCED',
  'OBSERVING',
  'OLD_REVOKED',
  'OLD_RETIRED',
  'COMPLETE',
  'FAILED',
  'RECOVERING',
] as const;
export type SigningRotationState = (typeof signingRotationStates)[number];
type ProviderStep = readonly [
  slot: string,
  method: 'PREPARE' | 'DISTRIBUTE' | 'PROVE' | 'REVOKE' | 'RETIRE',
];
export interface SigningTransitionEffects {
  readonly kind: 'ADVANCE' | 'FAILURE' | 'RECOVERY' | 'RENEWAL' | 'FORWARD_RECOVERY';
  readonly providerSteps: readonly ProviderStep[];
  readonly prepare: boolean;
  readonly admitTrust: boolean;
  readonly cutover: boolean;
  readonly revoke: boolean;
  readonly eventType: string | null;
  readonly resumeFrom: SigningRotationState | null;
}
interface Transition {
  readonly action: string;
  readonly prior: SigningRotationState;
  readonly target: SigningRotationState;
  readonly effects: SigningTransitionEffects;
}
// Each successful ADVANCE owns its provider slots and local effects. Recovery never acquires them.
export const signingAdvanceTransitions: readonly (readonly [
  SigningRotationState,
  SigningRotationState,
  readonly ProviderStep[],
])[] = [
  ['APPROVED', 'PREPARED', [['new', 'PREPARE']]],
  ['PREPARED', 'DISTRIBUTED', [['new', 'DISTRIBUTE']]],
  [
    'DISTRIBUTED',
    'VERIFIED',
    [
      ['old', 'PROVE'],
      ['new', 'PROVE'],
    ],
  ],
  ['VERIFIED', 'CUTOVER_FENCED', []],
  ['CUTOVER_FENCED', 'OBSERVING', [['effective', 'PROVE']]],
  ['OBSERVING', 'OLD_REVOKED', [['old', 'REVOKE']]],
  ['OLD_REVOKED', 'OLD_RETIRED', [['old', 'RETIRE']]],
  ['OLD_RETIRED', 'COMPLETE', []],
];
const noEffects = (kind: SigningTransitionEffects['kind']): SigningTransitionEffects => ({
  kind,
  providerSteps: [],
  prepare: false,
  admitTrust: false,
  cutover: false,
  revoke: false,
  eventType: null,
  resumeFrom: null,
});
const transitions: Transition[] = [];
for (const [prior, target, providerSteps] of signingAdvanceTransitions) {
  const effects: SigningTransitionEffects = {
    kind: 'ADVANCE',
    providerSteps,
    prepare: target === 'PREPARED',
    admitTrust: target === 'VERIFIED',
    cutover: target === 'CUTOVER_FENCED',
    revoke: target === 'OLD_REVOKED',
    eventType:
      target === 'OLD_REVOKED'
        ? 'io.openpc.ops.secret.revoked.v1'
        : target === 'COMPLETE'
          ? 'io.openpc.ops.secret.rotated.v1'
          : null,
    resumeFrom: null,
  };
  transitions.push({ action: signingRotationActions.advance, prior, target, effects });
  transitions.push({
    action: signingRotationActions.advance,
    prior: 'RECOVERING',
    target,
    effects: { ...effects, resumeFrom: prior },
  });
  transitions.push({
    action: signingRotationActions.recover,
    prior,
    target: prior,
    effects: noEffects('RENEWAL'),
  });
  transitions.push({
    action: signingRotationActions.recover,
    prior,
    target: 'RECOVERING',
    effects: noEffects('RECOVERY'),
  });
}
for (const prior of [...signingAdvanceTransitions.map(([from]) => from), 'RECOVERING'] as const)
  transitions.push({
    action: signingRotationActions.advance,
    prior,
    target: 'FAILED',
    effects: noEffects('FAILURE'),
  });
transitions.push({
  action: signingRotationActions.recover,
  prior: 'RECOVERING',
  target: 'RECOVERING',
  effects: noEffects('RECOVERY'),
});
transitions.push({
  action: signingRotationActions.recover,
  prior: 'FAILED',
  target: 'RECOVERING',
  effects: noEffects('FORWARD_RECOVERY'),
});
for (const transition of transitions) {
  for (const step of transition.effects.providerSteps) Object.freeze(step);
  Object.freeze(transition.effects.providerSteps);
  Object.freeze(transition.effects);
  Object.freeze(transition);
}
for (const advance of signingAdvanceTransitions) Object.freeze(advance);
Object.freeze(signingAdvanceTransitions);
export const signingTransitionMatrix: readonly Transition[] = Object.freeze(transitions);
export function signingTransitionEffects(
  action: string,
  prior: string,
  target: string,
): SigningTransitionEffects | undefined {
  return signingTransitionMatrix.find(
    (transition) =>
      transition.action === action && transition.prior === prior && transition.target === target,
  )?.effects;
}
