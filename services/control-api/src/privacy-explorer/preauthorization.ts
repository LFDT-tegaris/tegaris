import { type PrivacyExplorerLocalContext, requireLocalContext } from './context.js';
import { immutableJsonCopy } from './immutable.js';
import { boundedString } from './profile-registration.js';

export type RegisteredPurposeAction = Readonly<{
  purpose: string;
  action: string;
  resource: string;
}>;
export type PrivacyExplorerPreauthorizedIntent = Readonly<{
  context: PrivacyExplorerLocalContext;
  purpose: string;
  action: string;
  resource: string;
}>;
const intents = new WeakSet<PrivacyExplorerPreauthorizedIntent>();

export const preauthorize = (
  context: PrivacyExplorerLocalContext,
  input: RegisteredPurposeAction,
): PrivacyExplorerPreauthorizedIntent => {
  const bound = requireLocalContext(context);
  const candidate = immutableJsonCopy(input);
  if (
    Reflect.ownKeys(candidate).length !== 3 ||
    !Object.hasOwn(candidate, 'purpose') ||
    !Object.hasOwn(candidate, 'action') ||
    !Object.hasOwn(candidate, 'resource')
  )
    throw new Error('common terminal denial');
  const purpose = boundedString(candidate.purpose, 'purpose');
  const action = boundedString(candidate.action, 'action');
  const resource = boundedString(candidate.resource, 'resource');
  if (
    resource !== bound.resource ||
    !bound.allowedPurposeActions.some(
      (allowed) => allowed.purpose === purpose && allowed.action === action,
    )
  )
    throw new Error('common terminal denial');
  const intent = Object.freeze({ context: bound, purpose, action, resource });
  intents.add(intent);
  return intent;
};
export const requirePreauthorizedIntent = (value: unknown): PrivacyExplorerPreauthorizedIntent => {
  if (
    !value ||
    typeof value !== 'object' ||
    !intents.has(value as PrivacyExplorerPreauthorizedIntent)
  )
    throw new Error('unpreauthorized intent');
  return value as PrivacyExplorerPreauthorizedIntent;
};
