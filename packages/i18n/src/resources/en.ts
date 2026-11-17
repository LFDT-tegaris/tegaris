export const en = {
  action: {
    cancel: 'Cancel',
    continue: 'Continue',
  },
  common: {
    greeting: 'Hello, {{name}}',
  },
} as const;

export type TranslationKey = 'action.cancel' | 'action.continue' | 'common.greeting';
