import i18next from 'i18next';

import { en } from './resources/en.js';

export const defaultLanguage = 'en';
export const resources = { en: { translation: en } } as const;

export async function createOpenPcI18n(language = defaultLanguage) {
  const instance = i18next.createInstance();
  await instance.init({
    fallbackLng: defaultLanguage,
    interpolation: { escapeValue: true },
    lng: language,
    resources,
  });
  return instance;
}
