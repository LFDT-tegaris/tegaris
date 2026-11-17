import { z } from 'zod';
import { walletBindingCreation } from '../domain/wallet-binding.js';

export const walletBindingView = z.strictObject({
  ...walletBindingCreation.shape,
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  state: z.enum(['ACTIVE', 'REVOKED']),
  bindingEpoch: z.string().regex(/^[1-9][0-9]*$/u),
  revision: z.string().regex(/^[1-9][0-9]*$/u),
  operationId: z.uuidv7(),
  permissionEffect: z.literal('NONE_WITHOUT_EFFECTIVE_AUTHORITY'),
});
