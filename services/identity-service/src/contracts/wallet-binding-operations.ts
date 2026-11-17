import { operationDefaults, type OperationContract } from './catalog.js';

/** Additive lifecycle for the already registered WalletBinding aggregate. */
export const walletBindingOperations = (['CREATE', 'REVOKE'] as const).map((mutation) => ({
  id: `ID-OP-WALLET-BINDING-${mutation}`,
  requestType: mutation === 'CREATE' ? 'WalletBindingCreation' : 'WalletBindingRevocation',
  responseType: 'WalletBinding',
  stateMachine: 'WALLET_BINDING',
  allowedFromStates: mutation === 'CREATE' ? [] : ['ACTIVE'],
  successStates: mutation === 'CREATE' ? ['ACTIVE'] : ['REVOKED'],
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  webauthnStepUpRequired: true,
  makerCheckerRequired: true,
  ...operationDefaults,
})) satisfies readonly OperationContract[];
