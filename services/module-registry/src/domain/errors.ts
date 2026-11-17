export type ModuleErrorCode =
  `PC-MODULE-${7000 | 7001 | 7002 | 7003 | 7004 | 7005 | 7006 | 7007 | 7008 | 7009}`;
export type PolicyErrorCode = `PC-POLICY-${2000 | 2001 | 2002 | 2003 | 2004 | 2005}`;

/** Only exhausted, known-aborted PostgreSQL serialization/deadlock attempts. */
export class PolicyTransactionConflict extends Error {
  constructor() {
    super('Policy transaction conflict');
    this.name = 'PolicyTransactionConflict';
  }
}

/** Identity transport failure does not establish an authorization decision. */
export class PolicyIdentityUnavailable extends Error {
  constructor() {
    super('Identity authorization unavailable');
    this.name = 'PolicyIdentityUnavailable';
  }
}

export class ContractError extends Error {
  constructor(
    readonly code: ModuleErrorCode | PolicyErrorCode,
    readonly detail?: string,
  ) {
    super(code);
    this.name = 'ContractError';
  }
}
