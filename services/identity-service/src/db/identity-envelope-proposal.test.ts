import { describe, expect, it } from 'vitest';

import {
  envelopeFixtureId,
  envelopeFixtureScope,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import type { EnvelopeProposal } from '../../../../packages/security-kernel/src/identity-envelope/types.js';
import { assertEnvelopeScopeNarrowing } from '@openpc/security-kernel';
import { AuthorityFenceError } from './authority-fence.js';
import { projectUsableEnvelopePermission } from './identity-envelope-proposal.js';

function proposal(): EnvelopeProposal {
  const usable = envelopeFixtureScope();
  usable.administration = {
    participantIds: [],
    privacyDomainIds: [],
    resourceIds: [],
    dataClasses: [],
    targetProfileIds: [],
    riskClasses: [],
    actionIntentIds: [],
  };
  return {
    envelopeId: envelopeFixtureId(60),
    semanticRevision: '1',
    participantId: envelopeFixtureId(1),
    participantEpoch: '1',
    authorityEpoch: '1',
    delegationEpoch: '0',
    issuance: 'PLATFORM_ROOT',
    usable,
    grantable: usable,
    issuer: {
      kind: 'PLATFORM',
      authority: {} as EnvelopeProposal['issuer']['authority'],
      platformContextId: envelopeFixtureId(4),
      platformAuthorityEpoch: '1',
      platformAuthorityDigest: `sha256:${'1'.padStart(64, '0')}`,
      parent: null,
    },
  };
}

function administrationProposal(): EnvelopeProposal {
  const value = proposal();
  const runtime = value.usable.runtime;
  const dimensions = {
    participantIds: [...runtime.participantIds],
    privacyDomainIds: [...runtime.privacyDomainIds],
    resourceIds: [...runtime.resourceIds],
    dataClasses: [...runtime.dataClasses],
    targetProfileIds: [...runtime.targetProfileIds],
    riskClasses: [...runtime.riskClasses],
  };
  value.usable = {
    ...value.usable,
    administration: {
      ...dimensions,
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
    },
    runtime: {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [],
      capabilityIds: [],
    },
  };
  value.grantable = structuredClone(value.usable);
  value.grantable.runtime.participantIds = [...dimensions.participantIds];
  value.grantable.runtime.privacyDomainIds = [...dimensions.privacyDomainIds];
  return value;
}

describe('typed envelope flat permission projection', () => {
  it('preserves a runtime-only capability and its exact dimensions', () => {
    const value = proposal();
    expect(projectUsableEnvelopePermission(value)).toEqual({
      privacyDomainIds: value.usable.runtime.privacyDomainIds,
      actionIntentIds: [],
      runtimeCapabilityIds: ['CALL_RESULT_DISCLOSURE'],
      resourceIds: value.usable.runtime.resourceIds,
      dataClasses: ['METADATA'],
      targetProfileIds: ['target-1'],
      riskClasses: ['HIGH'],
    });
  });

  it('rejects mixed slices instead of projecting an authority cross-product', () => {
    const value = proposal();
    value.usable.administration = {
      ...value.usable.runtime,
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
    };
    expect(() => projectUsableEnvelopePermission(value)).toThrow();
  });

  it('rejects dimensions in an unused runtime slice even when its capabilities are empty', () => {
    const value = administrationProposal();
    value.usable.runtime.participantIds = [...value.grantable.runtime.participantIds];
    value.usable.runtime.privacyDomainIds = [...value.grantable.runtime.privacyDomainIds];
    expect(value.usable.runtime.capabilityIds).toEqual([]);
    expect(() => projectUsableEnvelopePermission(value)).toThrow(AuthorityFenceError);
  });

  it('preserves administration permissions and the original bounds with an empty unused slice', () => {
    const value = administrationProposal();
    const originalBounds = structuredClone(value.grantable);
    expect(() => assertEnvelopeScopeNarrowing(value.grantable, value.usable)).not.toThrow();
    expect(projectUsableEnvelopePermission(value)).toEqual({
      privacyDomainIds: value.usable.administration.privacyDomainIds,
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
      runtimeCapabilityIds: [],
      resourceIds: value.usable.administration.resourceIds,
      dataClasses: value.usable.administration.dataClasses,
      targetProfileIds: value.usable.administration.targetProfileIds,
      riskClasses: value.usable.administration.riskClasses,
    });
    expect(value.grantable).toEqual(originalBounds);
  });
});
