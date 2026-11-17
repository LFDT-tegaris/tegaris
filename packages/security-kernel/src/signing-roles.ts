/** Closed role grants. A target key cannot acquire the other role's profiles during rotation. */
export const signingRoleProfiles = Object.freeze({
  BUSINESS_EFFECT: Object.freeze([
    'pc.control.notification-endpoint.create',
    'pc.control.notification-endpoint.update',
    'pc.control.notification-endpoint.verify',
    'pc.control.notification.create',
    'pc.control.notification.acknowledge',
    'pc.control.work-item.create',
    'pc.control.work-item.update',
    'pc.control.work-item.claim',
    'pc.control.work-item.complete',
    'pc.control.indexer-profile.create',
    'pc.control.indexer-profile.update',
    'pc.control.evidence-hold.create',
    'pc.control.evidence-hold.release',
    'pc.control.evidence-participant-hold.create',
    'pc.control.evidence-participant-hold.release',
    'pc.control.evidence-deletion.local',
    'pc.control.evidence-deletion.batch',
    'pc.control.evidence-deletion.raw-proof',
    'pc.control.evidence-deletion.projection',
    'pc.control.store-retirement.admit',
    'pc.control.runtime-artifact.disposition',
    'pc.control.evidence-deletion.runtime-artifact',
    'pc.control.retention-policy.activate',
    'pc.control.retention-policy.retire',
    'pc.identity.workload-renewal-policy.create',
    'pc.identity.workload-renewal-policy.revise',
    'pc.identity.workload-renewal-policy.suspend',
    'pc.identity.workload-renewal-policy.revoke',
  ]),
  LIFECYCLE_EVIDENCE: Object.freeze([
    'pc.control.signing-rotation.advance',
    'pc.control.signing-rotation.recover',
  ]),
});
export type SigningRole = keyof typeof signingRoleProfiles;

/** Receipt keys retain their exact admitted subset. Lifecycle evidence retains
 * both closed lifecycle grants; neither rotation can acquire another role. The
 * business upper bound is the immutable trust format's existing 64-grant limit. */
export const signingRoleGrantBounds = Object.freeze({
  BUSINESS_EFFECT: Object.freeze({ minimum: 1, maximum: 64 }),
  LIFECYCLE_EVIDENCE: Object.freeze({ minimum: 2, maximum: 2 }),
});
