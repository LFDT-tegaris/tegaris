import { resourceReadAuthoritySql } from './resource-read-authority.js';

// Collection admission has already authenticated the context and its finite
// Participant anchor. Each row still needs exactly one complete READ chain;
// neither the anchor nor knowledge of an approval ID grants row visibility.
export const approvalReadAuthoritySql = resourceReadAuthoritySql(
  'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  'request.approval_request_id',
);
