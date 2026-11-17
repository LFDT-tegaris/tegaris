import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';

import { ActionPanel } from './action-panel';

it('does not invent actions when the server snapshot declares none', () => {
  render(<ActionPanel actions={[]} />);
  expect(
    screen.getByText('No action is currently authorized for this process.'),
  ).toBeInTheDocument();
});

it('wraps an arbitrarily long registered operation label within the action container', () => {
  render(
    <ActionPanel
      actions={[
        {
          actionIntentId: 'ACT-UI_MEMBERSHIP_GROUP_ROLE_DELEGATION_ROLLBACK-V1',
          actionIntentDigest: `sha256:${'1'.repeat(64)}`,
          operationId: 'commandUiMembershipGroupRoleDelegationROLLBACK',
          method: 'POST',
          path: '/api/v1/ui/process-domains/membership-group-role-delegation/actions/rollback',
          riskClass: 'STANDARD',
          stepUp: 'NONE',
          idempotency: 'KEY_24H_MINIMUM',
          etagRequired: true,
        },
      ]}
      session={{
        csrfToken: 'csrf',
        etag: 'etag',
        idempotencyKey: 'idempotency',
        locale: 'en',
        timeZone: 'UTC',
        density: 'COMFORTABLE',
        theme: 'LIGHT',
      }}
    />,
  );
  expect(screen.getByRole('button')).toHaveClass('max-w-full', 'break-all');
});
