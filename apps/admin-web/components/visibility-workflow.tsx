import Link from 'next/link';

import type { AuthorizedAction } from '@openpc/ui-shell';

import { PolicyComposer } from './policy-composer';

export function VisibilityWorkflow(
  props: Readonly<{
    actions: readonly AuthorizedAction[];
    authorityContextKey: string;
    participantRef: string;
  }>,
) {
  return (
    <div className="space-y-4">
      <section aria-labelledby="state-read-visibility" className="space-y-2">
        <h2 id="state-read-visibility" className="text-xl font-semibold">
          Visibility policies
        </h2>
        <p className="max-w-3xl">
          Govern state reads, transactions, whole receipts, events and Explorer disclosure with a
          typed policy. Choose the policy ID, purpose, dimensions and fields for each simulation.
          Active access depends on approval, activation and current Facts.
        </p>
        <p className="max-w-3xl">
          State reads use STATE_READ, transactions use TRANSACTION_READ, receipts use RECEIPT_READ
          and events use EVENT_READ. Receipts are released whole; a denied state output withholds
          the complete result. Explorer reads use the purpose governed by their registered profile
          and disclosure policy.
        </p>
        <p>
          Simulate the policy here, then use{' '}
          <Link className="underline" href="/govern/policy-releases">
            policy releases
          </Link>{' '}
          for approval and activation. Simulation does not change active access.
        </p>
      </section>
      <PolicyComposer {...props} stateReadVisibility />
    </div>
  );
}
