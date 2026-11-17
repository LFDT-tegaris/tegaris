import { expect, type Page } from '@playwright/test';

// Exercise the authorized catalogue, including its exclusion of the maker.
// The workload form deliberately does not accept pasted principal identifiers.
export async function selectWorkloadPrincipals(
  page: Page,
  input: {
    workloadPrincipalId?: string;
    checkerPrincipalId: string;
    checkerKind: 'USER' | 'PLATFORM_OPERATOR';
  },
) {
  if (input.workloadPrincipalId) {
    await page.getByRole('button', { name: 'Choose workload principal', exact: true }).click();
    await page
      .getByRole('region', { name: 'Choose a workload principal', exact: true })
      .getByRole('article')
      .filter({ has: page.getByText(input.workloadPrincipalId, { exact: true }) })
      .getByRole('button', { name: /^Select /u })
      .click();
    const selected = page.getByRole('textbox', { name: 'Workload principal ID', exact: true });
    await expect(selected).toHaveValue(input.workloadPrincipalId);
    await expect(selected).toHaveAttribute('readonly', '');
  }
  await page
    .getByRole('combobox', { name: /^Checker principal type/u })
    .selectOption(input.checkerKind);
  await page.getByRole('button', { name: 'Choose checker', exact: true }).click();
  await page
    .getByRole('region', { name: 'Choose an independent checker', exact: true })
    .getByRole('article')
    .filter({ has: page.getByText(input.checkerPrincipalId, { exact: true }) })
    .getByRole('button', { name: /^Select /u })
    .click();
  const checker = page.getByRole('textbox', { name: 'Checker principal ID', exact: true });
  await expect(checker).toHaveValue(input.checkerPrincipalId);
  await expect(checker).toHaveAttribute('readonly', '');
}
