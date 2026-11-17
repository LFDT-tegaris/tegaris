import { test } from '@playwright/test';

test('foundation discovery reserves browser execution for the I08 application suite', async () => {
  test.skip(true, 'I01 validates Playwright discovery only; browser E2E belongs to I08.');
});
