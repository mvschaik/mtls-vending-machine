import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test('complete vending flow', async ({ page }) => {
  // Set up mock auth header
  await page.setExtraHTTPHeaders({
    'X-Authentik-Username': 'test-e2e-user'
  });

  await page.goto('/');

  // Check if username is displayed
  await expect(page.locator('#display-username')).toHaveText('test-e2e-user');

  // Start vending
  await page.click('#btn-start');

  // Wait for password prompt
  await expect(page.locator('#content-password')).toBeVisible({ timeout: 10000 });

  // Enter password
  const transportPassword = 'test-password-123';
  await page.fill('#p12-password', transportPassword);

  // Finalize and download
  const downloadPromise = page.waitForEvent('download');
  await page.click('#btn-finalize');
  const download = await downloadPromise;

  // Save the download
  // Use process.cwd() instead of __dirname in ESM if needed,
  // or just relative to project root which for playwright is often where config is.
  const downloadPath = path.resolve('../test-vending.p12');
  await download.saveAs(downloadPath);

  expect(fs.existsSync(downloadPath)).toBeTruthy();

  // Verify success message
  await expect(page.locator('#content-success')).toBeVisible();
});
