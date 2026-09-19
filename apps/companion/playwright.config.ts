import { defineConfig, devices } from '@playwright/test'

// Section 27 puts every test artefact in one platform-resolved directory. The harness build is
// served by `vite preview`; the application under test is the same bundle the desktop shell loads,
// with the fake host in place of a paired one.
const artefacts = process.env.KR_TEST_ARTIFACTS_DIR ?? '/tmp/kr-test-artifacts'

export default defineConfig({
  testDir: './e2e',
  outputDir: `${artefacts}/companion-e2e`,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [['list'], ['html', { outputFolder: `${artefacts}/companion-e2e-report`, open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4188',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure'
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } }
  ],
  webServer: {
    command: 'pnpm preview --port 4188 --strictPort',
    url: 'http://localhost:4188/harness.html',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000
  }
})
