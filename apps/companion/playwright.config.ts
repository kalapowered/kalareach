import { defineConfig, devices } from '@playwright/test'

// Section 27 puts every test artefact in one platform-resolved directory. The harness build is
// served by `vite preview`; the application under test is the same bundle the desktop shell loads,
// with the fake host in place of a paired one.
const artefacts = process.env.KR_TEST_ARTIFACTS_DIR ?? '/tmp/kr-test-artifacts'

export default defineConfig({
  testDir: './e2e',
  outputDir: `${artefacts}/companion-e2e`,
  // One at a time. Several of these measure layout, a gesture or a scroll position, and workers
  // competing for the same cores measure the machine rather than the interface.
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
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
    command: 'node scripts/preview-harness.mjs',
    url: 'http://localhost:4188/harness.html',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000
  }
})
