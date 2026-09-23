import { defineConfig, devices } from '@playwright/test'

import { DESKTOP_PORT, HARNESS_PORT } from './e2e/served.ts'

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
    baseURL: `http://localhost:${HARNESS_PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure'
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } }
  ],
  // Both servers are this run's own. A server already listening on either port could be serving
  // another checkout's bundle, so the run stops rather than test it.
  webServer: [
    {
      command: `node scripts/preview-harness.mjs ${HARNESS_PORT}`,
      url: `http://localhost:${HARNESS_PORT}/harness.html`,
      reuseExistingServer: false,
      timeout: 60_000
    },
    // The bundle the desktop window loads, served beside the harness so one test can open it.
    {
      command: `node scripts/preview-desktop.mjs ${DESKTOP_PORT}`,
      url: `http://localhost:${DESKTOP_PORT}/`,
      reuseExistingServer: false,
      timeout: 60_000
    }
  ]
})
