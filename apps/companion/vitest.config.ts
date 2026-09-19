import { defineConfig, mergeConfig } from 'vitest/config'

import viteConfig from './vite.config.ts'

// The component tests run against the same build configuration the application is built with, so a
// test never passes because of a transform the real bundle does not have.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: 'jsdom',
      include: ['test/**/*.test.ts', 'test/**/*.test.tsx'],
      setupFiles: ['./test/setup.ts'],
      restoreMocks: true,
      css: true,
      // One file at a time. Two of these tests are measurements, and files racing each other for
      // the same cores would be measuring the test runner rather than the interface.
      fileParallelism: false
    }
  })
)
