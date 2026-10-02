/**
 * Where this run serves the two bundles.
 *
 * Each run serves both itself and never uses a server it finds already listening, which could be
 * serving another checkout's bundle. `scripts/e2e.mjs` starts a server for each bundle on a port
 * the system gives it, and names the two ports in the environment, so runs on one machine never
 * meet. A run started any other way has no ports and stops.
 */

import { env } from 'node:process'

const served = (name: string): string => {
  const port = env[name]
  if (port === undefined || port === '') {
    throw new Error(`${name} is not set: start the end-to-end run with \`pnpm run e2e\`, which serves both bundles`)
  }
  return port
}

/** The port the harness bundle is served on. */
export const HARNESS_PORT = served('KR_E2E_HARNESS_PORT')

/** The port the bundle the desktop window loads is served on. */
export const DESKTOP_PORT = served('KR_E2E_DESKTOP_PORT')

/** Where the bundle the desktop window loads is served for this run. */
export const DESKTOP_BUNDLE = `http://localhost:${DESKTOP_PORT}/`
