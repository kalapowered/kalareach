/**
 * Where this run serves the two bundles.
 *
 * Each run serves both itself and never uses a server it finds already listening, which could be
 * serving another checkout's bundle. `scripts/e2e.mjs` asks the system for two ports nothing is
 * listening on and names them in the environment, so runs on one machine never meet; a run
 * started without it uses 4188 and 4189, and stops if either is taken.
 */

import { env } from 'node:process'

/** The port the harness bundle is served on. */
export const HARNESS_PORT = env.KR_E2E_HARNESS_PORT ?? '4188'

/** The port the bundle the desktop window loads is served on. */
export const DESKTOP_PORT = env.KR_E2E_DESKTOP_PORT ?? '4189'

/** Where the bundle the desktop window loads is served for this run. */
export const DESKTOP_BUNDLE = `http://localhost:${DESKTOP_PORT}/`
