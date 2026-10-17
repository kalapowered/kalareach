// The colour mode is applied before the first paint, so a dark-mode window never flashes white.
// This runs as its own module in the document head rather than inside the application, because the
// application's first render is already one frame too late.
//
// The mode is the person's setting, and native code keeps it: the window is opened with the mode
// already in its document, as data, before any script runs. This page keeps no copy of its own.
// Opened without the native shell (the browser harness), there is no setting and the device's own
// mode is followed.

import type { ColourMode } from './host/port'

export type { ColourMode }

const MODES: readonly ColourMode[] = ['light', 'dark', 'system']

declare global {
  interface Window {
    /** The person's settings as native code opened this window with them. Absent in the harness. */
    kalareachSettings?: { readonly colour_mode?: unknown }
  }
}

/** Whether a value is one of the three modes. */
export function isColourMode(value: unknown): value is ColourMode {
  return typeof value === 'string' && (MODES as readonly string[]).includes(value)
}

/** The mode native code opened this window in, or the device's own when it opened it in none. */
export function openedMode(): ColourMode {
  const mode = window.kalareachSettings?.colour_mode
  return isColourMode(mode) ? mode : 'system'
}

/** The mode the document is in now, which is what the person sees. */
export function shownMode(): ColourMode {
  const mode = document.documentElement.dataset.preference
  return isColourMode(mode) ? mode : openedMode()
}

/** How many times a mode has been applied, so that an answer can tell whether one came after it. */
let applications = 0

/** The number of modes applied so far in this window. */
export function modeApplications(): number {
  return applications
}

/** Applies a preference to the document and the browser chrome. */
export function applyMode(mode: ColourMode): void {
  applications += 1
  const root = document.documentElement
  const resolved =
    mode === 'system'
      ? matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
      : mode
  root.dataset.preference = mode
  root.dataset.theme = resolved
  const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')
  if (meta) meta.content = (resolved === 'dark' ? meta.dataset.dark : meta.dataset.light) ?? ''
}

applyMode(openedMode())

// System mode follows the device while the window is open.
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (document.documentElement.dataset.preference === 'system') applyMode('system')
})
