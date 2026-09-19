// The colour mode is applied before the first paint, so a dark-mode window never flashes white.
// This runs as its own module in the document head rather than inside the application, because the
// application's first render is already one frame too late.

const MODES = ['light', 'dark', 'system'] as const
export type ColourMode = (typeof MODES)[number]

/** The key the chosen mode is remembered under. */
export const THEME_KEY = 'kalareach-theme'

/** Reads the stored preference, treating an unreadable store as "follow the system". */
export function storedMode(): ColourMode {
  try {
    const stored = localStorage.getItem(THEME_KEY)
    if (stored && (MODES as readonly string[]).includes(stored)) return stored as ColourMode
  } catch {
    // A private window or blocked site data is not an error: the controls still work for this page.
  }
  return 'system'
}

/** Applies a preference to the document and the browser chrome. */
export function applyMode(mode: ColourMode): void {
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

applyMode(storedMode())

// System mode follows the device while the window is open.
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (document.documentElement.dataset.preference === 'system') applyMode('system')
})
