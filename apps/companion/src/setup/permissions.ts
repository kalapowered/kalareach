/**
 * The macOS permission categories, one at a time.
 *
 * Section 3 is exact about this and it is worth repeating where the code is: these are separate
 * permissions. Full Disk Access is a fourth grant beside Accessibility, Screen & System Audio
 * Recording and the Automation grants, not a master switch above them, and an application holding
 * it still cannot take a screen image. Two more categories exist and belong only to the features
 * that use them: the microphone for voice, and Remote Management for reaching this desktop from
 * somewhere else.
 *
 * Every one of them needs System Settings. None of them can be enabled by this application, and
 * the interface says so where a person can read it rather than in a comment.
 */

/** One macOS permission category. */
export interface PermissionCategory {
  /** The name macOS gives it. */
  readonly name: string
  /** The settings pane this application will open for it. */
  readonly pane: string
  /** Where the pane is, in the platform's own words. */
  readonly route: string
  /** What it is for, in one sentence. */
  readonly purpose: string
  /** The capabilities in the host's report that this grant governs. */
  readonly governs: readonly string[]
  /** Whether it belongs to the desktop automation every installation needs. */
  readonly core: boolean
  /** The feature it belongs to, when it is not one of the core four. */
  readonly onlyFor?: string
  /** Anything about this category that is easy to get wrong. */
  readonly caveat?: string
}

/** The categories, core ones first, in the order section 3 names them. */
export const PERMISSION_CATEGORIES: readonly PermissionCategory[] = [
  {
    name: 'Accessibility',
    pane: 'accessibility',
    route: 'System Settings → Privacy & Security → Accessibility',
    purpose:
      'Lets a tool running in your session read what is on screen as elements, and move the ' +
      'pointer and keyboard.',
    governs: ['desktop.accessibility', 'desktop.input_injection'],
    core: true
  },
  {
    name: 'Screen & System Audio Recording',
    pane: 'screen_recording',
    route: 'System Settings → Privacy & Security → Screen & System Audio Recording',
    purpose: 'Lets a tool take an image of the desktop.',
    governs: ['desktop.screen_capture'],
    core: true,
    caveat: 'Reading the accessibility tree is a different grant. Neither covers the other.'
  },
  {
    name: 'Full Disk Access',
    pane: 'full_disk_access',
    route: 'System Settings → Privacy & Security → Full Disk Access',
    purpose: 'Lets a tool read files in the places macOS protects, such as Mail and Messages.',
    governs: ['desktop.authorised_file_read'],
    core: true,
    caveat:
      'This does not stand in for the others. An application with Full Disk Access still cannot ' +
      'take a screen image or send a keystroke.'
  },
  {
    name: 'Automation',
    pane: 'automation',
    route: 'System Settings → Privacy & Security → Automation',
    purpose:
      'Lets this application ask another one to do something. macOS grants it per pair, so each ' +
      'application you automate is its own entry.',
    governs: ['desktop.accessibility', 'desktop.input_injection'],
    core: true,
    caveat:
      'A grant for one application is not a grant for the next one. The entry appears the first ' +
      'time something asks.'
  },
  {
    name: 'Microphone',
    pane: 'microphone',
    route: 'System Settings → Privacy & Security → Microphone',
    purpose: 'Lets you talk to an agent.',
    governs: [],
    core: false,
    onlyFor: 'voice'
  },
  {
    name: 'Remote Management',
    pane: 'remote_management',
    route: 'System Settings → General → Sharing → Remote Management',
    purpose: 'Lets you reach this desktop from another machine to watch a session on it.',
    governs: [],
    core: false,
    onlyFor: 'reaching this desktop from elsewhere'
  }
]

/** The four every desktop installation is guided through. */
export function coreCategories(): readonly PermissionCategory[] {
  return PERMISSION_CATEGORIES.filter((category) => category.core)
}

/** The ones that belong to a feature rather than to desktop automation itself. */
export function featureCategories(): readonly PermissionCategory[] {
  return PERMISSION_CATEGORIES.filter((category) => !category.core)
}

/** The categories one capability is behind, in the order they are shown. */
export function categoriesFor(capability: string): readonly PermissionCategory[] {
  return PERMISSION_CATEGORIES.filter((category) => category.governs.includes(capability))
}

/**
 * What this application can and cannot do about any of these, stated once.
 *
 * It is the honest ceiling and it belongs on the screen, not in a footnote: setup can take
 * somebody to the right pane and it cannot press the switch, and no check anywhere can report a
 * permission as granted without performing the operation the permission guards.
 */
export const CEILING =
  'KalaReach cannot grant any of these. It opens the right pane; the switch is yours. And no ' +
  'check can tell you a permission is granted without doing the thing the permission guards, so ' +
  'that is exactly what the checks below do.'
