/**
 * Settings sync, in the words the page uses for it.
 *
 * The colour mode is the first setting. Native code keeps it on this computer, and when the person
 * turns settings sync on, keeps it sealed at the sync service so their other devices find it. The
 * page is told where that stands and how many copies of another device's settings wait for a
 * choice; the key, the identities and the content stay in native code.
 */

import type { SettingsSyncView } from '../host/port'

/** What settings sync is, and what it is not. */
export const SETTINGS_SYNC_HELP =
  'Your colour mode follows you to your other devices. It is sealed on this device first, with a ' +
  'key only your devices hold, so the sync service keeps something it cannot read.'

/** The sentence a person reads first, for where settings sync stands. */
export function describeSettingsSync(sync: SettingsSyncView): string {
  switch (sync.state) {
    case 'off':
      return 'Your settings stay on this device.'
    case 'starting':
      return `Waiting for ${sync.kept_at ?? 'the sync service'} to start keeping your settings.`
    case 'on':
      return `Your settings are kept in step through ${sync.kept_at ?? 'the sync service'}.`
  }
}

/** What is waiting, other than a choice, when something is. Null when nothing is. */
export function describeWaiting(sync: SettingsSyncView): string | null {
  if (sync.paused) return 'Privacy mode has stopped settings from being sent.'
  if (sync.outstanding > 0) return 'A change was sent and has not been answered yet.'
  return null
}
