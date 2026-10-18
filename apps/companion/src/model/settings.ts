/**
 * Settings sync, in the words the page uses for it.
 *
 * The colour mode is the first setting. Native code keeps it on this computer, and when the person
 * turns settings sync on, keeps it sealed at the sync service so their other devices find it. The
 * page is told where that stands and how many copies of another device's settings wait for a
 * choice; the key, the identities and the content stay in native code.
 */

import type {
  ColourMode,
  DeviceHappened,
  DeviceOffer,
  DevicesView,
  KeptDrafts,
  SettingsChoice,
  SettingsKeep,
  SettingsSyncView
} from '../host/port'

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

/** What keeping drafts in step does, said where the person turns it on. */
export const DRAFTS_SYNC_HELP =
  'Your unsent prompts follow you to your other devices, sealed like your settings. A draft from ' +
  'another device is kept beside yours and is never sent.'

/** The drafts, counted: "1 draft", "3 drafts". */
function countDrafts(count: number): string {
  return count === 1 ? '1 draft' : `${count} drafts`
}

/** Why some drafts stay on this device and are not sent, in words. */
export function describeKeptHere(kept: KeptDrafts): string {
  const stays = kept.drafts === 1 ? 'stays' : 'stay'
  const place = kept.host === null ? 'that host' : kept.host
  switch (kept.why) {
    case 'private':
      return `${countDrafts(kept.drafts)} for ${place} ${stays} on this device while privacy mode is on there.`
    case 'unreadable':
      return (
        `${countDrafts(kept.drafts)} for ${place} ${stays} on this device because this device cannot ` +
        `read whether privacy mode is on there` +
        (kept.detail === null ? '.' : `: ${kept.detail}.`)
      )
    case 'unknown_host':
      return `${countDrafts(kept.drafts)} ${stays} on this device until this device is connected to the host ${kept.drafts === 1 ? 'it is' : 'they are'} for.`
    case 'too_large':
      return `${countDrafts(kept.drafts)} ${kept.drafts === 1 ? 'is' : 'are'} too large to keep in step and ${stays} on this device.`
  }
}

/** What is waiting, other than a choice, when something is. Null when nothing is. */
export function describeWaiting(sync: SettingsSyncView): string | null {
  if (sync.paused) return 'Privacy mode has stopped settings from being sent.'
  if (sync.outstanding > 0) return 'A change was sent and has not been answered yet.'
  return null
}

/** What the colour mode is called. */
export function colourModeName(mode: ColourMode): string {
  switch (mode) {
    case 'light':
      return 'Light'
    case 'dark':
      return 'Dark'
    case 'system':
      return 'System'
  }
}

/** What two devices changed, and what the person is asked to do about it. */
export const SETTINGS_CHOICE_HELP =
  'You changed how KalaReach looks on this device, and another device changed it too. Nothing has ' +
  'been replaced. Keep one; the other is let go.'

/** One version the person can keep, in the words the choice shows it in. */
export interface Keepable {
  /** What chooses it: this device's own, or a copy another device wrote. */
  readonly keep: SettingsKeep
  /** A stable key. */
  readonly id: string
  /** The colour mode it holds, or null when this version cannot show it. */
  readonly mode: ColourMode | null
  /** Whose it is, in words. */
  readonly whose: string
  /** When the device that wrote it recorded it, formatted for a person, never used to order. */
  readonly recorded: string
}

/** The time a version was recorded, as a person reads it. */
export function recordedAt(ms: number): string {
  if (ms <= 0) return ''
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(ms)
  )
}

/**
 * The versions to choose between: this device's own first, then each other device's in the order
 * this device received them. None is placed or marked for being later than another.
 */
export function keepables(choice: SettingsChoice): readonly Keepable[] {
  return [
    {
      keep: { choice: 'mine' },
      id: 'mine',
      mode: choice.mine.colour_mode,
      whose: 'This device',
      recorded: recordedAt(choice.mine.updated_at_ms)
    },
    ...choice.others.map((other) => ({
      keep: { choice: 'copy', conflict_id: other.conflict_id } as const,
      id: other.conflict_id,
      mode: other.colour_mode,
      whose: 'Another device',
      recorded: recordedAt(other.updated_at_ms)
    }))
  ]
}

/** What sharing the settings with another device is, and what it asks of the person. */
export const DEVICES_HELP =
  'Your settings can follow you to your other devices. A device your hosts list as yours is given ' +
  'the key only when you confirm here, on this computer.'

/** The sentence a person reads first, for who shares the settings. */
export function describeDevices(devices: DevicesView): string {
  if (devices.out) return 'This computer was taken out of the shared settings.'
  const others = devices.members.filter((member) => !member.this_computer).length
  if (others === 0) return 'The settings are not shared with another device yet.'
  return others === 1
    ? 'The settings are shared with 1 other device.'
    : `The settings are shared with ${String(others)} other devices.`
}

/** Why this computer has not yet read the shared settings. */
export const DEVICES_WAITING =
  'The shared settings were sealed before this computer joined, or before a device was taken out. ' +
  'A device that has them seals them again when it next checks, and they appear here then.'

/** What the person is asked before a device is taken out of the shared settings. */
export function describeTakingOut(name: string): string {
  return (
    `Take ${name} out? It reads nothing written from now on. To share with it again you confirm ` +
    'on this computer and on that device.'
  )
}

/** What an offer says of the device the settings were started on. */
export function describeOffer(offer: DeviceOffer): string {
  return offer.name === null
    ? 'Settings shared by your other devices'
    : `Settings started on ${offer.name}`
}

/** What the control that joins an offer is called, for a screen reader. */
export function offerLabel(offer: DeviceOffer): string {
  return offer.name === null
    ? 'Join the settings your other devices share'
    : `Join the settings started on ${offer.name}`
}

/** Said under the button that starts settings sync, when another device already shares some. */
export const DEVICES_START_OWN =
  'Another of your devices already shares settings. Join them in the card below: a computer that ' +
  'starts its own cannot join those afterwards.'

/**
 * Texts with a key each, the second of two equal texts keyed apart from the first, for a list whose
 * rows have no identity but their words.
 */
export function uniqueKeys(
  texts: readonly string[]
): readonly { readonly text: string; readonly key: string }[] {
  const seen = new Map<string, number>()
  return texts.map((text) => {
    const times = (seen.get(text) ?? 0) + 1
    seen.set(text, times)
    return { text, key: `${text}#${String(times)}` }
  })
}

/** Why no device can be added or joined from this computer. */
export const DEVICES_CANNOT_CONFIRM =
  'This computer cannot ask you to confirm, so it adds no device and joins no settings.'

/** What a device no host lists any more is told, and what happens to it. */
export const DEVICE_NOT_VOUCHED = 'No host lists it any more, so it is taken out at the next check.'

/** What an offer says. */
export const DEVICES_OFFER =
  'Another of your devices keeps its settings in step. Join them, and this computer follows them.'

/** What became of a change, in a sentence. */
export function describeHappened(happened: DeviceHappened): string {
  const name = happened.name ?? 'The device'
  switch (happened.what) {
    case 'addition':
      return happened.ended === 'done'
        ? `${name} was given the settings.`
        : happened.ended === 'cancelled'
          ? `Giving ${name} the settings was cancelled by taking it out.`
          : `${name} could not be given the settings: no host lists it, or it was being taken out.`
    case 'removal':
      return happened.ended === 'done'
        ? `${name} was taken out of the shared settings.`
        : happened.ended === 'cancelled'
          ? `Taking out ${name} was cancelled.`
          : `${name} could not be taken out.`
    case 'join':
      return happened.ended === 'done'
        ? 'This computer joined the shared settings.'
        : 'Joining the shared settings did not complete.'
  }
}
