/**
 * Recovery and the sync service, in the words the page uses for them.
 *
 * Recovery keeps an encrypted bundle with the account and gives the person a kit. The page is told
 * where recovery stands and what stops the next step, and never holds the seed, the locator or a
 * token: those are native code's, and a kit is written by native code to a file the person chose.
 * Like the account's words, these say nothing about money.
 */

import type { HostCoverView, HostLeft, RecoveryBlocker, RecoveryView } from '../host/port'

/** What recovery is for, and what the kit is. */
export const RECOVERY_HELP =
  'Recovery keeps an encrypted bundle with your account and gives you a kit to keep. Without the kit, ' +
  'KalaReach cannot bring your data back for you.'

/** What the sync service setting is. */
export const SYNC_SERVICE_HELP = 'An https address, like https://reach.kala.to.'

/** The name a kit is offered under in the save dialog. */
export const KIT_FILE_NAME = 'kalareach-recovery-kit.txt'

/** The sentence a person reads first, for where recovery stands. */
export function describeRecovery(view: RecoveryView): string {
  switch (view.state) {
    case 'off':
      return 'Recovery is off.'
    case 'unfinished':
      return 'Turning recovery on did not finish.'
    case 'on':
      return `Recovery is on. The bundle is kept at ${view.kept_at ?? 'the sync service'}.`
    case 'unsettled':
      return 'A write to the recovery bundle got no answer, so it is not known whether it landed.'
  }
}

/**
 * What a sync service setting that is not where the bundle is kept does to recovery: nothing yet.
 * The bundle stays where it was made, because the kit names that service and that locator, and
 * moving it is a step of its own. Null when the setting and the bundle agree, or there is no bundle.
 */
export function describeStaysAt(view: RecoveryView): string | null {
  if (view.kept_at === null || view.kept_at === view.sync_service.host) return null
  return (
    `Recovery stays at ${view.kept_at}, where its kit points. Choosing another sync service does ` +
    'not move it.'
  )
}

/** What to do about a write that got no answer. */
export const SETTLE_HELP = 'Nothing else is written until it is settled.'

/** What stops the next step, and what to do about it. */
export function describeBlocker(blocker: RecoveryBlocker): string {
  switch (blocker.reason) {
    case 'signed_out':
      return 'Sign in to use recovery. It keeps its bundle with your account.'
    case 'needs_sign_in':
      return 'This sign-in cannot keep recovery data. Sign in again to allow it.'
    case 'wrong_service':
      return (
        `The sync service setting names ${blocker.sync_service}, which is not the service this ` +
        `device is signed in to (${blocker.account}), so your sign-in is not sent there. Change ` +
        `the setting to ${blocker.account} to use recovery.`
      )
  }
}

/** What covering the host's backups does, and why it is a step of its own. */
export const HOST_COVER_HELP =
  'The host on this computer backs up with the kit it was set up under, and only that kit opens ' +
  'those backups. Cover them to make this recovery the one that opens what the host backs up.'

/** What starting new backups under this recovery does, said before the person confirms it. */
export const HOST_REPLACE_WARNING =
  'The host starts a new archive under this recovery. What it backed up before stays at the ' +
  'service and opens only with the kit it was set up under. The host stops adding to it and does ' +
  'not remove its old backups. Backups from now on open with this recovery.'

/** Whether the host can be set up again under this recovery, on the person's word. */
export function offersReplacement(view: HostCoverView | null): boolean {
  return (
    view !== null &&
    view.state === 'left' &&
    (view.why.reason === 'other_kit' || view.why.reason === 'unusable')
  )
}

function describeLeft(why: HostLeft): string {
  switch (why.reason) {
    case 'no_service':
      return 'The host on this computer uses no storage service, so it has no backups to cover. Nothing was changed.'
    case 'other_service':
      return (
        `The host stores its backups at ${why.host}, which is not the service this recovery is ` +
        'kept at. Nothing was changed.'
      )
    case 'sign_in':
      return (
        'The host is not signed in in a way that lets it keep backups. Sign the host in, then ' +
        'cover its backups. Nothing was changed.'
      )
    case 'setup_under_way':
      return (
        'A setup of the host\'s backups has not ended. Wait for it, then cover them. Nothing ' +
        'was changed.'
      )
    case 'other_kit':
      return (
        `The host's backups are set up under another kit (${why.host_fingerprint}), so this ` +
        'recovery does not open them. Keep the kit printed when they were set up: it still opens ' +
        'them. Nothing was changed.'
      )
    case 'unusable':
      return (
        'The host\'s backups are set up under this recovery, but the host cannot make backups ' +
        'now. Nothing was changed.'
      )
    case 'declined':
      return why.cause.kind === 'bundle_conflict'
        ? 'Another device changed the recovery bundle meanwhile. Try again. The host\'s backups were not changed.'
        : 'The host did not set its backups up under this recovery. Its backups were not changed.'
  }
}

/** The sentence that says where covering the host's backups ended. */
export function describeHostCover(view: HostCoverView): string {
  if (view.state === 'left') return describeLeft(view.why)
  if (view.already) {
    return `The host's backups are set up under this recovery (kit ${view.kit_fingerprint}).`
  }
  const replaced =
    view.replaced === null
      ? ''
      : ` What it backed up under the kit ${view.replaced} stays readable with that kit, and the host no longer adds to it.`
  return (
    `The host's backups are set up under this recovery (kit ${view.kit_fingerprint}): this ` +
    `recovery's kit opens what the host backs up from now on.${replaced}`
  )
}
