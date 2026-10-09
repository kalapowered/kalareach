/**
 * Recovery and the sync service, in the words the page uses for them.
 *
 * Recovery keeps an encrypted bundle with the account and gives the person a kit. The page is told
 * where recovery stands and what stops the next step, and never holds the seed, the locator or a
 * token: those are native code's, and a kit is written by native code to a file the person chose.
 * Like the account's words, these say nothing about money.
 */

import type { RecoveryBlocker, RecoveryView } from '../host/port'

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
