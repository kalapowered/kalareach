/**
 * An environment's account name, as the companion prints it.
 *
 * A host tells its owner, at their own machine, which account each environment runs as and where
 * its directories are. Every other reader, a paired device included, gets the export form of the
 * same record, in which each of those three values is only its class and its length:
 * `[name withheld, 5 bytes]` for the account, `[path withheld, 43 bytes]` for each directory. That
 * text is the host's record that it kept the value back, not a name, so it is never printed as one.
 *
 * The record is recognised by the whole environment rather than by its account name alone. The
 * name a host reports comes from its login environment, so an owner's own account could in
 * principle be called anything, the export form's text included; its directories cannot, because
 * the host resolves each one to an absolute path. So an account name is taken as withheld only when
 * both directories are withheld too, and an owner's reading is always printed as it came.
 */

import type { EnvironmentListResult } from '@kalareach/protocol'

/** One environment, as a host lists it. */
type Environment = EnvironmentListResult['environments'][number]

/** What the companion says in place of an account name the host withheld. */
export const ACCOUNT_NAME_WITHHELD = 'account name withheld'

/** The export form of a withheld name, and nothing else. */
const WITHHELD_NAME = /^\[name withheld, \d+ bytes\]$/

/** The export form of a withheld path, and nothing else. */
const WITHHELD_PATH = /^\[path withheld, \d+ bytes\]$/

/** The account an environment runs as, in words a person reads. */
export function accountName(environment: Environment): string {
  const exported =
    WITHHELD_NAME.test(environment.os_user) &&
    WITHHELD_PATH.test(environment.runtime_directory) &&
    WITHHELD_PATH.test(environment.state_directory)
  return exported ? ACCOUNT_NAME_WITHHELD : environment.os_user
}
