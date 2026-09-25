/**
 * An environment's account name, as the companion prints it.
 *
 * A host tells its owner, at their own machine, which account each environment runs as. Every other
 * reader, a paired device included, gets the export form of the same answer, in which the name is
 * only its class and its length: `[name withheld, 5 bytes]`. That text is the host's record that it
 * kept the name back, not a name, so it is never printed as one.
 *
 * The record is recognised by its whole shape. To take it, an account name would need brackets, a
 * comma and spaces, which Windows forbids in an account name and the tools that create accounts on
 * macOS and Linux refuse.
 */

/** What the companion says in place of an account name the host withheld. */
export const ACCOUNT_NAME_WITHHELD = 'account name withheld'

/** The export form of a withheld name, and nothing else. */
const WITHHELD_NAME = /^\[name withheld, \d+ bytes\]$/

/** The account an environment runs as, in words a person reads. */
export function accountName(osUser: string): string {
  return WITHHELD_NAME.test(osUser) ? ACCOUNT_NAME_WITHHELD : osUser
}
