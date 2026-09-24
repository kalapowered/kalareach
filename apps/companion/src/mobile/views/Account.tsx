/**
 * The account screen: who you are, what you have used, and nothing to buy.
 *
 * Section 17 permits exactly two things on a store build: signing in, and seeing usage. Signing in
 * hands the passkey ceremony to the system browser on reach.kala.to; there is no payment form, no
 * embedded checkout and no control whose purpose is to send a person somewhere to buy something.
 *
 * The screen also states the thing a person most needs to know: an account is not what makes the
 * product work. Hosts, sessions and agents on your own machines behave identically without one.
 */

import type { ReactNode } from 'react'

import { useApp } from '../../app/state'
import { AccountPanel, useAccount } from '../../components/AccountPanel'
import type { Channel } from '../../model/account'
import type { Surface } from '../platform'

/** The account screen. */
export function Account({
  surface,
  channel
}: {
  readonly surface: Surface
  readonly channel: Channel
}): ReactNode {
  const { port } = useApp()
  const account = useAccount(port)
  // Every channel signs in and shows usage, and none carries a way to pay
  // (`commercialSurface`), so the channel changes nothing the panel draws.
  return (
    <div data-testid="mobile-account" data-channel={channel}>
      <AccountPanel account={account} surface={surface} />
    </div>
  )
}
