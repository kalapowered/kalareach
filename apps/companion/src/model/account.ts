/**
 * The account, as the page is told about it, and what any build may say about money: nothing.
 *
 * Signing in hands the passkey ceremony to the system browser on reach.kala.to. The page never
 * holds the address the browser opens, a code or a token: it asks the backend to sign the device
 * in and is told where the device stands. These are the words for each place.
 *
 * Section 17 is exact about the store builds: they sign in and show usage, and carry no embedded
 * checkout, no payment form and no call to action that sends a person somewhere to buy. The rule
 * is stated here as data so a test can hold the rendered surface to it rather than trusting that
 * nobody added a button.
 */

/** How this build reached the device. */
export type Channel = 'app_store' | 'play' | 'independent'

/** What a build's commercial surface may contain. */
export interface CommercialSurface {
  /** Signing in is always offered: an account is how usage is attributed. */
  readonly signIn: true
  /** Usage is always shown to a signed-in person. */
  readonly usage: true
  /** A payment form. Never, on any build. */
  readonly checkout: false
  /** A control whose purpose is to send the person somewhere to buy. Never. */
  readonly purchaseCallToAction: false
}

/**
 * The surface a build has.
 *
 * The channel is taken and ignored on purpose: an independently signed Android build is under no
 * store's rule, and it still carries no payment form, because the product sells on the website and
 * a second place to buy is a second place to get it wrong. The argument stays so that the rule is
 * stated against the channel rather than assumed away.
 */
export function commercialSurface(channel: Channel): CommercialSurface {
  void channel
  return { signIn: true, usage: true, checkout: false, purchaseCallToAction: false }
}

/**
 * Words a purchase surface is made of.
 *
 * The tests read the rendered account panel and fail on any of them. It is a coarse instrument and
 * that is the point: the panel has no reason to contain them, so a build that grows one fails
 * there rather than at review.
 */
export const PURCHASE_WORDS: readonly string[] = [
  'buy',
  'purchase',
  'subscribe',
  'subscription',
  'upgrade',
  'checkout',
  'payment',
  'card',
  'billing',
  'price',
  'pricing',
  'free trial',
  'per month'
]

/** How the last sign-in attempt, or the last sign-out, ended. */
export type AccountOutcome =
  | 'cancelled'
  | 'tab_closed'
  | 'refused'
  | 'unreachable'
  | 'could_not_return'
  | 'not_for_this_sign_in'
  | 'port_busy'
  | 'timed_out'
  | 'not_kept'
  | 'service_refused'
  | 'browser_failed'
  | 'signed_out'
  | 'signed_out_pending'
  | 'sign_out_failed'

/** Why this device offers no sign-in. */
export type UnavailableReason = 'no_returning_browser' | 'link_handling_off'

/** Where this device stands with an account. */
export type AccountView =
  /** No account on this device: the supported way to use the product, not a degraded one. */
  | { readonly state: 'signed_out'; readonly outcome: AccountOutcome | null }
  /** No browser here can bring a sign-in back to the application. */
  | { readonly state: 'unavailable'; readonly reason: UnavailableReason }
  /** The browser is open and the application is waiting for the person. */
  | { readonly state: 'browser_open' }
  /** The answer came back and is being exchanged. */
  | { readonly state: 'finishing' }
  /** An account is signed in. */
  | {
      readonly state: 'signed_in'
      readonly email: string | null
      readonly name: string | null
      readonly usage_readable: boolean
    }
  /** The sign-in ended by itself. */
  | { readonly state: 'ended' }

/** One measured figure. */
export interface UsageLine {
  readonly label: string
  readonly used: number
  readonly included: number | null
  readonly unit: string
}

/** The account's usage. */
export type UsageView =
  | { readonly state: 'read'; readonly period_label: string; readonly lines: readonly UsageLine[] }
  | { readonly state: 'not_granted' }
  | { readonly state: 'could_not_read' }
  | { readonly state: 'signed_out' }

/** The origin the ceremony runs on, named as text and never as a link. */
export const ACCOUNT_HOST = 'reach.kala.to'

/** What the Sign in button leads to, said beside it. */
export const SIGN_IN_HELP = `Opens ${ACCOUNT_HOST}, where you use a passkey or an email code.`

/** The sentence a person reads first, for where the device stands. */
export function describeAccount(view: AccountView): string {
  switch (view.state) {
    case 'signed_out':
    case 'unavailable':
      return 'No account on this device. Your hosts, sessions and agents work exactly as they do with one.'
    case 'browser_open':
      return `Continue on ${ACCOUNT_HOST}. This screen updates when you come back.`
    case 'finishing':
      return 'Signing in…'
    case 'signed_in':
      return view.email === null
        ? "Signed in. The account's address has not been read yet."
        : `Signed in as ${view.email}.`
    case 'ended':
      return 'Your sign-in on this device has ended. Your hosts, sessions and agents keep working.'
  }
}

/** Why no sign-in is offered here. */
export function describeUnavailable(reason: UnavailableReason): string {
  switch (reason) {
    case 'no_returning_browser':
      return 'Signing in needs a browser that can return you to KalaReach, such as a current Chrome.'
    case 'link_handling_off':
      return (
        `Signing in needs KalaReach to open ${ACCOUNT_HOST} links. Turn on opening supported ` +
        "links for KalaReach in Android's app settings, or make a current Chrome your browser."
      )
  }
}

/** How the last attempt or sign-out ended, in the application's own words. */
export function describeOutcome(outcome: AccountOutcome): string {
  switch (outcome) {
    case 'cancelled':
      return 'Sign-in cancelled. Nothing changed.'
    case 'tab_closed':
      return (
        `Sign-in cancelled. Nothing changed. If the browser stayed on ${ACCOUNT_HOST} after you ` +
        'signed in, it did not hand the sign-in back; a current Chrome does.'
      )
    case 'refused':
      return `${ACCOUNT_HOST} did not sign this device in.`
    case 'unreachable':
      return `${ACCOUNT_HOST} could not be reached. Check the connection and try again.`
    case 'could_not_return':
      return `${ACCOUNT_HOST} could not return the sign-in to this app. Try again later.`
    case 'not_for_this_sign_in':
      return 'The answer that came back was not for this sign-in, so KalaReach ignored it.'
    case 'port_busy':
      return 'Another app is using port 8765, which signing in needs. Close it and try again.'
    case 'timed_out':
      return 'The browser did not come back within 15 minutes, so signing in stopped.'
    case 'not_kept':
      return 'KalaReach could not keep the sign-in safely on this device, so it kept nothing.'
    case 'service_refused':
      return `${ACCOUNT_HOST} refused the sign-in.`
    case 'browser_failed':
      return 'The browser could not be opened, so signing in stopped.'
    case 'signed_out':
      return 'Signed out on this device.'
    case 'signed_out_pending':
      return (
        `Signed out on this device. ${ACCOUNT_HOST} has not heard yet; KalaReach tells it the ` +
        'next time it can.'
      )
    case 'sign_out_failed':
      return 'KalaReach could not remove the sign-in from this device.'
  }
}

/** One usage line, in words. */
export function describeUsage(line: UsageLine): string {
  if (line.included === null) return `${line.used} ${line.unit}`
  return `${line.used} of ${line.included} ${line.unit}`
}

/** How far through its allowance a line is, between 0 and 1, or null when there is no allowance. */
export function usageFraction(line: UsageLine): number | null {
  if (line.included === null || line.included <= 0) return null
  return Math.min(1, line.used / line.included)
}

/** Whether a view is one where the application is waiting on the browser or the exchange. */
export function isSigningIn(view: AccountView): boolean {
  return view.state === 'browser_open' || view.state === 'finishing'
}
