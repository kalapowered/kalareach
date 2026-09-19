/**
 * What the mobile builds may say about money, which is nothing.
 *
 * Section 17 is exact about this: a store mobile build signs in and shows usage, and carries no
 * embedded checkout, no payment form and no call to action that sends a person somewhere to buy.
 * Purchase happens on the website, reached by a person who goes there, and the application does
 * not steer them.
 *
 * The rule is stated here as data rather than as care taken in a screen, so a test can read the
 * rendered surface and hold it to the rule rather than trusting that nobody added a button.
 */

/** How this build reached the device. */
export type Channel = 'app_store' | 'play' | 'independent'

/** What a build's commercial surface may contain. */
export interface CommercialSurface {
  /** Signing in is always offered: an account is how usage is attributed. */
  readonly signIn: true
  /** Usage is always shown to a signed-in person. */
  readonly usage: true
  /** A payment form. Never, on any mobile build. */
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
 * The mobile test reads the rendered account screen and fails on any of them. It is a coarse
 * instrument and that is the point: the screen has no reason to contain them, so a build that
 * grows one fails here rather than at review.
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

/** Where the person stands with an account. */
export type AccountState =
  /** No account. Everything local still works; this is the supported way to use the product. */
  | { readonly kind: 'local_only' }
  /** An account exists and this device is not signed in to it. */
  | { readonly kind: 'signed_out' }
  /** Signed in, with what the managed service reports. */
  | { readonly kind: 'signed_in'; readonly identity: string; readonly plan: string }

/** One measured figure the account screen shows. */
export interface UsageLine {
  readonly label: string
  readonly used: number
  readonly included: number | null
  readonly unit: string
}

/** What the account screen shows for usage. */
export interface Usage {
  readonly periodLabel: string
  readonly lines: readonly UsageLine[]
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

/**
 * What the account screen says at the top.
 *
 * The local-only sentence is the important one. A person with no account is not in a degraded
 * state and must not be told they are: hosts, sessions and agents on their own machines work
 * exactly the same, and the screen says so.
 */
export function describeAccount(state: AccountState): string {
  switch (state.kind) {
    case 'local_only':
      return 'No account on this device. Your hosts, sessions and agents work exactly as they do with one.'
    case 'signed_out':
      return 'Signed out. Your hosts, sessions and agents keep working.'
    case 'signed_in':
      return `Signed in as ${state.identity}. Plan: ${state.plan}.`
  }
}
