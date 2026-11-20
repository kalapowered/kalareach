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
