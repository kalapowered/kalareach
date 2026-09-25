/**
 * The value both devices show while the owner decides.
 *
 * Two groups of four, large, in monospace with tabular figures, so the person can compare it with
 * the host's at a glance. It is the one moment in pairing the person must look at, and it arrives
 * from the network rather than from their keystroke, so it arrives with a short fade and rise; with
 * reduced motion, the fade alone. At a large text size it wraps between the groups, never inside
 * one. A screen reader hears it spelled out, character by character.
 */

import type { ReactNode } from 'react'

import { spelledValue } from './words'

/** The value, grouped as native code sent it: `f3c1 46fd`. */
export function VerificationValue({ value }: { readonly value: string }): ReactNode {
  return (
    <p className="verification-value" data-testid="verification-value">
      <span className="visually-hidden">{spelledValue(value)}</span>
      <span className="verification-groups" aria-hidden="true">
        {value.split(' ').map((group, index) => (
          // The groups are positions in one value, and never reorder.
          <span key={index} className="verification-group">
            {group}
          </span>
        ))}
      </span>
    </p>
  )
}

/**
 * The value inside a sentence, as an owner's request shows it: grouped, monospace with tabular
 * figures, and spelled out for a screen reader, which reads only the spelled form.
 */
export function SpelledValue({ value }: { readonly value: string }): ReactNode {
  return (
    <span className="mono tabular">
      <span className="visually-hidden">{spelledValue(value)}</span>
      <span aria-hidden="true">{value}</span>
    </span>
  )
}
