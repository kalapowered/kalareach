/**
 * The accessory row, which is the terminal keys a phone keyboard does not have.
 *
 * It sits above the software keyboard and scrolls sideways, because a row that wrapped would move
 * the composer every time a modifier changed. Each key is a button of the platform's own minimum
 * size in both dimensions, each says what it is to a screen reader, and a modifier announces which
 * of its three states it is in rather than leaving that to a colour.
 */

import type { ReactNode } from 'react'

import {
  ACCESSORY_KEYS,
  describeLatch,
  type AccessoryKey,
  type Latch
} from '../model/accessory'
import { minimumTarget, type Surface } from '../platform'

/** The row of keys. */
export function AccessoryRow({
  latch,
  onKey,
  surface,
  disabled
}: {
  readonly latch: Latch
  readonly onKey: (key: AccessoryKey) => void
  readonly surface: Surface
  readonly disabled?: boolean
}): ReactNode {
  const target = minimumTarget(surface)
  return (
    <div className="m-accessory" role="group" aria-label="Terminal keys">
      {ACCESSORY_KEYS.map((key) => {
        const state = key.modifier ? latch[key.modifier] : 'off'
        return (
          <button
            key={key.id}
            type="button"
            className="m-key"
            style={{ minInlineSize: target, minBlockSize: target }}
            data-latch={key.modifier ? state : undefined}
            data-key={key.id}
            aria-label={describeLatch(key, latch)}
            aria-pressed={key.modifier ? state !== 'off' : undefined}
            disabled={disabled}
            onClick={() => {
              onKey(key)
            }}
          >
            <span aria-hidden="true">{key.label}</span>
          </button>
        )
      })}
    </div>
  )
}
