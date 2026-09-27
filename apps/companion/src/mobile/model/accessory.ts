/**
 * The keys a phone keyboard does not have.
 *
 * A terminal needs Escape, Tab, Control, the arrows and a few punctuation marks that a software
 * keyboard buries two layers down. Section 13 asks for an accessory row carrying them, and for a
 * hardware keyboard to work as a hardware keyboard.
 *
 * A key of the row is named as a hardware keyboard's is (`../../terminal/keys.ts`), with the
 * modifiers the row holds for it, and native code spells both in the encoding the program reads, so
 * the row and the keyboard cannot disagree about what Control-C is.
 */

import type { TypedKey } from '../../host/port'

/** A key the accessory row offers. */
export interface AccessoryKey {
  /** The identity used in state and in tests. */
  readonly id: string
  /** What is printed on the key. */
  readonly label: string
  /** What a screen reader says, where the printed label is a symbol. */
  readonly description: string
  /** True for the modifiers, which latch rather than send. */
  readonly modifier?: 'ctrl' | 'alt' | 'shift'
  /** The key it is: the character it makes, or the name of a key that makes none. */
  readonly key?: string
}

/** The row, in the order it is shown. */
export const ACCESSORY_KEYS: readonly AccessoryKey[] = [
  { id: 'esc', label: 'esc', description: 'Escape', key: 'Escape' },
  { id: 'tab', label: 'tab', description: 'Tab', key: 'Tab' },
  { id: 'ctrl', label: 'ctrl', description: 'Control', modifier: 'ctrl' },
  { id: 'alt', label: 'alt', description: 'Alt', modifier: 'alt' },
  { id: 'up', label: '↑', description: 'Up arrow', key: 'ArrowUp' },
  { id: 'down', label: '↓', description: 'Down arrow', key: 'ArrowDown' },
  { id: 'left', label: '←', description: 'Left arrow', key: 'ArrowLeft' },
  { id: 'right', label: '→', description: 'Right arrow', key: 'ArrowRight' },
  { id: 'home', label: 'home', description: 'Home', key: 'Home' },
  { id: 'end', label: 'end', description: 'End', key: 'End' },
  { id: 'pipe', label: '|', description: 'Vertical bar', key: '|' },
  { id: 'dash', label: '-', description: 'Hyphen', key: '-' },
  { id: 'slash', label: '/', description: 'Slash', key: '/' },
  { id: 'tilde', label: '~', description: 'Tilde', key: '~' }
]

/** Which modifiers are held for the next key, and which are held until released. */
export interface Latch {
  readonly ctrl: 'off' | 'once' | 'locked'
  readonly alt: 'off' | 'once' | 'locked'
  readonly shift: 'off' | 'once' | 'locked'
}

/** Nothing held. */
export const NO_LATCH: Latch = { ctrl: 'off', alt: 'off', shift: 'off' }

/**
 * Presses a modifier.
 *
 * Off becomes held-for-one-key, held-for-one-key becomes locked, and locked turns off. Three
 * states from one control, in the order a person discovers them: the common case is one key.
 */
export function pressModifier(latch: Latch, modifier: 'ctrl' | 'alt' | 'shift'): Latch {
  const next = latch[modifier] === 'off' ? 'once' : latch[modifier] === 'once' ? 'locked' : 'off'
  return { ...latch, [modifier]: next }
}

/** Clears whatever was held for exactly one key. */
export function afterKey(latch: Latch): Latch {
  return {
    ctrl: latch.ctrl === 'once' ? 'off' : latch.ctrl,
    alt: latch.alt === 'once' ? 'off' : latch.alt,
    shift: latch.shift === 'once' ? 'off' : latch.shift
  }
}

/** Whether a modifier applies to the key being sent now. */
export function held(latch: Latch, modifier: 'ctrl' | 'alt' | 'shift'): boolean {
  return latch[modifier] !== 'off'
}

/**
 * The key a key of the row is, with the modifiers the row holds for it and the locks that were on
 * when it was tapped, or null for a modifier, which latches rather than sends. A character of the
 * row is the key that makes it with nothing held: the row has no Shift of its own to make it with.
 */
export function rowKey(
  key: AccessoryKey,
  latch: Latch,
  locks: { readonly capsLock: boolean; readonly numLock: boolean }
): TypedKey | null {
  if (key.modifier !== undefined || key.key === undefined) return null
  const character = [...key.key].length === 1
  return {
    key: key.key,
    base: character ? key.key : null,
    keypad: null,
    shift: held(latch, 'shift'),
    alt: held(latch, 'alt'),
    control: held(latch, 'ctrl'),
    caps_lock: locks.capsLock,
    num_lock: locks.numLock
  }
}

/** What a screen reader announces for a modifier in each of its three states. */
export function describeLatch(key: AccessoryKey, latch: Latch): string {
  if (!key.modifier) return key.description
  switch (latch[key.modifier]) {
    case 'off':
      return `${key.description}, off`
    case 'once':
      return `${key.description}, held for the next key`
    case 'locked':
      return `${key.description}, held`
  }
}
