/**
 * The keys a phone keyboard does not have, and the hardware keyboard that does.
 *
 * A terminal needs Escape, Tab, Control, the arrows and a few punctuation marks that a software
 * keyboard buries two layers down. Section 13 asks for an accessory row carrying them, and for a
 * hardware keyboard to work as a hardware keyboard.
 *
 * Both end up in the same place: a key, whatever produced it, becomes the bytes a terminal
 * expects. That translation is here, once, so the accessory row and the hardware keyboard cannot
 * disagree about what Control-C is.
 */

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
  /** The bytes this key sends on its own. */
  readonly sequence?: string
}

/** The row, in the order it is shown. */
export const ACCESSORY_KEYS: readonly AccessoryKey[] = [
  { id: 'esc', label: 'esc', description: 'Escape', sequence: '\u001b' },
  { id: 'tab', label: 'tab', description: 'Tab', sequence: '\t' },
  { id: 'ctrl', label: 'ctrl', description: 'Control', modifier: 'ctrl' },
  { id: 'alt', label: 'alt', description: 'Alt', modifier: 'alt' },
  { id: 'up', label: '↑', description: 'Up arrow', sequence: '\u001b[A' },
  { id: 'down', label: '↓', description: 'Down arrow', sequence: '\u001b[B' },
  { id: 'left', label: '←', description: 'Left arrow', sequence: '\u001b[D' },
  { id: 'right', label: '→', description: 'Right arrow', sequence: '\u001b[C' },
  { id: 'home', label: 'home', description: 'Home', sequence: '\u001b[H' },
  { id: 'end', label: 'end', description: 'End', sequence: '\u001b[F' },
  { id: 'pipe', label: '|', description: 'Vertical bar', sequence: '|' },
  { id: 'dash', label: '-', description: 'Hyphen', sequence: '-' },
  { id: 'slash', label: '/', description: 'Slash', sequence: '/' },
  { id: 'tilde', label: '~', description: 'Tilde', sequence: '~' }
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

/** The control character a letter produces when Control is held, where there is one. */
function controlOf(text: string): string | null {
  if (text.length !== 1) return null
  const code = text.toUpperCase().codePointAt(0)
  if (code === undefined) return null
  // Control-A through Control-Z, and the six that follow the alphabet.
  if (code >= 0x40 && code <= 0x5f) return String.fromCodePoint(code - 0x40)
  if (code === 0x3f) return '\u007f'
  return null
}

/**
 * The bytes a key produces with the modifiers currently held.
 *
 * Returns null when the combination has no terminal meaning, which the caller shows as nothing
 * happening rather than sending the unmodified key: a person who held Control meant to hold it.
 */
export function sequenceFor(key: AccessoryKey, latch: Latch): string | null {
  if (key.modifier) return null
  const base = key.sequence
  if (base === undefined) return null
  if (held(latch, 'ctrl')) {
    const control = controlOf(base)
    if (control === null) return null
    return held(latch, 'alt') ? `\u001b${control}` : control
  }
  if (held(latch, 'alt')) return `\u001b${base}`
  return base
}

/** One press of a hardware key, in the shape a keyboard event reports it. */
export interface KeyPress {
  readonly key: string
  readonly ctrlKey: boolean
  readonly altKey: boolean
  readonly metaKey: boolean
  readonly shiftKey: boolean
}

/** The named keys a hardware keyboard sends that are not a character. */
const NAMED: Readonly<Record<string, string>> = {
  Enter: '\r',
  Tab: '\t',
  Escape: '\u001b',
  Backspace: '\u007f',
  Delete: '\u001b[3~',
  ArrowUp: '\u001b[A',
  ArrowDown: '\u001b[B',
  ArrowRight: '\u001b[C',
  ArrowLeft: '\u001b[D',
  Home: '\u001b[H',
  End: '\u001b[F',
  PageUp: '\u001b[5~',
  PageDown: '\u001b[6~'
}

/**
 * The bytes a hardware key press produces.
 *
 * A key with a platform modifier on it is not the terminal's: Command-C on iOS and the same chord
 * on an Android keyboard are the system's copy, and a terminal that swallowed them would be taking
 * a key the person aimed somewhere else.
 */
export function sequenceForKeyPress(press: KeyPress): string | null {
  if (press.metaKey) return null
  const named = NAMED[press.key]
  if (named !== undefined) {
    if (press.ctrlKey && press.key === 'Enter') return '\n'
    return press.altKey ? `\u001b${named}` : named
  }
  if (press.key.length !== 1) return null
  if (press.ctrlKey) {
    const control = controlOf(press.key)
    if (control === null) return null
    return press.altKey ? `\u001b${control}` : control
  }
  return press.altKey ? `\u001b${press.key}` : press.key
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
