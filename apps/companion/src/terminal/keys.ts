/**
 * The person's keys, as the page names them for the program.
 *
 * A key goes to native code named, never spelled: the key the platform reported, the character it
 * makes with nothing held where the platform says, the keypad key it is, the modifiers held, the
 * locks on, and whether it went down, repeated or came up. Native code spells it in the encoding the
 * program negotiated, the ordinary encoding, `modifyOtherKeys` or the Kitty keyboard protocol, so
 * the page never holds a byte of it. The desktop's keyboard, a phone's hardware keyboard and the
 * phone's software keyboard are all read here, so they cannot disagree about what a key is.
 *
 * Not every keyboard event is a key. An input method owns its own keydowns, and what it commits
 * reaches the program as text, never as keys invented for it. The platform keeps its own chords:
 * anything with Command or the Windows key, and off Apple platforms Control-Shift-C and
 * Control-Shift-V, a terminal's copy and paste there. A modifier or a lock alone is no key, and
 * neither is a key native code has no name for, so a volume key still turns the volume.
 *
 * AltGraph, and Option on Apple platforms, make characters: a character made with them carries no
 * Control or Alt. Elsewhere Alt is the program's Alt.
 *
 * The character a key makes with nothing held comes only from the platform: its keyboard layout
 * where it offers the map, or the key itself when nothing that changes a character is held. It is
 * never worked out by changing a character's case, which is wrong for a Turkish dotless i and for a
 * character whose lower case is two. Scan codes are never read: a key's code names a keypad key and
 * the press a release ends, and nothing else.
 */

import { KEYPAD_CODES, type KeypadCode, type TypedKey } from '../host/port'

/**
 * The invisible character the program's keyboard holds between edits, so that a software keyboard's
 * Backspace always has something to delete. It is never sent.
 */
export const SENTINEL = '​'

/** The most bytes of text one input carries, as native code reads it: one input frame. */
export const MAX_TEXT_BYTES = 64 * 1024

/**
 * The most bytes of a paste one input carries: one input frame less the two delimiters of bracketed
 * paste, so a paste fits whether or not the program asked for them.
 */
export const MAX_PASTE_BYTES = MAX_TEXT_BYTES - '\u001b[200~'.length - '\u001b[201~'.length

/** Why text or a paste too long for one input does not go. */
export const TOO_LONG = 'it is longer than one input can carry'

/** Words for an input that did not reach the program, as native code says them. */
export function unsent(what: 'That key' | 'That text' | 'That paste', why: string): string {
  return `${what} did not reach the program: ${why}.`
}

/** The keys that make no character which native code names. */
const NAMED_KEYS: ReadonlySet<string> = new Set([
  'Enter',
  'Tab',
  'Backspace',
  'Escape',
  'ArrowUp',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
  'Home',
  'End',
  'PageUp',
  'PageDown',
  'Insert',
  'Delete',
  'ContextMenu',
  'PrintScreen',
  'Pause',
  ...Array.from({ length: 24 }, (_, index) => `F${index + 1}`)
])

/** The key the keypad's middle key is with Num Lock off, which only the keypad has. */
const KEYPAD_BEGIN = 'Clear'

/** The keys an input method is using: the platform's own, left to it. */
const INPUT_METHOD_KEYS: ReadonlySet<string> = new Set(['Process', 'Dead', 'Unidentified'])

/** What a terminal off Apple platforms copies and pastes with, Control and Shift held. */
const COPY_AND_PASTE: ReadonlySet<string> = new Set(['c', 'C', 'v', 'V'])

/** One keyboard event, as the page reads it. */
export interface KeyReading {
  readonly key: string
  /** The platform's code for the key's place, or empty where it gives none. */
  readonly code: string
  readonly keyCode: number
  readonly isComposing: boolean
  readonly repeat: boolean
  readonly shiftKey: boolean
  readonly altKey: boolean
  readonly ctrlKey: boolean
  readonly metaKey: boolean
  readonly capsLock: boolean
  readonly numLock: boolean
  readonly altGraph: boolean
}

/** What the page reads of a keyboard event. */
export function readingOf(event: KeyboardEvent): KeyReading {
  return {
    key: event.key,
    code: event.code,
    keyCode: event.keyCode,
    isComposing: event.isComposing,
    repeat: event.repeat,
    shiftKey: event.shiftKey,
    altKey: event.altKey,
    ctrlKey: event.ctrlKey,
    metaKey: event.metaKey,
    capsLock: event.getModifierState('CapsLock'),
    numLock: event.getModifierState('NumLock'),
    altGraph: event.getModifierState('AltGraph')
  }
}

/** Where a key was typed, as far as naming it goes. */
export interface KeyPlatform {
  /** Whether it is an Apple platform, where Option makes characters and Command is the platform's. */
  readonly apple: boolean
  /**
   * The character each key of the keyboard layout makes with nothing held, by the key's code, where
   * the platform offers the map, and null where it does not.
   */
  readonly layout: { get(code: string): string | undefined } | null
}

/** Whether a user agent is an Apple platform's: a Macintosh, an iPhone or an iPad. */
export function applePlatform(userAgent: string): boolean {
  return /macintosh|mac os x|iphone|ipad|ipod/i.test(userAgent)
}

/** Whether a code point is a control character: C0, Delete, or C1. */
function isControl(point: number): boolean {
  return point <= 0x1f || (point >= 0x7f && point <= 0x9f)
}

/** Whether `text` is one character that is not a control character. */
export function isCharacter(text: string): boolean {
  const scalars = [...text]
  const point = scalars.length === 1 ? text.codePointAt(0) : undefined
  return point !== undefined && !isControl(point)
}

/**
 * Whether a keydown belongs to an input method, which keeps it: one it is composing with, one at a
 * composition's edges, where the platform reports key code 229 and not that it composes, or a key
 * the platform names as the input method's.
 */
export function ownedByInputMethod(reading: KeyReading): boolean {
  return reading.isComposing || reading.keyCode === 229 || INPUT_METHOD_KEYS.has(reading.key)
}

/**
 * Which way a keydown moves the focus out of the program's keyboard: Control-Tab to the next
 * control, Control-Shift-Tab to the one before, as a field that takes Tab does on macOS, Windows and
 * Linux. Null for every other key.
 */
export function focusEscape(reading: KeyReading): 'next' | 'previous' | null {
  if (reading.key !== 'Tab' || !reading.ctrlKey || reading.altKey || reading.metaKey) return null
  return reading.shiftKey ? 'previous' : 'next'
}

/** The keypad key a code names, or null for any other key. */
function keypadOf(code: string): KeypadCode | null {
  return KEYPAD_CODES.find((each) => each === code) ?? null
}

/**
 * The character the key makes with nothing held: the layout's, where the platform offers the map
 * and it holds the key, and otherwise the key's own character while nothing that changes one is
 * held. Null where neither says: never a guess.
 */
function baseOf(reading: KeyReading, platform: KeyPlatform): string | null {
  const mapped = reading.code === '' ? undefined : platform.layout?.get(reading.code)
  if (mapped !== undefined) return isCharacter(mapped) ? mapped : null
  const changed = reading.shiftKey || reading.capsLock || reading.altGraph || (platform.apple && reading.altKey)
  return changed ? null : reading.key
}

/**
 * The key a keydown is, as native code takes it, or null when the keydown is not one of the
 * program's keys and is left to the platform.
 */
export function keyOf(reading: KeyReading, platform: KeyPlatform): TypedKey | null {
  if (ownedByInputMethod(reading) || reading.metaKey) return null
  if (!platform.apple && reading.ctrlKey && reading.shiftKey && COPY_AND_PASTE.has(reading.key)) return null
  const keypad = keypadOf(reading.code)
  const character = isCharacter(reading.key)
  const named = NAMED_KEYS.has(reading.key) || (keypad !== null && reading.key === KEYPAD_BEGIN)
  if (!character && !named) return null
  // A character AltGraph or Apple's Option made is the character: they are how it is typed.
  const made = character && (reading.altGraph || (platform.apple && reading.altKey))
  return {
    key: reading.key,
    base: character && keypad === null ? baseOf(reading, platform) : null,
    keypad,
    shift: reading.shiftKey,
    alt: made ? false : reading.altKey,
    control: made ? false : reading.ctrlKey,
    caps_lock: reading.capsLock,
    num_lock: reading.numLock
  }
}

/**
 * The modifiers a keyup reports for the key its press named: its own, under the same rule, so a
 * character AltGraph or Option made is let go with neither.
 */
export function releasedWith(
  reading: KeyReading,
  pressed: TypedKey,
  platform: KeyPlatform
): Pick<TypedKey, 'shift' | 'alt' | 'control' | 'caps_lock' | 'num_lock'> {
  const made = isCharacter(pressed.key) && (reading.altGraph || (platform.apple && reading.altKey))
  return {
    shift: reading.shiftKey,
    alt: made ? false : reading.altKey,
    control: made ? false : reading.ctrlKey,
    caps_lock: reading.capsLock,
    num_lock: reading.numLock
  }
}

/**
 * Which key a press was, so its release finds it: its code, or its key where the platform gives no
 * code.
 */
export function identityOf(reading: KeyReading): string {
  return reading.code === '' ? `key ${reading.key}` : `code ${reading.code}`
}

/**
 * Text as it may go to the program: the program keyboard's invisible character taken off wherever it
 * is, and every control character dropped. A line break a software keyboard typed is Enter, a key,
 * and text never becomes one.
 */
export function sendableText(text: string): string {
  let kept = ''
  for (const scalar of text) {
    const point = scalar.codePointAt(0) ?? 0
    if (scalar !== SENTINEL && !isControl(point)) kept += scalar
  }
  return kept
}

/** How many bytes `text` is in UTF-8. */
export function utf8Length(text: string): number {
  return new TextEncoder().encode(text).length
}
