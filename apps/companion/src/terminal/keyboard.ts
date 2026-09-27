/**
 * The program's keyboard: the field that takes the person's keys, text and paste for the program
 * while a raw view controls it, on the desktop and on the phone alike.
 *
 * Between edits it holds one invisible character (`SENTINEL`) and nothing else, with the caret after
 * it, so a software keyboard's Backspace always has something to delete, and is seen. A key is taken
 * at its keydown, named (`keys.ts`) and sent, and inserts nothing. Everything else the platform does
 * to the field is an edit, read and undone in its own handler: the edit's own text is what the field
 * holds besides that character, and the field holds that character alone again, with the caret
 * after it, before the handler returns, whatever order the platform delivers edits in.
 *
 * An input method composes in the field, and a composition is one transaction: what it commits goes
 * as text, once, at its end, and nothing it did on the way goes at all, its own Enter and Backspace
 * included. Outside one, a software keyboard's line break is Enter and its deletion backward is
 * Backspace, each a press alone, and what it inserts is text. Text is never made into keys. A paste
 * goes as a paste, and inserts nothing. A key the page names the phone's latched terminal keys hold
 * for, and they let it go after.
 *
 * Tab and Shift-Tab are the program's. Control-Tab and Control-Shift-Tab move the focus on to the
 * next control, or back to the one before, and stop at the first and the last, as a field that takes
 * Tab does on each desktop platform.
 */

import { useCallback, useLayoutEffect, useRef, useState, type RefObject } from 'react'

import type { ProgramInput, TypedKey } from '../host/port'
import {
  focusEscape,
  identityOf,
  keyOf,
  MAX_PASTE_BYTES,
  MAX_TEXT_BYTES,
  ownedByInputMethod,
  readingOf,
  releasedWith,
  sendableText,
  SENTINEL,
  TOO_LONG,
  unsent,
  utf8Length,
  type KeyPlatform
} from './keys'

/** Modifiers the phone's terminal keys hold for a key. */
export interface Latched {
  readonly control: boolean
  readonly alt: boolean
}

/** Nothing held. */
const NOTHING_LATCHED: Latched = { control: false, alt: false }

/** What the program's keyboard is told of the view it types into. */
export interface ProgramKeyboardOptions {
  /** The take an input would go under now, or null while nothing would go. */
  readonly controlTake: () => number | null
  /** Sends one input to the program. */
  readonly toProgram: (input: ProgramInput) => Promise<void>
  /** Says why an input the page held back did not reach the program. */
  readonly refuse: (words: string) => void
  /** Whether the keys are typed on an Apple platform. */
  readonly apple: boolean
  /**
   * The modifiers the phone's terminal keys hold for the next key, which that key takes: they are
   * let go as it takes them if they were held for one key only.
   */
  readonly latched?: () => Latched
}

/** The program's keyboard, for the textarea that is it. */
export interface ProgramKeyboard {
  /** Makes a textarea the program's keyboard: its callback ref. */
  readonly attach: (element: HTMLTextAreaElement | null) => (() => void) | undefined
  /** What an input method is composing, without the invisible character, or null while nothing is. */
  readonly composing: string | null
  /** Puts the focus in the field, where it is while the view controls the program. */
  readonly focus: () => void
}

/** The input types of a composition, which belong to the input method and never send. */
const COMPOSITION_TYPES: ReadonlySet<string> = new Set([
  'insertCompositionText',
  'insertFromComposition',
  'deleteCompositionText',
  'deleteByComposition'
])

/** The most presses the field keeps for their releases at once: far more than a person holds. */
const MOST_PRESSES = 256

/** A press the field sent: under which take, as which key, and what the terminal keys held for it. */
interface Pressed {
  readonly take: number
  readonly key: TypedKey
  readonly latched: Latched
}

/** Where a platform offers its keyboard layout. */
interface LayoutSource {
  readonly keyboard?: {
    readonly getLayoutMap?: () => Promise<{ get(code: string): string | undefined }>
  }
}

/** The elements a keyboard can reach, before the ones it cannot are taken out. */
const FOCUSABLE =
  'a[href], area[href], button, input, select, textarea, iframe, summary, [tabindex], [contenteditable]'

/** Whether a keyboard can reach `element`. */
function reachable(element: HTMLElement): boolean {
  if (element.tabIndex < 0 || element.matches(':disabled')) return false
  if (element.closest('[inert], [hidden]') !== null) return false
  return typeof element.checkVisibility === 'function' ? element.checkVisibility() : true
}

/**
 * Moves the focus from `from` to the next control a keyboard reaches in the page's order, or to the
 * one before, and leaves it where it is at the first and the last.
 */
export function moveFocus(from: HTMLElement, direction: 'next' | 'previous'): void {
  const order = Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (element) => element === from || reachable(element)
  )
  const at = order.indexOf(from)
  if (at === -1) return
  order[direction === 'next' ? at + 1 : at - 1]?.focus()
}

/** The program's keyboard, attached to `element`, told of the view through `latest`. */
function attach(
  element: HTMLTextAreaElement,
  latest: RefObject<ProgramKeyboardOptions>,
  setComposing: (composing: string | null) => void
): () => void {
  let composition = false
  let layout: KeyPlatform['layout'] = null
  const presses = new Map<string, Pressed>()
  const platform = (): KeyPlatform => ({ apple: latest.current.apple, layout })

  /** Puts the field back to the invisible character alone, with the caret after it. */
  const restore = () => {
    if (element.value !== SENTINEL) element.value = SENTINEL
    if (element.selectionStart !== 1 || element.selectionEnd !== 1) element.setSelectionRange(1, 1)
  }

  const send = (input: ProgramInput) => {
    latest.current.toProgram(input).catch(() => {
      // The view says why an input did not reach the program.
    })
  }

  const sendText = (text: string) => {
    if (text === '') return
    if (utf8Length(text) > MAX_TEXT_BYTES) {
      latest.current.refuse(unsent('That text', TOO_LONG))
      return
    }
    send({ kind: 'text', text })
  }

  /** A key a software keyboard's edit stands for: pressed alone, with nothing held. */
  const sendAlone = (key: 'Enter' | 'Backspace') => {
    send({
      kind: 'key',
      event: 'press',
      key,
      base: null,
      keypad: null,
      shift: false,
      alt: false,
      control: false,
      caps_lock: false,
      num_lock: false
    })
  }

  const readLayout = () => {
    const source = navigator as unknown as LayoutSource
    source.keyboard?.getLayoutMap?.().then(
      (map) => {
        layout = map
      },
      () => {
        // A platform that will not say keeps the key's own character.
      }
    )
  }

  const onKeyDown = (event: KeyboardEvent) => {
    const reading = readingOf(event)
    if (composition || ownedByInputMethod(reading)) return
    const escape = focusEscape(reading)
    if (escape !== null) {
      event.preventDefault()
      moveFocus(element, escape)
      return
    }
    const take = latest.current.controlTake()
    if (take === null) return
    const typed = keyOf(reading, platform())
    if (typed === null) return
    event.preventDefault()
    const identity = identityOf(reading)
    // A repeat holds what its press held; a press takes what the terminal keys hold for it.
    const latched = reading.repeat
      ? (presses.get(identity)?.latched ?? NOTHING_LATCHED)
      : (latest.current.latched?.() ?? NOTHING_LATCHED)
    const key: TypedKey = { ...typed, control: typed.control || latched.control, alt: typed.alt || latched.alt }
    if (!reading.repeat && (presses.size < MOST_PRESSES || presses.has(identity))) {
      presses.set(identity, { take, key, latched })
    }
    send({ kind: 'key', event: reading.repeat ? 'repeat' : 'press', ...key })
  }

  const onKeyUp = (event: KeyboardEvent) => {
    const reading = readingOf(event)
    const identity = identityOf(reading)
    const pressed = presses.get(identity)
    if (pressed === undefined) return
    presses.delete(identity)
    // A release goes only under the take its press went under.
    if (latest.current.controlTake() !== pressed.take) return
    const own = releasedWith(reading, pressed.key, platform())
    send({
      kind: 'key',
      event: 'release',
      key: pressed.key.key,
      base: pressed.key.base,
      keypad: pressed.key.keypad,
      ...own,
      control: own.control || pressed.latched.control,
      alt: own.alt || pressed.latched.alt
    })
  }

  const onCompositionStart = () => {
    composition = true
    setComposing('')
  }

  const onCompositionUpdate = (event: CompositionEvent) => {
    setComposing(sendableText(event.data))
  }

  const onCompositionEnd = (event: CompositionEvent) => {
    composition = false
    setComposing(null)
    if (latest.current.controlTake() !== null) sendText(sendableText(event.data))
    restore()
  }

  const onInput = (event: Event) => {
    const type = event instanceof InputEvent ? event.inputType : ''
    if (COMPOSITION_TYPES.has(type)) {
      // During a composition the field is the input method's; after it, what it left goes.
      if (!composition) restore()
      return
    }
    if (composition) return
    if (latest.current.controlTake() !== null) {
      if (type === 'insertLineBreak' || type === 'insertParagraph') sendAlone('Enter')
      else if (type === 'deleteContentBackward') sendAlone('Backspace')
      else if (!/^(delete|history|format)/.test(type)) sendText(sendableText(element.value))
    }
    restore()
  }

  const onPaste = (event: ClipboardEvent) => {
    event.preventDefault()
    if (latest.current.controlTake() === null) return
    const text = event.clipboardData?.getData('text/plain') ?? ''
    if (text === '') return
    if (utf8Length(text) > MAX_PASTE_BYTES) {
      latest.current.refuse(unsent('That paste', TOO_LONG))
      return
    }
    send({ kind: 'paste', text })
  }

  const onFocus = () => {
    if (!composition) restore()
    readLayout()
  }

  // The caret stays after the invisible character, wherever a tap or the platform puts it.
  const onSelectionChange = () => {
    if (composition || document.activeElement !== element || element.value !== SENTINEL) return
    if (element.selectionStart !== 1 || element.selectionEnd !== 1) element.setSelectionRange(1, 1)
  }

  restore()
  element.addEventListener('keydown', onKeyDown)
  element.addEventListener('keyup', onKeyUp)
  element.addEventListener('compositionstart', onCompositionStart)
  element.addEventListener('compositionupdate', onCompositionUpdate)
  element.addEventListener('compositionend', onCompositionEnd)
  element.addEventListener('input', onInput)
  element.addEventListener('paste', onPaste)
  element.addEventListener('focus', onFocus)
  document.addEventListener('selectionchange', onSelectionChange)
  return () => {
    element.removeEventListener('keydown', onKeyDown)
    element.removeEventListener('keyup', onKeyUp)
    element.removeEventListener('compositionstart', onCompositionStart)
    element.removeEventListener('compositionupdate', onCompositionUpdate)
    element.removeEventListener('compositionend', onCompositionEnd)
    element.removeEventListener('input', onInput)
    element.removeEventListener('paste', onPaste)
    element.removeEventListener('focus', onFocus)
    document.removeEventListener('selectionchange', onSelectionChange)
  }
}

/** The program's keyboard of one view. */
export function useProgramKeyboard(options: ProgramKeyboardOptions): ProgramKeyboard {
  const [composing, setComposing] = useState<string | null>(null)
  const latest = useRef(options)
  useLayoutEffect(() => {
    latest.current = options
  })
  const field = useRef<HTMLTextAreaElement | null>(null)

  const attachTo = useCallback((element: HTMLTextAreaElement | null) => {
    if (element === null) return undefined
    field.current = element
    const detach = attach(element, latest, setComposing)
    return () => {
      detach()
      if (field.current === element) field.current = null
      setComposing(null)
    }
  }, [])

  const focus = useCallback(() => {
    field.current?.focus({ preventScroll: true })
  }, [])

  return { attach: attachTo, composing, focus }
}
