/**
 * The program's keyboard: the field a raw view types into the program with, on the desktop and on
 * the phone alike. What is checked is what reaches the program for each thing a platform does to the
 * field: a key, an input method's composition, a software keyboard's edits, a paste, and the focus
 * moving on with Control-Tab.
 */

import { useState, type ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { ProgramInput } from '../src/host/port'
import { useProgramKeyboard, type Latched, type ProgramKeyboardOptions } from '../src/terminal/keyboard'
import { MAX_PASTE_BYTES, MAX_TEXT_BYTES, SENTINEL } from '../src/terminal/keys'

/** What the harness records, and how a test steers it. */
interface Recorder {
  /** Every input sent to the program, in order. */
  readonly sent: ProgramInput[]
  /** Every refusal the page itself said. */
  readonly refused: string[]
  /** The take inputs go under, or null while none would go. */
  take: number | null
  /** What the terminal keys hold for the next key, and how often a key took it. */
  latch: Latched
  taken: number
}

function recorder(): Recorder {
  return { sent: [], refused: [], take: 1, latch: { control: false, alt: false }, taken: 0 }
}

/** What the program's keyboard is told, recorded in `record`; with the terminal keys' latch when told. */
function optionsFor(record: Recorder, latching: boolean): ProgramKeyboardOptions {
  return {
    controlTake: () => record.take,
    toProgram: (input) => {
      record.sent.push(input)
      return Promise.resolve()
    },
    refuse: (words) => {
      record.refused.push(words)
    },
    apple: false,
    ...(latching
      ? {
          latched: () => {
            record.taken += 1
            const held = record.latch
            record.latch = { control: false, alt: false }
            return held
          }
        }
      : {})
  }
}

/** The program's keyboard among other controls, as a view places it, or alone in the page. */
function Harness({
  record,
  latching = false,
  alone = false
}: {
  readonly record: Recorder
  /** Whether the phone's terminal keys hold modifiers for it. */
  readonly latching?: boolean
  /** Whether it is the only control a keyboard reaches, and so the first and the last. */
  readonly alone?: boolean
}): ReactNode {
  const [shown, setShown] = useState(true)
  const [options] = useState(() => optionsFor(record, latching))
  const { attach, composing } = useProgramKeyboard(options)
  return (
    <div>
      {alone ? null : (
        <>
          <button type="button">Before</button>
          <button type="button" disabled>
            Disabled
          </button>
        </>
      )}
      {shown ? (
        <textarea
          ref={attach}
          data-program-keyboard=""
          aria-label="Type to the program"
          defaultValue={SENTINEL}
        />
      ) : null}
      <span data-testid="composing">{composing ?? 'none'}</span>
      {alone ? null : (
        <>
          <button
            type="button"
            onClick={() => {
              setShown(false)
            }}
          >
            End control
          </button>
          <button type="button">After</button>
        </>
      )}
    </div>
  )
}

function field(): HTMLTextAreaElement {
  return screen.getByLabelText<HTMLTextAreaElement>('Type to the program')
}

/** A key's press or release, named as the page names it, with nothing held unless told. */
function key(
  name: string,
  event: 'press' | 'repeat' | 'release',
  over: Partial<Extract<ProgramInput, { kind: 'key' }>> = {}
): ProgramInput {
  return {
    kind: 'key',
    event,
    key: name,
    base: [...name].length === 1 ? name : null,
    keypad: null,
    shift: false,
    alt: false,
    control: false,
    caps_lock: false,
    num_lock: false,
    ...over
  }
}

/** What a software keyboard's edit leaves in the field, and the input event it fires for it. */
function edit(value: string, inputType: string, data: string | null = null): void {
  const element = field()
  act(() => {
    element.value = value
    element.setSelectionRange(value.length, value.length)
    element.dispatchEvent(new InputEvent('input', { bubbles: true, inputType, data }))
  })
}

function composition(type: 'compositionstart' | 'compositionupdate' | 'compositionend', data: string): void {
  act(() => {
    field().dispatchEvent(new CompositionEvent(type, { bubbles: true, data }))
  })
}

/** A paste of `text`, as the platform's paste command fires it. */
function paste(text: string): Event {
  const event = new Event('paste', { bubbles: true, cancelable: true })
  Object.defineProperty(event, 'clipboardData', {
    value: { getData: (type: string) => (type === 'text/plain' ? text : '') }
  })
  act(() => {
    field().dispatchEvent(event)
  })
  return event
}

/** Whether the field holds the invisible character alone, with the caret after it. */
function atRest(): boolean {
  const element = field()
  return element.value === SENTINEL && element.selectionStart === 1 && element.selectionEnd === 1
}

describe('a key reaches the program named, and inserts nothing (KR-REQ-13.17, 08.59)', () => {
  it('sends each key as its press and its release, and leaves the field as it was', async () => {
    const person = userEvent.setup()
    const record = recorder()
    render(<Harness record={record} />)
    field().focus()
    await person.keyboard('a{Enter}{Escape}{ArrowUp}')
    expect(record.sent).toEqual([
      key('a', 'press'),
      key('a', 'release'),
      key('Enter', 'press'),
      key('Enter', 'release'),
      key('Escape', 'press'),
      key('Escape', 'release'),
      key('ArrowUp', 'press'),
      key('ArrowUp', 'release')
    ])
    expect(atRest()).toBe(true)
  })

  it('sends Control-C and its release with what is held as it is let go', async () => {
    const person = userEvent.setup()
    const record = recorder()
    render(<Harness record={record} />)
    field().focus()
    await person.keyboard('{Control>}c{/Control}')
    // Control goes up before the key.
    await person.keyboard('{Control>}{c>}{/Control}{/c}')
    expect(record.sent).toEqual([
      key('c', 'press', { control: true }),
      key('c', 'release', { control: true }),
      key('c', 'press', { control: true }),
      key('c', 'release')
    ])
  })

  it('sends a repeat as a repeat, and a key held with Shift as the character it makes', () => {
    const record = recorder()
    render(<Harness record={record} />)
    const element = field()
    element.focus()
    fireEvent.keyDown(element, { key: 'A', code: 'KeyA', shiftKey: true })
    fireEvent.keyDown(element, { key: 'A', code: 'KeyA', shiftKey: true, repeat: true })
    fireEvent.keyUp(element, { key: 'a', code: 'KeyA' })
    expect(record.sent).toEqual([
      key('A', 'press', { base: null, shift: true }),
      key('A', 'repeat', { base: null, shift: true }),
      // The release names the key its press established, however the platform names it now.
      key('A', 'release', { base: null })
    ])
  })

  it("sends the locks that are on, and a keypad key by its code", () => {
    const record = recorder()
    render(<Harness record={record} />)
    const element = field()
    fireEvent.keyDown(element, { key: '7', code: 'Numpad7', modifierNumLock: true })
    fireEvent.keyDown(element, { key: 'Q', code: 'KeyQ', modifierCapsLock: true })
    expect(record.sent).toEqual([
      key('7', 'press', { base: null, keypad: 'Numpad7', num_lock: true }),
      key('Q', 'press', { base: null, caps_lock: true })
    ])
  })

  it("leaves a platform chord and an input method's keydown to the platform", () => {
    const record = recorder()
    render(<Harness record={record} />)
    const element = field()
    for (const init of [
      { key: 'v', code: 'KeyV', metaKey: true },
      { key: 'V', code: 'KeyV', ctrlKey: true, shiftKey: true },
      { key: 'Backspace', code: 'Backspace', keyCode: 229 },
      { key: 'a', code: 'KeyA', isComposing: true },
      { key: 'Dead', code: 'Quote' },
      { key: 'Shift', code: 'ShiftLeft', shiftKey: true }
    ]) {
      // A keydown the platform keeps is not prevented: its default still happens.
      expect(fireEvent.keyDown(element, init), JSON.stringify(init)).toBe(true)
    }
    expect(record.sent).toEqual([])
  })

  it('sends no release but under the take its press went under', () => {
    const record = recorder()
    render(<Harness record={record} />)
    const element = field()
    fireEvent.keyDown(element, { key: 'x', code: 'KeyX' })
    record.take = 2
    fireEvent.keyUp(element, { key: 'x', code: 'KeyX' })
    // And a release whose press this field never sent is nothing.
    fireEvent.keyUp(element, { key: 'y', code: 'KeyY' })
    expect(record.sent).toEqual([key('x', 'press')])
  })

  it('sends nothing, and prevents nothing, while nothing would go', async () => {
    const person = userEvent.setup()
    const record = recorder()
    record.take = null
    render(<Harness record={record} />)
    field().focus()
    await person.keyboard('q')
    expect(record.sent).toEqual([])
    // Tab is then no key: the focus moves on.
    await person.tab()
    expect(screen.getByRole('button', { name: 'End control' })).toHaveFocus()
  })
})

describe('Tab is the program’s, and Control-Tab moves on (KR-REQ-13.18)', () => {
  it('sends Tab and Shift-Tab to the program, and keeps the focus in the field', async () => {
    const person = userEvent.setup()
    const record = recorder()
    render(<Harness record={record} />)
    field().focus()
    await person.keyboard('{Tab}{Shift>}{Tab}{/Shift}{Alt>}{Tab}{/Alt}')
    expect(record.sent).toEqual([
      key('Tab', 'press'),
      key('Tab', 'release'),
      key('Tab', 'press', { shift: true }),
      key('Tab', 'release', { shift: true }),
      key('Tab', 'press', { alt: true }),
      key('Tab', 'release', { alt: true })
    ])
    expect(field()).toHaveFocus()
  })

  it('moves the focus on with Control-Tab and back with Control-Shift-Tab, past what a keyboard cannot reach, sending nothing', async () => {
    const person = userEvent.setup()
    const record = recorder()
    render(<Harness record={record} />)
    field().focus()
    await person.keyboard('{Control>}{Tab}{/Control}')
    expect(screen.getByRole('button', { name: 'End control' })).toHaveFocus()
    field().focus()
    await person.keyboard('{Control>}{Shift>}{Tab}{/Shift}{/Control}')
    // The disabled control between is passed over.
    expect(screen.getByRole('button', { name: 'Before' })).toHaveFocus()
    expect(record.sent).toEqual([])
  })

  it('stops at the last control and at the first', () => {
    const record = recorder()
    render(<Harness record={record} alone />)
    const element = field()
    element.focus()
    // Never sent, and its default prevented, at either end.
    expect(fireEvent.keyDown(element, { key: 'Tab', code: 'Tab', ctrlKey: true })).toBe(false)
    expect(element).toHaveFocus()
    expect(fireEvent.keyDown(element, { key: 'Tab', code: 'Tab', ctrlKey: true, shiftKey: true })).toBe(false)
    expect(element).toHaveFocus()
    expect(record.sent).toEqual([])
  })
})

describe("an input method's text goes once, as text (KR-REQ-08.56)", () => {
  it('sends a composition once, at its end, and shows it while it lasts', () => {
    const record = recorder()
    render(<Harness record={record} />)
    composition('compositionstart', '')
    expect(screen.getByTestId('composing').textContent).toBe('')
    composition('compositionupdate', 'に')
    edit(`${SENTINEL}に`, 'insertCompositionText', 'に')
    expect(screen.getByTestId('composing').textContent).toBe('に')
    composition('compositionupdate', '日本')
    edit(`${SENTINEL}日本`, 'insertCompositionText', '日本')
    expect(record.sent).toEqual([])
    composition('compositionend', '日本')
    expect(record.sent).toEqual([{ kind: 'text', text: '日本' }])
    expect(screen.getByTestId('composing').textContent).toBe('none')
    expect(atRest()).toBe(true)
  })

  it('sends nothing more for the input a platform fires after a composition ends, and sends text typed after it', () => {
    const record = recorder()
    render(<Harness record={record} />)
    composition('compositionstart', '')
    composition('compositionupdate', 'é')
    composition('compositionend', 'é')
    // WebKit fires the committing input after the end.
    edit(`${SENTINEL}é`, 'insertFromComposition', 'é')
    expect(atRest()).toBe(true)
    // The same text typed at once after it is new text.
    edit(`${SENTINEL}é`, 'insertText', 'é')
    expect(record.sent).toEqual([
      { kind: 'text', text: 'é' },
      { kind: 'text', text: 'é' }
    ])
    expect(atRest()).toBe(true)
  })

  it('sends nothing for a composition that was cancelled, and never the invisible character it took in', () => {
    const record = recorder()
    render(<Harness record={record} />)
    composition('compositionstart', '')
    composition('compositionupdate', 'k')
    composition('compositionend', '')
    expect(record.sent).toEqual([])
    composition('compositionstart', '')
    composition('compositionend', `${SENTINEL}漢字`)
    expect(record.sent).toEqual([{ kind: 'text', text: '漢字' }])
  })

  it("leaves the input method its own Enter and Backspace during a composition", () => {
    const record = recorder()
    render(<Harness record={record} />)
    composition('compositionstart', '')
    edit(`${SENTINEL}かな`, 'insertCompositionText', 'かな')
    expect(fireEvent.keyDown(field(), { key: 'Backspace', code: 'Backspace' })).toBe(true)
    edit(`${SENTINEL}か`, 'deleteCompositionText')
    expect(fireEvent.keyDown(field(), { key: 'Enter', code: 'Enter' })).toBe(true)
    expect(record.sent).toEqual([])
    composition('compositionend', 'か')
    expect(record.sent).toEqual([{ kind: 'text', text: 'か' }])
  })

  it('sends nothing when control ends in the middle of a composition', () => {
    const record = recorder()
    render(<Harness record={record} />)
    edit(`${SENTINEL}a`, 'insertText', 'a')
    composition('compositionstart', '')
    composition('compositionupdate', 'b')
    fireEvent.click(screen.getByRole('button', { name: 'End control' }))
    expect(record.sent).toEqual([{ kind: 'text', text: 'a' }])
    expect(screen.getByTestId('composing').textContent).toBe('none')
  })

  it("keeps the terminal keys' held modifiers through text and a composition, for the next key", () => {
    const record = recorder()
    render(<Harness record={record} latching />)
    record.latch = { control: true, alt: false }
    composition('compositionstart', '')
    composition('compositionend', 'ü')
    edit(`${SENTINEL}x`, 'insertText', 'x')
    edit('', 'deleteContentBackward')
    expect(record.taken).toBe(0)
    fireEvent.keyDown(field(), { key: 'c', code: 'KeyC' })
    fireEvent.keyDown(field(), { key: 'c', code: 'KeyC', repeat: true })
    fireEvent.keyUp(field(), { key: 'c', code: 'KeyC' })
    // The key took what was held, once; its repeat and its release hold it too.
    expect(record.taken).toBe(1)
    expect(record.sent.slice(-3)).toEqual([
      key('c', 'press', { control: true }),
      key('c', 'repeat', { control: true }),
      key('c', 'release', { control: true })
    ])
  })
})

describe("a software keyboard's edits (KR-REQ-13.17)", () => {
  it('sends Backspace for a deletion of the invisible character, after text, and again, with the caret after it each time', () => {
    const record = recorder()
    render(<Harness record={record} />)
    edit('', 'deleteContentBackward')
    expect(atRest()).toBe(true)
    edit(`${SENTINEL}ok`, 'insertText', 'ok')
    edit('', 'deleteContentBackward')
    edit('', 'deleteContentBackward')
    expect(record.sent).toEqual([
      key('Backspace', 'press', { base: null }),
      { kind: 'text', text: 'ok' },
      key('Backspace', 'press', { base: null }),
      key('Backspace', 'press', { base: null })
    ])
    expect(atRest()).toBe(true)
  })

  it('sends one Backspace for a deletion whose beforeinput was cancelled, and never takes a keydown of code 229 for it', () => {
    const record = recorder()
    render(<Harness record={record} />)
    const element = field()
    expect(fireEvent.keyDown(element, { key: 'Unidentified', keyCode: 229 })).toBe(true)
    act(() => {
      const before = new InputEvent('beforeinput', { bubbles: true, cancelable: true, inputType: 'deleteContentBackward' })
      element.dispatchEvent(before)
      before.preventDefault()
    })
    edit('', 'deleteContentBackward')
    expect(record.sent).toEqual([key('Backspace', 'press', { base: null })])
  })

  it('sends each of two quick insertions and two quick deletions once', () => {
    const record = recorder()
    render(<Harness record={record} />)
    edit(`${SENTINEL}a`, 'insertText', 'a')
    edit(`${SENTINEL}b`, 'insertText', 'b')
    edit('', 'deleteContentBackward')
    edit('', 'deleteContentBackward')
    expect(record.sent).toEqual([
      { kind: 'text', text: 'a' },
      { kind: 'text', text: 'b' },
      key('Backspace', 'press', { base: null }),
      key('Backspace', 'press', { base: null })
    ])
  })

  it('sends Enter for a line break, nothing for a deletion of a word, and a replacement or an insertion before the invisible character as text', () => {
    const record = recorder()
    render(<Harness record={record} />)
    edit(`${SENTINEL}\n`, 'insertLineBreak')
    edit(`${SENTINEL}\n`, 'insertParagraph')
    edit('', 'deleteWordBackward')
    edit('', 'deleteSoftLineBackward')
    edit('hello', 'insertReplacementText', 'hello')
    edit(`x${SENTINEL}`, 'insertText', 'x')
    edit(`${SENTINEL}a\tb\u001b`, 'insertFromDrop')
    expect(record.sent).toEqual([
      key('Enter', 'press', { base: null }),
      key('Enter', 'press', { base: null }),
      { kind: 'text', text: 'hello' },
      { kind: 'text', text: 'x' },
      { kind: 'text', text: 'ab' }
    ])
    expect(atRest()).toBe(true)
  })

  it('says why text too long for one input did not go, and sends none of it', () => {
    const record = recorder()
    render(<Harness record={record} />)
    edit(`${SENTINEL}${'x'.repeat(MAX_TEXT_BYTES + 1)}`, 'insertFromDrop')
    expect(record.sent).toEqual([])
    expect(record.refused).toEqual(['That text did not reach the program: it is longer than one input can carry.'])
    expect(atRest()).toBe(true)
  })
})

describe('a paste goes as a paste (KR-REQ-08.59)', () => {
  it('sends the pasted text as it is, and inserts nothing', () => {
    const record = recorder()
    render(<Harness record={record} />)
    const event = paste('echo one\necho two\t\u001b')
    expect(event.defaultPrevented).toBe(true)
    expect(record.sent).toEqual([{ kind: 'paste', text: 'echo one\necho two\t\u001b' }])
    expect(atRest()).toBe(true)
  })

  it('refuses a paste longer than one input with words, and sends nothing for an empty one', () => {
    const record = recorder()
    render(<Harness record={record} />)
    expect(paste('é'.repeat(MAX_PASTE_BYTES / 2)).defaultPrevented).toBe(true)
    expect(paste('x'.repeat(MAX_PASTE_BYTES + 1)).defaultPrevented).toBe(true)
    expect(paste('').defaultPrevented).toBe(true)
    expect(record.sent).toEqual([{ kind: 'paste', text: 'é'.repeat(MAX_PASTE_BYTES / 2) }])
    expect(record.refused).toEqual(['That paste did not reach the program: it is longer than one input can carry.'])
  })
})
