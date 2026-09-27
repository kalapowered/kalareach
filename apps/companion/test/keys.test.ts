/**
 * The person's keys as the page names them for the program: which keyboard events are keys, what
 * each key is named, the character it makes with nothing held where the platform says, and what
 * text may go.
 */

import { describe, expect, it } from 'vitest'

import {
  applePlatform,
  focusEscape,
  identityOf,
  isCharacter,
  keyOf,
  MAX_PASTE_BYTES,
  MAX_TEXT_BYTES,
  releasedWith,
  sendableText,
  SENTINEL,
  type KeyPlatform,
  type KeyReading
} from '../src/terminal/keys'

/** A keydown of `key` at `code` with nothing held, with any reading `over` gives. */
function reading(key: string, code: string, over: Partial<KeyReading> = {}): KeyReading {
  return {
    key,
    code,
    keyCode: 0,
    isComposing: false,
    repeat: false,
    shiftKey: false,
    altKey: false,
    ctrlKey: false,
    metaKey: false,
    capsLock: false,
    numLock: false,
    altGraph: false,
    ...over
  }
}

const LINUX: KeyPlatform = { apple: false, layout: null }
const MAC: KeyPlatform = { apple: true, layout: null }

/** A platform whose keyboard layout map says what each code makes with nothing held. */
function withLayout(entries: Record<string, string>, apple = false): KeyPlatform {
  const map = new Map(Object.entries(entries))
  return { apple, layout: { get: (code) => map.get(code) } }
}

describe('which keyboard events are keys (KR-REQ-13.17, 08.59)', () => {
  it("leaves an input method's keydowns to it, however it reports them", () => {
    for (const owned of [
      reading('a', 'KeyA', { isComposing: true }),
      // At a composition's edges the platform reports key code 229 and not that it composes.
      reading('a', 'KeyA', { keyCode: 229 }),
      reading('Backspace', 'Backspace', { keyCode: 229 }),
      reading('Enter', 'Enter', { keyCode: 229 }),
      reading('Process', 'KeyA'),
      reading('Dead', 'Quote'),
      reading('Unidentified', '')
    ]) {
      expect(keyOf(owned, LINUX), JSON.stringify(owned)).toBeNull()
    }
  })

  it("leaves the platform's chords to it: Command, the Windows key, and a terminal's copy and paste off Apple platforms", () => {
    expect(keyOf(reading('c', 'KeyC', { metaKey: true }), MAC)).toBeNull()
    expect(keyOf(reading('v', 'KeyV', { metaKey: true }), LINUX)).toBeNull()
    expect(keyOf(reading('ArrowLeft', 'ArrowLeft', { metaKey: true }), MAC)).toBeNull()
    for (const key of ['C', 'V', 'c', 'v']) {
      expect(keyOf(reading(key, `Key${key.toUpperCase()}`, { ctrlKey: true, shiftKey: true }), LINUX)).toBeNull()
    }
    // On an Apple platform Command copies and pastes, so Control-Shift-C is the program's.
    expect(keyOf(reading('C', 'KeyC', { ctrlKey: true, shiftKey: true }), MAC)).toMatchObject({
      key: 'C',
      control: true,
      shift: true
    })
    // Control-C alone is the program's everywhere.
    expect(keyOf(reading('c', 'KeyC', { ctrlKey: true }), LINUX)).toMatchObject({ key: 'c', control: true })
  })

  it('takes no modifier or lock alone, and no key native code has no name for', () => {
    for (const [key, code] of [
      ['Shift', 'ShiftLeft'],
      ['Control', 'ControlLeft'],
      ['Alt', 'AltLeft'],
      ['AltGraph', 'AltRight'],
      ['Meta', 'MetaLeft'],
      ['CapsLock', 'CapsLock'],
      ['NumLock', 'NumLock'],
      ['AudioVolumeUp', 'AudioVolumeUp'],
      ['F25', 'F25'],
      // The Clear key of an Apple keyboard stands where Num Lock does, and is no keypad key.
      ['Clear', 'NumLock'],
      // A key that types more than one character goes as the text it types.
      ['ch', 'KeyC']
    ]) {
      expect(keyOf(reading(key, code), LINUX), key).toBeNull()
    }
  })

  it('names every key native code spells', () => {
    for (const name of [
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
      'F1',
      'F12',
      'F13',
      'F24'
    ]) {
      expect(keyOf(reading(name, name), LINUX), name).toEqual({
        key: name,
        base: null,
        keypad: null,
        shift: false,
        alt: false,
        control: false,
        caps_lock: false,
        num_lock: false
      })
    }
  })
})

describe('what a key is named (KR-REQ-13.17, 08.59)', () => {
  it('names a character with the modifiers and the locks the platform reported', () => {
    expect(keyOf(reading('a', 'KeyA'), LINUX)).toEqual({
      key: 'a',
      base: 'a',
      keypad: null,
      shift: false,
      alt: false,
      control: false,
      caps_lock: false,
      num_lock: false
    })
    expect(keyOf(reading('x', 'KeyX', { ctrlKey: true, altKey: true, numLock: true }), LINUX)).toEqual({
      key: 'x',
      base: 'x',
      keypad: null,
      shift: false,
      alt: true,
      control: true,
      caps_lock: false,
      num_lock: true
    })
    // Alt with a key that makes no character is Alt on an Apple platform too.
    expect(keyOf(reading('ArrowLeft', 'ArrowLeft', { altKey: true }), MAC)).toMatchObject({ alt: true })
  })

  it('names a character AltGraph or Option made as the character, with neither Control nor Alt', () => {
    // AltGraph on Windows is reported as Control and Alt as well.
    expect(
      keyOf(reading('@', 'KeyQ', { altGraph: true, ctrlKey: true, altKey: true }), LINUX)
    ).toMatchObject({ key: '@', base: null, control: false, alt: false })
    expect(keyOf(reading('å', 'KeyA', { altKey: true }), MAC)).toMatchObject({
      key: 'å',
      base: null,
      control: false,
      alt: false
    })
    // Off Apple platforms Alt is the program's Alt.
    expect(keyOf(reading('a', 'KeyA', { altKey: true }), LINUX)).toMatchObject({ key: 'a', alt: true })
    // AltGraph with a key that makes no character leaves its modifiers as they are.
    expect(
      keyOf(reading('ArrowUp', 'ArrowUp', { altGraph: true, ctrlKey: true, altKey: true }), LINUX)
    ).toMatchObject({ control: true, alt: true })
  })

  it("takes the unshifted character only from the layout or from a key nothing changed, never from its case", () => {
    const turkish = withLayout({ KeyI: 'ı', KeyQ: 'q', Digit2: '2', Quote: 'ab' })
    // Without the map, a character Shift, Caps Lock, AltGraph or Option changed has no known base.
    expect(keyOf(reading('A', 'KeyA', { shiftKey: true }), LINUX)?.base).toBeNull()
    expect(keyOf(reading('A', 'KeyA', { capsLock: true }), LINUX)?.base).toBeNull()
    expect(keyOf(reading('1', 'Digit1', { capsLock: true }), LINUX)?.base).toBeNull()
    expect(keyOf(reading('I', 'KeyI', { shiftKey: true }), LINUX)?.base).toBeNull()
    expect(keyOf(reading('İ', 'KeyI', { shiftKey: true }), LINUX)?.base).toBeNull()
    expect(keyOf(reading('a', 'KeyA', { altKey: true }), MAC)?.base).toBeNull()
    // With the map, the key's own character, whatever is held: a dotless i is a dotless i.
    expect(keyOf(reading('I', 'KeyI', { shiftKey: true, ctrlKey: true }), turkish)?.base).toBe('ı')
    expect(keyOf(reading('@', 'Digit2', { shiftKey: true, ctrlKey: true }), turkish)?.base).toBe('2')
    // An entry that is not one character says nothing.
    expect(keyOf(reading('"', 'Quote', { shiftKey: true }), turkish)?.base).toBeNull()
    // A key the map does not hold is read as it would be without one.
    expect(keyOf(reading('z', 'KeyZ'), turkish)?.base).toBe('z')
    expect(keyOf(reading('Z', 'KeyZ', { shiftKey: true }), turkish)?.base).toBeNull()
    // Control and Alt change no character, so the key's own character is its base.
    expect(keyOf(reading('c', 'KeyC', { ctrlKey: true, altKey: true }), LINUX)?.base).toBe('c')
    // A key with no code is read by itself.
    expect(keyOf(reading('k', ''), LINUX)?.base).toBe('k')
  })

  it('names a keypad key by its code and what it made, with Num Lock on or off', () => {
    expect(keyOf(reading('7', 'Numpad7', { numLock: true }), LINUX)).toEqual({
      key: '7',
      base: null,
      keypad: 'Numpad7',
      shift: false,
      alt: false,
      control: false,
      caps_lock: false,
      num_lock: true
    })
    expect(keyOf(reading('Home', 'Numpad7'), LINUX)).toMatchObject({ key: 'Home', keypad: 'Numpad7' })
    // The middle key with Num Lock off is the keypad's own.
    expect(keyOf(reading('Clear', 'Numpad5'), LINUX)).toMatchObject({ key: 'Clear', keypad: 'Numpad5' })
    expect(keyOf(reading('Enter', 'NumpadEnter'), LINUX)).toMatchObject({ key: 'Enter', keypad: 'NumpadEnter' })
    expect(keyOf(reading(',', 'NumpadDecimal'), LINUX)).toMatchObject({ key: ',', keypad: 'NumpadDecimal' })
    expect(keyOf(reading('Delete', 'NumpadDecimal'), LINUX)).toMatchObject({ key: 'Delete', keypad: 'NumpadDecimal' })
    expect(keyOf(reading('+', 'NumpadAdd'), LINUX)).toMatchObject({ key: '+', keypad: 'NumpadAdd' })
    // A code native code does not know is no keypad key.
    expect(keyOf(reading('(', 'NumpadParenLeft'), LINUX)).toMatchObject({ key: '(', keypad: null })
  })

  it('knows a press by its code, or by its key where the platform gives no code', () => {
    expect(identityOf(reading('a', 'KeyA'))).toBe(identityOf(reading('A', 'KeyA', { shiftKey: true })))
    expect(identityOf(reading('a', 'KeyA'))).not.toBe(identityOf(reading('a', 'KeyB')))
    expect(identityOf(reading('a', ''))).toBe(identityOf(reading('a', '')))
    expect(identityOf(reading('a', ''))).not.toBe(identityOf(reading('b', '')))
  })

  it('lets a character AltGraph or Option made go with neither Control nor Alt', () => {
    const at = keyOf(reading('@', 'KeyQ', { altGraph: true, ctrlKey: true, altKey: true }), LINUX)
    if (at === null) throw new Error('a key')
    expect(releasedWith(reading('@', 'KeyQ', { altGraph: true, ctrlKey: true, altKey: true }), at, LINUX)).toEqual({
      shift: false,
      alt: false,
      control: false,
      caps_lock: false,
      num_lock: false
    })
    const c = keyOf(reading('c', 'KeyC', { ctrlKey: true }), LINUX)
    if (c === null) throw new Error('a key')
    // Control let go before the key: the release says so.
    expect(releasedWith(reading('c', 'KeyC'), c, LINUX).control).toBe(false)
    expect(releasedWith(reading('c', 'KeyC', { ctrlKey: true, capsLock: true }), c, LINUX)).toMatchObject({
      control: true,
      caps_lock: true
    })
  })

  it('tells an Apple platform by its user agent', () => {
    expect(applePlatform('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15')).toBe(true)
    expect(applePlatform('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15')).toBe(true)
    expect(applePlatform('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0')).toBe(false)
    expect(applePlatform('Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 Chrome/140.0 Mobile')).toBe(false)
    expect(applePlatform('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko)')).toBe(false)
  })
})

describe('Control-Tab moves on out of the program keyboard (KR-REQ-13.18)', () => {
  it('moves on with Control-Tab and back with Control-Shift-Tab, and leaves every other Tab to the program', () => {
    expect(focusEscape(reading('Tab', 'Tab', { ctrlKey: true }))).toBe('next')
    expect(focusEscape(reading('Tab', 'Tab', { ctrlKey: true, shiftKey: true }))).toBe('previous')
    expect(focusEscape(reading('Tab', 'Tab'))).toBeNull()
    expect(focusEscape(reading('Tab', 'Tab', { shiftKey: true }))).toBeNull()
    expect(focusEscape(reading('Tab', 'Tab', { altKey: true }))).toBeNull()
    expect(focusEscape(reading('Tab', 'Tab', { ctrlKey: true, altKey: true }))).toBeNull()
    expect(focusEscape(reading('Tab', 'Tab', { ctrlKey: true, metaKey: true }))).toBeNull()
    expect(focusEscape(reading('i', 'KeyI', { ctrlKey: true }))).toBeNull()
  })
})

describe('what text may go (KR-REQ-08.56)', () => {
  it('takes off the invisible character wherever it is, and drops every control character', () => {
    expect(sendableText(`${SENTINEL}ls`)).toBe('ls')
    expect(sendableText(`l${SENTINEL}s${SENTINEL}`)).toBe('ls')
    expect(sendableText('one\ntwo\r\tthree\u001b[A\u007f\u0085')).toBe('onetwothree[A')
    expect(sendableText('日本語 é')).toBe('日本語 é')
    expect(sendableText(SENTINEL)).toBe('')
  })

  it('knows a character from a control character or more than one', () => {
    expect(isCharacter('a')).toBe(true)
    expect(isCharacter('😀')).toBe(true)
    expect(isCharacter('\u001b')).toBe(false)
    expect(isCharacter('\u009b')).toBe(false)
    expect(isCharacter('ab')).toBe(false)
    expect(isCharacter('')).toBe(false)
  })

  it("holds text and a paste to what one input carries, a paste less bracketed paste's delimiters", () => {
    expect(MAX_TEXT_BYTES).toBe(65_536)
    expect(MAX_PASTE_BYTES).toBe(65_536 - 12)
  })
})
