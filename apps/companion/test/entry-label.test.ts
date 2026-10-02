/**
 * Every kind of history entry and document node has a label in words, and a kind this application
 * does not know is called by a generic name, never by its identifier.
 *
 * KR-REQ-13.19: a screen reader reads what the screen says, and an identifier such as
 * `thread.started` is not language: it is spelled out, and a style that sets labels in capitals
 * made it worse.
 */

import { describe, expect, it } from 'vitest'

// Where the worker names the kinds it records an observed history under.
import bridge from '../../../crates/kr-worker/src/broker/bridge.rs?raw'

import { RENDERED_NODE_KINDS } from '../src/model/controls'
import {
  entryLabel,
  nodeKindLabel,
  UNKNOWN_ENTRY_LABEL,
  UNKNOWN_NODE_LABEL
} from '../src/model/entry-label'

/**
 * The kinds the worker records an observed history under, read from where it names them, so a kind
 * the worker gains is a kind this test requires a label for.
 */
function recordedKinds(): string[] {
  const start = bridge.indexOf('pub const fn kind(self)')
  expect(start, 'the worker names its observed kinds in `ObservedEvent::kind`').toBeGreaterThan(0)
  const body = bridge.slice(start, bridge.indexOf('\n    }\n', start))
  return [...body.matchAll(/Self::\w+ => "([^"]+)"/g)].map((match) => match[1])
}

/** A label a person can read: words, with no identifier's dots or underscores in it. */
function isWords(label: string): boolean {
  return /^[A-Z][a-z]+( [A-Za-z]+)*$/.test(label)
}

describe('the labels of the history entries (KR-REQ-13.19)', () => {
  it('names a conversation starting in words', () => {
    expect(entryLabel('thread.started')).toBe('Conversation started')
    expect(entryLabel('thread.continued')).toBe('Conversation continued')
    expect(entryLabel('thread.ended')).toBe('Conversation ended')
  })

  it('names tools, notices and the agent’s own messages in words', () => {
    expect(entryLabel('tool.finished')).toBe('Tool finished')
    expect(entryLabel('tool.failed')).toBe('Tool failed')
    expect(entryLabel('notification')).toBe('Notice')
    expect(entryLabel('message')).toBe('Agent message')
  })

  it('has a label in words for every kind the worker records', () => {
    const kinds = recordedKinds()
    // Six observed events and the message an agent writes.
    expect(kinds).toEqual(
      expect.arrayContaining([
        'thread.started',
        'thread.continued',
        'thread.ended',
        'tool.finished',
        'tool.failed',
        'notification'
      ])
    )
    for (const kind of ['message', ...kinds]) {
      const label = entryLabel(kind)
      expect(label, `the label of ${kind}`).not.toBe(UNKNOWN_ENTRY_LABEL)
      expect(isWords(label), `the label of ${kind}: ${label}`).toBe(true)
    }
  })

  it('calls a kind it does not know by a generic label in words, never by the identifier', () => {
    for (const kind of [
      'plan.revised',
      'x.custom_event',
      'THREAD.STARTED',
      '',
      'constructor',
      '__proto__',
      'toString'
    ]) {
      const label = entryLabel(kind)
      expect(label).toBe(UNKNOWN_ENTRY_LABEL)
      expect(isWords(label)).toBe(true)
      if (kind !== '') expect(label.toLowerCase()).not.toContain(kind.toLowerCase())
    }
  })
})

describe('the labels of the document nodes (KR-REQ-13.19)', () => {
  it('has a label in words for every kind the application draws', () => {
    for (const kind of RENDERED_NODE_KINDS) {
      const label = nodeKindLabel(kind)
      expect(label, `the label of ${kind}`).not.toBe(UNKNOWN_NODE_LABEL)
      expect(isWords(label), `the label of ${kind}: ${label}`).toBe(true)
    }
  })

  it('calls a kind it does not know by a generic label in words, never by the identifier', () => {
    for (const kind of ['sparkline', 'unknown', 'a_new_kind', 'constructor', '__proto__']) {
      const label = nodeKindLabel(kind)
      expect(label).toBe(UNKNOWN_NODE_LABEL)
      expect(isWords(label)).toBe(true)
    }
  })
})
