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
  // Every arm names its kind as a string, however it is spaced; an arm that does anything else
  // would leave a kind this test cannot read, so there is none.
  expect(body, 'every arm of `ObservedEvent::kind` is a plain string').not.toMatch(/=>\s*\{/)
  const arms = body.split('\n').filter((line) => line.includes('=>'))
  const kinds = [...body.matchAll(/=>\s*"([^"]+)"/g)].map((match) => match[1])
  expect(kinds, 'a kind read for every arm').toHaveLength(arms.length)
  return kinds
}

/** What a person can read as words: a capital to begin, and none of an identifier's marks in it. */
function isWords(label: string): boolean {
  return /^[A-Z]/.test(label) && !/[._]|[a-z][A-Z]/.test(label)
}

/** Each kind and what a person is told it is, written out so a change of a label is a change here. */
const ENTRY_LABELS = {
  message: 'Agent message',
  'thread.started': 'Conversation started',
  'thread.continued': 'Conversation continued',
  'thread.ended': 'Conversation ended',
  'tool.finished': 'Tool finished',
  'tool.failed': 'Tool failed',
  notification: 'Notice'
} as const

const NODE_LABELS = {
  message: 'Message',
  markdown: 'Message',
  tool: 'Tool',
  diff: 'Changes',
  progress: 'Progress',
  form: 'Form',
  attachment: 'Attachment',
  attachment_entry: 'Request for a file',
  approval_ref: 'Decision',
  terminal_ref: 'Terminal',
  action_button: 'Action',
  action_group: 'Actions',
  command_palette: 'Commands'
} as const

describe('the labels of the history entries (KR-REQ-13.19)', () => {
  it('are exactly these, in words', () => {
    for (const [kind, label] of Object.entries(ENTRY_LABELS)) expect(entryLabel(kind), kind).toBe(label)
    for (const [kind, label] of Object.entries(NODE_LABELS)) expect(nodeKindLabel(kind), kind).toBe(label)
    // Nothing this application draws, or the worker records, is missing from what is written out.
    expect(Object.keys(NODE_LABELS).sort()).toEqual([...RENDERED_NODE_KINDS].sort())
    for (const kind of recordedKinds()) expect(Object.keys(ENTRY_LABELS), kind).toContain(kind)
  })

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
