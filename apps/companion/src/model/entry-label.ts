/**
 * What each kind of history entry and document node is called beside it, in words.
 *
 * An agent's history records each observation under a kind that is an identifier, such as
 * `thread.started`, and a package names the kind of each node it shows the same way. A person
 * never reads the identifier: it is not language, a screen reader spells it out, and a package may
 * name a kind this application has never seen. Every kind this application knows has a label here,
 * and a kind this table does not hold is called by a generic name, never by its identifier. The
 * identifier stays on the element as data, for anything that needs it.
 */

const ENTRY_LABELS: ReadonlyMap<string, string> = new Map([
  ['message', 'Agent message'],
  ['thread.started', 'Conversation started'],
  ['thread.continued', 'Conversation continued'],
  ['thread.ended', 'Conversation ended'],
  ['tool.finished', 'Tool finished'],
  ['tool.failed', 'Tool failed'],
  ['notification', 'Notice']
])

const NODE_LABELS: ReadonlyMap<string, string> = new Map([
  ['message', 'Message'],
  ['markdown', 'Message'],
  ['tool', 'Tool'],
  ['diff', 'Changes'],
  ['progress', 'Progress'],
  ['form', 'Form'],
  ['attachment', 'Attachment'],
  ['attachment_entry', 'Request for a file'],
  ['approval_ref', 'Decision'],
  ['terminal_ref', 'Terminal'],
  ['action_button', 'Action'],
  ['action_group', 'Actions'],
  ['command_palette', 'Commands']
])

/** What a history entry of a kind this application does not know is called. */
export const UNKNOWN_ENTRY_LABEL = 'Update from the agent'

/** What a document node of a kind this application does not know is called. */
export const UNKNOWN_NODE_LABEL = 'Content from the session'

/** The label a kind of history entry is shown under. */
export function entryLabel(kind: string): string {
  return ENTRY_LABELS.get(kind) ?? UNKNOWN_ENTRY_LABEL
}

/** The label a kind of document node is shown under. */
export function nodeKindLabel(kind: string): string {
  return NODE_LABELS.get(kind) ?? UNKNOWN_NODE_LABEL
}
