/**
 * The draft contract, on the device that owns the draft.
 *
 * A draft is a durable identity this device owns, with its own revision and the target it was
 * written for. An attachment is only the association that presents it right now: losing the
 * connection removes the association, not the draft. The same authorised device may rebind it on
 * reconnect, and a changed application or binding revision marks it conflicted for the person to
 * retarget explicitly. Nothing here ever submits anything.
 *
 * The store behind this is the native client's, which is where durability lives. This module is
 * the part the interface needs: what the state is, what a rebind does to it, and what the person is
 * offered when insertion is refused.
 */

/** What a draft was written for. */
export interface DraftTarget {
  readonly sessionId: string
  readonly applicationInstanceId: string | null
  readonly agentBindingRevision: string | null
}

/** Where a draft stands. */
export type DraftState =
  /** Bound to the editor it was written for. */
  | 'bound'
  /** The connection went away; the text is intact and the association is not. */
  | 'detached'
  /** The application or its binding changed. The person retargets it; nothing does it for them. */
  | 'conflicted'
  /** The session it was written for is gone. */
  | 'orphaned'

/** One draft, as the interface holds it. */
export interface Draft {
  readonly draftId: string
  readonly revision: number
  readonly text: string
  readonly target: DraftTarget
  readonly state: DraftState
  readonly updatedAtMs: number
  /** The attachment presenting it, when one is. */
  readonly attachmentId: string | null
  /** The attachment handles the person added, which survive a failed insertion. */
  readonly attachments: readonly DraftAttachment[]
}

/** One attachment on a draft. */
export interface DraftAttachment {
  /** This device's own name for the file, from the moment it was added. */
  readonly localId: string
  /** The transfer that carried it, once the upload has published a verified handle. */
  readonly transferId: string | null
  readonly name: string
  readonly byteLen: number
  readonly mediaType: string
  readonly presentedAsImage: boolean
  /** Where its upload stands. A file stays on the draft whatever became of it. */
  readonly upload: 'uploading' | 'uploaded' | 'failed'
  /** True once the agent accepted it upstream, which only upstream evidence sets. */
  readonly acceptedUpstream: boolean
}

/** Starts a draft for a target. */
export function startDraft(
  draftId: string,
  target: DraftTarget,
  now: number,
  text = ''
): Draft {
  return {
    draftId,
    revision: 1,
    text,
    target,
    state: 'bound',
    updatedAtMs: now,
    attachmentId: null,
    attachments: []
  }
}

/** Records an edit. The revision moves with the text, not with the connection. */
export function edit(draft: Draft, text: string, now: number): Draft {
  if (text === draft.text) return draft
  return { ...draft, text, revision: draft.revision + 1, updatedAtMs: now }
}

/**
 * Records that the connection went away.
 *
 * The association goes; the text, the revision and the attachments stay exactly as they were.
 */
export function connectionLost(draft: Draft): Draft {
  if (draft.state === 'conflicted' || draft.state === 'orphaned') return draft
  return { ...draft, state: 'detached', attachmentId: null }
}

/**
 * Offers a rebind against what the host now reports.
 *
 * Only a detached draft has an association to restore: a draft that is bound has not lost one, and
 * a conflicted or an orphaned draft is the person's to settle, so what the host reports now changes
 * none of the three. A session that is gone orphans the draft. An application or binding revision
 * that changed conflicts it. A draft that holds nothing, or was written before this device knew
 * which conversation the agent was in, has no conversation of its own to compare, so it goes with
 * the one that is current, as it would have had it not been detached. Only an unchanged target
 * rebinds, and even then the caller decides whether to do it: this returns the state, it does not
 * submit anything.
 */
export function rebind(draft: Draft, observed: DraftTarget | null, attachmentId: string): Draft {
  if (draft.state !== 'detached') return draft
  if (!observed || observed.sessionId !== draft.target.sessionId) {
    return { ...draft, state: 'orphaned', attachmentId: null }
  }
  const empty = draft.text.length === 0 && draft.attachments.length === 0
  if (empty || draft.target.applicationInstanceId === null) {
    return { ...draft, target: observed, state: 'bound', attachmentId }
  }
  if (
    observed.applicationInstanceId !== draft.target.applicationInstanceId ||
    observed.agentBindingRevision !== draft.target.agentBindingRevision
  ) {
    return { ...draft, state: 'conflicted', attachmentId: null }
  }
  return { ...draft, state: 'bound', attachmentId }
}

/**
 * The draft as it stands against the conversation the session's agent is in now.
 *
 * A draft keeps the conversation it was written for: the instance and the binding revision the
 * person was writing to. One that holds nothing goes with whatever conversation is current, and so
 * does one written before this device knew which conversation that was. One whose conversation has
 * since moved, to another instance or another binding revision, is conflicted: the person chooses
 * whether it goes to the new one, and nothing sends it there for them. A draft that is detached,
 * orphaned or already conflicted stays as it is, and so does any draft while no agent is known.
 */
export function againstCurrent(draft: Draft, current: DraftTarget | null): Draft {
  if (current === null || draft.state !== 'bound') return draft
  const empty = draft.text.length === 0 && draft.attachments.length === 0
  if (empty || draft.target.applicationInstanceId === null) {
    return sameTarget(draft.target, current) ? draft : { ...draft, target: current }
  }
  return sameTarget(draft.target, current) ? draft : { ...draft, state: 'conflicted' }
}

/** Whether two targets are the same session, instance and binding revision. */
function sameTarget(a: DraftTarget, b: DraftTarget): boolean {
  return (
    a.sessionId === b.sessionId &&
    a.applicationInstanceId === b.applicationInstanceId &&
    a.agentBindingRevision === b.agentBindingRevision
  )
}

/**
 * Records the conversation a draft was written for, the first time one is known.
 *
 * A draft written before this device knew which conversation the agent was in takes the first one
 * it learns, and keeps it from then on: a later move is then a conflict like any other, rather than
 * a new conversation the text follows without a word. An empty draft needs no target kept, and any
 * other draft is returned as it is.
 */
export function adoptFirstTarget(draft: Draft, current: DraftTarget | null): Draft {
  if (current === null || draft.state !== 'bound') return draft
  if (draft.target.applicationInstanceId !== null) return draft
  if (draft.text.length === 0 && draft.attachments.length === 0) return draft
  return { ...draft, target: current }
}

/** Retargets a conflicted draft, which is the one thing that clears a conflict. */
export function retarget(draft: Draft, target: DraftTarget, attachmentId: string | null): Draft {
  return { ...draft, target, state: 'bound', attachmentId }
}

/**
 * Whether a file on the draft keeps a prompt from being sent.
 *
 * A prompt sent from here carries its text inline, so it cannot carry a file: one the agent has
 * not accepted into its own composer, whether it is still uploading, uploaded or failed, would be
 * left behind without a word. A draft that holds one is sent only once the person removes it.
 */
function holdsUnsentFiles(draft: Draft): boolean {
  return draft.attachments.some((attachment) => !attachment.acceptedUpstream)
}

/** Whether the person may submit this draft as it stands. */
export function submittable(draft: Draft): boolean {
  return (
    draft.state === 'bound' &&
    !holdsUnsentFiles(draft) &&
    (draft.text.trim().length > 0 || draft.attachments.length > 0)
  )
}

/** Why the draft cannot be submitted, for the composer to say. */
export function notSubmittableBecause(draft: Draft): string | null {
  switch (draft.state) {
    case 'bound':
      if (holdsUnsentFiles(draft)) {
        return 'A prompt sent from here cannot carry the files on this draft. Remove them to send the text on its own.'
      }
      return draft.text.trim().length === 0 && draft.attachments.length === 0
        ? 'Write something to send.'
        : null
    case 'detached':
      return 'Not in contact with this host. The draft is kept here.'
    case 'conflicted':
      return 'The conversation changed since this was written. Choose whether it goes to the new one.'
    case 'orphaned':
      return 'The session this was written for has gone. Choose another.'
  }
}

/** What a refused insertion leaves the person with. */
export interface InsertionRefusal {
  /** The protocol code the host answered with. */
  readonly code: string
  /** What the person can do instead, in plain words. */
  readonly fallback: string
  /** True when the draft and its uploads were kept, which they always are. */
  readonly retained: true
}

/**
 * Reads a refused composer insertion.
 *
 * `DRAFT_CONFLICT` is the one the specification names: the native buffer was not empty or its
 * state was unknown, so the draft is retained and the terminal workflow is offered. `LEASE_LOST`
 * is the other way in: insertion needs the current input lease.
 */
export function readInsertionRefusal(code: string): InsertionRefusal {
  switch (code) {
    case 'DRAFT_CONFLICT':
      return {
        code,
        fallback:
          'The agent composer was not at an empty, qualified boundary. The draft and its uploads are kept: copy the path into the terminal instead.',
        retained: true
      }
    case 'LEASE_LOST':
      return {
        code,
        fallback:
          'Another view holds terminal input. Take input back, then insert, or copy the path into the terminal.',
        retained: true
      }
    case 'EDITOR_BUSY':
      return {
        code,
        fallback:
          'The editor is mid-transaction. The draft is kept: try again, or copy the path into the terminal.',
        retained: true
      }
    default:
      return {
        code,
        fallback: 'The draft and its uploads are kept. Copy the path into the terminal instead.',
        retained: true
      }
  }
}
