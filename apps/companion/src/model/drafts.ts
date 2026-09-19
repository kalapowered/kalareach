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
  readonly transferId: string
  readonly name: string
  readonly byteLen: number
  readonly mediaType: string
  readonly presentedAsImage: boolean
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
 * A session that is gone orphans the draft. An application or binding revision that changed
 * conflicts it. Only an unchanged target rebinds, and even then the caller decides whether to do
 * it: this returns the state, it does not submit anything.
 */
export function rebind(draft: Draft, observed: DraftTarget | null, attachmentId: string): Draft {
  if (!observed || observed.sessionId !== draft.target.sessionId) {
    return { ...draft, state: 'orphaned', attachmentId: null }
  }
  if (
    observed.applicationInstanceId !== draft.target.applicationInstanceId ||
    observed.agentBindingRevision !== draft.target.agentBindingRevision
  ) {
    return { ...draft, state: 'conflicted', attachmentId: null }
  }
  return { ...draft, state: 'bound', attachmentId }
}

/** Retargets a conflicted draft, which is the one thing that clears a conflict. */
export function retarget(draft: Draft, target: DraftTarget, attachmentId: string | null): Draft {
  return { ...draft, target, state: 'bound', attachmentId }
}

/** Whether the person may submit this draft as it stands. */
export function submittable(draft: Draft): boolean {
  return draft.state === 'bound' && (draft.text.trim().length > 0 || draft.attachments.length > 0)
}

/** Why the draft cannot be submitted, for the composer to say. */
export function notSubmittableBecause(draft: Draft): string | null {
  switch (draft.state) {
    case 'bound':
      return draft.text.trim().length === 0 && draft.attachments.length === 0
        ? 'Write something, or add an attachment.'
        : null
    case 'detached':
      return 'Not in contact with this host. The draft is kept here.'
    case 'conflicted':
      return 'The application changed. Choose where this draft should go.'
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
