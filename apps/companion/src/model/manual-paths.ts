/**
 * The path a file can be read at on the host, for a person to give to their agent themselves.
 *
 * A file attached to a draft is sent to the host on this computer, and the host answers with the
 * path it can be read at for a short while. Nothing is put in front of the agent for the person:
 * the person types the path into the agent's terminal, and the path is not quoted for any shell, so
 * they quote it for theirs. This book asks the host for that path.
 *
 * The host keeps a draft of its own for the files of a session, because a path is given when a
 * file is bound to a draft. The window makes one for a session when it first has a file to bind,
 * and names the revision of it that it last saw with each binding. A draft only grows: a file the
 * person takes off the composer stays bound on the host, and a binding is limited in count and in
 * the size of the answer it makes. So a draft takes a few files, and the next file is bound to a
 * draft of its own. Only a binding the host confirmed leaves a draft in use: the window lets go of
 * it after any call on it that failed or that it was not told the outcome of, so the next attempt
 * makes another and binds the file again.
 */

import type { AttachmentHandle } from '@kalareach/protocol'

import { failureCode, failureMessage, type HostPort, type SessionSubject } from '../host/port'

/** Where a file's path stands. */
export type PathState =
  /** The host is being asked. */
  | { readonly kind: 'binding' }
  /** The host gave the path, which holds until `expiresAtMs`. */
  | { readonly kind: 'ready'; readonly hostPath: string; readonly expiresAtMs: number }
  /** The host, or this window, would not give one, and says why in words. */
  | { readonly kind: 'refused'; readonly words: string }
  /** The host may have bound the file, and the window was not told. */
  | { readonly kind: 'unconfirmed' }

/** The draft the host holds for a session's files, as far as this window has seen it. */
interface Anchor {
  readonly draftId: string
  revision: string
  /** The files bound to it. */
  readonly bound: Set<string>
}

/**
 * How many files one host draft takes.
 *
 * The host answers a binding with every file bound to the draft, each with the preview it carries,
 * and an answer has a size limit; a draft this small stays far inside it.
 */
const FILES_PER_DRAFT = 8

const PAIRED_WORDS = 'A host this device is paired with takes no file from it, so this file gets no path here.'
const OTHER_SESSION_WORDS =
  'This file was sent for another session. Take it off the draft and attach it again here.'
const NO_CONTACT_WORDS = 'Not in contact with this host, so the file has no path yet.'
const NO_PATH_WORDS = 'The host bound the file but gave no path to read it at. Try again.'

/** What a failure to give a path says, in words. */
function refusalWords(failure: unknown): string {
  switch (failureCode(failure)) {
    case 'DRAFT_CONFLICT':
      return 'The host’s record of this session’s files changed, so the file was not given a path. Try again.'
    case 'SESSION_CLOSED':
      return 'This session has ended, so the file was not given a path. It is still kept with the draft.'
    default:
      return failureMessage(failure)
  }
}

/** The members of a draft the host made that this book reads. */
function readDraft(value: unknown): { readonly draftId: string; readonly revision: string } | null {
  const draft = (value as { draft?: { draft_id?: unknown; revision?: unknown } } | null)?.draft
  return typeof draft?.draft_id === 'string' && typeof draft.revision === 'string'
    ? { draftId: draft.draft_id, revision: draft.revision }
    : null
}

/** The path and expiry a binding's answer carries for the file `transferId`, when it carries them. */
function readGrant(
  value: unknown,
  transferId: string
): { readonly hostPath: string; readonly expiresAtMs: number } | null {
  const grant = (
    value as {
      attachment?: {
        read_grant?: {
          host_path?: unknown
          expires_at_ms?: unknown
          transfer_id?: unknown
          insertion_method?: unknown
        } | null
      }
    } | null
  )?.attachment?.read_grant
  if (grant === null || grant === undefined) return null
  // A path is shown for the file it was asked for, and only as the manual path gives one.
  if (grant.transfer_id !== transferId || grant.insertion_method !== 'manual_terminal_workflow') {
    return null
  }
  const expires = Number(grant.expires_at_ms)
  return typeof grant.host_path === 'string' && grant.host_path !== '' && Number.isFinite(expires)
    ? { hostPath: grant.host_path, expiresAtMs: expires }
    : null
}

/** The paths of the files this window has asked the host for. */
export class ManualPaths {
  readonly #port: HostPort
  readonly #states = new Map<string, PathState>()
  readonly #anchors = new Map<string, Anchor>()
  readonly #listeners = new Set<() => void>()
  #cached: ReadonlyMap<string, PathState> | null = null
  /** One call on the host's drafts at a time, so that each names the revision the last left. */
  #chain: Promise<unknown> = Promise.resolve()

  constructor(port: HostPort) {
    this.#port = port
  }

  /** Calls `listener` when a path changes. */
  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  /** Where each file's path stands, by the file's transfer. The same object until something changes. */
  snapshot = (): ReadonlyMap<string, PathState> => {
    this.#cached ??= new Map(this.#states)
    return this.#cached
  }

  /**
   * Asks the host for the path of a file of `sessionId`, which is the file's own session.
   *
   * A file already being asked for is not asked for again. A path that has been given, or a refusal,
   * is asked for again, which is a new attempt.
   */
  attach(sessionId: string, subject: SessionSubject, handle: AttachmentHandle): Promise<void> {
    const id = handle.transfer_id
    if (this.#states.get(id)?.kind === 'binding') return this.#chain.then(() => undefined)
    this.#set(id, { kind: 'binding' })
    const run = this.#chain.then(() => this.#bind(sessionId, subject, handle))
    this.#chain = run
    return run
  }

  async #bind(sessionId: string, subject: SessionSubject, handle: AttachmentHandle): Promise<void> {
    const id = handle.transfer_id
    try {
      const connection = await this.#port.connectionState()
      if (!connection.connected || connection.environment_id === null) {
        this.#set(id, { kind: 'refused', words: NO_CONTACT_WORDS })
        return
      }
      if (connection.paired) {
        this.#set(id, { kind: 'refused', words: PAIRED_WORDS })
        return
      }
      if (handle.session_id !== null && handle.session_id !== sessionId) {
        this.#set(id, { kind: 'refused', words: OTHER_SESSION_WORDS })
        return
      }
      let anchor = this.#anchors.get(sessionId)
      // A draft that holds as many files as it takes is left, and the next file is bound to another.
      if (anchor !== undefined && !anchor.bound.has(id) && anchor.bound.size >= FILES_PER_DRAFT) {
        anchor = undefined
      }
      if (anchor === undefined) {
        const made = await this.#port.draftCreate(
          {
            environment_id: connection.environment_id,
            device_id: null,
            session_id: sessionId,
            application_instance_id: null,
            text: ''
          },
          subject
        )
        const draft = readDraft(made.value)
        if (draft === null) {
          // The host may have made a draft that this window will never name.
          this.#set(id, { kind: 'unconfirmed' })
          return
        }
        anchor = { draftId: draft.draftId, revision: draft.revision, bound: new Set() }
        this.#anchors.set(sessionId, anchor)
      }
      try {
        const answer = await this.#port.draftAddAttachment(
          {
            draft_id: anchor.draftId,
            expected_revision: anchor.revision,
            transfer_id: id,
            contribution: {
              operation_id: 'attach',
              accepted_media_types: [handle.declared_media_type],
              max_byte_len: handle.byte_len,
              max_count: String(FILES_PER_DRAFT),
              insertion_method: 'manual_terminal_workflow',
              external_destination: null,
              model_media_capability: false
            }
          },
          subject
        )
        const draft = readDraft(answer.value)
        const grant = readGrant(answer.value, id)
        if (draft === null) {
          // The host may have bound the file and moved the draft on, unseen: the revision is lost.
          this.#anchors.delete(sessionId)
          this.#set(id, { kind: 'unconfirmed' })
          return
        }
        anchor.revision = draft.revision
        anchor.bound.add(id)
        this.#set(
          id,
          grant === null ? { kind: 'refused', words: NO_PATH_WORDS } : { kind: 'ready', ...grant }
        )
      } catch (failure) {
        // What the host's refusal leaves of the draft is not the window's to judge: a draft only
        // grows, and the window cannot read it, so the next attempt starts from another.
        this.#anchors.delete(sessionId)
        throw failure
      }
    } catch (failure) {
      this.#set(id, { kind: 'refused', words: refusalWords(failure) })
    }
  }

  #set(id: string, state: PathState): void {
    this.#states.set(id, state)
    this.#cached = null
    for (const listener of this.#listeners) listener()
  }
}
