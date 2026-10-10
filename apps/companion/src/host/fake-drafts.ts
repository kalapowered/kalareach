/**
 * The drafts a device keeps, as the scripted host holds them.
 *
 * Native code keeps a device's drafts in a store of its own, and a window that runs against the
 * scripted host needs the same store: one that outlives the host in a test that restarts the
 * application, that can be written to by "another window", and that applies the rules the real
 * one applies. This is that store, and nothing else of the scripted host is in it.
 *
 * The rules are the real store's, in the same words where a page reads them:
 * - a save names the version it replaces; when it is not the stored one, this window's text is
 *   kept as a copy beside, carrying the stricter mark, and the stored draft stays as it is;
 * - a save of a draft that is no longer stored makes it again, under an identity of its own;
 * - a save keeps the draft's session, never takes it back to open, and moves the conversation it
 *   was written for only while it is empty or has none yet;
 * - a retarget names the version it was shown and is the one way back to open.
 */

import type { AttachmentHandle } from '@kalareach/protocol'

import type {
  DraftDiscardRequest,
  DraftRetargetRequest,
  DraftSaved,
  DraftSaveRequest,
  StoredDraft,
  StoredDrafts,
  StoredMark
} from './port'

/** A refusal in the shape native code rejects with. */
function refuse(code: string, message: string): never {
  // eslint-disable-next-line @typescript-eslint/only-throw-error -- a refusal is data, as native code's is
  throw { code, message, user_action: 'nothing' }
}

const RANK: Readonly<Record<StoredMark, number>> = { open: 0, conflicted: 1, orphaned: 2 }

/** Where a store keeps itself between windows: the part of `Storage` it uses. */
export interface DraftDisk {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

/** The key a store writes under when it is given a disk. */
export const FAKE_DRAFTS_KEY = 'kr.fake.device-drafts'

/** A store of a device's drafts. */
export class FakeDraftStore {
  #drafts = new Map<string, StoredDraft>()
  #counter = 0
  #clock = 0
  #opens = true
  #unreadable = 0
  #refuseSaves: { code: string; message: string } | null = null
  readonly #disk: DraftDisk | null
  /** Every save and discard this store was asked for, for a test to read. */
  readonly calls: { readonly kind: 'save' | 'retarget' | 'discard'; readonly text?: string }[] = []

  constructor(disk: DraftDisk | null = null) {
    this.#disk = disk
    const found = disk?.getItem(FAKE_DRAFTS_KEY) ?? null
    if (found === null) return
    try {
      const parsed = JSON.parse(found) as {
        drafts: StoredDraft[]
        counter: number
        clock: number
      }
      this.#drafts = new Map(parsed.drafts.map((draft) => [draft.id, draft]))
      this.#counter = parsed.counter
      this.#clock = parsed.clock
    } catch {
      // A disk that holds something else is a disk with no drafts on it.
    }
  }

  /** Makes the store refuse to open, as a device whose store cannot be read does. */
  breakOpening(): void {
    this.#opens = false
  }

  /** Makes the store report `count` files it could not read, which it leaves where they are. */
  leaveUnreadable(count: number): void {
    this.#unreadable = count
  }

  /** Lets the store open again, as a device whose store was mended does. */
  mendOpening(): void {
    this.#opens = true
  }

  /** Makes every save refuse with `code` until it is cleared. */
  refuseSaves(refusal: { code: string; message: string } | null): void {
    this.#refuseSaves = refusal
  }

  /** The stored drafts, oldest first, as a test reads them. */
  all(): readonly StoredDraft[] {
    return [...this.#drafts.values()].sort((a, b) => Number(a.createdAtMs) - Number(b.createdAtMs))
  }

  /**
   * Another window of the application writes to a draft: its version moves on.
   *
   * Answers the draft as stored after the write.
   */
  writeAsAnotherWindow(id: string, change: Partial<Pick<StoredDraft, 'text' | 'state'>>): StoredDraft {
    const held = this.#drafts.get(id)
    if (held === undefined) refuse('INVALID_ARGUMENT', `no draft ${id} is stored`)
    const next: StoredDraft = {
      ...held,
      ...change,
      revision: String(Number(held.revision) + 1),
      updatedAtMs: this.#tick()
    }
    this.#put(next)
    return next
  }

  list(): StoredDrafts {
    if (!this.#opens) {
      refuse('STORAGE_UNAVAILABLE', 'the drafts kept on this device could not be opened')
    }
    return { drafts: this.all(), unreadable: this.#unreadable }
  }

  save(request: DraftSaveRequest): DraftSaved {
    this.calls.push({ kind: 'save', text: request.text })
    if (!this.#opens) refuse('STORAGE_UNAVAILABLE', 'the drafts kept on this device could not be opened')
    if (this.#refuseSaves) refuse(this.#refuseSaves.code, this.#refuseSaves.message)
    const files = request.attachments.map(withoutPreview)
    if (request.id === null) {
      const made = this.#make(request, files)
      this.#put(made)
      return { outcome: 'stored', of: null, draft: made }
    }
    if (request.expectedRevision === null) {
      refuse('INVALID_ARGUMENT', 'a save of a stored draft names the version it replaces')
    }
    const held = this.#drafts.get(request.id)
    if (held === undefined) {
      // Another window removed it: what this window has is a draft again.
      const again = this.#make(request, files)
      this.#put(again)
      return { outcome: 'stored', of: null, draft: again }
    }
    if (held.revision !== request.expectedRevision) {
      const movedAway =
        (held.applicationInstanceId !== request.applicationInstanceId ||
          held.agentBindingRevision !== request.agentBindingRevision) &&
        held.applicationInstanceId !== null &&
        (held.text.length > 0 || held.attachments.length > 0)
      const mark = stricterMark(held.state, movedAway ? 'conflicted' : request.state, request.state)
      const copy = { ...this.#make(request, files, held.id), state: mark }
      this.#put(copy)
      return { outcome: 'copied', of: held.id, draft: copy }
    }
    if (held.sessionId !== request.sessionId) {
      refuse('INVALID_ARGUMENT', 'a draft keeps its session; send it to another one by retargeting it')
    }
    const moved =
      held.applicationInstanceId !== request.applicationInstanceId ||
      held.agentBindingRevision !== request.agentBindingRevision
    const empty = held.text.length === 0 && held.attachments.length === 0
    if (moved && held.applicationInstanceId !== null && !empty) {
      refuse('DRAFT_CONFLICT', 'the draft was written for another conversation; mark it conflicted instead of moving it')
    }
    const state = RANK[request.state] > RANK[held.state] ? request.state : held.state
    const next: StoredDraft = {
      ...held,
      applicationInstanceId: request.applicationInstanceId,
      agentBindingRevision: request.agentBindingRevision,
      state,
      text: request.text,
      attachments: files,
      revision: String(Number(held.revision) + 1),
      updatedAtMs: this.#tick()
    }
    this.#put(next)
    return { outcome: 'stored', of: null, draft: next }
  }

  retarget(request: DraftRetargetRequest): StoredDraft {
    this.calls.push({ kind: 'retarget' })
    const held = this.#drafts.get(request.id)
    if (held === undefined) refuse('INVALID_ARGUMENT', `no draft ${request.id} is stored`)
    if (held.revision !== request.expectedRevision) {
      refuse('DRAFT_CONFLICT', `draft ${request.id} is at version ${held.revision}, not ${request.expectedRevision}: another window changed it`)
    }
    const next: StoredDraft = {
      ...held,
      sessionId: request.sessionId,
      applicationInstanceId: request.applicationInstanceId,
      agentBindingRevision: request.agentBindingRevision,
      state: 'open',
      copyOf: null,
      revision: String(Number(held.revision) + 1),
      updatedAtMs: this.#tick()
    }
    this.#put(next)
    return next
  }

  discard(request: DraftDiscardRequest): { removed: boolean } {
    this.calls.push({ kind: 'discard' })
    const held = this.#drafts.get(request.id)
    if (held === undefined) return { removed: false }
    if (held.revision !== request.expectedRevision) {
      refuse('DRAFT_CONFLICT', `draft ${request.id} is at version ${held.revision}, not ${request.expectedRevision}: another window changed it`)
    }
    this.#drafts.delete(request.id)
    this.#write()
    return { removed: true }
  }

  #make(request: DraftSaveRequest, files: readonly AttachmentHandle[], copyOf: string | null = null): StoredDraft {
    this.#counter += 1
    const at = this.#tick()
    return {
      id: `00000000-0000-4000-8000-${String(this.#counter).padStart(12, '0')}`,
      revision: '1',
      sessionId: request.sessionId,
      applicationInstanceId: request.applicationInstanceId,
      agentBindingRevision: request.agentBindingRevision,
      state: request.state,
      text: request.text,
      attachments: files,
      copyOf,
      createdAtMs: at,
      updatedAtMs: at
    }
  }

  #tick(): string {
    this.#clock += 1
    return String(1_700_000_000_000 + this.#clock)
  }

  #put(draft: StoredDraft): void {
    this.#drafts.set(draft.id, draft)
    this.#write()
  }

  #write(): void {
    this.#disk?.setItem(
      FAKE_DRAFTS_KEY,
      JSON.stringify({ drafts: [...this.#drafts.values()], counter: this.#counter, clock: this.#clock })
    )
  }
}

/** The strictest of the marks a copy could take. */
function stricterMark(...marks: readonly StoredMark[]): StoredMark {
  return marks.reduce((strictest, mark) => (RANK[mark] > RANK[strictest] ? mark : strictest), 'open')
}

/** A handle as the store keeps it: whole, with no preview. */
function withoutPreview(handle: AttachmentHandle): AttachmentHandle {
  return { ...handle, preview: null }
}
