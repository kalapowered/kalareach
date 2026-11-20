/**
 * The messages a device keeps that were sent over a channel that confirms nothing, and the records
 * of sends under way, as the scripted host holds them.
 *
 * Native code keeps them in a store of its own, beside the drafts and never among them, and a
 * window that runs against the scripted host needs the same store: one that outlives the host in a
 * test that restarts the application, that applies the real store's rules in the same words, and
 * that can be made to fail where the real one can. A keep is whole or refused, a message is never
 * replaced, nothing is evicted, and what a keep makes the draft store owe is owed through the
 * draft store's own ledger.
 */

import type {
  ChannelHoldCreate,
  ChannelMessageKeep,
  ChannelMessageList,
  ChannelMessageRemoval,
  DraftDiscardRequest,
  StoredChannelMessage,
  StoredDrafts,
  StoredHold
} from './port'
import type { DraftDisk } from './fake-drafts'
import type { FakeDraftStore } from './fake-drafts'
import { fakeRetryOf } from './fake-retry'
import { receivedFailure } from './tauri'

/** The most characters of a text, as native code counts bytes of it. */
const MAX_TEXT = 64 * 1024
/** The bounds of the real store. */
export const FAKE_CHANNEL_LIMITS = { entries: 10_000, bytes: 64 * 1024 * 1024, holds: 1_000 } as const
/** The key a store writes under when it is given a disk. */
export const FAKE_CHANNEL_MESSAGES_KEY = 'kr.fake.channel-messages'

function refuse(code: string, message: string): never {
  // eslint-disable-next-line @typescript-eslint/only-throw-error -- a refusal is data, as native code's is
  throw receivedFailure({ code, message, user_action: 'nothing', retry: fakeRetryOf(code) })
}

interface Entry extends StoredChannelMessage {
  readonly text: string
  readonly drafts: readonly DraftDiscardRequest[]
}

const sizeOf = (entry: Entry): number => JSON.stringify(entry).length

/** A store of a device's channel messages. */
export class FakeChannelMessageStore {
  #entries = new Map<string, Entry>()
  #holds = new Map<string, StoredHold>()
  #limits: { entries: number; bytes: number; holds: number } = { ...FAKE_CHANNEL_LIMITS }
  #unreadableMessages = { layout: 0, now: 0 }
  #unreadableHolds = { layout: 0, now: 0 }
  #damagedHolds: string[] = []
  #refuseKeeps: { code: string; message: string } | null = null
  #stopAfterEntry = false
  #ledgerFaultAfterRename = false
  #unavailable = false
  #withoutRepair = false
  #refuseHoldWrites: { code: string; message: string } | null = null
  readonly #disk: DraftDisk | null
  /** Every call this store was asked for, for a test to read. */
  readonly calls: { readonly kind: string; readonly text?: string; readonly withText?: boolean }[] = []

  constructor(disk: DraftDisk | null = null) {
    this.#disk = disk
    const found = disk?.getItem(FAKE_CHANNEL_MESSAGES_KEY) ?? null
    if (found === null) return
    try {
      const parsed = JSON.parse(found) as { entries: Entry[]; holds: StoredHold[] }
      this.#entries = new Map(parsed.entries.map((entry) => [entry.actionId, entry]))
      this.#holds = new Map(parsed.holds.map((hold) => [hold.holdId, hold]))
    } catch {
      // A disk that holds something else is a disk with no messages on it.
    }
  }

  /** Makes every keep refuse with `refusal` until it is cleared. */
  refuseKeeps(refusal: { code: string; message: string } | null): void {
    this.#refuseKeeps = refusal
  }

  /** Makes the next keep stop after its entry is durable, as a stop of the process would: no ledger line is written. */
  stopAfterEntry(): void {
    this.#stopAfterEntry = true
  }

  /** Makes the next keep fail after the ledger was renamed: the entry stays and the keep rejects. */
  failLedgerAfterRename(): void {
    this.#ledgerFaultAfterRename = true
  }

  /** Holds the store to lower bounds. */
  lowerLimits(limits: Partial<{ entries: number; bytes: number; holds: number }>): void {
    this.#limits = { ...this.#limits, ...limits }
  }

  /** Makes the store report files it could not read, which it leaves where they are. */
  leaveUnreadable(kind: 'messages' | 'holds', counts: { layout?: number; now?: number }): void {
    const target = kind === 'messages' ? this.#unreadableMessages : this.#unreadableHolds
    if (counts.layout !== undefined) target.layout = counts.layout
    if (counts.now !== undefined) target.now = counts.now
  }

  /** Lists records of this layout whose bytes do not parse, by name. */
  leaveDamagedHolds(names: readonly string[]): void {
    this.#damagedHolds = [...names]
  }

  /** Makes the store's reads, and the drafts' with them, refuse: its folder cannot be read. */
  makeUnavailable(unavailable = true): void {
    this.#unavailable = unavailable
  }

  /** Reads the drafts as an older release does: no repair, so a message's record is a draft again. */
  readWithoutRepair(without = true): void {
    this.#withoutRepair = without
  }

  /** Makes every write of a record of a send refuse with `refusal` until it is cleared. */
  refuseHoldWrites(refusal: { code: string; message: string } | null): void {
    this.#refuseHoldWrites = refusal
  }

  /** The messages kept, with their text, oldest first, as a test reads them. */
  all(): readonly StoredChannelMessage[] {
    return [...this.#entries.values()].sort(
      (a, b) => Number(a.sentAtMs) - Number(b.sentAtMs) || a.actionId.localeCompare(b.actionId)
    )
  }

  /** The records of sends under way, as a test reads them. */
  allHolds(): readonly StoredHold[] {
    return [...this.#holds.values()]
  }

  list(withText: boolean): ChannelMessageList {
    this.calls.push({ kind: 'list', withText })
    if (this.#unavailable) refuse('STORAGE_UNAVAILABLE', 'the messages kept on this device could not be read')
    const entries = [...this.#entries.values()]
    return {
      messages: this.all().map((message) => {
        const { text, drafts: _private, ...visible } = message as Entry
        void _private
        return withText ? { ...visible, text } : visible
      }),
      holds: [...this.#holds.values()],
      damagedHolds: this.#damagedHolds,
      unreadableMessages: this.#unreadableMessages,
      unreadableHolds: this.#unreadableHolds,
      used: {
        entries: entries.length + this.#unreadableMessages.layout + this.#unreadableMessages.now,
        bytes: entries.reduce((sum, entry) => sum + sizeOf(entry), 0)
      },
      limits: this.#limits
    }
  }

  keep(request: ChannelMessageKeep, draftStore: FakeDraftStore): { readonly resumed: boolean } {
    this.calls.push({ kind: 'keep', text: request.text })
    if (this.#refuseKeeps) refuse(this.#refuseKeeps.code, this.#refuseKeeps.message)
    if (this.#unavailable) refuse('STORAGE_UNAVAILABLE', 'the messages kept on this device could not be read')
    if (request.text === '' || request.text.length > MAX_TEXT) {
      refuse('INVALID_ARGUMENT', 'a message is 1 byte to 64 KiB of text')
    }
    if (request.drafts.length > 2) refuse('INVALID_ARGUMENT', 'a message names at most two drafts')
    const held = this.#entries.get(request.actionId)
    let resumed = false
    if (held !== undefined) {
      if (held.text !== request.text || held.sessionId !== request.sessionId) {
        refuse('INVALID_ARGUMENT', 'another message is already kept under this action')
      }
      resumed = true
    } else {
      const entry: Entry = { ...request }
      const used = [...this.#entries.values()].reduce((sum, each) => sum + sizeOf(each), 0)
      if (this.#entries.size >= this.#limits.entries || used + sizeOf(entry) > this.#limits.bytes) {
        refuse('QUOTA_EXCEEDED', 'Channel messages is full: nothing was kept and nothing was removed')
      }
      this.#entries.set(request.actionId, entry)
      this.#write()
    }
    if (this.#stopAfterEntry) {
      this.#stopAfterEntry = false
      refuse('RESOURCE_UNAVAILABLE', 'the process stopped after the message was kept')
    }
    for (const reference of request.drafts) draftStore.markRemoval(reference)
    if (this.#ledgerFaultAfterRename) {
      this.#ledgerFaultAfterRename = false
      refuse('RESOURCE_UNAVAILABLE', 'the removals cannot be proved durable')
    }
    if (request.holdId !== null) {
      this.#holds.delete(request.holdId)
      this.#write()
    }
    return { resumed }
  }

  remove(request: ChannelMessageRemoval): { readonly removed: number } {
    this.calls.push({ kind: 'remove' })
    let removed = 0
    for (const entry of [...this.#entries.values()]) {
      const chosen = request.actionId === undefined ? entry.sessionId === request.sessionId : entry.actionId === request.actionId
      if (!chosen) continue
      this.#entries.delete(entry.actionId)
      removed += 1
    }
    this.#write()
    return { removed }
  }

  createHold(request: ChannelHoldCreate): void {
    this.calls.push({ kind: 'hold-create' })
    if (this.#refuseHoldWrites) refuse(this.#refuseHoldWrites.code, this.#refuseHoldWrites.message)
    if (this.#holds.has(request.holdId)) refuse('INVALID_ARGUMENT', 'a record is already kept under this identity')
    if (this.#holds.size >= this.#limits.holds) refuse('QUOTA_EXCEEDED', 'too many records of messages being sent are kept')
    this.#holds.set(request.holdId, { ...request, actionId: null })
    this.#write()
  }

  updateHold(request: { readonly holdId: string; readonly actionId: string }): void {
    this.calls.push({ kind: 'hold-update' })
    if (this.#refuseHoldWrites) refuse(this.#refuseHoldWrites.code, this.#refuseHoldWrites.message)
    const held = this.#holds.get(request.holdId)
    if (held === undefined) refuse('INVALID_ARGUMENT', 'no record is kept under this identity')
    if (held.actionId !== null && held.actionId !== request.actionId) {
      refuse('INVALID_ARGUMENT', 'this record already names another action')
    }
    this.#holds.set(request.holdId, { ...held, actionId: request.actionId })
    this.#write()
  }

  clearHold(request: { readonly holdId: string }): void {
    this.calls.push({ kind: 'hold-clear' })
    if (this.#refuseHoldWrites) refuse(this.#refuseHoldWrites.code, this.#refuseHoldWrites.message)
    this.#holds.delete(request.holdId)
    this.#write()
  }

  /**
   * The drafts as a read of them leaves them, native code's repair included: every draft a durable
   * entry holds the text of is owed its removal before any is returned, and a record of a send that
   * an entry ends goes.
   */
  drafts(draftStore: FakeDraftStore): StoredDrafts {
    if (this.#unavailable) refuse('STORAGE_UNAVAILABLE', 'the messages kept on this device could not be read')
    const read = draftStore.list()
    if (!this.#withoutRepair) {
      for (const entry of this.#entries.values()) {
        for (const reference of entry.drafts) {
          if (read.drafts.some((draft) => draft.id === reference.id && draft.revision === reference.expectedRevision)) {
            draftStore.markRemoval(reference)
          }
        }
        for (const hold of [...this.#holds.values()]) {
          if (hold.holdId === entry.holdId || (hold.actionId !== null && hold.actionId === entry.actionId)) {
            this.#holds.delete(hold.holdId)
          }
        }
      }
      this.#write()
    }
    return {
      ...read,
      pendingRemovals: draftStore.pendingRemovals(),
      sources: this.#unreadableMessages.now > 0 ? 'unknown' : 'known'
    }
  }

  #write(): void {
    this.#disk?.setItem(
      FAKE_CHANNEL_MESSAGES_KEY,
      JSON.stringify({ entries: [...this.#entries.values()], holds: [...this.#holds.values()] })
    )
  }
}
