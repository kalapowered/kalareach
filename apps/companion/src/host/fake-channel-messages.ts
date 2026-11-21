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

import {
  failureMessage,
  type ChannelHoldCreate,
  type ChannelMessageKeep,
  type ChannelMessageList,
  type ChannelMessageRemoval,
  type DraftDiscardRequest,
  type LedgerSetAside,
  type StoredChannelMessage,
  type StoredDrafts,
  type StoredHold
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

const encoder = new TextEncoder()
/** Bytes, as native code counts them: a bound on text and on a record is on UTF-8, not on UTF-16 units. */
const bytesOf = (text: string): number => encoder.encode(text).length
/**
 * The file a message is in, as native code writes it: these members in this order, the time as a
 * number and each draft by its own members. The bound on bytes counts this file's length.
 */
const fileOf = (entry: Entry): string =>
  JSON.stringify({
    version: 1,
    action_id: entry.actionId,
    hold_id: entry.holdId,
    local_id: entry.localId,
    session_id: entry.sessionId,
    application_instance_id: entry.applicationInstanceId,
    agent_binding_revision: entry.agentBindingRevision,
    environment_id: entry.environmentId,
    host_name: entry.hostName,
    text: entry.text,
    sent_at_ms: Number(entry.sentAtMs),
    drafts: entry.drafts.map((each) => ({ id: each.id, expectedRevision: each.expectedRevision }))
  })
const sizeOf = (entry: Entry): number => bytesOf(fileOf(entry))
/** The list of removals' own words when it cannot be read, as native code says them. */
const LEDGER_UNREADABLE = 'This device could not read its list of removals.'
const NOT_SET_ASIDE = 'This device could not set the list aside. The original list is still in place.'
const key = (each: DraftDiscardRequest): string => `${each.id}\n${each.expectedRevision}`
/** The references of `entries`, each once, in the order they are first named. */
const referencesOf = (entries: Iterable<Entry>): DraftDiscardRequest[] => {
  const seen = new Map<string, DraftDiscardRequest>()
  for (const entry of entries) for (const each of entry.drafts) if (!seen.has(key(each))) seen.set(key(each), each)
  return [...seen.values()]
}
/** Whether two lists name the same drafts, as sets: an order or a repeat makes no difference. */
const sameDrafts = (left: readonly DraftDiscardRequest[], right: readonly DraftDiscardRequest[]): boolean => {
  const a = new Set(left.map(key))
  const b = new Set(right.map(key))
  return a.size === b.size && [...a].every((each) => b.has(each))
}

/** A store of a device's channel messages. */
export class FakeChannelMessageStore {
  #entries = new Map<string, Entry>()
  #holds = new Map<string, StoredHold>()
  #limits: { entries: number; bytes: number; holds: number } = { ...FAKE_CHANNEL_LIMITS }
  #unreadableMessages = { layout: 0, now: 0 }
  #unreadableMessageBytes = 0
  #unreadableHolds = { layout: 0, now: 0 }
  #damagedHolds: string[] = []
  #refuseKeeps: { code: string; message: string } | null = null
  #refuseKeepsLeft = Infinity
  #stopAfterEntry = false
  #ledgerFaultAfterRename = false
  #unavailable = false
  #withoutRepair = false
  #refuseHoldWrites: { code: string; message: string } | null = null
  #ledger: 'ok' | 'unreadable' | 'damaged' = 'ok'
  #refuseListings: { code: string; message: string } | null = null
  #refuseSetAside: { code: string; message: string } | null = null
  #setAsideUnconfirmed = false
  #flushOwed = false
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

  /** Makes the next `times` keeps refuse with `refusal`, one by default as a refused write is; `Infinity` refuses every keep until it is cleared. */
  refuseKeeps(refusal: { code: string; message: string } | null, times = 1): void {
    this.#refuseKeeps = refusal
    this.#refuseKeepsLeft = times
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

  /**
   * Makes the store report files it could not read, which it leaves where they are. The messages'
   * files take their places and their `bytes` (all together) against the bounds, as native code
   * counts the sizes the folder gives.
   */
  leaveUnreadable(kind: 'messages' | 'holds', counts: { layout?: number; now?: number; bytes?: number }): void {
    const target = kind === 'messages' ? this.#unreadableMessages : this.#unreadableHolds
    if (counts.layout !== undefined) target.layout = counts.layout
    if (counts.now !== undefined) target.now = counts.now
    if (kind === 'messages' && counts.bytes !== undefined) this.#unreadableMessageBytes = counts.bytes
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

  /** Makes the list of removals unreadable now, damaged (the state a person can set aside), or readable again. */
  damageLedger(state: 'ok' | 'unreadable' | 'damaged'): void {
    this.#ledger = state
  }

  /** Makes every listing of the messages refuse with `refusal` until it is cleared; the drafts' own read still answers. */
  refuseListings(refusal: { code: string; message: string } | null): void {
    this.#refuseListings = refusal
  }

  /** Makes setting the list aside refuse with `refusal` until it is cleared: nothing moves. */
  refuseSetAside(refusal: { code: string; message: string } | null): void {
    this.#refuseSetAside = refusal
  }

  /** Makes the next set-aside move the list and fail to confirm that on disk. */
  leaveSetAsideUnconfirmed(): void {
    this.#setAsideUnconfirmed = true
  }

  /**
   * Sets a damaged list aside and replaces it with the list the entries rebuild, every draft a
   * message names once: nothing else is set aside, a list that is readable is refused, and a
   * change of the list that is refused leaves the damaged one in place.
   */
  setAside(draftStore: FakeDraftStore): LedgerSetAside {
    this.calls.push({ kind: 'set-aside' })
    if (this.#refuseSetAside) refuse(this.#refuseSetAside.code, this.#refuseSetAside.message)
    if (this.#ledger !== 'damaged') refuse('INVALID_ARGUMENT', 'The list of removals is not damaged, so it was not set aside.')
    try {
      draftStore.replaceRemovals(referencesOf(this.#entries.values()))
    } catch (failure) {
      refuse('RESOURCE_UNAVAILABLE', `${NOT_SET_ASIDE} ${failureMessage(failure)}`)
    }
    this.#ledger = 'ok'
    const confirmed = !this.#setAsideUnconfirmed
    this.#setAsideUnconfirmed = false
    // A move that is not on disk yet is made so by the next read of the drafts, which refuses until then.
    this.#flushOwed = !confirmed
    return { moved: true, confirmed }
  }

  /** A removal recorded by the page, as native code records one: over a list that cannot be read it fails. */
  markRemoval(request: DraftDiscardRequest, draftStore: FakeDraftStore): void {
    if (this.#ledger !== 'ok') refuse('RESOURCE_UNAVAILABLE', LEDGER_UNREADABLE)
    draftStore.markRemoval(request)
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
    if (this.#refuseListings) refuse(this.#refuseListings.code, this.#refuseListings.message)
    if (this.#unavailable) refuse('STORAGE_UNAVAILABLE', 'This device could not read or write its channel messages.')
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
        bytes: entries.reduce((sum, entry) => sum + sizeOf(entry), this.#unreadableMessageBytes)
      },
      limits: this.#limits
    }
  }

  keep(request: ChannelMessageKeep, draftStore: FakeDraftStore): { readonly resumed: boolean } {
    this.calls.push({ kind: 'keep', text: request.text })
    if (this.#refuseKeeps) {
      const refusal = this.#refuseKeeps
      this.#refuseKeepsLeft -= 1
      if (this.#refuseKeepsLeft <= 0) this.#refuseKeeps = null
      refuse(refusal.code, refusal.message)
    }
    if (this.#unavailable) refuse('STORAGE_UNAVAILABLE', 'This device could not read or write its channel messages.')
    if (request.text === '' || bytesOf(request.text) > MAX_TEXT) {
      refuse('INVALID_ARGUMENT', 'a message is 1 byte to 64 KiB of text')
    }
    if (request.drafts.length > 2) refuse('INVALID_ARGUMENT', 'a message names at most two drafts')
    const held = this.#entries.get(request.actionId)
    let resumed = false
    if (held !== undefined) {
      if (
        held.text !== request.text ||
        held.sessionId !== request.sessionId ||
        held.applicationInstanceId !== request.applicationInstanceId ||
        held.agentBindingRevision !== request.agentBindingRevision ||
        !sameDrafts(held.drafts, request.drafts)
      ) {
        refuse('INVALID_ARGUMENT', 'another message is already kept under this action')
      }
      resumed = true
    } else {
      const entry: Entry = { ...request }
      const used = [...this.#entries.values()].reduce((sum, each) => sum + sizeOf(each), this.#unreadableMessageBytes)
      // A file that cannot be read still takes its place: it counts against the bound of entries.
      const places = this.#entries.size + this.#unreadableMessages.layout + this.#unreadableMessages.now
      if (places >= this.#limits.entries || used + sizeOf(entry) > this.#limits.bytes) {
        refuse('QUOTA_EXCEEDED', 'Channel messages is full. Remove some on the Kept drafts page.')
      }
      this.#entries.set(request.actionId, entry)
      this.#write()
    }
    if (this.#stopAfterEntry) {
      this.#stopAfterEntry = false
      refuse('RESOURCE_UNAVAILABLE', 'the process stopped after the message was kept')
    }
    // Every keep, a resume and one with no references included, takes the ledger step: one change
    // that names all the drafts or none. A list that cannot be read is never written over.
    if (this.#ledger !== 'ok') refuse('RESOURCE_UNAVAILABLE', LEDGER_UNREADABLE)
    try {
      draftStore.markRemovals(request.drafts)
    } catch (failure) {
      // An entry this keep wrote is undone while the list names none of its drafts; a resume's stays.
      const named = draftStore.pendingRemovals().some((line) => request.drafts.some((each) => key(each) === key(line)))
      if (!resumed && !named) {
        this.#entries.delete(request.actionId)
        this.#write()
      }
      throw failure
    }
    if (this.#ledgerFaultAfterRename) {
      this.#ledgerFaultAfterRename = false
      refuse('RESOURCE_UNAVAILABLE', 'This device could not read or write its list of removals.')
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
    this.#damagedHolds = this.#damagedHolds.filter((name) => name !== request.holdId)
    this.#write()
  }

  /**
   * The drafts as a read of them leaves them, native code's repair included: every draft a durable
   * entry holds the text of is owed its removal before any is returned, and a record of a send that
   * an entry ends goes.
   */
  drafts(draftStore: FakeDraftStore): StoredDrafts {
    if (this.#unavailable) refuse('STORAGE_UNAVAILABLE', 'This device could not read or write its channel messages.')
    if (this.#flushOwed) {
      this.#flushOwed = false
      refuse('STORAGE_UNAVAILABLE', 'the data directory could not be made durable yet')
    }
    const read = draftStore.list()
    // Every draft a durable entry holds the text of, and that is still stored at that version, is owed.
    const owed = this.#withoutRepair
      ? []
      : referencesOf(this.#entries.values()).filter((each) =>
          read.drafts.some((draft) => draft.id === each.id && draft.revision === each.expectedRevision)
        )
    if (!this.#withoutRepair && this.#ledger === 'ok') {
      let named = true
      try {
        draftStore.markRemovals(owed)
      } catch {
        // The owed references are still returned below; the records of sends stay for the next read.
        named = false
      }
      if (named) {
        for (const entry of this.#entries.values()) {
          for (const hold of [...this.#holds.values()]) {
            if (hold.holdId === entry.holdId || (hold.actionId !== null && hold.actionId === entry.actionId)) {
              this.#holds.delete(hold.holdId)
            }
          }
        }
        this.#write()
      }
    }
    // A list that cannot be read names nothing; what the entries owe is returned whatever happened to it.
    const lines = this.#ledger === 'ok' ? draftStore.pendingRemovals() : []
    const pendingRemovals = [...lines]
    for (const each of owed) if (!pendingRemovals.some((line) => key(line) === key(each))) pendingRemovals.push(each)
    return {
      ...read,
      pendingRemovals,
      sources: this.#unreadableMessages.now > 0 || this.#ledger !== 'ok' ? 'unknown' : 'known',
      ledger: this.#ledger
    }
  }

  #write(): void {
    this.#disk?.setItem(
      FAKE_CHANNEL_MESSAGES_KEY,
      JSON.stringify({ entries: [...this.#entries.values()], holds: [...this.#holds.values()] })
    )
  }
}
