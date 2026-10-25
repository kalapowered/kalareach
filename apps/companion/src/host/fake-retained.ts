/**
 * The scripted host's list of what has left it, and the deletion of a copy.
 *
 * It answers as the real commands do. The list is what privacy mode reports (the host's own
 * entries) and what this computer's own sync reports (the copies the sync service kept of writes it
 * refused). A copy is deleted in three steps the page cannot shorten: asking raises a dialog that
 * only the person answers, a yes returns a token, and the token deletes once. A test is the person:
 * it answers the dialog, and it can make the service not confirm a deletion, lose a token's time or
 * refuse an ask.
 */

import type { PrivacyExported, PrivacyReport } from '@kalareach/protocol'

import { FakeHostError } from './fake'
import type { RetainedAsked, RetainedFinished } from './port'

/** What a test can do as the person and as the service. */
export interface FakeRetained {
  /** The references the page asked to delete, in order, one for each ask. */
  readonly asked: readonly string[]
  /** The references whose deletion was asked for with a yes, in order. */
  readonly finished: readonly string[]
  /** The tokens the page dropped without using them. */
  readonly cancelled: number
  /** How many dialogs wait for the person's answer. */
  readonly dialogsWaiting: number
  /** Answers the oldest dialog as the person does. */
  answerDialog(yes: boolean): void
  /**
   * Makes the service not confirm a deletion from now on, as a service that is out of reach does:
   * the deletion is asked for and the copy stays listed, as asked and not confirmed.
   */
  serviceDoesNotConfirm(on: boolean): void
  /** Makes the next ask refuse with these words, as native code does, or stops that. */
  refuseNextAsk(message: string | null): void
  /** Makes the next finish wait until `release`, as a service that is slow to answer does. */
  holdNextFinish(): { release(): void }
  /** Lists a copy the sync service kept, as this computer's own sync would. */
  keepSyncCopy(copy: PrivacyExported): void
  /** Makes this computer's own sync list fail with these words, as a store that cannot be read does, or stops that. */
  syncListFails(message: string | null): void
  /** Lists the host's copy as deleted and awaiting removal at the service, as it is once the service confirms. */
  serviceHasDeleted(reference: string): void
}

/** The entries the scripted host lists before a test changes any. */
interface Entry {
  readonly copy: PrivacyExported
  /** Whether the entry is one of this computer's own sync's. */
  readonly sync: boolean
}

function refuse(code: string, message: string): never {
  // eslint-disable-next-line @typescript-eslint/only-throw-error -- a command's failure crosses as data
  throw new FakeHostError(code, message).toPayload()
}

/** A confirmation, as native code holds it between the person's yes and the deletion. */
interface Confirmation {
  readonly reference: string
}

export class ScriptedRetained implements FakeRetained {
  readonly asked: string[] = []
  readonly finished: string[] = []
  cancelled = 0

  private readonly entries: Entry[]
  private readonly dialogs: ((yes: boolean) => void)[] = []
  private readonly tokens = new Map<string, Confirmation>()
  private tokenCount = 0
  private confirming = true
  private refusal: string | null = null
  private listFailure: string | null = null
  private heldFinish: { release: () => void } | null = null
  private holdingFinish: Promise<void> | null = null

  constructor(
    private readonly nowMs: number,
    private readonly generation: () => number,
    private readonly mayDeleteHere: () => boolean
  ) {
    const left = (ago: number) => String(nowMs - ago)
    this.entries = [
      {
        sync: false,
        copy: {
          kind: 'backup archive',
          reference: 'archive 4c1f0b5e generation 12',
          left_at_ms: left(172_800_000),
          deletable: true
        }
      },
      {
        sync: false,
        copy: {
          kind: 'notification',
          reference: 'a turn summary, delivered through the push service',
          left_at_ms: left(90_000_000),
          deletable: false
        }
      },
      {
        sync: false,
        copy: {
          kind: "possible copy held by a viewer's device",
          reference: 'device 0d5e1a7c-31aa-4f09-9c47-5f7a7d3f6a10',
          left_at_ms: left(260_000_000),
          deletable: false
        }
      },
      {
        sync: true,
        copy: {
          kind: 'synchronised drafts, kept as a copy by the service',
          reference: 'drafts, which the service holds as copy 2f6d0c1e-8a3b-4c57-9d10-6b1e5a7c9f42',
          left_at_ms: left(40_000_000),
          deletable: true
        }
      }
    ]
  }

  get dialogsWaiting(): number {
    return this.dialogs.length
  }

  answerDialog(yes: boolean): void {
    this.dialogs.shift()?.(yes)
  }

  serviceDoesNotConfirm(on: boolean): void {
    this.confirming = !on
  }

  refuseNextAsk(message: string | null): void {
    this.refusal = message
  }

  holdNextFinish(): { release(): void } {
    let release!: () => void
    this.holdingFinish = new Promise<void>((resolve) => {
      release = resolve
    })
    const held = { release }
    this.heldFinish = held
    return held
  }

  keepSyncCopy(copy: PrivacyExported): void {
    this.entries.push({ sync: true, copy })
  }

  syncListFails(message: string | null): void {
    this.listFailure = message
  }

  serviceHasDeleted(reference: string): void {
    const at = this.entries.findIndex((each) => each.copy.reference === reference)
    const entry = this.entries[at]
    if (entry === undefined) throw new Error(`no entry lists ${reference}`)
    this.entries[at] = {
      ...entry,
      copy: {
        ...entry.copy,
        kind: 'backup archive, deleted and awaiting removal at the service',
        deletable: false
      }
    }
  }

  /** What privacy mode reports: the host's own entries. */
  report(): PrivacyReport {
    return {
      generation: String(this.generation()),
      enabled: true,
      changed_at_ms: String(this.nowMs - 86_400_000),
      completion: { state: 'complete' },
      sessions: [],
      disabled: [],
      kept: [],
      exported: this.entries
        .filter((entry) => !entry.sync)
        .map((entry) => ({ ...entry.copy })),
      unlisted: [{ subsystem: 'descriptions', reason: 'the description store could not be read' }]
    }
  }

  /** What this computer's own sync lists. */
  syncCopies(): readonly PrivacyExported[] {
    if (this.listFailure !== null) refuse('LOCAL_FAILURE', this.listFailure)
    return this.entries.filter((entry) => entry.sync).map((entry) => ({ ...entry.copy }))
  }

  /** The dialog the person answers, and the token a yes returns. */
  async ask(reference: string): Promise<RetainedAsked> {
    this.asked.push(reference)
    if (this.refusal !== null) {
      const words = this.refusal
      this.refusal = null
      refuse('PERMISSION_DENIED', words)
    }
    const entry = this.entries.find((each) => each.copy.reference === reference)
    if (entry === undefined) refuse('INVALID_ARGUMENT', 'the host lists no one copy under that reference')
    if (!entry.sync && !this.mayDeleteHere()) {
      refuse(
        'PERMISSION_DENIED',
        'a copy that left the host is deleted at the computer the host runs on, and this application is connected to another host'
      )
    }
    if (!entry.copy.deletable) refuse('PERMISSION_DENIED', 'the host has no way to ask for the removal of that copy')
    const yes = await new Promise<boolean>((resolve) => {
      this.dialogs.push(resolve)
    })
    if (!yes) return { confirmed: false, token: null, lasts_ms: 0 }
    this.tokenCount += 1
    const token = `token-${String(this.tokenCount)}`
    this.tokens.set(token, { reference })
    return { confirmed: true, token, lasts_ms: 120_000 }
  }

  /** The deletion, once, with the token a yes returned. */
  async finish(token: string): Promise<RetainedFinished> {
    const confirmation = this.tokens.get(token)
    this.tokens.delete(token)
    if (confirmation === undefined) {
      refuse('PERMISSION_DENIED', 'that confirmation has been used, cancelled or has run out; ask again')
    }
    this.finished.push(confirmation.reference)
    if (this.holdingFinish !== null && this.heldFinish !== null) {
      const waiting = this.holdingFinish
      this.holdingFinish = null
      this.heldFinish = null
      await waiting
    }
    const at = this.entries.findIndex((each) => each.copy.reference === confirmation.reference)
    const entry = this.entries[at]
    if (entry === undefined) {
      refuse('INVALID_ARGUMENT', 'the host lists no one copy under that reference')
    }
    if (!this.confirming) {
      this.entries[at] = {
        ...entry,
        copy: {
          ...entry.copy,
          kind: entry.sync
            ? entry.copy.kind
            : 'backup archive, deletion asked and not yet confirmed'
        }
      }
      return { deleted: false, report: entry.sync ? null : this.report() }
    }
    this.entries.splice(at, 1)
    return { deleted: true, report: entry.sync ? null : this.report() }
  }

  cancel(token: string): void {
    if (this.tokens.delete(token)) this.cancelled += 1
  }
}
