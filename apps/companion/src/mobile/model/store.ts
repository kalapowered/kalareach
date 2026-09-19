/**
 * Where a phone keeps what it must not lose.
 *
 * A phone suspends an application, terminates it in the background and restarts it cold, and none
 * of those are failures: they are how the platform manages memory. A draft the person typed has to
 * survive all three, so it is written where the operating system keeps an application's own data
 * rather than held in the page's memory.
 *
 * Two rules keep this honest. The record carries the version of the shape it was written in, so a
 * build that does not understand a record leaves it alone instead of discarding it. And every read
 * and write is guarded, because a device with storage disabled or full must still run: it loses
 * durability, which is reported, and nothing else.
 */

/** What a durable store does. Taken as an interface so a test supplies its own. */
export interface DurableStore {
  read(key: string): string | null
  write(key: string, value: string): void
  remove(key: string): void
  /** Whether what was written under this key will survive the process going away. */
  isDurable(key: string): boolean
}

/** The shape version written into every record. */
export const RECORD_VERSION = 1

/** One stored record, with the version it was written in. */
interface Record<T> {
  readonly version: number
  readonly value: T
}

/** The browser's own persistent storage, where it is available and permitted. */
export function deviceStore(storage: Storage | null | undefined): DurableStore {
  const memory = new Map<string, string>()
  // A key whose write the device refused. Reading it from the device again would answer with what
  // was there before the refusal, which is worse than saying nothing: the person would be shown an
  // older draft than the one they typed.
  const degraded = new Set<string>()
  const usable = (() => {
    if (!storage) return false
    try {
      const probe = '__kr_probe__'
      storage.setItem(probe, '1')
      storage.removeItem(probe)
      return true
    } catch {
      // A private window, a blocked origin or a full disk. The application still runs.
      return false
    }
  })()

  return {
    read(key) {
      if (!usable || degraded.has(key)) return memory.get(key) ?? null
      try {
        return storage?.getItem(key) ?? null
      } catch {
        return memory.get(key) ?? null
      }
    },
    write(key, value) {
      if (!usable) {
        memory.set(key, value)
        return
      }
      try {
        storage?.setItem(key, value)
        degraded.delete(key)
      } catch {
        // The device would not take it. This run keeps it, and every later read of this key comes
        // from here rather than from the older value the device still holds.
        memory.set(key, value)
        degraded.add(key)
      }
    },
    remove(key) {
      memory.delete(key)
      degraded.delete(key)
      if (!usable) return
      try {
        storage?.removeItem(key)
      } catch {
        // Nothing to do: the record is gone from memory and the device will not keep it either.
      }
    },
    /** True for a key the device refused, which is durability this run does not have. */
    isDurable(key) {
      return usable && !degraded.has(key)
    }
  }
}

/** A store held only in memory, which is what a device without usable storage falls back to. */
export function memoryStore(): DurableStore {
  const memory = new Map<string, string>()
  return {
    read: (key) => memory.get(key) ?? null,
    write: (key, value) => {
      memory.set(key, value)
    },
    remove: (key) => {
      memory.delete(key)
    },
    // Nothing here survives the process, and saying so is the point of the method.
    isDurable: () => false
  }
}

/** What a read of a record found. */
export type RecordRead<T> =
  /** Nothing has ever been written under this key. */
  | { readonly kind: 'absent' }
  /** A record this build reads. */
  | { readonly kind: 'read'; readonly value: T }
  /** A record this build does not understand, which it must neither read nor replace. */
  | { readonly kind: 'unsupported'; readonly version: number }
  /** Something under the key that is not a record at all. */
  | { readonly kind: 'invalid' }

/**
 * Reads one record.
 *
 * A record written by a newer build is reported as unsupported rather than as absent, because a
 * build that cannot read a draft must not be the build that deletes it, and "absent" is what a
 * caller would overwrite.
 */
export function readRecord<T>(store: DurableStore, key: string): RecordRead<T> {
  const raw = store.read(key)
  if (raw === null) return { kind: 'absent' }
  try {
    const parsed = JSON.parse(raw) as Record<T>
    if (typeof parsed !== 'object' || parsed === null) return { kind: 'invalid' }
    if (typeof parsed.version !== 'number') return { kind: 'invalid' }
    if (parsed.version !== RECORD_VERSION) return { kind: 'unsupported', version: parsed.version }
    return { kind: 'read', value: parsed.value }
  } catch {
    return { kind: 'invalid' }
  }
}

/**
 * Writes one record with its version.
 *
 * A key holding a record from a newer build is left alone: replacing it would destroy something
 * the build that wrote it can still read.
 */
export function writeRecord<T>(store: DurableStore, key: string, value: T): boolean {
  if (readRecord<T>(store, key).kind === 'unsupported') return false
  store.write(key, JSON.stringify({ version: RECORD_VERSION, value } satisfies Record<T>))
  return true
}

/** The key one session's drafts are kept under. */
export const DRAFTS_KEY = 'kr.mobile.drafts'

/** The key the unresolved submissions are kept under. */
export const SUBMISSIONS_KEY = 'kr.mobile.submissions'
