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
      if (!usable) return memory.get(key) ?? null
      try {
        return storage?.getItem(key) ?? null
      } catch {
        return null
      }
    },
    write(key, value) {
      if (!usable) {
        memory.set(key, value)
        return
      }
      try {
        storage?.setItem(key, value)
      } catch {
        memory.set(key, value)
      }
    },
    remove(key) {
      memory.delete(key)
      if (!usable) return
      try {
        storage?.removeItem(key)
      } catch {
        // Nothing to do: the record is gone from memory and the device will not keep it either.
      }
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
    }
  }
}

/**
 * Reads one record.
 *
 * A record written by a newer build is left where it is and reported as absent, because a build
 * that cannot read a draft must not be the build that deletes it.
 */
export function readRecord<T>(store: DurableStore, key: string): T | null {
  const raw = store.read(key)
  if (raw === null) return null
  try {
    const parsed = JSON.parse(raw) as Record<T>
    if (typeof parsed !== 'object' || parsed === null) return null
    if (parsed.version !== RECORD_VERSION) return null
    return parsed.value
  } catch {
    return null
  }
}

/** Writes one record with its version. */
export function writeRecord<T>(store: DurableStore, key: string, value: T): void {
  store.write(key, JSON.stringify({ version: RECORD_VERSION, value } satisfies Record<T>))
}

/** The key one session's drafts are kept under. */
export const DRAFTS_KEY = 'kr.mobile.drafts'

/** The key the unresolved submissions are kept under. */
export const SUBMISSIONS_KEY = 'kr.mobile.submissions'
