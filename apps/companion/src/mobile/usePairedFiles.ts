/**
 * What the composer does with the files it sends to a host the phone is paired with.
 *
 * The page hands a picked file to the application, which owns the upload from there: this sends
 * it under a key of the page's choosing, shows where it stands from the store (`PairedUploads`),
 * adds it to the draft the device keeps for the session when it is published, cancels it, and ends
 * the draft when the person takes a bound file off. A file the application kept from before a
 * restart is shown on its own session's composer.
 */

import { useCallback, useEffect, useMemo, useSyncExternalStore } from 'react'

import { useApp } from '../app/state'
import type { Draft, DraftAttachment } from '../model/drafts'
import type { AttachmentHandle, SessionSubject } from '../host/port'
import { failureWords } from '../host/port'
import { attachContribution } from '../model/manual-paths'
import type { UploadRow } from '../model/paired-uploads'
import { boundIdsOf, isReset, lineOf } from '../model/paired-uploads'
import { refusalOf } from '../model/transfer-words'
import { ask } from './model/call'
import type { Picked } from './model/media'

/** A key for an upload: a UUID, which is what the application names an upload by. */
function newKey(): string {
  const made = globalThis.crypto
  if (typeof made.randomUUID === 'function') return made.randomUUID()
  const bytes = made.getRandomValues(new Uint8Array(16))
  bytes[6] = (bytes[6] ?? 0) & 0x0f | 0x40
  bytes[8] = (bytes[8] ?? 0) & 0x3f | 0x80
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/** What the composer needs of the files it sends over a paired connection. */
export interface PairedFiles {
  /** The row of each file by its key, including the ones a restart found. */
  readonly rows: ReadonlyMap<string, UploadRow>
  /** The rows of this session that are not files on the composer. */
  readonly found: readonly UploadRow[]
  send(picked: Picked, file: File): void
  cancel(key: string): void
  /** Adds a file that was sent in full to the draft. */
  add(row: UploadRow): void
  /** Takes a file off the composer: ends the draft when the file is bound to it. */
  remove(key: string): void
}

export function usePairedFiles({
  active,
  sessionId,
  draft,
  nameSession,
  changeFiles,
  removed
}: {
  /** Whether the host is one this device is paired with and in contact. */
  readonly active: boolean
  readonly sessionId: string
  readonly draft: Draft
  readonly nameSession: () => Promise<SessionSubject>
  readonly changeFiles: (change: (files: readonly DraftAttachment[]) => readonly DraftAttachment[]) => void
  /** The files taken off the composer while their upload went on: nothing is said of them. */
  readonly removed: { readonly current: Set<string> }
}): PairedFiles {
  const { port, say, uploads } = useApp()
  const rows = useSyncExternalStore(uploads.subscribe, uploads.snapshot)
  // The cycle moves when the files of an earlier sign-in were cleared: the application is read again.
  const cycle = useSyncExternalStore(uploads.subscribe, () => uploads.cycle)
  const files = draft.attachments

  const found = useMemo(
    () => uploads.found(sessionId, new Set(files.map((file) => file.localId))),
    // `rows` changes whenever any row does.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [uploads, sessionId, files, rows]
  )

  // The application's account of the uploads, and the draft it keeps for this session: what a
  // restart left is shown, and a file the composer kept is said to be on the draft or not.
  useEffect(() => {
    if (!active) return
    let current = true
    void (async () => {
      const listed = await uploads.restore()
      const subject = await nameSession()
      const connection = await port.connectionState()
      if (connection.environment_id === null) return
      const made = await port.draftCreate(
        {
          environment_id: connection.environment_id,
          device_id: null,
          session_id: sessionId,
          application_instance_id: null,
          text: ''
        },
        subject
      )
      if (!current) return
      const boundIds = boundIdsOf(made.value)
      // The stored drafts keep no account, so a restart restores the cards of whoever was signed in
      // before. A card is kept only for a file this window has a row for, the application lists for
      // the account in force, or the kept draft holds; any other is dropped from the composer. An
      // application that could not be read says nothing, and nothing is dropped for it.
      const listedIds =
        listed === null ? null : new Set(listed.flatMap((view) => (view.handle ? [view.handle.transfer_id] : [])))
      const known = (file: DraftAttachment): boolean =>
        file.handle === null ||
        listedIds === null ||
        listedIds.has(file.handle.transfer_id) ||
        boundIds.has(file.handle.transfer_id) ||
        uploads.snapshot().has(file.localId)
      const foreign = new Set(
        files.filter((file) => file.upload === 'uploaded' && file.handle !== null && !known(file)).map((file) => file.localId)
      )
      if (foreign.size > 0) changeFiles((current) => current.filter((each) => !foreign.has(each.localId)))
      uploads.noteFiles(
        files.flatMap((file) =>
          file.upload === 'uploaded' && file.handle !== null && !foreign.has(file.localId)
            ? [
                {
                  row: {
                    key: file.localId,
                    sessionId,
                    name: file.name,
                    byteLen: file.byteLen,
                    phase: { kind: 'bound' as const },
                    handle: file.handle,
                    note: null,
                    awaited: false
                  },
                  bound: boundIds.has(file.handle.transfer_id)
                }
              ]
            : []
        )
      )
    })().catch(() => {
      // Not in contact: the rows stay as they were, and the next screen asks again.
    })
    return () => {
      current = false
    }
    // Asked when the screen opens and when contact returns, not on each change of a file.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, sessionId, uploads, port, cycle])

  /** Adds a published file to the draft the device keeps for this session. */
  const bind = useCallback(
    async (handle: AttachmentHandle): Promise<void> => {
      // A reset while the session is named leaves the file unbound: it belongs to an earlier sign-in.
      const still = uploads.guard()
      const subject = await nameSession()
      still()
      await port.draftAddAttachment(
        {
          session_id: sessionId,
          application_instance_id: draft.target.applicationInstanceId,
          text: draft.text,
          transfer_id: handle.transfer_id,
          contribution: attachContribution(handle)
        },
        subject
      )
    },
    [nameSession, port, sessionId, uploads, draft.target.applicationInstanceId, draft.text]
  )

  const send = useCallback(
    (picked: Picked, file: File) => {
      const key = newKey()
      changeFiles((current) => [
        ...current,
        {
          localId: key,
          transferId: null,
          name: picked.name,
          byteLen: picked.byteLen,
          mediaType: picked.mediaType,
          presentedAsImage: false,
          upload: 'uploading',
          acceptedUpstream: false,
          handle: null
        }
      ])
      const settle = (change: Partial<DraftAttachment>) => {
        changeFiles((current) => current.map((each) => (each.localId === key ? { ...each, ...change } : each)))
      }
      // A reset while the file is read or the session is named sends nothing: the file is the earlier
      // sign-in's, and its card is already off the composer.
      const still = uploads.guard()
      ask(() => file.arrayBuffer())
        .then(async (buffer) => {
          still()
          const subject = await nameSession()
          still()
          return await uploads.send(
            { key, sessionId, subject, file: { name: picked.name, bytes: new Uint8Array(buffer) } },
            bind
          )
        })
        .then((handle) => {
          settle({
            transferId: handle.transfer_id,
            name: handle.original_file_name,
            byteLen: Number(handle.byte_len),
            mediaType: handle.declared_media_type,
            presentedAsImage: handle.presented_as_image,
            upload: 'uploaded',
            handle
          })
          if (removed.current.has(key)) return
          const row = uploads.snapshot().get(key)
          if (row?.phase.kind === 'bound') say(`${handle.original_file_name} is sent and added to this draft.`)
          else if (row !== undefined) say(`${handle.original_file_name}: ${lineOf(row.phase).text}`, 'danger')
        })
        .catch((failure: unknown) => {
          if (isReset(failure)) return
          settle({ upload: 'failed' })
          if (removed.current.has(key)) return
          const refusal = refusalOf(failure)
          // The person cancelled it, and the file's own line says so.
          if (refusal.kind === 'cancelled') return
          say(`${picked.name} was not sent: ${refusal.words || failureWords(failure)}`, 'danger')
        })
    },
    [bind, changeFiles, nameSession, removed, say, sessionId, uploads]
  )

  const cancel = useCallback(
    (key: string) => {
      if (uploads.snapshot().get(key) === undefined) {
        // The card is on the screen while the file is read, before the application has been told of
        // it: the cancel is kept, nothing is handed over, and the card says so at once.
        const file = files.find((each) => each.localId === key)
        if (file?.upload !== 'uploading') return
        void uploads.cancel(key)
        changeFiles((current) => current.map((each) => (each.localId === key ? { ...each, upload: 'failed' } : each)))
        say(`${file.name}: ${lineOf({ kind: 'cancelled', released: null }).text}`)
        return
      }
      void uploads.cancel(key).then(() => {
        const row = uploads.snapshot().get(key)
        if (row !== undefined) {
          const said = row.phase.kind === 'cancelAsked' && row.phase.said !== null ? ` ${row.phase.said}` : ''
          say(`${row.name}: ${lineOf(row.phase).text}${said}`)
        }
        if (row?.phase.kind === 'cancelled') {
          changeFiles((current) => current.map((each) => (each.localId === key ? { ...each, upload: 'failed' } : each)))
        }
      })
    },
    [changeFiles, files, say, uploads]
  )

  const add = useCallback(
    (row: UploadRow) => {
      const { handle } = row
      if (handle === null) return
      // A file a restart found is not on the composer yet: it goes there as a sent file.
      if (!files.some((each) => each.localId === row.key)) {
        changeFiles((current) => [
          ...current,
          {
            localId: row.key,
            transferId: handle.transfer_id,
            name: handle.original_file_name,
            byteLen: Number(handle.byte_len),
            mediaType: handle.declared_media_type,
            presentedAsImage: handle.presented_as_image,
            upload: 'uploaded',
            acceptedUpstream: false,
            handle
          }
        ])
      }
      void uploads
        .bind(row.key, handle, bind)
        .then(() => {
          const after = uploads.snapshot().get(row.key)
          if (after?.phase.kind === 'bound') say(`${handle.original_file_name} is sent and added to this draft.`)
          else if (after !== undefined) say(`${handle.original_file_name}: ${lineOf(after.phase).text}`, 'danger')
        })
        .catch((failure: unknown) => {
          // A reset ended the bind: the file belongs to an earlier sign-in, and nothing is said of it.
          if (!isReset(failure)) throw failure
        })
    },
    [bind, changeFiles, files, say, uploads]
  )

  const remove = useCallback(
    (key: string) => {
      removed.current.add(key)
      const row = uploads.snapshot().get(key)
      const onDraft = (each: DraftAttachment) => {
        const phase = uploads.snapshot().get(each.localId)?.phase.kind
        return phase === 'bound' || phase === 'adding'
      }
      if (row?.phase.kind === 'bound') {
        // The host keeps one draft for the session and no way to take one file off it, so the draft
        // ends and every file bound to it leaves the composer.
        const gone = new Set(files.filter(onDraft).map((each) => each.localId))
        // The files leave the composer only once the draft is ended: while it cannot be, they stay
        // on the screen, and a later prompt does not carry files the person no longer sees.
        void nameSession()
          .then((subject) => port.draftEnd(subject, sessionId))
          .then(() => {
            for (const each of gone) {
              removed.current.add(each)
              uploads.forget(each)
            }
            changeFiles((current) => current.filter((each) => !gone.has(each.localId)))
          })
          .catch(() => {
            removed.current.delete(key)
          })
        return
      }
      uploads.forget(key)
      changeFiles((current) => current.filter((each) => each.localId !== key))
    },
    [changeFiles, files, nameSession, port, removed, sessionId, uploads]
  )

  return { rows, found, send, cancel, add, remove }
}
