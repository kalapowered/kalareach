/**
 * What has left the host, and the person's way to ask for a copy to be deleted.
 *
 * A copy is shown as the host reports it and as this computer's own sync reports it. Deleting one
 * is the person's act and this page is not the one that confirms it: pressing the button asks
 * native code, which raises a dialog of its own and returns a token only on a yes. The page holds
 * no method and no parameter of the deletion, so a page that is mistaken or compromised can ask for
 * the dialog and nothing more.
 *
 * Only the computer the host runs on offers it for a copy the host lists: a phone, and a host this
 * device is paired with, show the list and say where the copy is deleted. A copy this computer's own
 * sync kept is deleted from here whichever host is connected, because no host is asked.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react'

import type { PrivacyExported, PrivacyReport } from '@kalareach/protocol'

import { Button, Card } from '../components/ui'
import { useApp } from '../app/state'
import { useHeldConnection } from '../app/rights'
import { failureMessage } from '../host/port'
import { ask } from '../mobile/model/call'

/** Where one copy's deletion stands on this page. */
type Step =
  /** Nothing in hand. */
  | 'idle'
  /** The dialog is up and waits for the person. */
  | 'waiting'
  /** The person said yes and the deletion is being asked for. */
  | 'deleting'
  /** It was asked for and the service has not confirmed it. */
  | 'unconfirmed'

/** One listed copy, and whose list it came from. */
interface Row {
  readonly copy: PrivacyExported
  /** True for a copy this computer's own sync kept, false for one the host lists. */
  readonly sync: boolean
}

/** What a button says in each step: the label stays while the note beside it says where things stand. */
const LABEL: Readonly<Record<Step, string>> = {
  idle: 'Delete…',
  waiting: 'Delete…',
  deleting: 'Delete…',
  unconfirmed: 'Ask again…'
}

/** What the page says of a copy, in words that say where the copy is deleted from. */
function removalNote(row: Row, step: Step, here: boolean): string {
  if (step === 'waiting') return 'Waiting for your answer in the dialog.'
  if (step === 'deleting') return 'Asking the service to delete it…'
  if (step === 'unconfirmed') {
    return 'Deletion was asked for and the service has not confirmed it. The copy stays listed until it does.'
  }
  if (row.sync) {
    return row.copy.deletable
      ? 'This computer can ask the sync service to drop it. A confirmation dialog comes first.'
      : 'This computer cannot ask the sync service to drop it now: its sync is off, or the record of it cannot be read.'
  }
  if (!row.copy.deletable) {
    return 'This host cannot ask for its removal.'
  }
  return here
    ? 'This host can ask for its removal. A confirmation dialog comes first.'
    : 'This host can ask for its removal, at the computer it runs on. This page is not connected to that host.'
}

/** What has left the host, with a way to delete what the host and this computer's sync can. */
export function LeftTheHost({
  privacy,
  syncCopies,
  syncFailure,
  syncReading,
  reload,
  retry
}: {
  /** The host's report, or null when the host could not be asked. */
  readonly privacy: PrivacyReport | null
  /** The copies this computer's own sync kept. */
  readonly syncCopies: readonly PrivacyExported[]
  /** Why this computer's own sync records could not be read, when they could not: the list is then incomplete. */
  readonly syncFailure: string | null
  /** Whether those records are being read. */
  readonly syncReading: boolean
  /** Reads both lists again, after a deletion. */
  readonly reload: () => void
  /** Reads both lists again, because the person asked after a failure. */
  readonly retry: () => void
}): ReactNode {
  const { port, say } = useApp()
  const { rights, paired } = useHeldConnection()
  const here = rights !== null && !paired
  const [steps, setSteps] = useState<ReadonlyMap<string, Step>>(new Map())
  const [refusals, setRefusals] = useState<ReadonlyMap<string, string>>(new Map())
  // Whether the person asked to read again after a failure: when it works the button goes, and the
  // heading takes the focus it had.
  const retried = useRef(false)
  const heading = useRef<HTMLHeadingElement | null>(null)
  useEffect(() => {
    if (!retried.current || syncReading) return
    retried.current = false
    if (syncFailure === null) heading.current?.focus()
  }, [syncReading, syncFailure])
  // Whether this section is still on the screen: a dialog that is answered after it closed has no
  // page left to tell, and its token is dropped.
  const open = useRef(true)
  useEffect(() => {
    open.current = true
    return () => {
      open.current = false
    }
  }, [])

  const rows: readonly Row[] = [
    ...(privacy?.exported ?? []).map((copy) => ({ copy, sync: false })),
    ...syncCopies.map((copy) => ({ copy, sync: true }))
  ]

  // A deletion that was asked for and not confirmed is a note about a copy that is still listed as
  // one to ask again: once the list says the service has deleted it, the note has nothing to say.
  const stepOf = (row: Row): Step => {
    const step = steps.get(row.copy.reference) ?? 'idle'
    return step === 'unconfirmed' && !row.copy.deletable ? 'idle' : step
  }
  const setStep = (reference: string, step: Step) => {
    setSteps((held) => new Map(held).set(reference, step))
  }
  const refuse = (reference: string, words: string | null) => {
    setRefusals((held) => {
      const next = new Map(held)
      if (words === null) next.delete(reference)
      else next.set(reference, words)
      return next
    })
  }

  const remove = (row: Row) => {
    const reference = row.copy.reference
    setStep(reference, 'waiting')
    refuse(reference, null)
    void (async () => {
      let held: string | null = null
      try {
        const asked = await ask(() => port.retainedDeleteAsk(reference))
        const token = asked.token
        if (!asked.confirmed || token === null) {
          if (open.current) setStep(reference, 'idle')
          return
        }
        held = token
        if (!open.current) {
          // The section closed while the dialog was up: nothing is deleted behind the person's back.
          await ask(() => port.retainedDeleteCancel(token))
          return
        }
        setStep(reference, 'deleting')
        const finished = await ask(() => port.retainedDeleteFinish(token))
        held = null
        if (!open.current) return
        if (finished.deleted) {
          setStep(reference, 'idle')
          say('Deleted. The service confirmed it.', 'success')
        } else {
          setStep(reference, 'unconfirmed')
        }
        reload()
      } catch (failure: unknown) {
        const unused = held
        if (unused !== null) await ask(() => port.retainedDeleteCancel(unused)).catch(() => undefined)
        if (!open.current) return
        setStep(reference, 'idle')
        refuse(reference, failureMessage(failure))
      }
    })()
  }

  if (privacy === null && syncCopies.length === 0 && syncFailure === null) return null

  return (
    <section className="stack" data-testid="retained-artefacts">
      <header className="page-heading">
        <div>
          <p className="eyebrow">Privacy</p>
          <h2 ref={heading} tabIndex={-1}>
            What has left this host
          </h2>
          <p>
            {privacy === null
              ? 'This host could not be asked what it sent. These are the copies this computer’s own sync kept.'
              : privacy.enabled
                ? `Privacy mode is on, at generation ${privacy.generation}. Nothing new is retained. These were sent or shown before then, and they are still out there.`
                : 'Privacy mode is off. New sessions retain their history.'}
          </p>
        </div>
      </header>
      <Card>
        <div className="card-body">
          {rows.length === 0 && syncFailure === null ? (
            <p className="muted small">Nothing this host knows of has left it.</p>
          ) : null}
          {syncFailure === null ? null : (
            <div className="divided-row" data-testid="sync-copies-unread">
              <p className="small warning-text spacer" role="alert">
                The copies this computer’s own sync kept could not be read, so this list may be
                missing some: {syncFailure}
              </p>
              <Button
                aria-busy={syncReading}
                onClick={() => {
                  retried.current = true
                  retry()
                }}
              >
                Try again
              </Button>
            </div>
          )}
          {rows.map((row) => {
            const reference = row.copy.reference
            const step = stepOf(row)
            const refusal = refusals.get(reference)
            const offered = row.copy.deletable && (row.sync || here)
            return (
              <div
                className="divided-row"
                key={`${row.sync ? 'sync' : 'host'}\n${row.copy.kind}\n${reference}`}
                data-testid="left-copy"
              >
                <div className="spacer">
                  <strong>{row.copy.kind}</strong>
                  <p className="muted small">
                    {reference} ·{' '}
                    {Number(row.copy.left_at_ms) === 0
                      ? 'left at a time not known'
                      : `left ${new Date(Number(row.copy.left_at_ms)).toLocaleString()}`}
                  </p>
                  <p className="small" data-testid="removal" aria-live="polite">
                    {removalNote(row, step, here)}
                  </p>
                  {refusal === undefined ? null : (
                    <p className="small warning-text" role="alert" data-testid="removal-refusal">
                      {refusal}
                    </p>
                  )}
                </div>
                {offered ? (
                  <Button
                    data-testid="delete-copy"
                    aria-label={`${step === 'unconfirmed' ? 'Ask again to delete' : 'Delete'} ${row.copy.kind}, ${reference}`}
                    aria-busy={step === 'waiting' || step === 'deleting'}
                    disabled={step === 'waiting' || step === 'deleting'}
                    onClick={() => {
                      remove(row)
                    }}
                  >
                    {LABEL[step]}
                  </Button>
                ) : null}
              </div>
            )
          })}
          {privacy?.unlisted.map((missing) => (
            <p className="small warning-text" data-testid="unlisted" key={missing.subsystem}>
              Not everything could be listed. {missing.subsystem}: {missing.reason}.
            </p>
          ))}
          <p className="small faint">
            A copy somebody else holds cannot be recalled from here, and a device that was let see a
            session may keep what it was shown after it is revoked. Local deletion is a logical
            cleanup rather than a secure erase.
          </p>
        </div>
      </Card>
    </section>
  )
}
