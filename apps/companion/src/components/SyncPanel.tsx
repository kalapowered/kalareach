/**
 * The sync service and recovery, as sections of the account panel.
 *
 * The sync service is a setting of its own: the managed service until the person picks another,
 * which is how a self-hosted one is chosen. It is shown with a way to change it, as the pairing
 * service is. Recovery keeps an encrypted bundle on it, with the account's sign-in beside this
 * device's signature, and hands the person a kit. This panel asks the backend to do each step and
 * is told where recovery stands and what stops the next one; the seed, the locator and the token
 * never reach it, and the kit is written by the backend to a file the person chose.
 *
 * Recovery is offered on a desktop. A phone shows the setting and no more: its save dialog cannot
 * write a file the person chooses.
 *
 * Each card has one status line, a polite live region the panel moves focus to when a step ends,
 * because the control the person pressed is disabled while the step runs and may be gone when it
 * ends. A step ends when the card's state has been read again, so the line a person lands on says
 * where things now stand. Focus is moved only when it is on nothing or already in the card that
 * ran the step: a person who went on to type in the other card keeps the field they are in, and a
 * service the backend refused keeps focus in the field to correct, marked invalid and described by
 * the line. The line says how the step ended, in the backend's words when it refused. A read that
 * fails is said in place of the card's state, with a way to ask again, and never as an empty card.
 * Nothing here moves of its own; the cards sit in the account panel's frame.
 */

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react'

import { failureMessage, type HostPort, type RecoveryView, type SyncServiceView } from '../host/port'
import { minimumTarget, type Surface } from '../mobile/platform'
import type { AccountView } from '../model/account'
import {
  KIT_FILE_NAME,
  RECOVERY_HELP,
  SETTLE_HELP,
  SYNC_SERVICE_HELP,
  describeBlocker,
  describeRecovery,
  describeStaysAt
} from '../model/recovery'
import { Button, Card } from './ui'

/** Which card a step belongs to, so the status it ends with is said in that card. */
type Place = 'service' | 'recovery'

/** What the last step said. */
interface Said {
  readonly place: Place
  readonly text: string
  /** Whether the step was refused or failed. */
  readonly failed: boolean
}

/** Where a step that has ended leaves focus. */
interface Finished {
  readonly place: Place
  readonly failed: boolean
}

/** The sync service setting and, on a desktop, recovery. */
export function SyncPanel({
  port,
  account,
  surface
}: {
  readonly port: HostPort
  readonly account: AccountView | null
  readonly surface: Surface
}): ReactNode {
  const desktop = surface === 'desktop'
  const target = minimumTarget(surface)
  const inputId = useId()
  const serviceStatusId = useId()
  const [service, setService] = useState<SyncServiceView | null>(null)
  const [serviceProblem, setServiceProblem] = useState<string | null>(null)
  const [recovery, setRecovery] = useState<RecoveryView | null>(null)
  const [recoveryProblem, setRecoveryProblem] = useState<string | null>(null)
  const [changing, setChanging] = useState(false)
  const [draft, setDraft] = useState('')
  const [said, setSaid] = useState<Said | null>(null)
  const [busy, setBusy] = useState(false)
  const serviceStatus = useRef<HTMLDivElement | null>(null)
  const recoveryStatus = useRef<HTMLDivElement | null>(null)
  const serviceInput = useRef<HTMLInputElement | null>(null)
  const finished = useRef<Finished | null>(null)
  // A sign-in that changes what the account may do changes what stops recovery, so it is read again.
  const standing = account?.state === 'signed_in' ? account.generation : (account?.state ?? null)

  /** Reads both cards again; the promise is settled once each read has answered or failed. */
  const refresh = useCallback((): Promise<void> => {
    const reads: Promise<void>[] = [
      port
        .syncServiceView()
        .then((view) => {
          setService(view)
          setServiceProblem(null)
        })
        .catch((error: unknown) => {
          // What was shown before may no longer be true, so it is not shown beside the problem.
          setService(null)
          setServiceProblem(failureMessage(error))
        })
    ]
    if (desktop) {
      reads.push(
        port
          .recoveryView()
          .then((view) => {
            setRecovery(view)
            setRecoveryProblem(null)
          })
          .catch((error: unknown) => {
            setRecovery(null)
            setRecoveryProblem(failureMessage(error))
          })
      )
    }
    return Promise.all(reads).then(() => undefined)
  }, [port, desktop])

  useEffect(() => {
    void refresh()
  }, [refresh, standing])

  // When a step ends, focus goes to its card's status line: the pressed control may be disabled,
  // or gone, and a person using a keyboard or a screen reader would otherwise be left on nothing.
  // It is not taken from a field the person went on to use in the other card, and a refused change
  // of the service leaves it in the field the person has to correct.
  useEffect(() => {
    if (busy || finished.current === null) return
    const { place, failed } = finished.current
    finished.current = null
    if (place === 'service' && failed && serviceInput.current !== null) {
      serviceInput.current.focus()
      return
    }
    const status = place === 'service' ? serviceStatus : recoveryStatus
    const card = status.current?.closest('[data-card]') ?? null
    const active = document.activeElement
    const free = active === null || active === document.body || (card?.contains(active) ?? false)
    if (free) status.current?.focus()
  }, [busy])

  /**
   * Runs one step, says how it ended, and reads where things stand again; the step has ended, and
   * focus moves, once that read has answered. A step that has another owner of focus (the sign-in,
   * which the account card follows from the browser back to its own status line) moves none.
   */
  const step = (place: Place, work: () => Promise<string | null>, moveFocus = true) => {
    setBusy(true)
    setSaid(null)
    let failed = false
    work()
      .then((text) => {
        if (text !== null) setSaid({ place, text, failed: false })
      })
      .catch((error: unknown) => {
        failed = true
        setSaid({ place, text: failureMessage(error), failed: true })
      })
      .then(() => refresh())
      .then(() => {
        finished.current = moveFocus ? { place, failed } : null
        setBusy(false)
      })
      .catch(() => {
        // A read cannot reject (each says its own failure), but a step must always end.
        finished.current = moveFocus ? { place, failed } : null
        setBusy(false)
      })
  }

  if (service === null && serviceProblem === null) return null

  const blocker = recovery?.blocker ?? null
  const offersTurnOn =
    recovery !== null &&
    (recovery.state === 'off' || recovery.state === 'unfinished') &&
    blocker === null
  const staysAt = recovery !== null ? describeStaysAt(recovery) : null

  return (
    <>
      <p className="account-section-title">Sync service</p>
      <Card data-card="service">
        <div className="account-state">
          <div
            className="account-status"
            aria-live="polite"
            tabIndex={-1}
            ref={serviceStatus}
            id={serviceStatusId}
            data-testid="sync-status"
          >
            {service !== null ? (
              <p className="account-lead">
                This device uses <strong data-testid="sync-service">{service.host}</strong> as its
                sync service.
              </p>
            ) : null}
            {serviceProblem !== null ? (
              <p className="account-note" data-testid="sync-problem">
                {serviceProblem}
              </p>
            ) : null}
            {said?.place === 'service' ? <p className="account-note">{said.text}</p> : null}
          </div>
          <div className="account-actions">
            {service !== null ? (
              <Button
                data-testid="change-sync-service"
                aria-expanded={changing}
                style={{ minBlockSize: target }}
                onClick={() => {
                  setDraft(service.origin)
                  setChanging((open) => !open)
                }}
              >
                Change
              </Button>
            ) : (
              <Button
                disabled={busy}
                style={{ minBlockSize: target }}
                onClick={() => {
                  step('service', () => Promise.resolve(null))
                }}
              >
                Try again
              </Button>
            )}
          </div>
          {changing && service !== null ? (
            <form
              className="form-field"
              onSubmit={(event) => {
                event.preventDefault()
                step('service', () =>
                  port.syncServiceSet(draft).then((next) => {
                    setChanging(false)
                    return `This device now uses ${next.host} as its sync service.`
                  })
                )
              }}
            >
              <label htmlFor={inputId}>Sync service</label>
              <input
                id={inputId}
                ref={serviceInput}
                data-testid="sync-service-input"
                aria-invalid={said?.place === 'service' && said.failed ? true : undefined}
                aria-describedby={serviceStatusId}
                value={draft}
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                onChange={(event) => {
                  setDraft(event.target.value)
                }}
              />
              <p className="form-hint">{SYNC_SERVICE_HELP}</p>
              <div className="row">
                <Button
                  type="submit"
                  tone="primary"
                  data-testid="save-sync-service"
                  disabled={busy}
                  style={{ minBlockSize: target }}
                >
                  Use this service
                </Button>
              </div>
            </form>
          ) : null}
        </div>
      </Card>

      {desktop && (recovery !== null || recoveryProblem !== null) ? (
        <>
          <p className="account-section-title">Recovery</p>
          <Card data-card="recovery" data-testid="recovery" data-state={recovery?.state ?? 'unread'}>
            <div className="account-state">
              <div
                className="account-status"
                aria-live="polite"
                tabIndex={-1}
                ref={recoveryStatus}
                data-testid="recovery-status"
              >
                {recovery !== null ? (
                  <p className="account-lead">{describeRecovery(recovery)}</p>
                ) : null}
                {recovery?.state === 'unsettled' ? (
                  <p className="account-note">{SETTLE_HELP}</p>
                ) : null}
                {staysAt !== null ? (
                  <p className="account-note" data-testid="recovery-stays-at">
                    {staysAt}
                  </p>
                ) : null}
                {blocker !== null ? (
                  <p
                    className="account-note"
                    data-testid="recovery-blocker"
                    data-reason={blocker.reason}
                  >
                    {describeBlocker(blocker)}
                  </p>
                ) : null}
                {recovery?.state === 'off' ? (
                  <p className="account-note">{RECOVERY_HELP}</p>
                ) : null}
                {recoveryProblem !== null ? (
                  <p className="account-note" data-testid="recovery-problem">
                    {recoveryProblem}
                  </p>
                ) : null}
                {said?.place === 'recovery' ? (
                  <p className="account-note" data-testid="recovery-said">
                    {said.text}
                  </p>
                ) : null}
              </div>
              <div className="account-actions">
                {recoveryProblem !== null ? (
                  <Button
                    disabled={busy}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      step('recovery', () => Promise.resolve(null))
                    }}
                  >
                    Try again
                  </Button>
                ) : null}
                {offersTurnOn ? (
                  <Button
                    tone="primary"
                    data-testid="recovery-turn-on"
                    disabled={busy}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      step('recovery', () => port.recoveryTurnOn().then(() => null))
                    }}
                  >
                    Turn on recovery
                  </Button>
                ) : null}
                {blocker?.reason === 'needs_sign_in' ? (
                  <Button
                    tone="primary"
                    data-testid="recovery-sign-in"
                    disabled={busy}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      step('recovery', () => port.accountSignInForRecovery().then(() => null), false)
                    }}
                  >
                    Sign in again
                  </Button>
                ) : null}
                {recovery?.state === 'unsettled' && blocker === null ? (
                  <Button
                    tone="primary"
                    data-testid="recovery-settle"
                    disabled={busy}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      step('recovery', () => port.recoverySettle().then(() => null))
                    }}
                  >
                    Settle it
                  </Button>
                ) : null}
                {recovery?.state === 'on' ? (
                  <Button
                    data-testid="recovery-save-kit"
                    disabled={busy}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      step('recovery', async () => {
                        // The platform's dialog answers, and the backend writes the kit only there.
                        const path = await port.chooseExportPath(KIT_FILE_NAME)
                        if (path === null) return null
                        await port.recoverySaveKit(path)
                        return 'Recovery kit saved. Keep it where only you can reach it.'
                      })
                    }}
                  >
                    Save the recovery kit
                  </Button>
                ) : null}
              </div>
            </div>
          </Card>
        </>
      ) : null}
    </>
  )
}
