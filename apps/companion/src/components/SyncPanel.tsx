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
 * Nothing here moves, so there is no motion to reduce; a change of state replaces the words in place.
 */

import { useCallback, useEffect, useId, useState, type ReactNode } from 'react'

import { failureMessage, type HostPort, type RecoveryView, type SyncServiceView } from '../host/port'
import { minimumTarget, type Surface } from '../mobile/platform'
import type { AccountView } from '../model/account'
import {
  KIT_FILE_NAME,
  RECOVERY_HELP,
  SETTLE_HELP,
  SYNC_SERVICE_HELP,
  describeBlocker,
  describeRecovery
} from '../model/recovery'
import { Button, Card } from './ui'

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
  const [service, setService] = useState<SyncServiceView | null>(null)
  const [recovery, setRecovery] = useState<RecoveryView | null>(null)
  const [changing, setChanging] = useState(false)
  const [draft, setDraft] = useState('')
  const [said, setSaid] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // A sign-in that changes what the account may do changes what stops recovery, so it is read again.
  const standing = account?.state === 'signed_in' ? account.generation : (account?.state ?? null)

  const refresh = useCallback(() => {
    port
      .syncServiceView()
      .then(setService)
      .catch(() => undefined)
    if (desktop) {
      port
        .recoveryView()
        .then(setRecovery)
        .catch(() => {
          setRecovery(null)
        })
    }
  }, [port, desktop])

  useEffect(() => {
    refresh()
  }, [refresh, standing])

  /** Runs one step, says how it ended, and reads where things stand again. */
  const step = (work: () => Promise<string | null>) => {
    setBusy(true)
    setSaid(null)
    work()
      .then((text) => {
        if (text !== null) setSaid(text)
      })
      .catch((error: unknown) => {
        setSaid(failureMessage(error))
      })
      .finally(() => {
        setBusy(false)
        refresh()
      })
  }

  if (service === null) return null

  const blocker = recovery?.blocker ?? null
  const offersTurnOn =
    recovery !== null &&
    (recovery.state === 'off' || recovery.state === 'unfinished') &&
    blocker === null

  return (
    <>
      <p className="account-section-title">Sync service</p>
      <Card>
        <div className="account-state">
          <div className="account-actions">
            <p className="account-lead">
              Settings sync and recovery go through{' '}
              <strong data-testid="sync-service">{service.host}</strong>.
            </p>
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
          </div>
          {changing ? (
            <form
              className="form-field"
              onSubmit={(event) => {
                event.preventDefault()
                step(() =>
                  port.syncServiceSet(draft).then((next) => {
                    setChanging(false)
                    return `Sync now goes through ${next.host}.`
                  })
                )
              }}
            >
              <label htmlFor={inputId}>Sync service</label>
              <input
                id={inputId}
                data-testid="sync-service-input"
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
          <div aria-live="polite" data-testid="sync-status">
            {said !== null ? <p className="account-note">{said}</p> : null}
          </div>
        </div>
      </Card>

      {desktop && recovery !== null ? (
        <>
          <p className="account-section-title">Recovery</p>
          <Card data-testid="recovery">
            <div className="account-state" key={recovery.state}>
              <div className="account-status">
                <p className="account-lead">{describeRecovery(recovery)}</p>
                {recovery.state === 'unsettled' ? (
                  <p className="account-note">{SETTLE_HELP}</p>
                ) : null}
                {blocker !== null ? (
                  <p className="account-note" data-testid="recovery-blocker">
                    {describeBlocker(blocker)}
                  </p>
                ) : null}
                {recovery.state === 'off' ? (
                  <p className="account-note">{RECOVERY_HELP}</p>
                ) : null}
              </div>
              <div className="account-actions">
                {offersTurnOn ? (
                  <Button
                    tone="primary"
                    data-testid="recovery-turn-on"
                    disabled={busy}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      step(() => port.recoveryTurnOn().then(() => null))
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
                      step(() => port.accountSignInForRecovery().then(() => null))
                    }}
                  >
                    Sign in again
                  </Button>
                ) : null}
                {recovery.state === 'unsettled' && blocker === null ? (
                  <Button
                    tone="primary"
                    data-testid="recovery-settle"
                    disabled={busy}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      step(() => port.recoverySettle().then(() => null))
                    }}
                  >
                    Settle it
                  </Button>
                ) : null}
                {recovery.state === 'on' ? (
                  <Button
                    data-testid="recovery-save-kit"
                    disabled={busy}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      step(async () => {
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
