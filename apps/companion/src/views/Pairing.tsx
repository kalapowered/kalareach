/**
 * Pairing a device, and the two things that must be visible while it happens.
 *
 * The rendezvous origin is on the screen before an attempt starts, with a way to change it, even
 * when it is the one KalaReach ships with. And a scanned code that names a different origin does
 * not quietly switch to it: the full hostname goes in front of the person and waits.
 *
 * The confirmation itself is the platform's ceremony, not a button here. A click can be
 * synthesised; that is exactly why it is not the proof.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react'

import { Badge, Banner, Button, Card, CommitButton } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage, type RendezvousOrigin, type ScannedCode } from '../host/port'

/** The pairing screen. */
export function Pairing(): ReactNode {
  const { port, say } = useApp()
  const [origin, setOrigin] = useState<RendezvousOrigin | null>(null)
  const [changing, setChanging] = useState(false)
  const [draftOrigin, setDraftOrigin] = useState('')
  const [code, setCode] = useState('')
  const [scanned, setScanned] = useState<ScannedCode | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [presence, setPresence] = useState<string | null>(null)

  const load = useCallback(() => {
    port
      .pairingOrigin()
      .then((current) => {
        setOrigin(current)
        setDraftOrigin(current.origin)
      })
      .catch((error: unknown) => {
        setFailure(failureMessage(error))
      })
  }, [port])

  useEffect(load, [load])

  const scan = (payload: string) => {
    port
      .pairingScan(payload)
      .then((result) => {
        setScanned(result)
        setFailure(null)
      })
      .catch((error: unknown) => {
        setScanned(null)
        setFailure(failureMessage(error))
      })
  }

  const acceptScannedOrigin = () => {
    if (!scanned || scanned.mode !== 'code') return
    port
      .pairingSetOrigin(scanned.origin.origin)
      .then((next) => {
        setOrigin(next)
        setDraftOrigin(next.origin)
        setScanned({ ...scanned, needs_origin_confirmation: false })
        say(`Now using ${next.host}.`)
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
  }

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Pairing</p>
          <h1>Add a device</h1>
          <p>Enter the ten-character code from the host, or scan its code.</p>
        </div>
      </header>

      {failure ? <Banner tone="warning" title="That did not work" detail={failure} /> : null}

      <Card>
        <div className="card-header">
          <div className="spacer">
            <h2>Rendezvous service</h2>
            <p className="muted small">
              The service that introduces the two devices. It never sees your secret.
            </p>
          </div>
          <Badge tone={origin?.is_default ? 'neutral' : 'accent'}>
            {origin?.is_default ? 'Default' : 'Self-hosted'}
          </Badge>
        </div>
        <div className="card-body">
          <div className="divided-row">
            <div className="spacer">
              <strong className="mono" data-testid="rendezvous-origin">
                {origin?.origin ?? ''}
              </strong>
              <p className="muted small">Shown before every attempt, whichever service it is.</p>
            </div>
            <Button
              data-testid="change-origin"
              onClick={() => {
                setChanging((current) => !current)
              }}
            >
              Change
            </Button>
          </div>
          {changing ? (
            <div className="form-field">
              <label htmlFor="origin-input">Rendezvous origin</label>
              <input
                id="origin-input"
                value={draftOrigin}
                data-testid="origin-input"
                onChange={(event) => {
                  setDraftOrigin(event.target.value)
                }}
              />
              <p className="form-hint">
                An https origin. Changing it after an attempt has started would change what the code
                was for, so change it first.
              </p>
              <Button
                tone="primary"
                data-testid="save-origin"
                onClick={() => {
                  port
                    .pairingSetOrigin(draftOrigin)
                    .then((next) => {
                      setOrigin(next)
                      setChanging(false)
                      say(`Now using ${next.host}.`)
                    })
                    .catch((error: unknown) => {
                      say(failureMessage(error), 'danger')
                    })
                }}
              >
                Use this service
              </Button>
            </div>
          ) : null}
        </div>
      </Card>

      {scanned?.mode === 'code' && scanned.needs_origin_confirmation ? (
        <Card data-testid="origin-confirmation">
          <div className="card-header">
            <div className="spacer">
              <h2>This code is for a different service</h2>
              <p className="muted small">
                Contacting it tells that service you are pairing. Confirm before anything is sent.
              </p>
            </div>
            <Badge tone="warning">Confirm</Badge>
          </div>
          <div className="card-body">
            <p className="pair-code mono" data-testid="scanned-origin-host">
              {scanned.origin.host}
            </p>
            <p className="muted small">
              You are currently set to {origin?.host ?? 'the default service'}.
            </p>
          </div>
          <div className="card-footer">
            <Button
              onClick={() => {
                setScanned(null)
              }}
            >
              Keep {origin?.host ?? 'the current service'}
            </Button>
            <CommitButton tone="primary" data-testid="accept-origin" onCommit={acceptScannedOrigin}>
              Use {scanned.origin.host}
            </CommitButton>
          </div>
        </Card>
      ) : null}

      <Card>
        <div className="card-header">
          <div className="spacer">
            <h2>Pairing code</h2>
            <p className="muted small">Ten characters. Spaces and hyphens are ignored.</p>
          </div>
        </div>
        <div className="card-body">
          <div className="form-field">
            <label htmlFor="code-input">Code</label>
            <input
              id="code-input"
              value={code}
              data-testid="code-input"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              className="mono"
              onChange={(event) => {
                setCode(event.target.value)
              }}
            />
            <p className="form-hint">
              This code goes to {origin?.host ?? 'the configured service'}. Only its first four
              characters ever leave this device.
            </p>
          </div>
          <div className="row wrap">
            <Button
              data-testid="paste-qr"
              onClick={() => {
                // In the desktop application a scan arrives from the camera or a pasted payload.
                // Either way it is read by the backend, which is what decides whether it names
                // another origin.
                void navigator.clipboard
                  ?.readText()
                  .then(scan)
                  .catch(() => {
                    setFailure('Nothing readable was on the clipboard.')
                  })
              }}
            >
              Read a scanned code
            </Button>
            <CommitButton
              tone="primary"
              data-testid="verify-owner"
              onCommit={() => {
                port
                  .pairingVerifyOwner('Confirm this new device on your account')
                  .then((result) => {
                    setPresence(result.mechanism)
                    say('Verified on this device.')
                  })
                  .catch((error: unknown) => {
                    setPresence(null)
                    say(failureMessage(error), 'danger')
                  })
              }}
            >
              Confirm as the owner
            </CommitButton>
          </div>
          {presence ? (
            <p className="small success-text" data-testid="presence-mechanism">
              Verified through {presence}. The host records that verification with the
              confirmation.
            </p>
          ) : (
            <p className="small faint">
              Confirming uses this device&apos;s own verification, not a button in this window.
            </p>
          )}
        </div>
      </Card>
    </>
  )
}
