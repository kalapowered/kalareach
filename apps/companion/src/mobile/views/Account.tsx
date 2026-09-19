/**
 * The account screen: who you are, what you have used, and nothing to buy.
 *
 * Section 17 permits exactly two things on a mobile build: signing in, and seeing usage. There is
 * no payment form, no embedded checkout and no control whose purpose is to send a person somewhere
 * to buy something. The website is where an account is bought and changed, and a person goes there
 * because they went there.
 *
 * The screen also states the thing a person most needs to know: an account is not what makes the
 * product work. Hosts, sessions and agents on your own machines behave identically without one.
 */

import { useState, type ReactNode } from 'react'

import { Button, Card } from '../../components/ui'
import {
  commercialSurface,
  describeAccount,
  describeUsage,
  usageFraction,
  type AccountState,
  type Channel,
  type Usage
} from '../model/account'
import { minimumTarget, type Surface } from '../platform'

/** The account screen. */
export function Account({
  surface,
  channel,
  account,
  usage,
  onSignIn,
  onSignOut
}: {
  readonly surface: Surface
  readonly channel: Channel
  readonly account: AccountState
  readonly usage: Usage | null
  readonly onSignIn?: () => void
  readonly onSignOut?: () => void
}): ReactNode {
  const allowed = commercialSurface(channel)
  const target = minimumTarget(surface)
  const [working, setWorking] = useState(false)

  return (
    <div data-testid="mobile-account">
      <Card>
        <p>{describeAccount(account)}</p>
        {allowed.signIn && account.kind !== 'signed_in' ? (
          <Button
            tone="primary"
            style={{ minBlockSize: target }}
            disabled={working}
            onClick={() => {
              setWorking(true)
              onSignIn?.()
              setWorking(false)
            }}
          >
            Sign in
          </Button>
        ) : null}
        {account.kind === 'signed_in' ? (
          <Button
            style={{ minBlockSize: target }}
            onClick={() => {
              onSignOut?.()
            }}
          >
            Sign out
          </Button>
        ) : null}
      </Card>

      {allowed.usage && account.kind === 'signed_in' ? (
        <>
          <p className="m-section-title">{usage ? usage.periodLabel : 'Usage'}</p>
          {usage ? (
            <Card>
              {usage.lines.map((line) => {
                const fraction = usageFraction(line)
                return (
                  <div key={line.label} className="m-usage">
                    <span className="m-row-head">
                      <span className="m-row-title">{line.label}</span>
                      <span className="m-row-detail">{describeUsage(line)}</span>
                    </span>
                    {fraction === null ? null : (
                      <span
                        className="m-meter"
                        role="meter"
                        aria-label={`${line.label}: ${describeUsage(line)}`}
                        aria-valuenow={line.used}
                        aria-valuemin={0}
                        aria-valuemax={line.included ?? undefined}
                      >
                        <span style={{ inlineSize: `${Math.round(fraction * 100)}%` }} />
                      </span>
                    )}
                  </div>
                )
              })}
            </Card>
          ) : (
            <p className="m-empty">Usage has not been read yet.</p>
          )}
        </>
      ) : null}

      <p className="m-section-title">Working without an account</p>
      <Card>
        <p>
          Your hosts run on your machines. Sessions, agents and terminals work the same whether this
          device is signed in or not, and nothing here needs an account to reach a host you paired.
        </p>
      </Card>
    </div>
  )
}
