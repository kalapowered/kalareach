/**
 * The first-use step: what voice on this device is allowed to do, asked of the person.
 *
 * A host refuses a voice preparation to a device that holds no voice grant, and a grant is for
 * sessions the person names: a call is bound to them. So before the voice screen can say what a
 * call would be, the person is shown what allowing voice permits, action by action, in the
 * sentences the protocol states them in, and chooses the sessions. Allowing sends exactly those
 * sessions and the default actions; the host answers with what it granted, and says plainly any
 * action this device's own authority could not carry.
 *
 * The step holds no wording of its own for an action. The sentences come from native code, which
 * reads the protocol's table, so this screen cannot word an action more softly than the host does.
 */

import { useEffect, useId, useRef, useState, type ReactNode } from 'react'

import type { HostPort, VoiceAllowed, VoiceScope } from '../host/port'
import { failureMessage } from '../host/port'

/** A session the person can choose, as the host lists it. */
interface Choice {
  readonly id: string
  readonly name: string
}

/** The step. */
export function VoiceGrantStep({
  port,
  refusal,
  named,
  onAllowed
}: {
  readonly port: HostPort
  /** The host's own words for why it would not prepare a call, when it gave any. */
  readonly refusal: string | null
  /** Sessions the screen was opened for, chosen to begin with. None means every live one. */
  readonly named: readonly string[]
  /** Called with the sessions the person allowed, once the host has granted them. */
  readonly onAllowed: (sessionIds: readonly string[]) => void
}): ReactNode {
  const id = useId()
  const [scope, setScope] = useState<VoiceScope | null>(null)
  const [choices, setChoices] = useState<readonly Choice[] | null>(null)
  const [chosen, setChosen] = useState<ReadonlySet<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [granted, setGranted] = useState<VoiceAllowed | null>(null)
  /** The sessions the host granted, held while the person reads what it could not carry. */
  const [allowedIds, setAllowedIds] = useState<readonly string[] | null>(null)
  const continueButton = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    let current = true
    port.voiceScope().then(
      (read) => {
        if (current) setScope(read)
      },
      (error: unknown) => {
        if (current) setFailure(failureMessage(error))
      }
    )
    port.sessionList({ environment_id: null, include_closed: false }).then(
      (list) => {
        if (!current) return
        const listed = list.sessions.map((session) => ({
          id: session.session_id,
          name: `Session ${session.display_number}`
        }))
        setChoices(listed)
        setChosen(
          new Set(
            named.length > 0
              ? listed.filter((each) => named.includes(each.id)).map((each) => each.id)
              : listed.map((each) => each.id)
          )
        )
      },
      (error: unknown) => {
        if (current) setFailure(failureMessage(error))
      }
    )
    return () => {
      current = false
    }
  }, [named, port])

  // The result is read before the call is shown, and the way on is the one control left to press.
  useEffect(() => {
    if (granted !== null) continueButton.current?.focus()
  }, [granted])

  const allow = () => {
    if (busy || chosen.size === 0) return
    const sessionIds = [...chosen]
    setBusy(true)
    setFailure(null)
    port.voiceAllow({ sessionIds, actions: null }, {}).then(
      (settled) => {
        setBusy(false)
        // An answer with no result is a host that did not confirm: the grant may or may not stand,
        // so the person is not moved on, and allowing it again settles it.
        if (!settled.value) {
          setFailure(
            'The host did not confirm that voice was allowed. Allow it again to be sure.'
          )
          return
        }
        // What the host could not carry is read before the call is shown, not after: the person
        // goes on once they have seen it.
        if (settled.value.not_held_by_device.length === 0) {
          onAllowed(sessionIds)
          return
        }
        setGranted(settled.value)
        setAllowedIds(sessionIds)
      },
      (error: unknown) => {
        setBusy(false)
        setFailure(failureMessage(error))
      }
    )
  }

  return (
    <section className="kr-voice" aria-labelledby={`${id}-heading`} aria-busy={busy}>
      <h1 id={`${id}-heading`} className="kr-voice__title">
        Allow voice on this phone
      </h1>
      <p className="kr-voice__note">
        Voice lets you talk to your host. Before it can, you say what speaking is allowed to do, and
        for which sessions. You can stop a call at any time. What you allow here stays until you
        change it.
      </p>
      {refusal === null ? null : (
        <p className="kr-voice__refusal" role="status" data-testid="voice-grant-refusal">
          {refusal}
        </p>
      )}

      <section className="kr-voice__panel" aria-labelledby={`${id}-actions`}>
        <h2 id={`${id}-actions`}>What speaking will be allowed to do</h2>
        {scope === null ? (
          <p className="kr-voice__note">Reading what that includes…</p>
        ) : (
          <ul className="kr-voice__list" data-testid="voice-scope">
            {scope.actions.map((each) => (
              <li key={each.action}>
                <span className="kr-voice__kind">{each.action.replace(/_/g, ' ')}</span>
                <span className="kr-voice__summary">{each.sentence}</span>
                {each.needs_unlocked_screen ? (
                  <span className="kr-voice__summary">
                    Asks for your confirmation on the unlocked screen each time.
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        )}
        <p className="kr-voice__note">The host refuses anything not listed here.</p>
      </section>

      <section className="kr-voice__panel" aria-labelledby={`${id}-sessions`}>
        <h2 id={`${id}-sessions`}>Which sessions it may reach</h2>
        {choices === null ? (
          <p className="kr-voice__note">Reading the host’s sessions…</p>
        ) : choices.length === 0 ? (
          <p className="kr-voice__note" data-testid="voice-no-sessions">
            This host has no sessions yet. Start one, then come back.
          </p>
        ) : (
          <ul className="kr-voice__list">
            {choices.map((choice) => (
              <li key={choice.id}>
                <label className="kr-voice__choice">
                  <input
                    type="checkbox"
                    checked={chosen.has(choice.id)}
                    disabled={granted !== null}
                    onChange={(event) => {
                      setChosen((before) => {
                        const next = new Set(before)
                        if (event.target.checked) next.add(choice.id)
                        else next.delete(choice.id)
                        return next
                      })
                    }}
                  />
                  <span>{choice.name}</span>
                </label>
              </li>
            ))}
          </ul>
        )}
      </section>

      {granted === null || allowedIds === null ? null : (
        <div className="kr-voice__panel" role="status" data-testid="voice-grant-result">
          <p className="kr-voice__note">
            {`Allowed, except ${granted.not_held_by_device
              .map((action) => action.replace(/_/g, ' '))
              .join(', ')}: this phone’s own access to the host does not include ${
              granted.not_held_by_device.length === 1 ? 'it' : 'them'
            }.`}
          </p>
          <button
            ref={continueButton}
            type="button"
            className="kr-voice__start"
            data-testid="voice-grant-continue"
            onClick={() => {
              onAllowed(allowedIds)
            }}
          >
            Continue
          </button>
        </div>
      )}
      {failure === null ? null : (
        <p className="kr-voice__refusal" role="status" data-testid="voice-grant-failure">
          {failure}
        </p>
      )}

      <button
        type="button"
        className="kr-voice__start"
        onClick={allow}
        disabled={busy || chosen.size === 0 || scope === null || granted !== null}
        data-testid="voice-allow"
      >
        {busy ? 'Allowing…' : 'Allow voice'}
      </button>
    </section>
  )
}
