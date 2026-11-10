/**
 * What voice may do, for a person who already allowed it: the one place to add an action that
 * takes a confirmation on the unlocked screen to what a call may ask the host for.
 *
 * The first-use step grants the default scope and nothing more, so a person who allowed voice then
 * has no way to say a spoken close is welcome. This entry reads what the host says the standing
 * grant permits, shows the actions a person may add in the protocol's own sentences, and allowing
 * sends the call's sessions and the default actions with whatever was chosen as a replacement
 * grant. A replacement ends the calls that ran under the grant it replaces, so the host's answer
 * says which workers have not yet held the fence it owed, and so does this.
 *
 * It is offered only while a spoken request can reach the host at all: a person is not asked to
 * allow what cannot happen.
 */

import { useEffect, useId, useState, type ReactNode } from 'react'

import type { VoiceAction } from '@kalareach/protocol'

import type { HostPort, VoiceAllowed, VoiceScopeAction } from '../host/port'
import { failureMessage } from '../host/port'
import { FENCE_UNREADABLE_WORDS, toConfirmOfFence, toConfirmWords } from './model'

/** The entry. `standing` is the actions the host says the grant permits now. */
export function VoiceGrantEntry({
  port,
  sessions,
  sessionNames,
  standing,
  onChanged
}: {
  readonly port: HostPort
  /** The sessions the grant covers, as the host answered them. */
  readonly sessions: readonly string[]
  /** How the host names each session, where it said. */
  readonly sessionNames: Readonly<Record<string, string>>
  /** What the host says the standing grant permits. */
  readonly standing: readonly VoiceAction[]
  /** Called once the host has written the new grant, so the screen reads what a call would be. */
  readonly onChanged: () => void
}): ReactNode {
  const id = useId()
  const [defaults, setDefaults] = useState<readonly VoiceAction[]>([])
  const [offered, setOffered] = useState<readonly VoiceScopeAction[] | null>(null)
  /** What the person changed from what the host says the grant permits: an action and whether it is wanted. */
  const [edits, setEdits] = useState<ReadonlyMap<VoiceAction, boolean>>(new Map())
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [result, setResult] = useState<VoiceAllowed | null>(null)

  useEffect(() => {
    let current = true
    port.voiceScope().then(
      (scope) => {
        if (!current) return
        setDefaults(scope.actions.map((each) => each.action))
        setOffered(scope.optional)
      },
      () => {
        // A scope that cannot be read offers nothing.
        if (current) setOffered([])
      }
    )
    return () => {
      current = false
    }
  }, [port])

  if (offered === null || offered.length === 0) return null

  // The boxes show what the host says the grant permits, with what the person changed over it.
  const permitted = (action: VoiceAction) => edits.get(action) ?? standing.includes(action)
  const changed = offered.some((each) => permitted(each.action) !== standing.includes(each.action))

  const allow = () => {
    if (busy || !changed || sessions.length === 0) return
    setBusy(true)
    setFailure(null)
    setResult(null)
    const actions = [...defaults, ...offered.map((each) => each.action).filter(permitted)]
    port.voiceAllow({ sessionIds: sessions, actions }, {}).then(
      (settled) => {
        setBusy(false)
        // An answer with no result is a host that did not confirm: the grant may or may not stand.
        if (!settled.value) {
          setFailure('The host did not confirm the change. Allow it again to be sure.')
          return
        }
        setResult(settled.value)
        // The grant is what the host now says it is, which the screen reads again.
        setEdits(new Map())
        onChanged()
      },
      (error: unknown) => {
        setBusy(false)
        setFailure(failureMessage(error))
      }
    )
  }

  return (
    <section
      className="kr-voice kr-voice__panel"
      aria-labelledby={`${id}-heading`}
      aria-busy={busy}
      data-testid="voice-grant-entry"
    >
      <h2 id={`${id}-heading`}>What voice may do</h2>
      <p className="kr-voice__note">
        Voice may always do what is listed above. You can also let it close a session when you say
        so; each time, it asks for your confirmation on the unlocked screen of this phone first.
      </p>
      <ul className="kr-voice__list">
        {offered.map((each) => (
          <li key={each.action}>
            <label className="kr-voice__choice">
              <input
                type="checkbox"
                checked={permitted(each.action)}
                disabled={busy}
                onChange={(event) => {
                  setEdits((before) => new Map(before).set(each.action, event.target.checked))
                }}
              />
              <span>
                {each.sentence}
                {each.needs_unlocked_screen ? ' Asks for your confirmation each time.' : ''}
              </span>
            </label>
          </li>
        ))}
      </ul>
      {result === null ? null : (
        <p className="kr-voice__note" role="status" data-testid="voice-grant-entry-result">
          {[
            result.not_held_by_device.length === 0
              ? 'Allowed.'
              : `Allowed, except ${result.not_held_by_device
                  .map((action) => action.replace(/_/g, ' '))
                  .join(', ')}: this phone’s own access to the host does not include ${
                  result.not_held_by_device.length === 1 ? 'it' : 'them'
                }.`,
            result.fence.kind === 'unreadable'
              ? `Any calls that were running under the earlier allowance have ended. ${FENCE_UNREADABLE_WORDS}`
              : toConfirmOfFence(result.fence).sessions.length === 0
                ? null
                : `The calls that were running under the earlier allowance have ended. ${toConfirmWords(
                    toConfirmOfFence(result.fence),
                    sessionNames,
                    'calls'
                  )}`
          ]
            .filter((words) => words !== null)
            .join(' ')}
        </p>
      )}
      {failure === null ? null : (
        <p className="kr-voice__refusal" role="status" data-testid="voice-grant-entry-failure">
          {failure}
        </p>
      )}
      <button
        type="button"
        className="kr-voice__start"
        onClick={allow}
        disabled={busy || !changed || sessions.length === 0}
        data-testid="voice-grant-entry-allow"
      >
        {busy ? 'Changing…' : 'Change what voice may do'}
      </button>
    </section>
  )
}
