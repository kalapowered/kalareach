/**
 * What voice may do, for a person who already allowed it: the one place to add an action that
 * takes a confirmation on the unlocked screen to what a call may ask the host for.
 *
 * The first-use step grants the default scope and nothing more, so a person who allowed voice then
 * has no way to say a spoken close is welcome. This entry reads the standing grant from the host,
 * shows the actions a person may add in the protocol's own sentences, and changes only what it
 * shows: allowing sends the standing grant's other actions and its sessions as they stand, with
 * the one action the person ticked or cleared changed. A replacement ends the calls that ran under
 * the grant it replaces, so the host's answer says which workers have not yet held the fence it
 * owed, and so does this.
 *
 * What is shown is bound to the host it was read from: the change is sent for that host's
 * environment, and is not sent when the grant has changed or the host is another by the time the
 * person presses.
 *
 * It is offered only while a spoken request can reach the host at all: a person is not asked to
 * allow what cannot happen.
 */

import { useEffect, useId, useState, type ReactNode } from 'react'

import type { VoiceAction } from '@kalareach/protocol'

import type { HostPort, VoiceAllowed, VoiceScopeAction } from '../host/port'
import { failureMessage } from '../host/port'
import { FENCE_UNREADABLE_WORDS, toConfirmOfFence, toConfirmWords } from './model'

/** The standing grant as the host stated it, and the host it was read from. */
interface Standing {
  /** What the grant permits now. */
  readonly actions: readonly VoiceAction[]
  /** The sessions the grant covers, whichever session this screen was opened for. */
  readonly sessions: readonly string[]
  /** The actions a person may add, in the sentences that state them. */
  readonly offered: readonly VoiceScopeAction[]
  /** The environment of the host this was read from. */
  readonly environmentId: string
}

/**
 * Reads what may be added to the grant and, when something may, the standing grant from one host:
 * the connection is the same one before and after the read, or nothing is returned.
 */
async function readStanding(port: HostPort): Promise<Standing | null> {
  // Nothing of the host is asked while there is nothing to offer: the scope of what may be added is
  // this device's own, and is empty while no spoken request reaches the host.
  const scope = await port.voiceScope()
  if (scope.optional.length === 0) return null
  const before = await port.connectionState()
  const prepared = await port.voicePrepare({ session_ids: [], selected: [] })
  const after = await port.connectionState()
  if (
    !before.connected ||
    !after.connected ||
    before.environment_id === null ||
    before.environment_id !== after.environment_id
  ) {
    return null
  }
  return {
    actions: prepared.statement.actions,
    sessions: prepared.session_ids,
    offered: scope.optional,
    environmentId: after.environment_id
  }
}

/** Whether two readings of the standing grant say the same of the same host. */
function same(a: Standing, b: Standing): boolean {
  const sorted = (values: readonly string[]) => [...values].sort().join('\u0000')
  return (
    a.environmentId === b.environmentId &&
    sorted(a.actions) === sorted(b.actions) &&
    sorted(a.sessions) === sorted(b.sessions)
  )
}

/** The entry. `sessionNames` is how the host names each session, where it said. */
export function VoiceGrantEntry({
  port,
  sessionNames,
  onChanged
}: {
  readonly port: HostPort
  /** How the host names each session, where it said. */
  readonly sessionNames: Readonly<Record<string, string>>
  /** Called once the host has written the new grant, so the screen reads what a call would be. */
  readonly onChanged: () => void
}): ReactNode {
  const id = useId()
  const [standing, setStanding] = useState<Standing | null>(null)
  /** What the person changed from what the host says the grant permits: an action and whether it is wanted. */
  const [edits, setEdits] = useState<ReadonlyMap<VoiceAction, boolean>>(new Map())
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [result, setResult] = useState<VoiceAllowed | null>(null)
  /** Counts the readings asked for, so that the grant is read again once it changed. */
  const [reading, setReading] = useState(0)

  useEffect(() => {
    let current = true
    readStanding(port).then(
      (read) => {
        if (current) setStanding(read)
      },
      () => {
        // A grant that cannot be read offers nothing.
        if (current) setStanding(null)
      }
    )
    return () => {
      current = false
    }
  }, [port, reading])

  if (standing === null || standing.offered.length === 0) return null

  // The boxes show what the host says the grant permits, with what the person changed over it.
  const permitted = (action: VoiceAction) => edits.get(action) ?? standing.actions.includes(action)
  const changed = standing.offered.some(
    (each) => permitted(each.action) !== standing.actions.includes(each.action)
  )
  const offeredActions = new Set(standing.offered.map((each) => each.action))

  const allow = () => {
    if (busy || !changed || standing.sessions.length === 0) return
    setBusy(true)
    setFailure(null)
    setResult(null)
    void (async () => {
      try {
        // What is shown is what is sent a change to: the grant is read once more, and a change of
        // the grant or of the host since it was shown is not sent over.
        const now = await readStanding(port)
        if (now === null || !same(now, standing)) {
          setFailure('What voice may do has changed since this was shown. It is shown again: check it, then change it.')
          setReading((count) => count + 1)
          setEdits(new Map())
          return
        }
        // Every action of the grant the person did not tick or clear stays as it is.
        const actions = [
          ...standing.actions.filter((action) => !offeredActions.has(action)),
          ...standing.offered.map((each) => each.action).filter(permitted)
        ]
        const settled = await port.voiceAllow(
          { sessionIds: standing.sessions, actions, environmentId: standing.environmentId },
          {}
        )
        // An answer with no result is a host that did not confirm: the grant may or may not stand.
        if (!settled.value) {
          setFailure('The host did not confirm the change. Allow it again to be sure.')
          return
        }
        setResult(settled.value)
        // The grant is what the host now says it is, which the screen reads again.
        setEdits(new Map())
        setReading((count) => count + 1)
        onChanged()
      } catch (error: unknown) {
        setFailure(failureMessage(error))
      } finally {
        setBusy(false)
      }
    })()
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
        {standing.offered.map((each) => (
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
        disabled={busy || !changed || standing.sessions.length === 0}
        data-testid="voice-grant-entry-allow"
      >
        {busy ? 'Changing…' : 'Change what voice may do'}
      </button>
    </section>
  )
}
