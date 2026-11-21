/**
 * The host's saved launch commands, in Settings.
 *
 * A command is a label, a program and separate arguments; no command line is parsed, and a press
 * sends the program and the arguments as they were saved. The list is the host's and is read from
 * it. It is changed only from the local connection to the host: a paired device, and the phone,
 * look and cannot change.
 *
 * The form keeps the revision of the list the person saw when they began to edit, and a read that
 * answers while they edit does not change it. A save over a list that has moved on is a conflict:
 * nothing is saved, the person is told, and the list as it stands is shown, so a change made
 * elsewhere is never overwritten without being seen. The host is the authority on what it saves;
 * the form says what it would refuse before the host is asked, and shows the host's own words for
 * a refusal it did not foresee.
 */

import { useId, useState, type ReactNode } from 'react'

import type { NamedLaunch, ShellLaunchCommandsListResult } from '@kalareach/protocol'

import { useHeldConnection } from '../app/rights'
import { useSavedCommands } from '../app/launch-commands'
import { useApp } from '../app/state'
import { Button } from '../components/ui'
import { failureWords } from '../host/port'
import {
  changed,
  commandOf,
  foresee,
  replaced,
  replaceWarning,
  WORDS,
  type LaunchDraft
} from '../model/launch-commands'

/** Where the section is drawn: the desktop's session Settings, or the phone's. */
export type LaunchCommandsPlace = 'desktop' | 'phone'

const NOTHING: LaunchDraft = { label: '', program: '', arguments: [] }

/** Whether a command is the one a list holds under its label, as written. */
function holdsAsWritten(commands: readonly NamedLaunch[], command: NamedLaunch): boolean {
  return commands.some(
    (held) =>
      held.label === command.label &&
      held.program === command.program &&
      held.arguments.length === command.arguments.length &&
      held.arguments.every((argument, index) => argument === command.arguments[index])
  )
}

/** The launch commands section of Settings. */
export function LaunchCommands({ place }: { readonly place: LaunchCommandsPlace }): ReactNode {
  const { port, say } = useApp()
  const { rights, paired } = useHeldConnection()
  const mayRead = rights?.includes('host.manage') === true
  const { saved, again, adopt } = useSavedCommands(port, mayRead)
  const nameId = useId()
  const programId = useId()
  const [draft, setDraft] = useState<LaunchDraft>(NOTHING)
  // The revision of the list the person saw when they began to edit; a read that answers while
  // they edit does not change it. Null while nothing is being edited.
  const [editingFrom, setEditingFrom] = useState<string | null>(null)
  const [attempted, setAttempted] = useState(false)
  const [busy, setBusy] = useState(false)
  // What the last save or remove came to, beside the form, until the next one is tried.
  const [outcome, setOutcome] = useState<{
    readonly kind: 'conflict' | 'unconfirmed' | 'refused'
    readonly words: string
  } | null>(null)

  const list = saved.state === 'served' ? saved.list : null
  const editable = place === 'desktop' && !paired && list !== null

  const edit = (next: LaunchDraft) => {
    if (editingFrom === null && list !== null) setEditingFrom(list.revision)
    setDraft(next)
    setOutcome(null)
  }

  const finished = (after: ShellLaunchCommandsListResult) => {
    adopt(after)
    setEditingFrom(null)
  }

  const save = () => {
    if (list === null || busy) return
    const problem = foresee(draft, list.commands)
    setAttempted(true)
    setOutcome(null)
    if (problem !== null) return
    const command = commandOf(draft)
    setBusy(true)
    port
      .launchCommandSave({ expected_revision: editingFrom ?? list.revision, command })
      .then(
        (settled) => {
          const result = settled.value
          if (result === null) {
            // The answer was lost or the host could not say: the list is read again, and the
            // person looks at it.
            setOutcome({ kind: 'unconfirmed', words: WORDS.unconfirmed })
            again()
            return
          }
          const after = { revision: result.revision, commands: result.commands }
          if (result.applied) {
            say(
              changed(
                !result.changed ? 'already' : result.replaced ? 'replaced' : 'saved',
                command.label
              ),
              'success'
            )
            finished(after)
            setDraft(NOTHING)
            setAttempted(false)
          } else if (holdsAsWritten(result.commands, command)) {
            // The list moved on, and already holds this command as written.
            say(changed('already', command.label), 'success')
            finished(after)
            setDraft(NOTHING)
            setAttempted(false)
          } else {
            setOutcome({ kind: 'conflict', words: WORDS.conflict })
            finished(after)
          }
        },
        (failure: unknown) => {
          // A refusal the form did not foresee: the host's words, and nothing was saved.
          setOutcome({ kind: 'refused', words: failureWords(failure) })
        }
      )
      .finally(() => {
        setBusy(false)
      })
  }

  const remove = (label: string) => {
    if (list === null || busy) return
    setOutcome(null)
    setBusy(true)
    port
      .launchCommandRemove({ expected_revision: list.revision, label })
      .then(
        (settled) => {
          const result = settled.value
          if (result === null) {
            setOutcome({ kind: 'unconfirmed', words: WORDS.unconfirmed })
            again()
            return
          }
          const after = { revision: result.revision, commands: result.commands }
          if (result.applied) {
            say(changed(result.removed ? 'removed' : 'absent', label), 'success')
            adopt(after)
          } else if (replaced(label, result.commands) === null) {
            // The host compares labels in lower case, as `replaced` does.
            say(changed('absent', label), 'success')
            adopt(after)
          } else {
            setOutcome({ kind: 'conflict', words: WORDS.conflict })
            adopt(after)
          }
        },
        (failure: unknown) => {
          setOutcome({ kind: 'refused', words: failureWords(failure) })
        }
      )
      .finally(() => {
        setBusy(false)
      })
  }

  const problem = list === null ? null : foresee(draft, list.commands)
  // A field left empty is said only once a save is tried; a character or size the host refuses is
  // said as it is typed.
  const feedback = problem === null || (problem.kind === 'needed' && !attempted) ? null : problem
  const replacing = list === null ? null : replaced(draft.label, list.commands)

  return (
    <section data-testid="launch-commands">
      <h2>{WORDS.section}</h2>
      <p data-testid="launch-commands-whose">
        {WORDS.whose} {WORDS.secret}
      </p>
      {editable ? (
        <>
          <p className="muted" data-testid="launch-commands-press">
            {WORDS.press} {WORDS.shell}
          </p>
          <p className="muted" data-testid="launch-commands-passed">
            {WORDS.passed}
          </p>
          <p className="muted" data-testid="launch-commands-batch">
            {WORDS.batch}
          </p>
        </>
      ) : saved.state === 'unread' || saved.state === 'served' ? (
        <p className="muted" data-testid="launch-commands-local-only">
          {WORDS.localOnly}
        </p>
      ) : null}

      {saved.state === 'not_served' ? (
        <p className="muted" data-testid="launch-commands-not-served">
          {WORDS.notServed}
        </p>
      ) : saved.state === 'refused' || (rights !== null && !mayRead) ? (
        <p className="muted" data-testid="launch-commands-refused">
          {WORDS.refused}
        </p>
      ) : saved.state === 'failed' ? (
        <p className="muted" data-testid="launch-commands-unread">
          {WORDS.unread}
        </p>
      ) : saved.state === 'served' ? (
        <>
          {saved.unread !== null ? (
            <p className="muted" data-testid="launch-commands-unread">
              {WORDS.unread}
            </p>
          ) : null}
          {saved.list.commands.length === 0 ? (
            <p className="muted" data-testid="launch-commands-none">
              {WORDS.none}
            </p>
          ) : (
            <ul className="settings-list" data-testid="launch-commands-list">
              {saved.list.commands.map((command) => (
                <li key={command.label} data-label={command.label} className="settings-row">
                  <div>
                    <h3>{command.label}</h3>
                    <p className="mono small">
                      {[command.program, ...command.arguments]
                        .map((word) => JSON.stringify(word))
                        .join(' ')}
                    </p>
                  </div>
                  {editable ? (
                    <Button
                      data-testid="launch-commands-remove"
                      aria-label={`Remove ${command.label}`}
                      disabled={busy}
                      onClick={() => {
                        remove(command.label)
                      }}
                    >
                      Remove
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </>
      ) : null}

      {editable ? (
        <form
          className="form-field"
          data-testid="launch-commands-form"
          onSubmit={(event) => {
            event.preventDefault()
            save()
          }}
        >
          <label htmlFor={nameId}>Name</label>
          <input
            id={nameId}
            data-testid="launch-commands-name"
            value={draft.label}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            onChange={(event) => {
              edit({ ...draft, label: event.target.value })
            }}
          />
          <label htmlFor={programId}>Program</label>
          <input
            id={programId}
            data-testid="launch-commands-program"
            value={draft.program}
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            onChange={(event) => {
              edit({ ...draft, program: event.target.value })
            }}
          />
          <fieldset>
            <legend>Arguments</legend>
            {draft.arguments.map((argument, index) => (
              <div className="row" key={index}>
                <input
                  data-testid="launch-commands-argument"
                  data-index={index}
                  aria-label={`Argument ${index + 1}`}
                  value={argument}
                  autoCapitalize="off"
                  autoCorrect="off"
                  spellCheck={false}
                  onChange={(event) => {
                    edit({
                      ...draft,
                      arguments: draft.arguments.map((each, at) =>
                        at === index ? event.target.value : each
                      )
                    })
                  }}
                />
                <Button
                  data-testid="launch-commands-remove-argument"
                  aria-label={`Remove argument ${index + 1}`}
                  onClick={() => {
                    edit({
                      ...draft,
                      arguments: draft.arguments.filter((_, at) => at !== index)
                    })
                  }}
                >
                  Remove argument
                </Button>
              </div>
            ))}
            <Button
              data-testid="launch-commands-add-argument"
              onClick={() => {
                edit({ ...draft, arguments: [...draft.arguments, ''] })
              }}
            >
              Add argument
            </Button>
          </fieldset>
          <div data-testid="launch-commands-preview">
            <p className="small faint">{WORDS.preview}</p>
            <ul className="mono small">
              {[draft.program, ...draft.arguments].map((word, index) => (
                <li key={index}>{`"${word}"`}</li>
              ))}
            </ul>
          </div>
          {replacing !== null ? (
            <p className="small warning-text" data-testid="launch-commands-replaces">
              {replaceWarning(replacing.label)}
            </p>
          ) : null}
          {feedback !== null ? (
            <p className="small warning-text" role="alert" data-testid="launch-commands-feedback">
              {feedback.words}
            </p>
          ) : null}
          {outcome !== null ? (
            <p
              className="small warning-text"
              role="alert"
              data-testid={`launch-commands-${outcome.kind}`}
            >
              {outcome.words}
            </p>
          ) : null}
          <Button data-testid="launch-commands-save" type="submit" disabled={busy}>
            Save
          </Button>
        </form>
      ) : null}
    </section>
  )
}
