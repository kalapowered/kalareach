/**
 * Creating a session on the host, with its shell chosen before it exists.
 *
 * Section 7 gives a session one of two shells. A managed shell is the host's qualified package: at
 * an empty prompt Ctrl-D detaches the view instead of ending the shell, a launch button starts an
 * agent at the prompt through the shell's own editor, and the host reads that editor, so it knows
 * when the prompt is empty. A stock shell is the system's own, chosen explicitly for compatibility:
 * it keeps everything else and claims none of those three. The difference is shown here, side by
 * side, before anything is created, and again in the session's status.
 *
 * A managed shell the host cannot qualify is refused with the host's reason. The page never creates
 * a stock shell in its place: choosing one from that refusal chooses it, and the person creates it.
 */

import { useEffect, useId, useState, type ReactNode } from 'react'

import type { HostInfoResult, SessionCreateParams } from '@kalareach/protocol'

import { Banner, Button, Sheet } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage, watch } from '../host/port'
import { ask } from '../mobile/model/call'
import { answeredState, outcomeMessage } from '../model/receipts'

/** The two shells a session can run. */
export type ShellMode = SessionCreateParams['shell_mode']

/** What each shell does where the two differ, and what both keep, in the person's words. */
export const SHELL_DIFFERENCE: readonly {
  readonly what: string
  readonly managed: string
  readonly stock: string
}[] = [
  {
    what: 'Ctrl-D at an empty prompt',
    managed: 'Detaches this view, and the session keeps running',
    stock: 'Does what the shell does, and can close the session'
  },
  {
    what: 'Launch buttons',
    managed: 'Start the agent at the prompt for you',
    stock: 'Show the command for you to type'
  },
  {
    what: 'The shell’s editor',
    managed: 'Read, so the host knows when the prompt is empty',
    stock: 'Not read'
  }
]

/** What both shells keep. */
export const SHELL_COMMON =
  'Attaching, detaching and closing, file transfer, agents you start, and the terminal. Detach is always there.'

/** Why a creation did not happen, in the host's words. */
interface Refusal {
  readonly title: string
  readonly detail: string
  /** Whether the host refused a managed shell it could not qualify. */
  readonly unqualified: boolean
}

/** The host's refusal of a managed shell it has no qualified package for. */
const UNQUALIFIED = 'SHELL_INTEGRATION_UNSUPPORTED'

/** The sheet that creates a session. */
export function NewSession({
  open,
  onClose
}: {
  readonly open: boolean
  readonly onClose: () => void
}): ReactNode {
  const { port, go, say } = useApp()
  const [directory, setDirectory] = useState('')
  const [mode, setMode] = useState<ShellMode>('managed')
  const [host, setHost] = useState<HostInfoResult | null>(null)
  const [unread, setUnread] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [refusal, setRefusal] = useState<Refusal | null>(null)
  const field = useId()

  // What the host creates by default and in which environment, read each time the sheet opens.
  useEffect(() => {
    if (!open) return
    const reads = watch([], () => {
      const current = reads.read()
      if (current === null) return
      ask(() => port.hostInfo())
        .then((info) => {
          if (!current()) return
          setHost(info)
          setUnread(null)
        })
        .catch((error: unknown) => {
          if (!current()) return
          setUnread(failureMessage(error))
        })
    })
    return reads.stop
  }, [open, port])

  const cwd = directory.trim()
  const ready = host !== null && cwd.length > 0 && !creating

  const create = () => {
    if (host === null || cwd.length === 0) return
    const params: SessionCreateParams = {
      environment_id: host.environment_id,
      // The session is shown here, so the host opens no terminal window of its own for it.
      presentation: 'invisible',
      shell: null,
      shell_mode: mode,
      cwd,
      dimensions: null,
      worker_profile: host.default_worker_profile,
      // None of this device's environment is sent: the host decides what the session starts with.
      environment_snapshot: [],
      palette: null,
      launch_profile: {
        startup: 'host_default',
        // A stock shell has no fenced launch to allow.
        fenced_launch: mode === 'managed',
        command_integrations: []
      },
      terminal: null
    }
    setCreating(true)
    setRefusal(null)
    port
      .sessionCreate(params, {})
      .then((answer) => {
        const created = answer.value?.session ?? null
        if (answeredState(answer) !== 'applied' || created === null) {
          setRefusal({
            title: 'The session was not created',
            detail: outcomeMessage('Created', answer),
            unqualified: false
          })
          return
        }
        onClose()
        setDirectory('')
        say(`Session ${created.display_number} started in ${created.cwd}.`, 'success')
        go({ view: 'session', sessionId: created.session_id, pane: 'semantic' })
      })
      .catch((error: unknown) => {
        const unqualified =
          mode === 'managed' &&
          typeof error === 'object' &&
          error !== null &&
          (error as { code?: unknown }).code === UNQUALIFIED
        setRefusal({
          title: unqualified ? 'This host has no managed shell to start' : 'The session was not created',
          detail: failureMessage(error),
          unqualified
        })
      })
      .finally(() => {
        setCreating(false)
      })
  }

  return (
    <Sheet
      open={open}
      title="New session"
      description="It starts on this host, in the directory you name, and keeps running when this window closes."
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button tone="primary" disabled={!ready} onClick={create} aria-busy={creating}>
            Create session
          </Button>
        </>
      }
    >
      <div className="new-session" data-testid="new-session">
        {unread !== null ? (
          <Banner tone="warning" title="This host is not answering" detail={unread} />
        ) : null}
        {refusal !== null ? (
          <Banner
            tone="danger"
            title={refusal.title}
            detail={refusal.detail}
            action={
              refusal.unqualified ? (
                <Button
                  onClick={() => {
                    setMode('native_compat')
                    setRefusal(null)
                  }}
                >
                  Choose a stock shell
                </Button>
              ) : undefined
            }
          />
        ) : null}

        <div className="form-field">
          <label htmlFor={`${field}-directory`}>Directory</label>
          <input
            id={`${field}-directory`}
            type="text"
            value={directory}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            placeholder="/Users/you/work/project"
            aria-describedby={`${field}-hint`}
            onChange={(event) => {
              setDirectory(event.target.value)
            }}
          />
          <span className="form-hint" id={`${field}-hint`}>
            Where the shell starts: a directory on this host.
          </span>
        </div>

        <fieldset className="settings-group shell-choice">
          <legend>Shell</legend>
          <label className="choice-row">
            <input
              type="radio"
              name={`${field}-shell`}
              value="managed"
              checked={mode === 'managed'}
              onChange={() => {
                setMode('managed')
              }}
            />
            <span>
              Managed shell
              <span className="small faint"> · the host’s qualified shell, recommended</span>
            </span>
          </label>
          <label className="choice-row">
            <input
              type="radio"
              name={`${field}-shell`}
              value="native_compat"
              checked={mode === 'native_compat'}
              onChange={() => {
                setMode('native_compat')
              }}
            />
            <span>
              Stock shell
              <span className="small faint"> · the system’s own shell, for compatibility</span>
            </span>
          </label>
        </fieldset>

        <ShellDifference chosen={mode} />
      </div>
    </Sheet>
  )
}

/** The two shells side by side, the chosen one marked. */
export function ShellDifference({ chosen }: { readonly chosen: ShellMode }): ReactNode {
  return (
    <div className="shell-difference" data-testid="shell-difference" data-chosen={chosen}>
      <table>
        <caption className="visually-hidden">What each shell does</caption>
        <thead>
          <tr>
            <td />
            <th scope="col" data-mode="managed">
              Managed shell
            </th>
            <th scope="col" data-mode="native_compat">
              Stock shell
            </th>
          </tr>
        </thead>
        <tbody>
          {SHELL_DIFFERENCE.map((row) => (
            <tr key={row.what}>
              <th scope="row">{row.what}</th>
              <td data-mode="managed">{row.managed}</td>
              <td data-mode="native_compat">{row.stock}</td>
            </tr>
          ))}
          <tr>
            <th scope="row">Both</th>
            <td colSpan={2}>{SHELL_COMMON}</td>
          </tr>
        </tbody>
      </table>
    </div>
  )
}
