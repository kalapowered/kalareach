/**
 * Deleting the account: the step the Account panel opens, from what it would do to the result.
 *
 * Five things happen, in order, and a person can leave before the fourth. They read what deleting
 * removes and what stays; the service emails a code to the account's own address; they type it and
 * confirm; and the result says the account is closed and then that the removal is done. The code is
 * the confirmation, so there is no second "are you sure": an account that owns an organisation is
 * the one place a second explicit step is asked for, because the service asks for it.
 *
 * The step replaces the panel's cards while it is open and the cards stay where they were, so
 * cancelling puts back exactly what was there. A change of step fades in over the existing state
 * duration with no travel, which reduced motion needs no second version of. Nothing here spins:
 * while the service works, the words say what is happening and the status is marked busy.
 *
 * The page never holds a token, the address the code goes to or the receipt that settles a lost
 * answer. It holds the code the person typed for as long as the step is open, and the organisations
 * they accepted losing.
 */

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react'

import { failureMessage, type HostPort } from '../host/port'
import { minimumTarget, type Surface } from '../mobile/platform'
import type { AccountView } from '../model/account'
import {
  ACKNOWLEDGED_MAXIMUM,
  ACKNOWLEDGE_LINE,
  CANNOT_SHOW_LINE,
  CODE_DIGITS,
  DEVICE_LINE,
  MONEY_LINES,
  NOT_DONE_LINE,
  POLICY_LINE,
  RESULT_CLOSED,
  RESULT_DONE,
  RESULT_FINISHING,
  RESULT_NO_EMAIL,
  RESULT_STILL,
  STATUS_EVERY_MS,
  STATUS_FOR_MS,
  STILL_UNKNOWN_LINE,
  TOO_MANY_ORGANISATIONS_LINE,
  UNLISTED_LINE,
  UNSETTLED_LINE,
  describeBackupFiles,
  describeCodeSent,
  describeDeleted,
  describeKept,
  describeProblem,
  describeRefusal,
  describeWarning,
  digitsOf,
  type CodeRefusal,
  type DeletionPreview,
  type DeletionProblem,
  type OwnedOrganisation,
  type Stage
} from '../model/deletion'
import { Button, Card } from './ui'

/** Where the step stands. */
export type DeletionStep =
  | { readonly name: 'idle' }
  | { readonly name: 'reading' }
  | { readonly name: 'failed' }
  | { readonly name: 'cannot_show' }
  | { readonly name: 'read' }
  | { readonly name: 'sending' }
  | { readonly name: 'code' }
  | { readonly name: 'confirming' }
  | { readonly name: 'acknowledge'; readonly organisations: readonly OwnedOrganisation[] }
  | { readonly name: 'unsettled' }
  | { readonly name: 'notdone' }
  | { readonly name: 'result'; readonly progress: 'open' | 'done' | 'still' }

/** The steps a person can still walk away from: nothing has been sent that cannot be taken back. */
const LEAVABLE: readonly DeletionStep['name'][] = [
  'reading',
  'failed',
  'cannot_show',
  'read',
  'sending',
  'code',
  'acknowledge',
  'notdone'
]

/** The line a step shows under its words: a step that could not be taken, or this device's own failure. */
type Said =
  | { readonly problem: DeletionProblem; readonly stage: Stage }
  | { readonly text: string }

/** The grant a view says is signed in, or null. */
function generationOf(view: AccountView | null): string | null {
  return view?.state === 'signed_in' ? view.generation : null
}

/** The step, and what drives it. */
export interface DeletionFlow {
  readonly step: DeletionStep
  readonly open: boolean
  readonly preview: DeletionPreview | null
  readonly code: string
  /** Whether the code is known to have been sent, or may have been. */
  readonly codeSure: boolean
  /** Whether a look at how the deletion stands is out. */
  readonly checking: boolean
  readonly refusal: { readonly reason: CodeRefusal; readonly attemptsLeft: number } | null
  readonly said: Said | null
  readonly begin: () => void
  readonly cancel: () => void
  readonly setCode: (text: string) => void
  readonly sendCode: () => void
  readonly confirm: () => void
  readonly acknowledgeAll: () => void
  readonly back: () => void
  readonly checkAgain: () => void
  readonly finish: () => void
}

/**
 * Drives the step. A step that asks the backend something remembers which ask it was, so an answer
 * that arrives after the person left, or after they asked again, is not shown.
 */
export function useDeletion(port: HostPort, view: AccountView | null): DeletionFlow {
  const [step, setStep] = useState<DeletionStep>({ name: 'idle' })
  const [preview, setPreview] = useState<DeletionPreview | null>(null)
  const [code, setCodeText] = useState('')
  const [codeSure, setCodeSure] = useState(true)
  const [checking, setChecking] = useState(false)
  const [refusal, setRefusal] = useState<DeletionFlow['refusal']>(null)
  const [said, setSaid] = useState<Said | null>(null)
  const ask = useRef(0)
  // Whether a confirmation has left without an answer that says whether it went through: what
  // happens after that is not "nothing changed".
  const unresolved = useRef(false)
  const startedWith = useRef<string | null>(null)
  const accepted = useRef<readonly string[]>([])
  // Where the step stands, as the callbacks see it: every change of step goes through `next`.
  const current = useRef<DeletionStep>(step)

  const next = useCallback((to: DeletionStep) => {
    current.current = to
    setStep(to)
  }, [])

  const problemOf = useCallback((problem: DeletionProblem, stage: Stage = 'before') => {
    setSaid({ problem, stage })
  }, [])

  /** Where a failure leaves the person: with the code, or, if a confirmation is unresolved, still at the unsettled step. */
  const failedAt = useCallback((): DeletionStep => {
    return unresolved.current ? { name: 'unsettled' } : { name: 'code' }
  }, [])

  const failure = useCallback((error: unknown) => {
    // A failure of this device's own records, in the backend's words.
    setSaid({ text: failureMessage(error) })
  }, [])

  const begin = useCallback(() => {
    const mine = (ask.current += 1)
    startedWith.current = generationOf(view)
    accepted.current = []
    unresolved.current = false
    setChecking(false)
    setCodeSure(true)
    setPreview(null)
    setCodeText('')
    setRefusal(null)
    setSaid(null)
    next({ name: 'reading' })
    port
      .accountDeletionView()
      .then((answer) => {
        if (ask.current !== mine) return
        if (answer.state === 'ready') {
          setPreview(answer.preview)
          next({ name: 'read' })
        } else if (answer.state === 'cannot_show') {
          next({ name: 'cannot_show' })
        } else {
          problemOf(answer.problem)
          next({ name: 'failed' })
        }
      })
      .catch((error: unknown) => {
        if (ask.current !== mine) return
        failure(error)
        next({ name: 'failed' })
      })
  }, [failure, next, port, problemOf, view])

  const cancel = useCallback(() => {
    ask.current += 1
    startedWith.current = null
    unresolved.current = false
    setChecking(false)
    setCodeText('')
    setRefusal(null)
    setSaid(null)
    next({ name: 'idle' })
  }, [next])

  const setCode = useCallback((text: string) => {
    setCodeText(digitsOf(text))
  }, [])

  const sendCode = useCallback(() => {
    const mine = (ask.current += 1)
    const from = current.current
    setSaid(null)
    next({ name: 'sending' })
    port
      .accountDeletionSendCode()
      .then((answer) => {
        if (ask.current !== mine) return
        if (answer.state === 'sent') {
          setRefusal(null)
          setCodeSure(true)
          next({ name: 'code' })
          return
        }
        problemOf(answer.problem)
        setCodeSure(answer.problem.kind !== 'unsure')
        // An email that may have been sent is waited for at the field; any other failure leaves
        // the person where they were.
        next(answer.problem.kind === 'unsure' ? { name: 'code' } : from.name === 'code' ? from : { name: 'read' })
      })
      .catch((error: unknown) => {
        if (ask.current !== mine) return
        failure(error)
        next(from.name === 'code' ? from : { name: 'read' })
      })
  }, [failure, next, port, problemOf])

  const send = useCallback(
    (typed: string, accept: readonly string[]) => {
      if (accept.length > ACKNOWLEDGED_MAXIMUM) {
        setSaid({ text: TOO_MANY_ORGANISATIONS_LINE })
        next({ name: 'code' })
        return
      }
      const mine = (ask.current += 1)
      accepted.current = accept
      setSaid(null)
      setRefusal(null)
      next({ name: 'confirming' })
      port
        .accountDeletionConfirm(typed, accept)
        .then((answer) => {
          if (ask.current !== mine) return
          switch (answer.state) {
            case 'closed':
              unresolved.current = false
              next({ name: 'result', progress: answer.finished ? 'done' : 'open' })
              return
            case 'code_refused':
              unresolved.current = false
              setRefusal({ reason: answer.reason, attemptsLeft: answer.attempts_left })
              setCodeText('')
              next({ name: 'code' })
              return
            case 'acknowledge':
              unresolved.current = false
              next({ name: 'acknowledge', organisations: answer.organisations })
              return
            case 'unsettled':
              unresolved.current = true
              next({ name: 'unsettled' })
              return
            case 'problem':
              problemOf(answer.problem, unresolved.current ? 'unknown' : 'before')
              next(failedAt())
          }
        })
        .catch((error: unknown) => {
          if (ask.current !== mine) return
          failure(error)
          next(failedAt())
        })
    },
    [failedAt, failure, next, port, problemOf]
  )

  const confirm = useCallback(() => {
    if (code.length === CODE_DIGITS) send(code, accepted.current)
  }, [code, send])

  const acknowledgeAll = useCallback(() => {
    const now = current.current
    if (now.name !== 'acknowledge') return
    send(
      code,
      now.organisations.map((each) => each.organisation_id)
    )
  }, [code, send])

  const back = useCallback(() => {
    ask.current += 1
    next({ name: 'code' })
  }, [next])

  // One look at how the deletion stands, from the unsettled step. A person presses it once and
  // waits for it: Try again is not offered while it is out, because the two together would send a
  // confirmation while the look decides whether one is still running.
  const checkAgain = useCallback(() => {
    if (checking) return
    const mine = ask.current
    setChecking(true)
    port
      .accountDeletionStatus()
      .then((answer) => {
        setChecking(false)
        if (ask.current !== mine) return
        const stage = current.current.name === 'result' ? 'after' : 'unknown'
        if (answer.state === 'problem') {
          problemOf(answer.problem, stage)
        } else if (answer.state === 'open' || answer.state === 'done') {
          unresolved.current = false
          setSaid(null)
          next({ name: 'result', progress: answer.state })
        } else if (answer.state === 'none') {
          unresolved.current = false
          setSaid(null)
          next({ name: 'notdone' })
        } else {
          setSaid({ text: STILL_UNKNOWN_LINE })
        }
      })
      .catch(() => {
        setChecking(false)
        if (ask.current === mine) problemOf({ kind: 'unreachable' }, 'unknown')
      })
  }, [checking, next, port, problemOf])

  const finish = useCallback(() => {
    ask.current += 1
    startedWith.current = null
    unresolved.current = false
    setChecking(false)
    setCodeText('')
    setSaid(null)
    next({ name: 'idle' })
  }, [next])

  // A look when the panel opens, and again when the account changes under it: a deletion that was
  // under way when the application last ran is shown as the result it is, and a confirmation that
  // is still out, or whose answer is not known, is shown as that. Only when nothing else has begun.
  const standing = view === null ? null : view.state === 'signed_in' ? view.generation : view.state
  useEffect(() => {
    let live = true
    port
      .accountDeletionStatus()
      .then((answer) => {
        if (!live || current.current.name !== 'idle') return
        if (answer.state === 'open' || answer.state === 'done') {
          next({ name: 'result', progress: answer.state })
        } else if (answer.state === 'unsettled') {
          unresolved.current = true
          next({ name: 'unsettled' })
        }
      })
      .catch(() => undefined)
    return () => {
      live = false
    }
  }, [next, port, standing])

  // The sign-in the step began under is the one it goes on under: a different sign-in, or none,
  // ends it before a code is sent, and never while a confirmation is out or after the account is
  // closed, because the backend signs the device out before it answers.
  const generation = generationOf(view)
  useEffect(() => {
    if (!LEAVABLE.includes(step.name)) return
    // A step that began without the person asking for it (what an unsettled confirmation came to)
    // is under the sign-in it was first seen under.
    if (startedWith.current === null && generation !== null) {
      startedWith.current = generation
      return
    }
    if (generation === null || generation !== startedWith.current) {
      startedWith.current = null
      ask.current += 1
      setCodeText('')
      setRefusal(null)
      setSaid(null)
      next({ name: 'idle' })
    }
  }, [generation, next, step.name])

  // The result asks how the removal goes until it is done, for about two minutes, and then says it
  // is still finishing; the next time the panel opens it asks again.
  const progress = step.name === 'result' ? step.progress : null
  useEffect(() => {
    if (progress !== 'open') return
    const began = Date.now()
    let timer: ReturnType<typeof setTimeout> | undefined
    let live = true
    const look = () => {
      port
        .accountDeletionStatus()
        .then((answer) => {
          if (!live) return
          if (answer.state === 'done') {
            next({ name: 'result', progress: 'done' })
            return
          }
          if (Date.now() - began >= STATUS_FOR_MS) {
            next({ name: 'result', progress: 'still' })
            return
          }
          const wait =
            answer.state === 'problem' && answer.problem.kind === 'busy'
              ? Math.max(STATUS_EVERY_MS, answer.problem.seconds * 1000)
              : STATUS_EVERY_MS
          timer = setTimeout(look, wait)
        })
        .catch(() => {
          if (!live) return
          if (Date.now() - began >= STATUS_FOR_MS) {
            next({ name: 'result', progress: 'still' })
            return
          }
          timer = setTimeout(look, STATUS_EVERY_MS)
        })
    }
    timer = setTimeout(look, STATUS_EVERY_MS)
    return () => {
      live = false
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [next, port, progress])

  // An unsettled confirmation is looked at again by itself for about two minutes, since by then
  // nothing can still be running: it ends as the closed account, or as a deletion that did not go
  // through. After that the person's own Check again is what is left.
  const unsettled = step.name === 'unsettled'
  useEffect(() => {
    if (!unsettled) return
    const began = Date.now()
    let timer: ReturnType<typeof setTimeout> | undefined
    let live = true
    const look = () => {
      port
        .accountDeletionStatus()
        .then((answer) => {
          if (!live) return
          if (answer.state === 'open' || answer.state === 'done') {
            unresolved.current = false
            setSaid(null)
            next({ name: 'result', progress: answer.state })
            return
          }
          if (answer.state === 'none') {
            unresolved.current = false
            setSaid(null)
            next({ name: 'notdone' })
            return
          }
          if (Date.now() - began < STATUS_FOR_MS) timer = setTimeout(look, STATUS_EVERY_MS)
        })
        .catch(() => {
          if (live && Date.now() - began < STATUS_FOR_MS) timer = setTimeout(look, STATUS_EVERY_MS)
        })
    }
    timer = setTimeout(look, STATUS_EVERY_MS)
    return () => {
      live = false
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [next, port, unsettled])

  return {
    step,
    open: step.name !== 'idle',
    preview,
    code,
    codeSure,
    checking,
    refusal,
    said,
    begin,
    cancel,
    setCode,
    sendCode,
    confirm,
    acknowledgeAll,
    back,
    checkAgain,
    finish
  }
}

/** The step. */
export function DeleteAccount({
  flow,
  surface
}: {
  readonly flow: DeletionFlow
  readonly surface: Surface
}): ReactNode {
  const { step, preview, code, codeSure, checking, refusal, said } = flow
  const target = minimumTarget(surface)
  const statusRef = useRef<HTMLDivElement | null>(null)
  const codeRef = useRef<HTMLInputElement | null>(null)
  const fieldId = useId()
  const statusId = useId()

  // Each step puts focus where the next action is: the field on the Code step, the status line on
  // every other, so a screen reader reads where things stand.
  useEffect(() => {
    if (step.name === 'code') codeRef.current?.focus()
    else statusRef.current?.focus()
  }, [step.name])

  // A refused code puts focus back in the emptied field.
  useEffect(() => {
    if (refusal !== null) codeRef.current?.focus()
  }, [refusal])

  const busy = step.name === 'reading' || step.name === 'sending' || step.name === 'confirming'
  const line =
    said === null ? null : 'text' in said ? said.text : describeProblem(said.problem, said.stage)
  const kind = said !== null && 'problem' in said ? said.problem.kind : 'local'

  const cancel = (
    <Button
      data-wraps
      data-testid="delete-account-cancel"
      style={{ minBlockSize: target }}
      onClick={flow.cancel}
    >
      Cancel
    </Button>
  )

  let lead: string
  let body: ReactNode = null
  let actions: ReactNode = null
  switch (step.name) {
    case 'reading':
      lead = 'Reading what deleting does…'
      actions = cancel
      break
    case 'failed':
      lead = 'KalaReach could not read what deleting does.'
      actions = (
        <>
          <Button
            data-wraps
            tone="primary"
            data-testid="delete-account-retry"
            style={{ minBlockSize: target }}
            onClick={flow.begin}
          >
            Try again
          </Button>
          {cancel}
        </>
      )
      break
    case 'cannot_show':
      lead = CANNOT_SHOW_LINE
      actions = cancel
      break
    case 'read':
    case 'sending':
      lead = `This deletes the account ${preview?.address ?? ''}. It cannot be undone.`
      body = preview === null ? null : <Reading preview={preview} surface={surface} />
      actions = (
        <>
          <Button
            data-wraps
            tone="primary"
            data-testid="delete-account-send-code"
            disabled={step.name === 'sending'}
            style={{ minBlockSize: target }}
            onClick={flow.sendCode}
          >
            Send code
          </Button>
          {cancel}
        </>
      )
      if (step.name === 'sending') lead = 'Sending the code…'
      break
    case 'code':
    case 'confirming':
      lead = preview === null ? '' : describeCodeSent(preview, codeSure)
      body = (
        <div className="deletion-field">
          <label className="deletion-label" htmlFor={fieldId}>
            Code from the email
          </label>
          <input
            id={fieldId}
            ref={codeRef}
            className="deletion-code"
            data-testid="delete-account-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            enterKeyHint="done"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            value={code}
            disabled={step.name === 'confirming'}
            aria-invalid={refusal === null ? undefined : true}
            aria-describedby={statusId}
            style={{ minBlockSize: target }}
            onChange={(event) => {
              flow.setCode(event.target.value)
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault()
                flow.confirm()
              }
            }}
          />
        </div>
      )
      actions = (
        <>
          <Button
            data-wraps
            data-testid="delete-account-resend"
            disabled={step.name === 'confirming'}
            style={{ minBlockSize: target }}
            onClick={flow.sendCode}
          >
            Send another code
          </Button>
          <Button
            data-wraps
            tone="danger"
            data-testid="delete-account-confirm"
            disabled={code.length !== CODE_DIGITS || step.name === 'confirming'}
            style={{ minBlockSize: target }}
            onClick={flow.confirm}
          >
            Delete account permanently
          </Button>
          {step.name === 'confirming' ? null : cancel}
        </>
      )
      if (step.name === 'confirming') lead = 'Deleting the account…'
      break
    case 'acknowledge':
      lead = ACKNOWLEDGE_LINE
      body = (
        <ul className="deletion-list" data-testid="delete-account-organisations">
          {step.organisations.map((each) => (
            <li key={each.organisation_id}>{describeWarning({ kind: 'organisation_owner', ...each })}</li>
          ))}
        </ul>
      )
      actions = (
        <>
          <Button
            data-wraps
            tone="danger"
            data-testid="delete-account-acknowledge"
            style={{ minBlockSize: target }}
            onClick={flow.acknowledgeAll}
          >
            Delete anyway
          </Button>
          <Button
            data-wraps
            data-testid="delete-account-back"
            style={{ minBlockSize: target }}
            onClick={flow.back}
          >
            Back
          </Button>
          {cancel}
        </>
      )
      break
    case 'unsettled':
      lead = UNSETTLED_LINE
      actions = (
        <>
          <Button
            data-wraps
            tone="primary"
            data-testid="delete-account-check"
            disabled={checking}
            style={{ minBlockSize: target }}
            onClick={flow.checkAgain}
          >
            Check again
          </Button>
          {code.length === CODE_DIGITS ? (
            <Button
              data-wraps
              data-testid="delete-account-again"
              disabled={checking}
              style={{ minBlockSize: target }}
              onClick={flow.confirm}
            >
              Try again
            </Button>
          ) : null}
        </>
      )
      break
    case 'notdone':
      lead = NOT_DONE_LINE
      actions = (
        <>
          <Button
            data-wraps
            tone="primary"
            data-testid="delete-account-restart"
            style={{ minBlockSize: target }}
            onClick={flow.begin}
          >
            Start again
          </Button>
          {cancel}
        </>
      )
      break
    case 'result':
      lead = step.progress === 'done' ? RESULT_DONE : RESULT_CLOSED
      body = (
        <>
          {step.progress === 'done' ? null : (
            <p className="account-note">
              {step.progress === 'still' ? RESULT_STILL : RESULT_FINISHING}
              {preview === null ? '' : ` ${describeBackupFiles(preview.backup_file_days)}`}
            </p>
          )}
          <p className="account-note">{RESULT_NO_EMAIL}</p>
        </>
      )
      actions = (
        <Button
          data-wraps
          tone="primary"
          data-testid="delete-account-done"
          style={{ minBlockSize: target }}
          onClick={flow.finish}
        >
          Done
        </Button>
      )
      break
    case 'idle':
      return null
  }

  return (
    <>
      <p className="account-section-title">Delete account</p>
      <Card data-testid="delete-account" data-step={step.name}>
        <div className="account-state" key={step.name}>
          <div
            className="account-status"
            id={statusId}
            role="status"
            tabIndex={-1}
            ref={statusRef}
            aria-busy={busy}
          >
            <p className="account-lead" data-testid="delete-account-lead">
              {lead}
            </p>
            {line === null ? null : (
              <p className="account-note" data-testid="delete-account-problem" data-kind={kind}>
                {line}
              </p>
            )}
            {refusal === null ? null : (
              <p
                className="account-note"
                data-testid="delete-account-refusal"
                data-reason={refusal.reason}
                data-left={refusal.attemptsLeft}
              >
                {describeRefusal(refusal.reason, refusal.attemptsLeft)}
              </p>
            )}
          </div>
          {body}
          <div className="account-actions">{actions}</div>
        </div>
      </Card>
    </>
  )
}

/** What deleting removes and keeps, in lists, with the money first. */
function Reading({
  preview,
  surface
}: {
  readonly preview: DeletionPreview
  readonly surface: Surface
}): ReactNode {
  const warnings = preview.warnings.map(describeWarning)
  // The sheet on a computer has its own title one level up, and a phone's screen has only the page's:
  // the headings follow whichever is above them, so no level is skipped.
  const Heading = surface === 'desktop' ? 'h3' : 'h2'
  return (
    <>
      <Heading className="deletion-heading">Before you go on</Heading>
      <ul className="deletion-list" data-testid="delete-account-before">
        {[...warnings, ...MONEY_LINES].map((text) => (
          <li key={text}>{text}</li>
        ))}
      </ul>
      <Heading className="deletion-heading">What is deleted</Heading>
      <ul className="deletion-list" data-testid="delete-account-deleted">
        {preview.deleted.map((kind) => (
          <li key={kind}>{describeDeleted(kind, preview)}</li>
        ))}
      </ul>
      <Heading className="deletion-heading">What stays</Heading>
      <ul className="deletion-list" data-testid="delete-account-kept">
        {preview.kept.map((kind) => (
          <li key={kind}>{describeKept(kind, preview)}</li>
        ))}
        {preview.unlisted ? <li>{UNLISTED_LINE}</li> : null}
        <li>{DEVICE_LINE}</li>
      </ul>
      <p className="account-note">{POLICY_LINE}</p>
    </>
  )
}

