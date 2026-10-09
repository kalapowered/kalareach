/**
 * The questions an agent is waiting on a person for, and the answers kept while the worker could
 * not be reached.
 *
 * A question is the worker's. The identity above it is the program the worker verified, and the
 * name the program gave itself is shown beside it as the program's own, unverified. An answer is
 * sent only on a completed press, and it names the revision the person was shown: a question that
 * changed underneath is not answered for them.
 *
 * An answer the worker could not take is kept on this device and said to be kept. Nothing sends it
 * again but the person, after the question has been read again, and one whose question ended or
 * moved is kept, with what became of the question, until the person dismisses it.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import type { Question } from '@kalareach/protocol'

import { Banner, Button, CommitButton } from '../components/ui'
import { AGENT_READ_CADENCE_MS } from '../app/agent'
import { readOnCadence } from '../app/cadence'
import { useLastKnownRights } from '../app/rights'
import { useApp } from '../app/state'
import {
  failureCode,
  failureMessage,
  watch,
  type KeptAnswer,
  type SettledAnswer,
  type Watch
} from '../host/port'
import { ask } from '../mobile/model/call'
import {
  EMPTY_FORM,
  answerOf,
  answerWords,
  askerOf,
  endedWords,
  expiryWords,
  holdsSomething,
  listedChoices,
  offersSomethingElse,
  refusalWords,
  standingWords,
  typedWords,
  type Form
} from '../model/questions'

/** How long after one read of the kept answers the next one starts while they are shown. */
const KEPT_READ_CADENCE_MS = 3_000

/** Why this device may not answer, or null when it may. */
function unavailable(rights: readonly string[] | null): string | null {
  if (rights === null) return 'This device does not know yet what it may do here.'
  return rights.includes('question.respond')
    ? null
    : 'This device was not given the right to answer questions in this session.'
}

/** The record without `key`. */
function without<T>(record: Readonly<Record<string, T>>, key: string): Readonly<Record<string, T>> {
  return Object.fromEntries(Object.entries(record).filter(([each]) => each !== key))
}

/** A question that ended before the person's answer reached it, and what they had chosen. */
interface Closed {
  readonly question: Question
  readonly words: string
  readonly chosen: string
}

/** The questions waiting in one session. */
export function QuestionRequests({
  sessionId,
  onAnswered
}: {
  readonly sessionId: string
  /** Called once an answer has been taken, so what listed the question can read again. */
  readonly onAnswered?: () => void
}): ReactNode {
  const { port, say, keptChanged } = useApp()
  const rights = useLastKnownRights()
  // This view of this session: nothing read in an earlier visit to it is shown on a return.
  const visit = useMemo(() => ({ sessionId }), [sessionId])
  const [waiting, setWaiting] = useState<{
    readonly visit: object
    readonly questions: readonly Question[]
    readonly atMs: number
  } | null>(null)
  const [failure, setFailure] = useState<{ readonly visit: object; readonly words: string } | null>(
    null
  )
  const [forms, setForms] = useState<Readonly<Record<string, Form>>>({})
  const [refusals, setRefusals] = useState<Readonly<Record<string, string>>>({})
  const [answering, setAnswering] = useState<string | null>(null)
  // Questions that ended under a person's answer. Once the worker stops listing them, what they
  // chose and why it was not recorded would go with them, so they stay until dismissed.
  const [closed, setClosed] = useState<Readonly<Record<string, Closed>>>({})
  const reads = useRef<Watch | null>(null)
  const again = useRef<() => void>(() => undefined)
  // What the last read listed, and what the person had typed, as the read that follows sees them: a
  // question that stops being listed with an answer half made in it is not lost with its form.
  const listed = useRef<readonly Question[]>([])
  const typed = useRef<Readonly<Record<string, Form>>>({})
  useEffect(() => {
    typed.current = forms
  }, [forms])
  // The questions this person has answered here: they stop being listed because they were answered,
  // and the form that made the answer is not one to keep.
  const answeredHere = useRef(new Set<string>())

  const load = useCallback((): Promise<void> => {
    const current = reads.current?.read() ?? null
    if (current === null) return Promise.resolve()
    return ask(() => port.questionRead({ session_id: sessionId, question_id: null, include_resolved: false }))
      .then((result) => {
        if (!current()) return
        const before = listed.current
        listed.current = result.questions
        setWaiting({ visit, questions: result.questions, atMs: Date.now() })
        setFailure(null)
        for (const gone of before) {
          if (result.questions.some((each) => each.question_id === gone.question_id)) continue
          if (answeredHere.current.has(gone.question_id)) continue
          const form = typed.current[gone.question_id]
          if (form === undefined || !holdsSomething(form)) continue
          // Another device answered it, or it expired or was withdrawn: say how it ended, with
          // what the person had chosen, and keep that until they dismiss it.
          void ask(() =>
            port.questionRead({
              session_id: sessionId,
              question_id: gone.question_id,
              include_resolved: true
            })
          )
            .catch(() => undefined)
            .then((final) => {
              const ended = final?.questions.find((each) => each.question_id === gone.question_id)
              setClosed((held) => ({
                ...held,
                [gone.question_id]: {
                  question: ended ?? gone,
                  words: ended === undefined ? 'This question is no longer waiting.' : endedWords(ended),
                  chosen: typedWords(gone, form)
                }
              }))
              setForms((held) => without(held, gone.question_id))
            })
        }
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure({ visit, words: failureMessage(error) })
      })
  }, [port, sessionId, visit])

  useEffect(() => {
    const cadence = readOnCadence(load, AGENT_READ_CADENCE_MS)
    const reading = watch([], cadence.now)
    reads.current = reading
    again.current = cadence.now
    return () => {
      cadence.stop()
      reading.stop()
      if (reads.current === reading) reads.current = null
      again.current = () => undefined
    }
  }, [load])

  const readAgain = useCallback(() => {
    again.current()
  }, [])

  const formOf = (question: Question): Form => forms[question.question_id] ?? EMPTY_FORM

  const change = (question: Question, next: Partial<Form>) => {
    setForms((current) => {
      const before = current[question.question_id] ?? EMPTY_FORM
      return {
        ...current,
        [question.question_id]: { ...before, ...next, at: before.at ?? question.revision }
      }
    })
    setRefusals((current) =>
      question.question_id in current ? without(current, question.question_id) : current
    )
  }

  const send = (question: Question) => {
    const form = formOf(question)
    // A question that changed since the person began is read again by them first: what they are
    // answering is what they see now.
    if (form.at !== null && form.at !== question.revision) {
      setForms((current) => ({
        ...current,
        [question.question_id]: { ...form, at: question.revision }
      }))
      setRefusals((current) => ({
        ...current,
        [question.question_id]:
          'This question changed while you were answering it. Read it again, then press Send.'
      }))
      return
    }
    const made = answerOf(question, form)
    if (!('answer' in made)) return
    setAnswering(question.question_id)
    ask(() =>
      port.questionAnswer({
        session_id: sessionId,
        question_id: question.question_id,
        expected_revision: question.revision,
        answer: made.answer
      })
    )
      .then((outcome) => {
        answeredHere.current.add(question.question_id)
        setForms((current) => without(current, question.question_id))
        if (outcome.outcome === 'taken') {
          say(
            outcome.leftover
              ? 'Your answer was recorded. An older copy of it could not be removed from this device, and it will not be sent again.'
              : 'Your answer was recorded.'
          )
        } else {
          say(
            'The host did not confirm that. A copy of your answer is kept on this device, and it is sent again only if you send it.',
            'pending'
          )
        }
        keptChanged()
        onAnswered?.()
      })
      .catch((error: unknown) => {
        const words = refusalWords(error, failureMessage(error))
        const code = failureCode(error)
        if (code === 'QUESTION_RESOLVED' || code === 'QUESTION_EXPIRED') {
          setClosed((current) => ({
            ...current,
            [question.question_id]: { question, words, chosen: answerWords(made.answer, question) }
          }))
          setForms((current) => without(current, question.question_id))
          return
        }
        setRefusals((current) => ({ ...current, [question.question_id]: words }))
      })
      .finally(() => {
        setAnswering(null)
        readAgain()
      })
  }

  const shown = waiting?.visit === visit ? waiting : null
  const questions = shown?.questions ?? []
  const refusal = failure?.visit === visit ? failure.words : null
  const now = shown?.atMs ?? 0
  const blocked = unavailable(rights)

  const ended = Object.values(closed).filter(
    (each) => !questions.some((listed) => listed.question_id === each.question.question_id)
  )

  if (refusal !== null && questions.length === 0 && ended.length === 0) {
    return (
      <Banner
        tone="warning"
        title="The questions waiting here could not be read"
        detail={refusal}
        action={<Button onClick={readAgain}>Try again</Button>}
      />
    )
  }
  if (questions.length === 0 && ended.length === 0) return null

  return (
    <section className="questions" aria-label="Waiting for your answer" data-testid="questions">
      {refusal !== null ? (
        <Banner
          tone="warning"
          title="These questions were last read some time ago"
          detail={`${refusal} If the host does not confirm an answer you give now, this device keeps a copy, and sends it again only if you send it.`}
          action={<Button onClick={readAgain}>Try again</Button>}
        />
      ) : null}
      {questions.map((question) => {
        const asker = askerOf(question)
        const form = formOf(question)
        const made = answerOf(question, form)
        const busy = answering === question.question_id
        const problem = 'problem' in made ? made.problem : null
        const note = refusals[question.question_id] ?? null
        const idBase = `question-${question.question_id}`
        return (
          <article
            className="question"
            key={question.question_id}
            data-question={question.question_id}
            data-kind={question.kind}
            data-testid="question"
          >
            <p className="eyebrow">Waiting for your answer</p>
            <p className="small muted" data-testid="question-asker">
              Asked by{' '}
              <strong>{asker.executable ?? 'a program the host could not name'}</strong>{' '}
              ({asker.process})
              {asker.label !== null ? (
                <>
                  {' '}
                  · calls itself “{asker.label}” (not verified)
                </>
              ) : null}
            </p>
            {asker.path !== null ? (
              <p className="small faint question-path" data-testid="question-asker-path">
                {asker.path}
              </p>
            ) : null}
            <h3 data-testid="question-text">{question.question}</h3>
            {question.context.length > 0 ? (
              <p className="small muted question-context" data-testid="question-context">
                {question.context}
              </p>
            ) : null}
            <p className="small faint">{expiryWords(question, now)}</p>
            {question.kind === 'input' ? (
              <label className="form-field" htmlFor={`${idBase}-text`}>
                <span>Your answer</span>
                <textarea
                  id={`${idBase}-text`}
                  rows={3}
                  value={form.text}
                  disabled={busy || blocked !== null}
                  onChange={(event) => {
                    change(question, { text: event.target.value })
                  }}
                />
              </label>
            ) : (
              <fieldset className="question-choices" disabled={busy || blocked !== null}>
                <legend className="small muted">
                  {question.kind === 'confirm' ? 'Yes or no' : 'Choose one'}
                </legend>
                {(question.kind === 'confirm'
                  ? [
                      { choice_id: 'yes', label: 'Yes' },
                      { choice_id: 'no', label: 'No' }
                    ]
                  : listedChoices(question)
                ).map((choice) => (
                  <label className="question-choice" key={choice.choice_id}>
                    <input
                      type="radio"
                      name={`${idBase}-pick`}
                      checked={!form.other && form.pick === choice.choice_id}
                      onChange={() => {
                        change(question, { pick: choice.choice_id, other: false })
                      }}
                    />
                    <span>{choice.label}</span>
                  </label>
                ))}
                {offersSomethingElse(question) ? (
                  <>
                    <label className="question-choice">
                      <input
                        type="radio"
                        name={`${idBase}-pick`}
                        checked={form.other}
                        onChange={() => {
                          change(question, { other: true })
                        }}
                      />
                      <span>Something else</span>
                    </label>
                    {form.other ? (
                      <label className="form-field" htmlFor={`${idBase}-other`}>
                        <span>What you would say instead</span>
                        <textarea
                          id={`${idBase}-other`}
                          rows={3}
                          value={form.text}
                          onChange={(event) => {
                            change(question, { text: event.target.value })
                          }}
                        />
                      </label>
                    ) : null}
                  </>
                ) : null}
              </fieldset>
            )}
            {problem !== null ? (
              <p className="small warning-text" data-testid="question-problem">
                {problem}
              </p>
            ) : null}
            {note !== null ? (
              <p className="small warning-text" role="status" data-testid="question-refusal">
                {note}
              </p>
            ) : null}
            {blocked !== null ? (
              <p className="small warning-text" data-testid="question-unavailable">
                {blocked}
              </p>
            ) : null}
            <div className="row wrap question-send">
              <CommitButton
                data-testid="question-send"
                disabled={!('answer' in made) || busy || blocked !== null}
                onCommit={() => {
                  send(question)
                }}
              >
                Send answer
              </CommitButton>
            </div>
          </article>
        )
      })}
      {ended.map(({ question, words, chosen }) => (
        <article
          className="question kept"
          key={question.question_id}
          data-question={question.question_id}
          data-testid="question-ended"
        >
          <p className="eyebrow">No longer waiting</p>
          <h3>{question.question}</h3>
          <p className="small warning-text" role="status" data-testid="question-refusal">
            {words}
          </p>
          <p className="small muted">You had chosen {chosen}.</p>
          <div className="row wrap">
            <Button
              tone="quiet"
              onClick={() => {
                setClosed((current) => without(current, question.question_id))
              }}
            >
              Dismiss
            </Button>
          </div>
        </article>
      ))}
    </section>
  )
}

/** One kept answer, as the person reads it. */
function KeptRow({
  kept,
  settled,
  where,
  busy,
  onSend,
  onDismiss
}: {
  readonly kept: KeptAnswer
  readonly settled: SettledAnswer | null
  /** The session it was given in, as a person names it, or null when it cannot be named now. */
  readonly where: string | null
  readonly busy: boolean
  readonly onSend: () => void
  readonly onDismiss: () => void
}): ReactNode {
  const question = settled?.question ?? null
  return (
    <article
      className="question kept"
      data-question={kept.question_id}
      data-standing={settled?.standing ?? 'unchecked'}
      data-testid="kept-answer"
    >
      <p className="eyebrow">Answers kept on this device</p>
      <p className="small muted" data-testid="kept-answer-where">
        {where ?? 'A session this device cannot name now'}
      </p>
      {question !== null ? (
        <p data-testid="kept-answer-question">
          The question: <strong>{question.question}</strong>
        </p>
      ) : null}
      <p data-testid="kept-answer-text">
        You answered {answerWords(kept.answer, question ?? undefined)}
        {question === null ? ' to a question in this session' : ''}, and the host did not confirm it
        took the answer. A copy is kept here.
      </p>
      <p className="small muted" data-testid="kept-answer-standing">
        {settled === null
          ? 'This session has not been checked since. This device has sent nothing since.'
          : standingWords(settled)}
      </p>
      <div className="row wrap">
        {settled?.standing === 'offered' ? (
          <CommitButton data-testid="kept-answer-send" disabled={busy} onCommit={onSend}>
            Send it now
          </CommitButton>
        ) : null}
        <CommitButton
          tone="quiet"
          data-testid="kept-answer-dismiss"
          disabled={busy}
          onCommit={onDismiss}
        >
          Discard
        </CommitButton>
      </div>
    </article>
  )
}

/**
 * The answers kept on this device, for one session or for all of them.
 *
 * The list needs no host and is shown first. Where a session can be reached, it is asked where each
 * answer's question stands, and each session's answer is applied when it arrives; where it cannot,
 * the answers are shown as they are kept, unchecked.
 */
export function KeptAnswers({ sessionId }: { readonly sessionId?: string }): ReactNode {
  const { port, say, keptVersion, keptChanged } = useApp()
  const [kept, setKept] = useState<readonly KeptAnswer[]>([])
  const [unreadable, setUnreadable] = useState(0)
  const [failure, setFailure] = useState<string | null>(null)
  const [settled, setSettled] = useState<ReadonlyMap<string, SettledAnswer>>(new Map())
  const [named, setNamed] = useState<ReadonlyMap<string, string>>(new Map())
  const [busy, setBusy] = useState<string | null>(null)
  const reads = useRef<Watch | null>(null)
  const again = useRef<() => void>(() => undefined)

  const load = useCallback((): Promise<void> => {
    const current = reads.current?.read() ?? null
    if (current === null) return Promise.resolve()
    return ask(() => port.questionKept())
      .then(async (list) => {
        if (!current()) return
        const all = list.answers.filter(
          (each) => sessionId === undefined || each.session_id === sessionId
        )
        setKept(all)
        setUnreadable(list.unreadable)
        setFailure(null)
        const here = new Set(all.map((each) => each.question_id))
        setSettled((held) => new Map([...held].filter(([id]) => here.has(id))))
        const sessions = [...new Set(all.map((each) => each.session_id))]
        // Each session's answer is applied as it arrives, so one that does not answer holds nothing.
        await Promise.all(
          sessions.map(async (session) => {
            try {
              const standing = await port.questionSettle(session)
              if (!current()) return
              setSettled((held) => {
                const next = new Map(held)
                for (const each of standing) next.set(each.draft.question_id, each)
                return next
              })
            } catch {
              // Not checked: a session that cannot be reached says nothing, and nothing is retired.
            }
          })
        )
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure(failureMessage(error))
      })
  }, [port, sessionId])

  useEffect(() => {
    const cadence = readOnCadence(load, KEPT_READ_CADENCE_MS)
    const reading = watch([], cadence.now)
    reads.current = reading
    again.current = cadence.now
    return () => {
      cadence.stop()
      reading.stop()
      if (reads.current === reading) reads.current = null
      again.current = () => undefined
    }
  }, [load])

  // Another screen kept, sent or dismissed an answer: read again at once rather than on the cadence.
  useEffect(() => {
    again.current()
  }, [keptVersion])

  // The sessions the answers were given in are named when the host can name them. A host out of
  // reach leaves the names out, and the answers are shown without them.
  useEffect(() => {
    if (kept.length === 0) return undefined
    let current = true
    ask(() => port.sessionList({ environment_id: null, include_closed: true }))
      .then((result) => {
        if (!current) return
        setNamed(
          new Map(
            result.sessions.map((each) => [
              each.session_id,
              `Session ${each.display_number} · ${each.cwd}`
            ])
          )
        )
      })
      .catch(() => undefined)
    return () => {
      current = false
    }
  }, [port, kept.length])

  if (kept.length === 0 && unreadable === 0 && failure === null) return null

  return (
    <section
      className="questions"
      aria-label="Answers kept on this device"
      data-testid="kept-answers"
    >
      {failure !== null ? (
        <Banner
          tone="warning"
          title="The answers kept on this device could not be read"
          detail={failure}
          action={<Button onClick={() => again.current()}>Try again</Button>}
        />
      ) : null}
      {unreadable > 0 ? (
        <Banner
          tone="warning"
          title="Some answers kept on this device could not be read"
          detail="They are left where they are, and nothing has been done with them."
        />
      ) : null}
      {kept.map((each) => (
        <KeptRow
          key={each.question_id}
          kept={each}
          settled={settled.get(each.question_id) ?? null}
          where={named.get(each.session_id) ?? null}
          busy={busy === each.question_id}
          onSend={() => {
            setBusy(each.question_id)
            ask(() =>
              port.questionSendKept({ questionId: each.question_id, draftedAtMs: each.drafted_at_ms })
            )
              .then((outcome) => {
                say(
                  outcome.outcome === 'taken' && outcome.leftover
                    ? 'Your answer was recorded. A copy of it could not be removed from this device, and it will not be sent again.'
                    : 'Your answer was recorded.'
                )
              })
              .catch((error: unknown) => {
                say(refusalWords(error, failureMessage(error)), 'danger')
              })
              .finally(() => {
                setBusy(null)
                keptChanged()
              })
          }}
          onDismiss={() => {
            setBusy(each.question_id)
            ask(() =>
              port.questionDismissKept({
                questionId: each.question_id,
                draftedAtMs: each.drafted_at_ms
              })
            )
              .catch((error: unknown) => {
                say(failureMessage(error), 'danger')
              })
              .finally(() => {
                setBusy(null)
                keptChanged()
              })
          }}
        />
      ))}
    </section>
  )
}
