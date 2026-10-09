/**
 * The scripted host's questions, and the answers it keeps while the worker cannot be reached.
 *
 * A session's worker holds its questions, resolves each one once for whoever answers first, and
 * refuses an answer to a revision that is no longer current. Native code adds one thing: an answer
 * the worker could not take is kept on the device and sent only when the person sends it. This
 * keeps both, in the forms the commands answer with.
 */

import type {
  Question,
  QuestionAnswer,
  QuestionAnswerParams,
  QuestionReadParams,
  QuestionReadResult
} from '@kalareach/protocol'

import { FakeHostError } from './fake'
import {
  QUESTION_ANSWER_PARAMS,
  QUESTION_READ_PARAMS,
  decodeParams,
  KEPT_REF_PARAMS
} from './fake-decode'
import type { AnswerOutcome, KeptAnswer, KeptRef, SettledAnswer, Standing } from './port'

function refuse(code: string, message: string): never {
  // eslint-disable-next-line @typescript-eslint/only-throw-error -- a command's failure crosses as data
  throw new FakeHostError(code, message).toPayload()
}

/** The most bytes of text one answer carries. */
const MAX_ANSWER_BYTES = 16 * 1024

/** The identities the questions are written against. */
export interface QuestionIds {
  readonly environment: string
  readonly sessions: { readonly main: string; readonly build: string; readonly offline: string }
  readonly nowMs: number
}

/** The questions the scripted host starts with, by the session each belongs to. */
export const QUESTION_SELECT = 'b1000000-0000-4000-8000-000000000001'
export const QUESTION_CONFIRM = 'b1000000-0000-4000-8000-000000000002'
export const QUESTION_INPUT = 'b1000000-0000-4000-8000-000000000003'

/** What a scripted host's question-keeping can be told to do. */
export interface FakeQuestions {
  /** The questions the host holds now, resolved ones included. */
  held(): readonly Question[]
  /** Another device answers the question first. */
  answerElsewhere(questionId: string, answer?: QuestionAnswer): void
  /** The question's deadline passes. */
  expire(questionId: string): void
  /** The question is revised, as the agent changing what it asks would. */
  revise(questionId: string, change: Partial<Pick<Question, 'question' | 'context'>>): void
  /** The session ends, and its questions with it. */
  endSession(sessionId: string): void
  /** Every answer the worker was sent, in order. */
  readonly sent: readonly QuestionAnswerParams[]
  /** Makes the worker unreachable, so an answer is kept, or reachable again. */
  setReachable(reachable: boolean): void
}

/** The questions and kept answers of the scripted host. */
export class ScriptedQuestions implements FakeQuestions {
  readonly #ids: QuestionIds
  #questions: Question[]
  #kept: KeptAnswer[] = []
  #ended = new Set<string>()
  #reachable = true
  readonly sent: QuestionAnswerParams[] = []

  constructor(ids: QuestionIds) {
    this.#ids = ids
    this.#questions = [
      this.#question(ids.sessions.build, QUESTION_SELECT, 'select'),
      this.#question(ids.sessions.build, QUESTION_CONFIRM, 'confirm'),
      this.#question(ids.sessions.main, QUESTION_INPUT, 'input')
    ]
  }

  #question(sessionId: string, questionId: string, kind: Question['kind']): Question {
    const now = this.#ids.nowMs
    const choices: Question['choices'] =
      kind === 'select'
        ? [
            { choice_id: 'main', label: 'main' },
            { choice_id: 'release', label: 'release/2026-09' },
            { choice_id: 'something_else', label: 'Something else' }
          ]
        : kind === 'confirm'
          ? [{ choice_id: 'something_else', label: 'Something else' }]
          : []
    return {
      question_id: questionId,
      revision: '2',
      state: 'pending',
      session_id: sessionId,
      session_epoch: '1',
      kind,
      context: 'The build finished with two failing tests.',
      question:
        kind === 'select'
          ? 'Which branch should the release be cut from?'
          : kind === 'confirm'
            ? 'Push the branch anyway?'
            : 'What should the release be called?',
      choices,
      source: {
        application_instance_id: '2a000000-0000-4000-8000-000000000001',
        process: { pid: '4242', source: 'macos_proc_bsd_info', start_value: '77' },
        executable: '/usr/local/bin/claude',
        agent_label: 'Claude Code',
        connection_id: '1a000000-0000-4000-8000-000000000001',
        launch_channel: true,
        session_member: true,
        ancestry: true,
        agent_binding_revision: null
      },
      created_at_ms: String(now - 200_000),
      expires_at_ms: String(now + 86_400_000 - 200_000),
      answer: null,
      resolved_at_ms: null
    }
  }

  held(): readonly Question[] {
    return this.#questions
  }

  setReachable(reachable: boolean): void {
    this.#reachable = reachable
  }

  #find(questionId: string): Question {
    const found = this.#questions.find((each) => each.question_id === questionId)
    if (found === undefined) throw new Error(`the host holds no question ${questionId}`)
    return found
  }

  #replace(questionId: string, change: (question: Question) => Question): void {
    this.#questions = this.#questions.map((each) =>
      each.question_id === questionId ? change(each) : each
    )
  }

  #resolve(questionId: string, state: Question['state'], answer?: QuestionAnswer): void {
    this.#replace(questionId, (question) => ({
      ...question,
      state,
      revision: String(BigInt(question.revision) + 1n),
      answer:
        answer === undefined
          ? null
          : {
              answer,
              actor_id: 'device:studio',
              device_id: null,
              question_revision: question.revision,
              answered_at_ms: String(this.#ids.nowMs)
            },
      resolved_at_ms: String(this.#ids.nowMs)
    }))
  }

  answerElsewhere(questionId: string, answer?: QuestionAnswer): void {
    this.#resolve(questionId, 'answered', answer ?? { kind: 'other', text: 'On the other device.' })
  }

  expire(questionId: string): void {
    this.#resolve(questionId, 'expired')
  }

  revise(questionId: string, change: Partial<Pick<Question, 'question' | 'context'>>): void {
    this.#replace(questionId, (question) => ({
      ...question,
      ...change,
      revision: String(BigInt(question.revision) + 1n)
    }))
  }

  endSession(sessionId: string): void {
    this.#ended.add(sessionId)
    this.#questions = this.#questions.filter((each) => each.session_id !== sessionId)
  }

  /* ---- The commands ------------------------------------------------------------------------- */

  #requireReachable(): void {
    if (!this.#reachable) {
      refuse('RESOURCE_UNAVAILABLE', 'This session’s worker cannot be reached right now.')
    }
  }

  read(params: unknown): QuestionReadResult {
    const read = decodeParams<QuestionReadParams>(params, QUESTION_READ_PARAMS)
    this.#requireReachable()
    if (this.#ended.has(read.session_id)) {
      refuse('UNKNOWN_SESSION', 'This session has no worker here.')
    }
    return {
      questions: this.#questions.filter(
        (question) =>
          question.session_id === read.session_id &&
          (read.question_id === null || question.question_id === read.question_id) &&
          (read.include_resolved || question.state === 'pending')
      )
    }
  }

  answer(params: unknown): AnswerOutcome {
    const asked = decodeParams<QuestionAnswerParams>(params, QUESTION_ANSWER_PARAMS)
    const shown = this.#questions.find((each) => each.question_id === asked.question_id)
    if (shown === undefined || shown.session_id !== asked.session_id) {
      refuse('DRAFT_CONFLICT', 'That question has not been read here: read it again.')
    }
    problemWith(shown, asked.answer)
    if (!this.#reachable) {
      const draft: KeptAnswer = {
        target: {
          environment_id: this.#ids.environment,
          session_id: shown.session_id,
          session_epoch: shown.session_epoch,
          application_instance_id: null,
          agent_binding_revision: null
        },
        session_id: shown.session_id,
        question_id: shown.question_id,
        question_revision: asked.expected_revision,
        answer: asked.answer,
        drafted_at_ms: String(this.#ids.nowMs + this.#kept.length + 1)
      }
      this.#kept = [
        ...this.#kept.filter((each) => each.question_id !== draft.question_id),
        draft
      ]
      return { outcome: 'kept', draft }
    }
    return this.#take(shown, asked.expected_revision, asked.answer)
  }

  #take(shown: Question, revision: string, answer: QuestionAnswer): AnswerOutcome {
    if (shown.state === 'answered' || shown.state === 'cancelled') {
      refuse('QUESTION_RESOLVED', `This question is already ${shown.state}.`)
    }
    if (shown.state === 'expired') refuse('QUESTION_EXPIRED', 'This question expired.')
    if (revision !== shown.revision) {
      refuse(
        'DRAFT_CONFLICT',
        `This question is at revision ${shown.revision}, and the answer named ${revision}.`
      )
    }
    this.sent.push({
      session_id: shown.session_id,
      question_id: shown.question_id,
      expected_revision: revision,
      answer
    })
    this.#resolve(shown.question_id, 'answered', answer)
    this.#kept = this.#kept.filter((each) => each.question_id !== shown.question_id)
    const after = this.#find(shown.question_id)
    return {
      outcome: 'taken',
      leftover: false,
      resolution: {
        question_id: after.question_id,
        revision: after.revision,
        state: after.state,
        session_id: after.session_id,
        resolved_at_ms: after.resolved_at_ms,
        question: after
      }
    }
  }

  kept(): readonly KeptAnswer[] {
    return this.#kept
  }

  settle(sessionId: string): readonly SettledAnswer[] {
    this.#requireReachable()
    return this.#kept
      .filter((draft) => draft.session_id === sessionId)
      .map((draft) => ({ draft, ...this.#standing(draft) }))
  }

  #standing(draft: KeptAnswer): Standing {
    const held = this.#questions.find((each) => each.question_id === draft.question_id)
    if (held === undefined) {
      return this.#ended.has(draft.session_id) ? { standing: 'gone' } : { standing: 'unlisted' }
    }
    if (held.state !== 'pending') return { standing: 'ended', state: held.state }
    if (held.revision !== draft.question_revision) {
      return { standing: 'moved', revision: held.revision }
    }
    return { standing: 'offered' }
  }

  sendKept(params: unknown): AnswerOutcome {
    const which = decodeParams<KeptRef>(params, KEPT_REF_PARAMS)
    const draft = this.#kept.find((each) => each.question_id === which.questionId)
    if (draft === undefined) {
      refuse('INVALID_ARGUMENT', 'No answer to that question is kept on this device.')
    }
    if (draft.drafted_at_ms !== which.draftedAtMs) {
      refuse('DRAFT_CONFLICT', 'The answer kept for that question has changed.')
    }
    this.#requireReachable()
    const held = this.#questions.find((each) => each.question_id === draft.question_id)
    if (held === undefined) refuse('RESOURCE_UNAVAILABLE', 'The session does not list that question.')
    return this.#take(held, draft.question_revision, draft.answer)
  }

  dismissKept(params: unknown): boolean {
    const which = decodeParams<KeptRef>(params, KEPT_REF_PARAMS)
    const draft = this.#kept.find((each) => each.question_id === which.questionId)
    if (draft === undefined || draft.drafted_at_ms !== which.draftedAtMs) return false
    this.#kept = this.#kept.filter((each) => each !== draft)
    return true
  }
}

/** Refuses an answer that does not fit the question's form, as the worker's form check does. */
function problemWith(question: Question, answer: QuestionAnswer): void {
  const invalid = (message: string): never => refuse('INVALID_ARGUMENT', message)
  if (answer.kind === 'input' || answer.kind === 'other') {
    if (answer.text.length === 0) invalid('An answer carries the text the person wrote.')
    if (new TextEncoder().encode(answer.text).length > MAX_ANSWER_BYTES) {
      invalid(`An answer is at most ${MAX_ANSWER_BYTES} bytes.`)
    }
  }
  switch (answer.kind) {
    case 'input':
      if (question.kind !== 'input') {
        invalid(`A ${question.kind} question is not answered with free text.`)
      }
      return
    case 'choice':
      if (question.kind !== 'select') invalid(`A ${question.kind} question offers no listed choices.`)
      if (answer.choice_id === 'something_else') {
        invalid('The free-text option is answered with its own text.')
      }
      if (!question.choices.some((choice) => choice.choice_id === answer.choice_id)) {
        invalid(`This question does not offer choice ${answer.choice_id}.`)
      }
      return
    case 'decision':
      if (question.kind !== 'confirm') invalid(`A ${question.kind} question is not answered yes or no.`)
      return
    case 'other':
      if (question.kind === 'input') {
        invalid('An input question has no free-text option beside itself.')
      }
      return
  }
}
