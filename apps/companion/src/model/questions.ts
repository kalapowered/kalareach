/**
 * An agent's question, and what a person is told about answering it.
 *
 * A question is the worker's: it verified the program that asked, holds the question through a
 * restart of the host's daemon, and resolves it once, for whoever answers first. The page shows what
 * the worker says and names the question and the revision a person was shown when they answer.
 *
 * The identity shown above a question is the worker's own reading of the program that asked: its
 * executable and its process. The agent's name for itself is a label the program supplied, shown
 * beside it as unverified, and never in the identity's place.
 */

import type { Question, QuestionAnswer } from '@kalareach/protocol'

import { failureCode, type Standing } from '../host/port'

/** The most bytes of text one answer carries. */
export const MAX_ANSWER_BYTES = 16 * 1024

/** The free-text choice every `select` and `confirm` question carries. */
export const SOMETHING_ELSE = 'something_else'

/** The program that asked, as the worker verified it, and what it called itself. */
export interface Asker {
  /** The executable's name, or null when the platform gave none. */
  readonly executable: string | null
  /** The executable's full path, for a person who wants it. */
  readonly path: string | null
  /** The process the worker verified. */
  readonly process: string
  /** The program's own label for itself, which nothing verified. */
  readonly label: string | null
}

/** Who asked a question. */
export function askerOf(question: Question): Asker {
  const path = question.source.executable
  const name = path === null ? null : (path.split(/[\\/]/).filter(Boolean).pop() ?? path)
  return {
    executable: name,
    path,
    process: `process ${question.source.process.pid}`,
    label: question.source.agent_label
  }
}

/** The choices a person picks one of: the question's own, without the free-text option. */
export function listedChoices(question: Question): Question['choices'] {
  return question.choices.filter((choice) => choice.choice_id !== SOMETHING_ELSE)
}

/** Whether a question offers the free-text option beside its other answers. */
export function offersSomethingElse(question: Question): boolean {
  return question.kind === 'select' || question.kind === 'confirm'
}

/** The whole of a form: what a person has picked or typed so far. */
export interface Form {
  /** The listed choice picked, `'yes'` or `'no'` for a confirmation, or null. */
  readonly pick: string | null
  /** What was typed for an input question, or for the free-text option. */
  readonly text: string
  /** Whether the free-text option is the one picked. */
  readonly other: boolean
  /** The revision of the question when the person began, or null before they have. */
  readonly at: string | null
}

/** A form with nothing in it. */
export const EMPTY_FORM: Form = { pick: null, text: '', other: false, at: null }

/** The bytes in some text. */
function bytes(text: string): number {
  return new TextEncoder().encode(text).length
}

/**
 * The answer a form makes, or why it makes none.
 *
 * The free-text option is its own answer, never a listed choice or a yes, so what a person typed
 * instead of choosing is read as what they typed.
 */
export function answerOf(
  question: Question,
  form: Form
): { readonly answer: QuestionAnswer } | { readonly problem: string | null } {
  const typed = form.text.trim().length > 0
  if (question.kind === 'input') {
    if (!typed) return { problem: null }
    if (bytes(form.text) > MAX_ANSWER_BYTES) return { problem: tooLong() }
    return { answer: { kind: 'input', text: form.text } }
  }
  if (form.other) {
    if (!typed) return { problem: null }
    if (bytes(form.text) > MAX_ANSWER_BYTES) return { problem: tooLong() }
    return { answer: { kind: 'other', text: form.text } }
  }
  if (form.pick === null) return { problem: null }
  if (question.kind === 'confirm') {
    return { answer: { kind: 'decision', decided: form.pick === 'yes' } }
  }
  return { answer: { kind: 'choice', choice_id: form.pick } }
}

function tooLong(): string {
  return `An answer is at most ${MAX_ANSWER_BYTES / 1024} KiB of text.`
}

/** An answer in words, for a line that says what was or will be sent. */
export function answerWords(answer: QuestionAnswer, question?: Question): string {
  switch (answer.kind) {
    case 'input':
    case 'other':
      return `“${answer.text}”`
    case 'decision':
      return answer.decided ? 'Yes' : 'No'
    case 'choice': {
      const label = question?.choices.find((choice) => choice.choice_id === answer.choice_id)?.label
      return `“${label ?? answer.choice_id}”`
    }
  }
}

/** Where a kept answer's question stands, in words that claim only what the worker said. */
export function standingWords(standing: Standing): string {
  switch (standing.standing) {
    case 'offered':
      return 'This question is still waiting, as it was when you answered. Nothing has been sent from here since.'
    case 'unlisted':
      return 'The session does not list this question, and nothing says the session ended. Nothing has been sent from here.'
    case 'ended':
      return `This question was ${standing.state} while your answer was kept. This device will not send your answer.`
    case 'moved':
      return 'This question changed after you answered it. This device will not send your answer.'
    case 'gone':
      return 'The session ended, and this question with it. This device will not send your answer.'
  }
}

/** What a refusal of an answer means for the person, in the words they act on. */
export function refusalWords(failure: unknown, fallback: string): string {
  switch (failureCode(failure)) {
    case 'QUESTION_RESOLVED':
      return 'This question was already answered or withdrawn. Your answer was not recorded.'
    case 'QUESTION_EXPIRED':
      return 'This question expired. Your answer was not recorded.'
    case 'DRAFT_CONFLICT':
      return 'This question changed since you saw it. Read it again before you answer.'
    case 'PERMISSION_DENIED':
      return 'This device was not given the right to answer questions in this session.'
    default:
      return fallback
  }
}

/** How long until a question expires, in words, or that it has. */
export function expiryWords(question: Question, nowMs: number): string {
  const left = Number(question.expires_at_ms) - nowMs
  if (left <= 0) return 'It has expired.'
  const minutes = Math.floor(left / 60_000)
  if (minutes < 60) return `It expires in ${Math.max(1, minutes)} minute${minutes === 1 ? '' : 's'}.`
  const hours = Math.floor(minutes / 60)
  return `It expires in ${hours} hour${hours === 1 ? '' : 's'}.`
}
