/**
 * The host's saved launch commands as the page draws and checks them.
 *
 * A command is a label, a program and separate arguments. The host is the authority on what it
 * saves: it refuses a control, format, invisible or line-break character and every size past its
 * limits, and the words below are the ones it uses, so the form can say the same before the host
 * is asked. A row the form misses is refused by the host, and the form then shows the host's words.
 * Both are held to one file of rows, `tests/fixtures/launch-command-rows.json`.
 *
 * A saved command is pressed as its vector, the program and then its arguments, which goes through
 * `shell.launch` unchanged. The page presses only a vector that the newest list it has read holds.
 */

import type { NamedLaunch, ShellLaunchCommandsListResult } from '@kalareach/protocol'

/** The most commands a host holds. */
export const MAX_COMMANDS = 32
/** The most characters a label has, once trimmed. */
export const MAX_LABEL_CHARACTERS = 48
/** The most bytes a program has, and each argument. */
export const MAX_FIELD_BYTES = 512
/** The most arguments a command has. */
export const MAX_ARGUMENTS = 16
/** The most bytes a command uses across its label, program and arguments. */
export const MAX_COMMAND_BYTES = 3072

/** The host's sentence for a label that breaks a rule. */
export const LABEL_RULE =
  'A label has 1 to 48 characters, with no control, format, invisible or line-break characters.'
/** The host's sentence for a program that breaks a rule. */
export const PROGRAM_RULE =
  'A program has 1 to 512 bytes, with no control, format, invisible or line-break characters.'
/** The host's sentence for an argument, or the number of them, that breaks a rule. */
export const ARGUMENT_RULE =
  'A command has at most 16 arguments of at most 512 bytes each, with no control, format, invisible or line-break characters. An argument may be empty.'
/** The host's sentence for a command that is too large in all. */
export const TOTAL_RULE = 'A command may use at most 3,072 bytes in all, label included.'
/** The host's sentence for a new command when the list is full. */
export const FULL_RULE = 'This host holds 32 launch commands. Replace one or remove one first.'

/** The words of the launch commands' places on the page. */
export const WORDS = {
  /** The group's heading on the launch surface. */
  group: 'Saved commands',
  /** The section's heading in Settings. */
  section: 'Launch commands',
  /** The first sentence of the saved commands' warning: whose the list is. */
  whose: "A command is saved as written and shown to this host's owner devices.",
  /** The rest of the warning. */
  secret:
    'Do not put a secret in one: when you press its button, the command is typed in the terminal, where anyone who can see that terminal or its history can read it.',
  /** What a press does at a verified prompt. */
  press:
    "On a computer, a command's button can be pressed when the terminal is at a verified empty prompt and you have taken control of it.",
  /** What the shell does with the program. */
  shell:
    "The shell looks up the program, and an accepted launch is typed at the prompt, so it runs in the shell's current directory.",
  /** How the words are passed. */
  passed:
    "The program and each argument are passed as written: a leading ~ or a $VARIABLE is not expanded, and there are no pipes or redirections. Use a full path, or a program on the shell's path.",
  /**
   * How the words are passed to PowerShell, which looks for a program that begins with ~ under the
   * home folder while an argument that begins with ~ stays as written.
   */
  passedInPowerShell:
    "The program and each argument are passed as written: a $VARIABLE, or a ~ at the start of an argument, is not expanded, and there are no pipes or redirections. A program that begins with ~ is looked for under the home folder. Use a full path, or a program on the shell's path.",
  /** What Windows does with a batch program. */
  batch:
    'On Windows, a .cmd or .bat program is not started when an argument is empty, holds white space and ends in a backslash, or holds one of " % ! ^ & | < > ( ), or when the program\'s path holds % or !.',
  /** The preview's caption. */
  preview: 'Preview: the saved program and arguments.',
  /** Where a change is made. */
  localOnly:
    'Launch commands can be changed only from the local connection to this host. Each environment keeps its own list.',
  /** An empty list that was read. */
  none: 'No launch commands yet.',
  /** A host that does not serve the list. */
  notServed: 'This host does not serve launch commands.',
  /** A list that could not be read. */
  unread: 'The saved launch commands could not be read.',
  /** A connection that may not read the list. */
  refused: "This device may not see this host's launch commands.",
  /** A label is missing. */
  nameNeeded: 'A name is needed.',
  /** A program is missing. */
  programNeeded: 'A program is needed.',
  /** The list moved on while the form was being filled in. */
  conflict: 'The launch commands changed while you were editing. Look at the list and save again.',
  /** The host could not say what became of a change. */
  unconfirmed: 'The host could not confirm the change. Look at the list to see what it holds.'
} as const

/** Replacing a command: the saved spelling of its label. */
export function replaceWarning(saved: string): string {
  return `A command named "${saved}" is already saved. Saving this one replaces it.`
}

/** The words after a change the host confirmed. */
export function changed(
  result: 'saved' | 'replaced' | 'removed' | 'already' | 'absent',
  label: string
): string {
  switch (result) {
    case 'saved':
      return `Saved the launch command "${label}".`
    case 'replaced':
      return `Replaced the launch command "${label}".`
    case 'removed':
      return `Removed the launch command "${label}".`
    case 'already':
      return `The launch command "${label}" is already saved as written.`
    case 'absent':
      return `No launch command is named "${label}".`
  }
}

/** What the form holds: a command as the person has typed it so far. */
export interface LaunchDraft {
  readonly label: string
  readonly program: string
  readonly arguments: readonly string[]
}

/** One problem the form sees before the host is asked, in the words it shows. */
export interface Foreseen {
  /** `needed` is a field left empty, which the form says only once a save is tried. */
  readonly kind: 'needed' | 'refused'
  readonly words: string
}

/** The characters the host refuses: control, format, line and paragraph separators, and invisible ones. */
const REFUSED = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u

/** The first refused character of `text`: its place counted in characters from 1, and its code point. */
function firstRefused(text: string): { position: number; codePoint: number } | null {
  let position = 0
  for (const character of text) {
    position += 1
    if (REFUSED.test(character)) {
      return { position, codePoint: character.codePointAt(0) ?? 0 }
    }
  }
  return null
}

/** A code point as the host writes it: upper-case hex of at least four digits. */
function codePointWords(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`
}

/** A rule's sentence, and after it which character broke it where one did. */
function refusal(
  rule: string,
  whose: string,
  found: { position: number; codePoint: number } | null
): Foreseen {
  return {
    kind: 'refused',
    words:
      found === null
        ? rule
        : `${rule} Character ${found.position} of ${whose} is ${codePointWords(found.codePoint)}, which is not allowed.`
  }
}

const encoder = new TextEncoder()
const bytes = (text: string): number => encoder.encode(text).length

/**
 * What the host would refuse in `draft`, or null: the first problem, in the order the host checks.
 * A character is looked for before the label is trimmed; sizes are counted after.
 *
 * This is feedback and the host is the authority: its character table may be of another Unicode
 * version than this browser's.
 */
export function foresee(draft: LaunchDraft, saved: readonly NamedLaunch[]): Foreseen | null {
  const labelCharacter = firstRefused(draft.label)
  if (labelCharacter !== null) return refusal(LABEL_RULE, 'the label', labelCharacter)
  const label = draft.label.trim()
  if (label === '') return { kind: 'needed', words: WORDS.nameNeeded }
  if (Array.from(label).length > MAX_LABEL_CHARACTERS) return refusal(LABEL_RULE, 'the label', null)
  const programCharacter = firstRefused(draft.program)
  if (programCharacter !== null) return refusal(PROGRAM_RULE, 'the program', programCharacter)
  if (draft.program === '') return { kind: 'needed', words: WORDS.programNeeded }
  if (bytes(draft.program) > MAX_FIELD_BYTES) return refusal(PROGRAM_RULE, 'the program', null)
  if (draft.arguments.length > MAX_ARGUMENTS) return refusal(ARGUMENT_RULE, 'the arguments', null)
  for (const [index, argument] of draft.arguments.entries()) {
    const whose = `argument ${index + 1}`
    const found = firstRefused(argument)
    if (found !== null) return refusal(ARGUMENT_RULE, whose, found)
    if (bytes(argument) > MAX_FIELD_BYTES) return refusal(ARGUMENT_RULE, whose, null)
  }
  const total =
    bytes(label) + bytes(draft.program) + draft.arguments.reduce((sum, each) => sum + bytes(each), 0)
  if (total > MAX_COMMAND_BYTES) return { kind: 'refused', words: TOTAL_RULE }
  if (saved.length >= MAX_COMMANDS && replaced(label, saved) === null) {
    return { kind: 'refused', words: FULL_RULE }
  }
  return null
}

/** The saved command that a save of `label` would replace, compared in lower case, or null. */
export function replaced(label: string, saved: readonly NamedLaunch[]): NamedLaunch | null {
  const wanted = label.trim().toLowerCase()
  if (wanted === '') return null
  return saved.find((held) => held.label.toLowerCase() === wanted) ?? null
}

/** The command a save sends: the label is trimmed here as the host trims it. */
export function commandOf(draft: LaunchDraft): NamedLaunch {
  return {
    label: draft.label.trim(),
    program: draft.program,
    arguments: [...draft.arguments]
  }
}

/** A saved command as a button draws it. */
export interface SavedOffer {
  readonly label: string
  /** The program as saved, drawn under the label. */
  readonly program: string
  /** What a press sends: the program, and then the arguments, unchanged. */
  readonly vector: readonly string[]
}

/** The buttons of a list, in the order the host first saved the commands. */
export function offersOf(list: ShellLaunchCommandsListResult): readonly SavedOffer[] {
  return list.commands.map((command) => ({
    label: command.label,
    program: command.program,
    vector: [command.program, ...command.arguments]
  }))
}

/** Whether two vectors are the same words in the same order. */
export function sameVector(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((word, index) => word === b[index])
}

/** Whether `list` holds a command with this label and exactly this vector. */
export function holds(
  list: ShellLaunchCommandsListResult | null,
  label: string,
  vector: readonly string[]
): boolean {
  if (list === null) return false
  return list.commands.some(
    (command) =>
      command.label === label && sameVector([command.program, ...command.arguments], vector)
  )
}
