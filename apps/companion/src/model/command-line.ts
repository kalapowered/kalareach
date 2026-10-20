/**
 * An argument vector as a person types it at a stock shell's prompt.
 *
 * The page never types into a stock shell, so it shows the command for the person to type. Each
 * shell reads quotes its own way, and text quoted for another shell runs as something else in this
 * one, so the vector is quoted for the shell the session runs. The rules are the ones the product
 * applies to a command it installs itself: a word that holds only characters no shell treats as
 * more than themselves is written as it is, and any other word is one quoted string.
 */

import type { ShellKind } from './pending'

/** Characters every shell here reads as themselves. */
const PLAIN = /^[\w@%+=:,./-]+$/

/** The four characters PowerShell reads as a single quote besides the ASCII one. */
const POWERSHELL_QUOTES = /['‘’‚‛]/g

/** One argument as a single word of the shell `kind`. */
function word(argument: string, kind: ShellKind): string {
  if (kind === 'powershell') {
    // Its stop-parsing token is left out of a program's arguments wherever it is written, quoted or
    // not, and the array expression is the one spelling that passes it on.
    if (argument === '--%') return "@('--%')"
    // `@` at the start of a word splats a variable, and a comma makes a list.
    if (PLAIN.test(argument) && !/[@,]/.test(argument)) return argument
    return `'${argument.replace(POWERSHELL_QUOTES, '$&$&')}'`
  }
  if (PLAIN.test(argument)) return argument
  if (kind === 'fish') return `'${argument.replaceAll('\\', '\\\\').replaceAll("'", "\\'")}'`
  return `'${argument.replaceAll("'", `'\\''`)}'`
}

/** The vector `argv` as one line for the shell `kind`. */
export function commandLine(argv: readonly string[], kind: ShellKind): string {
  const words = argv.map((argument) => word(argument, kind))
  // PowerShell reads a quoted word at the start of a line as a string to print. The call operator
  // is what runs it, and it is needed exactly when the program's name had to be quoted.
  if (kind === 'powershell' && words[0]?.startsWith("'")) words[0] = `& ${words[0]}`
  return words.join(' ')
}
