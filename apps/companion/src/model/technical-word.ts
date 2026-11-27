/**
 * Where a technical word may end a line.
 *
 * A technical word is an application identifier, a path, a command's option, a host name or an
 * address: text a person did not write as prose, with its own separators and no spaces to break
 * at. The engine breaks such a word wherever the line ends, in the middle of a part. The parts
 * below are the places it may end a line instead.
 *
 * A line may end at an internal dot that a letter or an underscore follows. Where the part after the
 * dot is short, four characters or fewer, the line ends before the dot, so that a familiar ending
 * stays whole (`KalaReach` and `.app`, `archive` and `.tar` and `.gz`). Where it is longer, the line
 * ends after the dot: a dot in front would only make the part wider, and a part wider than its line is
 * cut sooner (`com.` and `kalareach.` and `companion`). The dot follows the same rule after underscores,
 * whether they open the word or close a part (`_` and `.py`). A line may also end before an internal at
 * sign (`git` and `@host`, `"sam"` and `@example`) and before a run of hyphens, so that an option keeps
 * its hyphens: `--cache-dir` ends a line at `--cache` and never between `--` and `cache`. It may end
 * after a run of underscores, and after a run of slashes, backslashes, colons and equals signs: a run of
 * such separators is one place, after its last character. These never end a line: a separator that opens
 * a word (the slash of a path, the dot of `.local`, the underscores of `__init__`, the at sign of
 * `@types`), a dot that a digit follows (an address, a version or a file's number is not cut, and no
 * line starts with `.1`), a dot or an at sign that closes a word (the stop of a sentence, the root dot of
 * a host name), and a run of hyphens that opens a word or follows a quote. A word with a space in it
 * keeps its spaces as the places the engine breaks at already.
 */

/** The longest part after a dot that keeps the dot in front of it. */
const SHORT_PART = 4

/** Separators after which a run ends a line when a word follows. */
const AFTER_RUN = new Set(['/', '\\', ':', '='])

const QUOTES = new Set(['"', "'", '`'])

const OPENERS = new Set([...QUOTES, '(', '[', '{', '<'])

function isWordCharacter(character: string | undefined): boolean {
  return character !== undefined && /[\p{L}\p{N}]/u.test(character)
}

/** Whether `character` can end a part that a dot or an at sign follows: text, or an underscore of any run. */
function endsStem(character: string | undefined): boolean {
  return isWordCharacter(character) || character === '_'
}

function isLetter(character: string | undefined): boolean {
  return character !== undefined && /\p{L}/u.test(character)
}

function isDigit(character: string | undefined): boolean {
  return character !== undefined && /\p{N}/u.test(character)
}

/** Whether `character` ends the part that follows a dot: a separator, a space, or the word's end. */
function endsPart(character: string | undefined): boolean {
  return character === undefined || /[\s._/\\:=@-]/u.test(character)
}

/** How many characters the part that starts at `from` has, up to the next separator or the word's end. */
function partLength(characters: readonly string[], from: number): number {
  let end = from
  while (!endsPart(characters[end])) end += 1
  return end - from
}

/** Whether `character` starts a word: the text start, a space, or an opening quote or bracket. */
function opensWord(character: string | undefined): boolean {
  return character === undefined || /\s/u.test(character) || OPENERS.has(character)
}

/**
 * The parts of `text`, in order, that a line may end between. Joined, they are `text`: nothing is
 * added, dropped or changed.
 */
export function breakParts(text: string): readonly string[] {
  const characters = Array.from(text)
  const parts: string[] = []
  let current = ''
  for (let at = 0; at < characters.length; at += 1) {
    if (at > 0 && endsLineBefore(characters, at)) {
      parts.push(current)
      current = ''
    }
    current += characters[at]
  }
  if (current !== '') parts.push(current)
  return parts.filter((part) => part !== '')
}

/** Where the run of `character` that ends at `at` (inclusive) starts. */
function runStart(characters: readonly string[], at: number, inRun: (character: string) => boolean): number {
  let start = at
  while (start > 0 && inRun(characters[start - 1])) start -= 1
  return start
}

/** Whether the run of underscores that ends at `at` opens its word, as the first ones of `__init__` do. */
function underscoresOpen(characters: readonly string[], at: number): boolean {
  const start = runStart(characters, at, (character) => character === '_')
  return !isWordCharacter(characters[start - 1])
}

/** Whether a line may end right before the character at `at`, which is not the first. */
function endsLineBefore(characters: readonly string[], at: number): boolean {
  const character = characters[at]
  const before = characters[at - 1]
  const after = characters[at + 1]
  if (character === '.') {
    if (!endsStem(before)) return runAfterSeparator(characters, at)
    // Before an internal dot that a letter or an underscore follows, where the part after it is short.
    // A dot that opens or closes a word is no place, and neither is one that a digit follows: a line
    // that starts with `.1` reads as a fraction, so `libfoo.so.1` ends a line before `.so` and not
    // before the `.1`.
    return (isLetter(after) || after === '_') && partLength(characters, at + 1) <= SHORT_PART
  }
  // After an internal dot, where the part that follows it is longer.
  if (before === '.' && dotLeavesLine(characters, at - 1)) return true
  if (character === '@') {
    if (AFTER_RUN.has(before)) return runAfterSeparator(characters, at)
    return isWordCharacter(after) && atSignInside(characters, at)
  }
  if (character === '-') {
    // Before a run of hyphens that follows a letter or a digit, unless a digit stands on both sides.
    if (before === '-' || !isWordCharacter(before)) return runAfterSeparator(characters, at)
    let end = at
    while (characters[end] === '-') end += 1
    const following = characters[end]
    return isWordCharacter(following) && !(isDigit(before) && isDigit(following))
  }
  if (before === '_') return !underscoresOpen(characters, at - 1) && isWordCharacter(character)
  return runAfterSeparator(characters, at)
}

/** Whether the line ends after the dot at `dot`: an internal dot that a letter follows and a long part. */
function dotLeavesLine(characters: readonly string[], dot: number): boolean {
  return endsStem(characters[dot - 1]) && isLetter(characters[dot + 1]) && partLength(characters, dot + 1) > SHORT_PART
}

/**
 * Whether the at sign at `at`, which no run of slashes or the like precedes, stands inside its word:
 * what stands before it is text, a quote that closes the text it follows (`"sam"@example.com`) or
 * a closing bracket, not the start of the word, an opening quote or bracket, another at sign, or a dot or
 * a hyphen (a run of those belongs to what follows).
 */
function atSignInside(characters: readonly string[], at: number): boolean {
  const before = characters[at - 1]
  if (endsStem(before)) return true
  if (QUOTES.has(before)) return !opensWord(characters[at - 2])
  return !(opensWord(before) || before === '@' || before === '.' || before === '-')
}

/**
 * Whether the run of separators that ends right before `at` closes a part, and what follows it may
 * start the next: a word, or a dot, an underscore, an at sign or a hyphen that a word follows.
 */
function runAfterSeparator(characters: readonly string[], at: number): boolean {
  const before = characters[at - 1]
  if (!AFTER_RUN.has(before)) return false
  const character = characters[at]
  if (AFTER_RUN.has(character)) return false
  const start = runStart(characters, at - 1, (one) => AFTER_RUN.has(one))
  // A run that opens its word (the slash of a path) belongs to what follows it.
  if (opensWord(characters[start - 1])) return false
  // A dot that a digit follows starts no line, whatever stands before it.
  if (character === '.') return !isDigit(characters[at + 1])
  return isWordCharacter(character) || character === '_' || character === '@' || character === '-'
}
