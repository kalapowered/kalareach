/**
 * Where a technical word may end a line.
 *
 * A technical word is an application identifier, a path, a command's option, a host name or an
 * address: text a person did not write as prose, with its own separators and no spaces to break
 * at. The engine breaks such a word wherever the line ends, in the middle of a part. The parts
 * below are the places it may end a line instead.
 *
 * A line may end after a dot, a slash, a backslash, a colon, an at sign, an underscore or an
 * equals sign, and before a run of hyphens, so that an option keeps its hyphens: `--cache-dir`
 * ends a line at `--cache` and never between `--` and `cache`. These never end a line: a separator
 * that opens a word (the slash of a path, the dot of `.local`), a dot between two digits (an
 * address or a version is one number), and a run of hyphens that opens a word or follows a quote.
 * A word with a space in it keeps its spaces as the places the engine breaks at already.
 */

/** Characters after which a run ends a line when a word character follows. */
const AFTER_RUN = new Set(['/', '\\', ':', '@', '='])

const OPENERS = new Set(['"', "'", '`', '(', '[', '{', '<'])

function isWordCharacter(character: string | undefined): boolean {
  return character !== undefined && /[\p{L}\p{N}]/u.test(character)
}

function isDigit(character: string | undefined): boolean {
  return character !== undefined && /\p{N}/u.test(character)
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
    const character = characters[at]
    const before = characters[at - 1]
    const after = characters[at + 1]
    if (character === '-' && before !== '-' && isWordCharacter(before)) {
      // Before a run of hyphens that follows a letter or a digit, unless a digit stands on both sides.
      let end = at
      while (characters[end] === '-') end += 1
      const following = characters[end]
      if (isWordCharacter(following) && !(isDigit(before) && isDigit(following))) {
        parts.push(current)
        current = ''
      }
    }
    current += character
    if (!endsLineAfter(characters, at, before, after)) continue
    parts.push(current)
    current = ''
  }
  if (current !== '') parts.push(current)
  return parts.filter((part) => part !== '')
}

/** Whether a line may end right after the character at `at`. */
function endsLineAfter(
  characters: readonly string[],
  at: number,
  before: string | undefined,
  after: string | undefined
): boolean {
  const character = characters[at]
  if (character === '.' || character === '_') {
    // Between two word characters only, and not between two digits.
    return isWordCharacter(before) && isWordCharacter(after) && !(character === '.' && isDigit(before) && isDigit(after))
  }
  if (!AFTER_RUN.has(character) || AFTER_RUN.has(after ?? '')) return false
  // The end of a run of such characters: not one that opens its word, and one a word follows.
  let start = at
  while (start > 0 && AFTER_RUN.has(characters[start - 1])) start -= 1
  if (opensWord(characters[start - 1])) return false
  return isWordCharacter(after) || after === '.' || after === '_'
}
