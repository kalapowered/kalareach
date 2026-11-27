/**
 * Where a technical word may end a line.
 *
 * A technical word is an application identifier, a path, a command's option, a host name or an
 * address: text a person did not write as prose, with its own separators and no spaces to break
 * at. The engine breaks such a word wherever the line ends, in the middle of a part. The parts
 * below are the places it may end a line instead.
 *
 * A line may end at an internal dot: one that follows a letter, a digit or an underscore (any
 * underscore, whether the run opens the word or closes a part: `_.py`, `main_.py`) and that a letter or
 * an underscore follows. Where the part after the dot is short, four characters or fewer, the line ends
 * before the dot, so that a familiar ending stays whole (`KalaReach` and `.app`, `archive` and `.tar`
 * and `.gz`, `_` and `.py`). Where it is longer, the line ends after the dot: a dot in front would only
 * make the part wider, and a part wider than its line is cut sooner (`com.` and `kalareach.` and
 * `companion`).
 *
 * A line may end before an at sign that stands inside its word and that a letter or a digit follows
 * (`git` and `@host`): after text or an underscore, after a quote that closes (`"sam"` and `@example`,
 * `"a("` and `@example`), after a closing bracket or another sign (`(sam)` and `@example`, `sam!` and
 * `@example`). Whether a quote closes or opens is read from the quotes of the word, followed from its
 * start, and not from the character before it. A line may also end before a run of hyphens, so that an
 * option keeps its hyphens: `--cache-dir` ends a line at `--cache` and never between `--` and `cache`.
 * It may end after a run of underscores, and after a run of slashes, backslashes, colons and equals
 * signs: a run of such separators is one place, after its last character. A dot, an at sign or a hyphen
 * that follows such a run starts a part only where a letter or a digit stands further on in the word,
 * past the signs that follow it (`../../x` keeps its places, `a/.`, `a/@` and `--input=-` are not cut),
 * so that no mark is left alone at the end of a line.
 *
 * These never end a line: a separator that opens a word (the slash of a path, the dot of `.local`, the
 * underscores of `__init__`, the at sign of `@types`, of `(@x)`, of `"@x"` and of `--file="@name"`, where
 * the quote opens); a dot that a sign precedes, unless a run of slashes, backslashes, colons or equals
 * signs does (`report!.txt`), or that a digit follows (an address, a version or a file's number is not
 * cut, and no line starts with `.1`); a dot or
 * an at sign that closes a word (the stop of a sentence, the root dot of a host name, `sam@`); an at sign
 * after another at sign, a dot or a hyphen; and a run of hyphens that opens a word or follows a quote. A
 * word with a space in it keeps its spaces as the places the engine breaks at already.
 *
 * What the model does not handle. It reads text by rules; it is not a parser of quoting:
 * - A backslash escape inside a quote: in `"a\"@x"` the escaped quote closes the quote, so a line may
 *   end before the at sign, inside the quoted text.
 * - A quote that is never closed stays open to the end of the word, and it decides how each later quote
 *   reads.
 * - Typographic quotes: `“` and `”` are text, not quotes, so a line may end after the opening one in
 *   `“@x”`.
 * - Combining marks: they are not letters. In a decomposed `café.txt` no line may end before `.txt`,
 *   and the four characters that a short part may have are code points, marks included.
 * - A second opening quote that closes the first: in `x="a,y="@b"` the quote after `y=` has the
 *   innermost open quote's character, so it closes the first quote and a line may end before the at sign.
 *
 * The word is read once, from its start. The walk carries what it has seen (the quotes that are open, and
 * whether the run of underscores, and the run of slashes and the like, that it is in opened its word), so
 * that no rule looks back over the word. A rule looks ahead only for the next five characters of a part,
 * for the end of a run of hyphens that starts at the character, and, once for all the marks of a run of
 * signs, for the next letter, digit or space. The time is linear in the length of the word.
 */

/** The longest part after a dot that keeps the dot in front of it. */
const SHORT_PART = 4

/** Separators after which a run ends a line when a word follows. */
const AFTER_RUN = new Set(['/', '\\', ':', '='])

/** The signs that start a part after a run of separators only where text follows them. */
const MARKS = new Set(['.', '@', '-'])

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

function isSpace(character: string | undefined): boolean {
  return character !== undefined && /\s/u.test(character)
}

/** Whether `character` ends the part that follows a dot: a separator, a space, or the word's end. */
function endsPart(character: string | undefined): boolean {
  return character === undefined || /[\s._/\\:=@-]/u.test(character)
}

/** Whether the part that starts at `from` has more than `SHORT_PART` characters; it reads at most one more than that. */
function isLongPart(characters: readonly string[], from: number): boolean {
  for (let at = from; at <= from + SHORT_PART; at += 1) {
    if (endsPart(characters[at])) return false
  }
  return true
}

/** Whether `character` starts a word: the text start, a space, or an opening quote or bracket. */
function opensWord(character: string | undefined): boolean {
  return character === undefined || isSpace(character) || OPENERS.has(character)
}

/** What the walk through a word has seen so far. A place's rule reads it, and does not look back. */
interface Walk {
  /** The quotes that are open, the innermost last. */
  readonly quotes: string[]
  /** Whether the latest quote opened a quote, as against closing one. */
  quoteOpened: boolean
  /** Whether the run of underscores in hand opened its word, as the first ones of `__init__` do. */
  underscoresOpened: boolean
  /** Whether the run of slashes, backslashes, colons or equals signs in hand opened its word. */
  separatorsOpened: boolean
  /** The first character, from the latest sign that asked, that is a letter, a digit, a space or the word's end. */
  anchor: number
}

/**
 * The parts of `text`, in order, that a line may end between. Joined, they are `text`: nothing is
 * added, dropped or changed.
 */
export function breakParts(text: string): readonly string[] {
  const characters = Array.from(text)
  const walk: Walk = { quotes: [], quoteOpened: false, underscoresOpened: false, separatorsOpened: false, anchor: -1 }
  const parts: string[] = []
  let current = ''
  for (let at = 0; at < characters.length; at += 1) {
    if (at > 0 && endsLineBefore(characters, at, walk)) {
      parts.push(current)
      current = ''
    }
    current += characters[at]
    follow(characters, at, walk)
  }
  if (current !== '') parts.push(current)
  return parts.filter((part) => part !== '')
}

/**
 * Takes the character at `at` into the walk. A quote follows the quotes of the word: one that has the
 * innermost open quote's character closes it; any other quote opens one, unless a letter or a digit stands
 * before it (the apostrophe of `it's`, the stray quote of `sam"`), which makes it close what it follows and
 * open nothing. What stands before the quote says nothing by itself: the bracket of `"a("` is text inside
 * a quote, the equals sign of `--file="` stands before a quote that opens.
 */
function follow(characters: readonly string[], at: number, walk: Walk): void {
  const character = characters[at]
  const before = characters[at - 1]
  if (QUOTES.has(character)) {
    if (walk.quotes[walk.quotes.length - 1] === character) {
      walk.quotes.pop()
      walk.quoteOpened = false
    } else {
      walk.quoteOpened = !isWordCharacter(before)
      if (walk.quoteOpened) walk.quotes.push(character)
    }
  } else if (character === '_') {
    if (before !== '_') walk.underscoresOpened = !isWordCharacter(before)
  } else if (AFTER_RUN.has(character) && !AFTER_RUN.has(before)) {
    walk.separatorsOpened = opensWord(before)
  }
}

/** Whether a line may end right before the character at `at`, which is not the first. */
function endsLineBefore(characters: readonly string[], at: number, walk: Walk): boolean {
  const character = characters[at]
  const before = characters[at - 1]
  const after = characters[at + 1]
  if (character === '.') {
    if (!endsStem(before)) return runAfterSeparator(characters, at, walk)
    // Before an internal dot that a letter or an underscore follows, where the part after it is short.
    // A dot that opens or closes a word is no place, and neither is one that a digit follows: a line
    // that starts with `.1` reads as a fraction, so `libfoo.so.1` ends a line before `.so` and not
    // before the `.1`.
    return (isLetter(after) || after === '_') && !isLongPart(characters, at + 1)
  }
  // After an internal dot, where the part that follows it is longer.
  if (before === '.' && dotLeavesLine(characters, at - 1)) return true
  if (character === '@') {
    if (AFTER_RUN.has(before)) return runAfterSeparator(characters, at, walk)
    return isWordCharacter(after) && atSignInside(characters, at, walk)
  }
  if (character === '-') {
    // Before a run of hyphens that follows a letter or a digit, unless a digit stands on both sides.
    if (before === '-' || !isWordCharacter(before)) return runAfterSeparator(characters, at, walk)
    let end = at
    while (characters[end] === '-') end += 1
    const following = characters[end]
    return isWordCharacter(following) && !(isDigit(before) && isDigit(following))
  }
  if (before === '_') return !walk.underscoresOpened && isWordCharacter(character)
  return runAfterSeparator(characters, at, walk)
}

/** Whether the line ends after the dot at `dot`: an internal dot that a letter follows and a long part. */
function dotLeavesLine(characters: readonly string[], dot: number): boolean {
  return endsStem(characters[dot - 1]) && isLetter(characters[dot + 1]) && isLongPart(characters, dot + 1)
}

/**
 * Whether the at sign at `at`, which no run of slashes or the like precedes, stands inside its word:
 * what stands before it is text, a quote that closes (`"sam"@example.com`, `"a("@example.com`) or a
 * closing bracket or other sign (`(sam)@example.com`, `sam!@example.com`), and not the start of the
 * word, a quote that opens (`"@x"`, `--file="@name"`), an opening bracket, another at sign, or a dot or a
 * hyphen (a run of those belongs to what follows).
 */
function atSignInside(characters: readonly string[], at: number, walk: Walk): boolean {
  const before = characters[at - 1]
  if (endsStem(before)) return true
  if (QUOTES.has(before)) return !walk.quoteOpened
  return !(opensWord(before) || before === '@' || before === '.' || before === '-')
}

/**
 * Whether the run of separators that ends right before `at` closes a part, and what follows it may
 * start the next: a word or an underscore, or a dot, an at sign or a hyphen that text follows.
 */
function runAfterSeparator(characters: readonly string[], at: number, walk: Walk): boolean {
  if (!AFTER_RUN.has(characters[at - 1])) return false
  const character = characters[at]
  if (AFTER_RUN.has(character)) return false
  // A run that opens its word (the slash of a path) belongs to what follows it.
  if (walk.separatorsOpened) return false
  if (character === '_' || isWordCharacter(character)) return true
  if (!MARKS.has(character)) return false
  // A dot that a digit follows starts no line, whatever stands before it.
  if (character === '.' && isDigit(characters[at + 1])) return false
  return textFollows(characters, at, walk)
}

/**
 * Whether a letter or a digit follows the signs that start at `at`: the first character from `at` that is
 * not a sign is text, and not a space or the word's end. The walk keeps where that character stands, so
 * the signs of one run ask once for all.
 */
function textFollows(characters: readonly string[], at: number, walk: Walk): boolean {
  if (walk.anchor < at) {
    let end = at
    while (end < characters.length && !isWordCharacter(characters[end]) && !isSpace(characters[end])) end += 1
    walk.anchor = end
  }
  return isWordCharacter(characters[walk.anchor])
}
