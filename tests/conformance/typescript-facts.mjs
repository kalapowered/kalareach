// Reads TypeScript and JavaScript sources with the TypeScript compiler the packages already depend
// on, and prints, for each file, its test calls and its comments as JSON on standard output.
//
//   node tests/conformance/typescript-facts.mjs <repository> <file>...
//
// A test call is a call of `it`, `test`, `describe` or `suite`, including their modifiers
// (`it.skip`, `test.describe`, `describe.each(table)`), whose first argument is the title. The
// conformance report decides which test each comment keys; this script only says where things are.
// It uses the compiler's parser rather than a pattern so that a comment marker inside a string, a
// template or JSX text is never read as a comment.

import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const [repository, ...files] = process.argv.slice(2)
if (!repository) {
  process.stderr.write('usage: typescript-facts.mjs <repository> <file>...\n')
  process.exit(2)
}

// The compiler, from the first package of this script's own repository that depends on it, so a
// tree the report reads need not have one installed.
const own = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
let ts
for (const directory of ['apps/companion', 'packages/protocol', 'packages/plugin-sdk']) {
  try {
    ts = createRequire(join(own, directory, 'package.json'))('typescript')
    break
  } catch {
    // The next package, or the error below.
  }
}
if (!ts) {
  process.stderr.write(
    'typescript-facts: the TypeScript compiler is not installed; run `pnpm install --frozen-lockfile`\n'
  )
  process.exit(3)
}

const SUITES = new Set(['describe', 'suite'])
const TESTS = new Set(['it', 'test'])

// The names along a callee: `test.describe.serial` is test, describe, serial; `describe.each(t)`
// is describe, each.
function calleeNames(expression) {
  const names = []
  let node = expression
  for (;;) {
    if (ts.isIdentifier(node)) {
      names.unshift(node.text)
      return names
    }
    if (ts.isPropertyAccessExpression(node)) {
      names.unshift(node.name.text)
      node = node.expression
    } else if (ts.isCallExpression(node)) {
      node = node.expression
    } else {
      return null
    }
  }
}

function titleOf(argument, source) {
  if (!argument) return { title: null, text: '' }
  if (ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument)) {
    return { title: argument.text, text: argument.text }
  }
  return { title: null, text: argument.getText(source) }
}

const results = []
for (const file of files) {
  const path = join(repository, file)
  const text = readFileSync(path, 'utf8')
  const kind = /\.(tsx|jsx)$/.test(file) ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind)
  const line = (position) => source.getLineAndCharacterOfPosition(position).line + 1
  const calls = []
  const comments = new Map()

  const visit = (node, parent) => {
    let own = parent
    if (ts.isCallExpression(node) && node.arguments.length > 0) {
      const names = calleeNames(node.expression)
      const root = names?.[0]
      const isSuite = names && (SUITES.has(root) || names.slice(1).some((name) => SUITES.has(name)))
      const isTest = names && !isSuite && TESTS.has(root)
      const first = node.arguments[0]
      const titled =
        first &&
        (ts.isStringLiteral(first) ||
          ts.isNoSubstitutionTemplateLiteral(first) ||
          ts.isTemplateExpression(first) ||
          ts.isIdentifier(first) ||
          ts.isBinaryExpression(first))
      // `describe.each(table)` is itself a call whose result is called with the title.
      const table = names && ts.isCallExpression(node.expression) === false && names.includes('each')
      if ((isSuite || isTest) && titled && !table) {
        const start = node.getStart(source)
        const { title, text: titleText } = titleOf(first, source)
        calls.push({
          kind: isSuite ? 'suite' : 'test',
          title,
          titleText,
          line: line(start),
          column: source.getLineAndCharacterOfPosition(start).character + 1,
          end: line(node.getEnd()),
          // The line vitest reports the test at: where its callee ends and its arguments open,
          // which for `it.each(table)(title, ...)` is the line after the table, not the `it`.
          reported: line(node.expression.getEnd()),
          parent
        })
        own = calls.length - 1
      }
    }
    // Every comment in the file is the leading trivia of some token, and each token is a child
    // here. JSX text is not trivia, so it is never read as a comment.
    for (const child of node.getChildren(source)) {
      if (child.kind !== ts.SyntaxKind.JsxText) {
        for (const range of ts.getLeadingCommentRanges(text, child.pos) ?? []) {
          if (!comments.has(range.pos)) {
            comments.set(range.pos, {
              line: line(range.pos),
              endLine: line(range.end),
              text: text.slice(range.pos, range.end),
              next: line(child.getStart(source))
            })
          }
        }
      }
      visit(child, own)
    }
  }
  visit(source, null)

  const firstStatement = source.statements.length > 0 ? line(source.statements[0].getStart(source)) : null
  results.push({
    file,
    calls,
    comments: [...comments.values()].sort((a, b) => a.line - b.line),
    firstStatement
  })
}
process.stdout.write(JSON.stringify({ files: results }))
