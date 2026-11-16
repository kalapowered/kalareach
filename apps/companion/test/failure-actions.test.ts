/**
 * The words for a failure (KR-REQ-23.57).
 *
 * Section 23: the interface translates a code into a direct action and does not display raw
 * protocol internals by default. Native code attaches the action a code maps to, by its key, to
 * each failure it answers with, and the page says that action beside the host's own words.
 */

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

import { failureMessage, USER_ACTIONS } from '../src/host/port'

import retrySource from '../../../crates/kr-client/src/retry.rs?raw'
import capacityRefusals from './fixtures/capacity-refusals.json'

describe('the words for a failure', () => {
  it('offer the direct action its code translates to, and never the code', () => {
    const said = failureMessage({
      code: 'OUTCOME_UNKNOWN',
      message: 'The host lost the answer.',
      user_action: 'check_the_outcome'
    })
    expect(said).toContain('Check whether this went through before trying it again.')
    expect(said).not.toContain('OUTCOME_UNKNOWN')
  })

  it('say the host’s own words first and the action after them, for each action there is', () => {
    for (const [key, action] of Object.entries(USER_ACTIONS)) {
      expect(
        failureMessage({ code: 'PERMISSION_DENIED', message: 'The host said no.', user_action: key }),
        key
      ).toBe(`The host said no. ${action}`)
    }
    expect(Object.keys(USER_ACTIONS)).toHaveLength(7)
  })

  it('end the host’s words before the action when they do not end a sentence themselves', () => {
    expect(
      failureMessage({
        code: 'UPSTREAM_UNAVAILABLE',
        message: 'this application is not connected to a host',
        user_action: 'wait'
      })
    ).toBe('this application is not connected to a host. Wait a moment and try again.')
    expect(
      failureMessage({ code: 'RATE_LIMITED', message: 'slow down', user_action: 'wait' })
    ).toBe('slow down. Wait a moment and try again.')
  })

  it('leave out the code the client library puts in front of a host’s words, as native code sends it', () => {
    expect(
      failureMessage({
        code: 'UNKNOWN_SESSION',
        message: 'UNKNOWN_SESSION: no session has that number.',
        user_action: 'resync'
      })
    ).toBe('no session has that number. Refresh: this view has fallen behind.')
    expect(
      failureMessage({ code: 'SESSION_CLOSED', message: 'SESSION_CLOSED: the session closed.', user_action: 'nothing' })
    ).toBe('the session closed.')
    // Only its own code goes: another code in the words is the host's to say.
    expect(
      failureMessage({ code: 'SESSION_CLOSED', message: 'STALE_SESSION: the session closed.', user_action: 'nothing' })
    ).toBe('STALE_SESSION: the session closed.')
    // A refusal with no words after the code is a failure with no words.
    expect(failureMessage({ code: 'SESSION_CLOSED', message: 'SESSION_CLOSED: ', user_action: 'nothing' })).toBe(
      'Something went wrong.'
    )
  })

  it('offer the action of a failure that came with no words of its own too', () => {
    expect(failureMessage({ code: 'PAIRING_EXPIRED', message: ' ', user_action: 'pair_again' })).toBe(
      'Something went wrong. Pair this device with the host again.'
    )
  })

  it('keep the message alone for an action that asks nothing of the person, and for one it does not know', () => {
    expect(failureMessage({ code: 'SESSION_CLOSED', message: 'The session closed.', user_action: 'nothing' })).toBe(
      'The session closed.'
    )
    expect(failureMessage({ code: 'X', message: 'The host said no.', user_action: 'retry' })).toBe(
      'The host said no.'
    )
    expect(failureMessage({ code: 'X', message: 'The host said no.' })).toBe('The host said no.')
    expect(failureMessage(new Error('The call failed.'))).toBe('The call failed.')
  })

  it('word each action exactly as the client library does', () => {
    // The library's own sentence for each action, read from its source: the arms of
    // `UserAction::as_str` name the keys and the arms of `UserAction::message` the words.
    const arms = (from: string, to: string) => {
      const start = retrySource.indexOf(from)
      const end = retrySource.indexOf(to, start)
      const body = retrySource.slice(start, end)
      return Array.from(body.matchAll(/Self::(\w+) => "((?:[^"\\]|\\.)*)"/g), (arm) => [arm[1], arm[2]] as const)
    }
    const keys = new Map(arms('pub const fn as_str(self)', 'pub const fn message(self)'))
    const words = arms('pub const fn message(self)', '\n}\n')
    const described: Record<string, string> = {}
    for (const [variant, sentence] of words) {
      const key = keys.get(variant)
      if (key === undefined) throw new Error(`${variant} has no key`)
      if (sentence !== '') described[key] = sentence
    }
    expect(described).toEqual(USER_ACTIONS)
  })
})

describe('a refusal that says its own wait', () => {
  /** Every refusal native code sends for want of capacity, as the golden file holds it. */
  const sent = Object.entries(capacityRefusals).flatMap(([surface, kinds]) =>
    Object.entries(kinds).map(([kind, one]) => ({ name: `${surface} ${kind}`, ...one }))
  )

  it('is read as the whole text that native code composed, with no line of the page’s own after it', () => {
    expect(sent.length).toBeGreaterThanOrEqual(5)
    for (const one of sent) {
      const said = failureMessage({ code: one.code, message: one.message, user_action: one.user_action })
      expect(said, one.name).toBe(one.page)
      if (one.user_action === 'nothing') {
        expect(said, one.name).not.toContain(USER_ACTIONS.wait)
      } else {
        expect(said, one.name).toMatch(/ Wait a moment and try again\.$/)
      }
    }
  })

  const files = import.meta.glob('../src/**/*.{ts,tsx}', {
    query: '?raw',
    import: 'default',
    eager: true
  })

  /**
   * The ways a source reads the action of a failure, counted in its syntax tree and not in its text:
   * a property read, an element read, a binding of the member (a declaration, a parameter or an
   * assignment pattern) and a use of the table the key is looked up in. A comment and a string are
   * no reader.
   */
  const readsOf = (text: string, fileName = 'source.ts') => {
    const source = ts.createSourceFile(
      fileName,
      text,
      ts.ScriptTarget.Latest,
      true,
      fileName.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    )
    const reads = { property: 0, element: 0, binding: 0, table: 0 }
    const named = (name: ts.Node | undefined): boolean =>
      name !== undefined &&
      (ts.isComputedPropertyName(name)
        ? ts.isStringLiteralLike(name.expression) && name.expression.text === 'user_action'
        : (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === 'user_action')
    const visit = (node: ts.Node): void => {
      if (ts.isPropertyAccessExpression(node) && node.name.text === 'user_action') reads.property += 1
      else if (ts.isElementAccessExpression(node) && named(node.argumentExpression)) reads.element += 1
      else if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent) && named(node.propertyName ?? node.name))
        reads.binding += 1
      else if (
        (ts.isShorthandPropertyAssignment(node) || ts.isPropertyAssignment(node)) &&
        named(node.name) &&
        ts.isBinaryExpression(node.parent.parent) &&
        node.parent.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        node.parent.parent.left === node.parent
      )
        reads.binding += 1
      else if (ts.isIdentifier(node) && node.text === 'USER_ACTIONS') reads.table += 1
      ts.forEachChild(node, visit)
    }
    visit(source)
    return reads
  }

  it('meets one reader of the action, counted by its reads, so that no second reader adds a line after the first', () => {
    const readers = Object.entries(files)
      .filter(([path]) => !/\/src\/host\/fake[^/]*\.ts$/.test(path))
      .map(([path, text]) => [path, readsOf(text, path)] as const)
      .filter(([, reads]) => Object.values(reads).some((count) => count > 0))
    // `failureMessage` reads the key once and looks it up in the table: one property read, and the
    // table's own declaration, its membership test and its lookup.
    expect(readers).toEqual([['../src/host/port.ts', { property: 1, element: 0, binding: 0, table: 3 }]])
  })

  it('counts a second reader of the action in each form it can take', () => {
    const forms: readonly (readonly [keyof ReturnType<typeof readsOf>, string])[] = [
      ['property', 'const key = failure.user_action'],
      ['property', 'const key = failure?.user_action'],
      ['element', "const key = failure['user_action']"],
      ['element', 'const key = failure[`user_action`]'],
      ['binding', 'const { user_action } = failure'],
      ['binding', 'const { code, user_action: key } = failure'],
      ['binding', "const { 'user_action': key } = failure"],
      ['binding', "const { ['user_action']: key } = failure"],
      ['binding', 'const { user_action }: HostError = failure'],
      ['binding', 'function show({ user_action }: HostError) { return user_action }'],
      ['binding', 'const show = ({ code, user_action: key }: HostError) => key'],
      ['binding', 'let key; ({ user_action: key } = failure)'],
      ['table', 'const line = USER_ACTIONS.wait']
    ]
    for (const [how, second] of forms) {
      const reads = readsOf(second)
      expect(reads[how], second).toBe(1)
      expect(Object.values(reads).reduce((total, count) => total + count, 0), second).toBe(1)
    }
  })

  it('counts neither a comment nor a string as a reader of the action', () => {
    const none = [
      '// failure.user_action',
      '/* const { user_action } = failure; USER_ACTIONS */',
      "const words = 'failure.user_action'",
      'const text = `{ user_action } = failure`',
      'const valid = true // failure.user_action',
      'const made = { user_action: "wait" }',
      'interface HostError { readonly user_action: string }'
    ].join('\n')
    expect(readsOf(none)).toEqual({ property: 0, element: 0, binding: 0, table: 0 })
  })

  /**
   * The forms the scan above cannot follow to a read of the action, found with the compiler's types:
   * a spread or a rest of a failure object, an element read or a computed key that is not a string
   * literal on one, and an iteration over its members. A form is one only where the value it works
   * on has the member `user_action` in its type. A string-literal computed key is a read, and
   * `readsOf` counts it.
   */
  const unfollowedIn = (source: ts.SourceFile, checker: ts.TypeChecker): string[] => {
    const holdsTheAction = (node: ts.Node | undefined): boolean => {
      if (node === undefined) return false
      const type = checker.getTypeAtLocation(node)
      const members = type.isUnion() ? type.types : [type]
      return members.some((one) => one.getProperty('user_action') !== undefined)
    }
    /** The value a destructuring takes apart: a declaration's initializer or type, or a parameter's type. */
    const taken = (pattern: ts.Node): ts.Node | undefined => {
      const owner = pattern.parent
      if (ts.isVariableDeclaration(owner)) return owner.initializer ?? owner.type
      if (ts.isParameter(owner)) return owner.type
      return undefined
    }
    const found: string[] = []
    const visit = (node: ts.Node): void => {
      if (ts.isSpreadAssignment(node) && holdsTheAction(node.expression)) found.push('spread')
      else if (
        ts.isBindingElement(node) &&
        ts.isObjectBindingPattern(node.parent) &&
        holdsTheAction(taken(node.parent))
      ) {
        if (node.dotDotDotToken !== undefined) found.push('rest')
        else if (
          node.propertyName !== undefined &&
          ts.isComputedPropertyName(node.propertyName) &&
          !ts.isStringLiteralLike(node.propertyName.expression)
        )
          found.push('computed key')
      } else if (
        ts.isElementAccessExpression(node) &&
        !ts.isStringLiteralLike(node.argumentExpression) &&
        holdsTheAction(node.expression)
      )
        found.push('computed key')
      else if (ts.isForInStatement(node) && holdsTheAction(node.expression)) found.push('iteration')
      else if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression) &&
        node.expression.expression.text === 'Object' &&
        ['keys', 'values', 'entries', 'getOwnPropertyNames', 'fromEntries'].includes(node.expression.name.text) &&
        node.arguments.some((argument) => holdsTheAction(argument))
      )
        found.push('iteration')
      ts.forEachChild(node, visit)
    }
    visit(source)
    return found
  }

  /** A program over `texts` (by file name), with the project's own options where a file of it is wanted. */
  const programOf = (texts: Readonly<Record<string, string>>, options: ts.CompilerOptions): ts.Program => {
    const host = ts.createCompilerHost(options)
    const original = host.getSourceFile.bind(host)
    host.getSourceFile = (name, ...rest) =>
      name in texts ? ts.createSourceFile(name, texts[name], ts.ScriptTarget.Latest, true) : original(name, ...rest)
    host.fileExists = (name) => name in texts || ts.sys.fileExists(name)
    host.readFile = (name) => texts[name] ?? ts.sys.readFile(name)
    return ts.createProgram(Object.keys(texts), options, host)
  }

  const PLANT_OPTIONS: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2023,
    lib: ['lib.es2023.d.ts'],
    strict: true,
    noEmit: true,
    types: [],
    skipLibCheck: true
  }
  const FAILURE = 'declare const failure: { code: string; message: string; user_action: string }\n'
  const OTHER = 'declare const other: { a: number }\ndeclare const key: string\n'

  it('refuses what it cannot follow: each form on a failure object fails the scan, shown on a plant of each', () => {
    const plants: readonly (readonly [string, string])[] = [
      ['spread', 'export const copy = { ...failure, extra: 1 }'],
      ['spread', "export const { ['user_action']: said } = { ...failure }"],
      ['rest', 'export const { code, ...rest } = failure'],
      ['computed key', 'declare const key: string\nexport const said = failure[key]'],
      ['computed key', 'declare const key: string\nexport const { [key]: said } = failure'],
      ['iteration', 'export const names = Object.keys(failure)'],
      ['iteration', 'export const values = Object.values(failure)'],
      ['iteration', 'export const pairs = Object.entries(failure)'],
      ['iteration', 'export function each() { for (const name in failure) void name }']
    ]
    const texts = Object.fromEntries(plants.map(([, plant], at) => [`/plants/failing-${at}.ts`, FAILURE + plant]))
    const program = programOf(texts, PLANT_OPTIONS)
    const checker = program.getTypeChecker()
    plants.forEach(([form], at) => {
      const source = program.getSourceFile(`/plants/failing-${at}.ts`)
      expect(source, form).toBeDefined()
      expect(unfollowedIn(source!, checker), plants[at][1]).toContain(form)
    })
  })

  it('lets the same forms pass on a value that has no action, and a string-literal key is counted as a read', () => {
    const innocent = [
      'export const copy = { ...other }',
      'export const { a, ...rest } = other',
      'export const said = other[key as keyof typeof other]',
      'export const names = Object.keys(other)',
      'export const pairs = Object.entries(other)',
      'export function each() { for (const name in other) void name }',
      "export const { ['user_action']: said } = failure"
    ].join('\n')
    const program = programOf({ '/plants/innocent.ts': FAILURE + OTHER + innocent }, PLANT_OPTIONS)
    const source = program.getSourceFile('/plants/innocent.ts')!
    expect(unfollowedIn(source, program.getTypeChecker())).toEqual([])
    expect(readsOf("const { ['user_action']: key } = failure").binding).toBe(1)
  })

  it('meets no form it cannot follow on a failure object, outside the one formatter', { timeout: 120_000 }, () => {
    const root = decodeURIComponent(new URL('../', import.meta.url).pathname)
    const configFile = ts.readConfigFile(`${root}tsconfig.json`, (name) => ts.sys.readFile(name))
    const config = ts.parseJsonConfigFileContent(configFile.config, ts.sys, root)
    const sources = config.fileNames.filter((name) => name.includes('/src/') && !/\/src\/host\/fake[^/]*\.ts$/.test(name))
    const program = ts.createProgram(sources, config.options)
    const checker = program.getTypeChecker()
    const found = sources
      .filter((name) => !name.endsWith('/src/host/port.ts'))
      .map((name) => [name.slice(root.length), unfollowedIn(program.getSourceFile(name)!, checker)] as const)
      .filter(([, forms]) => forms.length > 0)
    expect(found).toEqual([])
  })
})
