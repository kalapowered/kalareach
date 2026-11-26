/**
 * A button's label wraps by default, and nothing in the interface's sources holds a button to one line.
 *
 * `.btn` lets its label wrap (`src/styles/components.css`), so a layout follows the person's text size
 * and no call asks for it. This reads the sources, not a page: it refuses the attribute that used to
 * ask for wrapping, anywhere, and any rule that makes a `.btn` single-line, a stylesheet rule on the
 * button itself or a style on a button element. A button that truly has to stay on one line is the
 * first one that needs an exception, and it brings the exception with it, in its own change.
 *
 * The cases below the real read draw each refused form and each form that is not refused, so the read
 * cannot pass for nothing.
 */

import { readFileSync, readdirSync } from 'node:fs'
import { cwd } from 'node:process'

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

interface Source {
  readonly file: string
  readonly text: string
}

/** The one-line values of `white-space`, and of `text-wrap` and `text-wrap-mode`, which hold a label on a line. */
const ONE_LINE = /^(nowrap|pre)$/i

/** A selector's subject: what it selects, after the last combinator, outside brackets and brackets' parentheses. */
function subject(selector: string): string {
  let depth = 0
  let start = 0
  for (let at = 0; at < selector.length; at += 1) {
    const each = selector[at]
    if (each === '(' || each === '[') depth += 1
    else if (each === ')' || each === ']') depth -= 1
    else if (depth === 0 && /[\s>+~]/.test(each)) start = at + 1
  }
  return selector.slice(start)
}

/** Whether a selector selects a `.btn` itself or one of its tone classes, which are drawn with it; not `.icon-btn`. */
function selectsButton(selector: string): boolean {
  return /(?<![\w-])\.btn(?![A-Za-z0-9_])/.test(subject(selector.trim()))
}

/** A selector list's selectors, split at the commas that are outside parentheses. */
function selectors(list: string): string[] {
  const found: string[] = []
  let depth = 0
  let start = 0
  for (let at = 0; at < list.length; at += 1) {
    if (list[at] === '(') depth += 1
    else if (list[at] === ')') depth -= 1
    else if (list[at] === ',' && depth === 0) {
      found.push(list.slice(start, at))
      start = at + 1
    }
  }
  found.push(list.slice(start))
  return found
}

/** Every style rule of a stylesheet, read by the engine's parser, those inside `@media` and `@supports` included. */
function styleRules(css: string): CSSStyleRule[] {
  const style = document.createElement('style')
  style.textContent = css
  document.head.append(style)
  const found: CSSStyleRule[] = []
  const visit = (rules: CSSRuleList): void => {
    for (const rule of Array.from(rules)) {
      if ('selectorText' in rule) found.push(rule as CSSStyleRule)
      else if ('cssRules' in rule) visit((rule as CSSGroupingRule).cssRules)
    }
  }
  if (style.sheet !== null) visit(style.sheet.cssRules)
  style.remove()
  return found
}

/** A stylesheet's refusals: each rule whose subject is a `.btn` and which holds its label to one line. */
function cssRefusals({ file, text }: Source): string[] {
  const found: string[] = []
  for (const rule of styleRules(text)) {
    if (!selectors(rule.selectorText).some(selectsButton)) continue
    for (const property of ['white-space', 'text-wrap', 'text-wrap-mode']) {
      const value = rule.style.getPropertyValue(property).trim()
      // A value that is not read as a word cannot be told from a one-line one, and is refused as well.
      if (ONE_LINE.test(value) || /var\(/.test(value)) {
        found.push(`${file}: "${rule.selectorText}" holds a button to one line with ${property}: ${value}`)
      }
    }
  }
  return found
}

/** A button element: `Button`, `CommitButton`, or any element drawn with the class `btn`. */
function isButton(element: ts.JsxOpeningLikeElement): boolean {
  const name = element.tagName.getText()
  if (name === 'Button' || name === 'CommitButton') return true
  return element.attributes.properties.some(
    (each) =>
      ts.isJsxAttribute(each) &&
      each.name.getText() === 'className' &&
      /(?<![\w-])btn(?![A-Za-z0-9_])/.test(each.initializer?.getText() ?? '')
  )
}

/** A source file's refusals: the retired attribute anywhere, and a style on a button that holds its label to one line. */
function sourceRefusals({ file, text }: Source): string[] {
  const found: string[] = []
  if (text.includes('data-wraps')) found.push(`${file}: the retired attribute data-wraps`)
  if (!/\.tsx$/.test(file)) return found
  const tree = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const visit = (node: ts.Node): void => {
    if ((ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) && isButton(node)) {
      for (const each of node.attributes.properties) {
        if (!ts.isJsxAttribute(each) || each.name.getText() !== 'style') continue
        const content = each.initializer?.getText() ?? ''
        if (/(whiteSpace|textWrap|textWrapMode)\s*:\s*['"](nowrap|pre)['"]/i.test(content)) {
          found.push(`${file}: a button element holds its label to one line with a style`)
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(tree)
  return found
}

function refusals(sources: readonly Source[]): string[] {
  return sources.flatMap((source) => [
    ...sourceRefusals(source),
    ...(source.file.endsWith('.css') ? cssRefusals(source) : [])
  ])
}

/** Every file under `folder`: a name that cannot be listed as a folder is a file. */
function filesUnder(folder: string): string[] {
  let names: string[]
  try {
    names = readdirSync(folder)
  } catch {
    return [folder]
  }
  return names.flatMap((name) => filesUnder(`${folder}/${name}`))
}

/** The interface's own sources: its scripts, its stylesheets, its two entry pages and its browser tests. */
function interfaceSources(): Source[] {
  const root = cwd()
  const files = [...filesUnder(`${root}/src`), ...filesUnder(`${root}/e2e`), `${root}/index.html`, `${root}/harness.html`].filter(
    (file) => /\.(tsx?|css|html)$/.test(file)
  )
  return files.map((file) => ({ file: file.slice(root.length + 1), text: readFileSync(file, 'utf8') }))
}

describe('the interface lets a button wrap and holds none to one line', () => {
  it('has no retired attribute and no rule or style that holds a button to one line', () => {
    const sources = interfaceSources()
    expect(sources.length, 'the read finds the interface sources').toBeGreaterThan(100)
    expect(sources.some((source) => source.file === 'src/styles/components.css')).toBe(true)
    expect(refusals(sources)).toEqual([])
  })

  it('refuses the retired attribute wherever it comes back', () => {
    expect(refusals([{ file: 'src/views/A.tsx', text: 'export const a = <Button data-wraps>Go</Button>' }])).toHaveLength(1)
    expect(refusals([{ file: 'src/views/A.tsx', text: 'export const a = <button className="btn" data-wraps="">Go</button>' }])).toHaveLength(1)
    expect(refusals([{ file: 'src/styles/a.css', text: '.btn[data-wraps] { white-space: normal }' }])).toHaveLength(1)
    expect(refusals([{ file: 'e2e/a.spec.ts', text: "const rule = '.btn[data-wraps] {}'" }])).toHaveLength(1)
  })

  it('refuses a rule that holds a button to one line, in every form it can be written', () => {
    const one = (css: string): string[] => refusals([{ file: 'src/styles/a.css', text: css }])
    expect(one('.btn { white-space: nowrap }')).toHaveLength(1)
    expect(one('.toolbar > .btn { white-space: pre }')).toHaveLength(1)
    expect(one('.btn-primary { white-space: nowrap; color: red }')).toHaveLength(1)
    expect(one('.card, .btn:hover { white-space: nowrap }')).toHaveLength(1)
    expect(one('@media (min-width: 40rem) { .m-shell .btn { text-wrap: nowrap } }')).toHaveLength(1)
    expect(one('.btn { text-wrap-mode: nowrap }')).toHaveLength(1)
    expect(one('.btn { white-space: var(--line) }')).toHaveLength(1)
    expect(one('.btn[data-armed="true"] { white-space: NOWRAP }')).toHaveLength(1)
  })

  it('refuses a style on a button element that holds its label to one line', () => {
    const one = (code: string): string[] => refusals([{ file: 'src/views/A.tsx', text: code }])
    expect(one("export const a = <Button style={{ whiteSpace: 'nowrap' }}>Go</Button>")).toHaveLength(1)
    expect(one("export const a = <CommitButton style={{ textWrap: 'nowrap' }} onCommit={f}>Go</CommitButton>")).toHaveLength(1)
    expect(one("export const a = <button className=\"btn btn-primary\" style={{ whiteSpace: 'pre' }}>Go</button>")).toHaveLength(1)
  })

  it('lets through what keeps a button wrapping, and what is not a button', () => {
    const css = (text: string): string[] => refusals([{ file: 'src/styles/a.css', text }])
    const code = (text: string): string[] => refusals([{ file: 'src/views/A.tsx', text }])
    expect(css('.icon-btn { white-space: nowrap }')).toEqual([])
    expect(css('.btn { white-space: normal; overflow-wrap: anywhere }')).toEqual([])
    expect(css('.btn .program { white-space: nowrap }')).toEqual([])
    expect(css('.btn:not(.quiet) { white-space: pre-wrap }')).toEqual([])
    expect(css('.badge, .tab { white-space: nowrap }')).toEqual([])
    expect(css('.button-bar { white-space: nowrap }')).toEqual([])
    expect(code("export const a = <span style={{ whiteSpace: 'nowrap' }}>Go</span>")).toEqual([])
    expect(code('export const a = <Button style={{ minBlockSize: target }}>Go</Button>')).toEqual([])
  })
})
