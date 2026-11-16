/**
 * The native bridge is named in the port module alone.
 *
 * THE CLAIM. No module of the page other than `src/host/tauri.ts` holds, as an identifier, a
 * property name or a whole string literal (a plain string or a template with no substitution), a
 * name of the table below (the TOKEN rule); no module holds a reference that the compiler resolves
 * to the DOM library's `alert` or `confirm`, which an injected script replaces (the SYMBOL rule,
 * for those two rows only); and none holds a string, or the head of a template, that is the
 * bridge's package or starts with its scope or with one of its URL schemes. The token rule reads
 * the TOKENS of each module, parsed by the project's own TypeScript compiler, so the form of the
 * access (a dot, a bracket with a literal, a template key, a destructuring, a variable taken from
 * the object, an import of any kind, a re-export, `require`) cannot hide a name that is written
 * out; a comment and the text of an element are not read. A template WITH a substitution gets the
 * package and address checks and NO check of a surface's name (`window[`ipc${''}`]` passes).
 * The symbol rule decides by what a name RESOLVES to, in a program made once from the page's own
 * compiler settings, so `window.alert`, `globalThis['alert']`, `self.alert`, `top.alert`, a
 * destructured `alert`, an alias (`const w = window; w.alert(…)`) and a bare `alert(…)` fail, and
 * a role string `"alert"`, a prop named `confirm` and its call, a question's kind and a local
 * function of that spelling pass, because they resolve elsewhere or to nothing.
 *
 * WHAT IT CANNOT SEE. A name that the program puts together at run time (`'__TAU' + 'RI__'`), a
 * template with a substitution that makes a name, a reference of the symbol kind that the compiler
 * cannot resolve (an `any`-typed receiver: `(window as any).alert`; the page's lint forbids that:
 * `eslint.config.js` takes `tseslint.configs.recommendedTypeChecked`, whose `no-explicit-any`,
 * `no-unsafe-member-access` and `no-unsafe-call` are errors, unless a module disables them with a
 * comment), and code that is made from a string, which `eslint.config.js` (`no-restricted-syntax`
 * against `new Function` and `eval(`) and the content policy (`src-tauri/tauri.conf.json`,
 * `security.csp`: `script-src 'self'`, no `unsafe-eval`) forbid.
 *
 * THE DERIVATION OF THE TABLE. It is read from every script that is injected into a page, at the
 * versions in `READ_AT` (the lock file's; a case fails when one differs, so that a person reads the
 * scripts again). The application's manifest (`src-tauri/Cargo.toml`, `src/lib.rs`) enables the
 * plugins clipboard-manager, dialog and opener, and its own platform plugin (native code, no page
 * script). The files, with what each defines or replaces:
 *
 * tauri 2.12.5, `scripts/` (composed by `scripts/init.js`; `src/manager/webview.rs:166-220` pushes them):
 * - `init.js`: composes the others; defines nothing. NONE.
 * - `freeze_prototype.js:5`: `Object.freeze(Object.prototype)`; a hardening, no native command. NONE.
 * - `process-ipc-message-fn.js`: a function template the two ipc scripts use; no global. NONE.
 * - `pattern.js:18`: `__TAURI_INTERNALS__.__TAURI_PATTERN__`, a constant on `__TAURI_INTERNALS__`. NONE (the name is a row).
 * - `ipc.js:142`: `__TAURI_INTERNALS__.ipc`; `ipc-protocol.js:88`: `.postMessage`; `core.js:13,51,55,59,64,81`:
 *   `convertFileSrc`, `transformCallback`, `unregisterCallback`, `runCallback`, `callbacks`, `invoke`: all
 *   properties of `__TAURI_INTERNALS__`, reached through that name. ROW `__TAURI_INTERNALS__`; scheme rows from
 *   `core.js:16-19`.
 * - `bundle.global.js:1`: `var __TAURI_IIFE__` and `window.__TAURI__=__TAURI_IIFE__` (`withGlobalTauri`, false here).
 *   ROWS `__TAURI_IIFE__`, `__TAURI__`.
 * - `isolation.js:6` (a `DOMContentLoaded` listener that makes the isolation frame): defines no name. NONE.
 * tauri 2.12.5, other injected files:
 * - `src/manager/webview.rs:166-190` (inline): `window.isTauri`, `window.__TAURI_INTERNALS__` (with `plugins`, `metadata`).
 *   ROWS `isTauri`, `__TAURI_INTERNALS__`.
 * - `src/event/init.js:6`: `window.__TAURI_EVENT_PLUGIN_INTERNALS__`. ROW. `src/event/mod.rs:178-229` makes
 *   listener objects and functions under names built per run (native to page; not nameable): reached through that row.
 * - `src/path/init.js:5`: `__TAURI_INTERNALS__.plugins.path`, a property of `__TAURI_INTERNALS__`. NONE (the name is a row).
 * - `src/webview/scripts/print.js:5`: `window.print = function () { … invoke('plugin:webview|print') }`, installed on
 *   macOS and iOS by `src/webview/plugin.rs:199-201`. ROW `print`.
 * - `src/webview/scripts/zoom-hotkey.js:12,30` and `toggle-devtools.js:14,29`: keyboard and wheel listeners; they define
 *   no name and are reached by a gesture. NONE.
 * - `src/window/scripts/drag.js:11,78,111`: `mousedown` and `mouseup` listeners; the DOM attribute
 *   `data-tauri-drag-region` (and its `dataset` form `tauriDragRegion`) starts a native window drag. ROWS.
 * tauri-utils 2.10.2: `src/pattern/isolation.js:115,129`: reads `window.__TAURI_ISOLATION_HOOK__` (set by an isolation
 *   application, which this one is not), listens for `message`. ROW `__TAURI_ISOLATION_HOOK__`.
 * wry 0.57.1 (the web view library; its initialisation scripts are in Rust): `src/webkitgtk/mod.rs:352`,
 *   `src/wkwebview/mod.rs:695`, `src/webview2/mod.rs:967`: `window.ipc` with `postMessage`, over
 *   `window.webkit.messageHandlers['ipc']` (macOS, iOS, Linux) or `window.chrome.webview` (Windows);
 *   Android `src/android/main_pipe.rs:307`: the interface `ipc` (`Ipc.kt:12`, `postMessage`). ROWS `ipc`, `postMessage`,
 *   `chrome`, `webview`, `webkit`, `messageHandlers`. wry has no other `window` definition (searched `window.`,
 *   `defineProperty`, `addEventListener`); tauri-runtime-wry 2.12.3 has no script.
 * tauri-plugin-dialog 2.7.3, `src/init-iife.js`: `window.alert` -> `plugin:dialog|message`, `window.confirm` ->
 *   `plugin:dialog|confirm`. ROWS `alert`, `confirm`, of the SYMBOL kind (below). It assigns nothing else: `prompt`,
 *   `open` and `close` are not replaced by any injected script.
 * tauri-plugin-opener 2.5.5, `src/init-iife.js`: one `click` listener that opens an `<a>` of http, https, mailto or tel
 *   with `plugin:opener|open_url`; defines no name, reached by a link and not by a name (the page opens links through
 *   its port's `openExternal`). NONE.
 * tauri-plugin-clipboard-manager 2.3.3: no initialisation script (`api-iife.js` is the guest API for `__TAURI__`). NONE.
 *
 * WHY `alert` AND `confirm` ARE OF ANOTHER KIND. Their names are common words of the page: `"alert"` is an ARIA role in
 * five modules (15 tokens) and `confirm` is a prop of `components/DeleteAccount.tsx` and a question's kind in three
 * modules, so the plain token rule would fail eight modules that use the words for their own purposes. Every other row
 * keeps the plain token rule, which is stricter.
 */

import ts from 'typescript'
import { beforeAll, describe, expect, it } from 'vitest'

import lockText from '../../../Cargo.lock?raw'

/** The versions at which the table was read, from `Cargo.lock`. A case fails when one differs. */
const READ_AT: Readonly<Record<string, string>> = {
  tauri: '2.12.5',
  'tauri-utils': '2.10.2',
  'tauri-runtime-wry': '2.12.3',
  wry: '0.57.1',
  'tauri-plugin-dialog': '2.7.3',
  'tauri-plugin-opener': '2.5.5',
  'tauri-plugin-clipboard-manager': '2.3.3'
}

/** The words of a failed guard: what a person is to do. */
function differences(lock: string, readAt: Readonly<Record<string, string>>): string[] {
  return Object.entries(readAt).flatMap(([crate, version]) => {
    const found = Array.from(lock.matchAll(new RegExp(`^name = "${crate}"\\nversion = "([^"]+)"`, 'gm')), (one) => one[1])
    return found.length === 1 && found[0] === version
      ? []
      : [
          `${crate} is at ${found.join(', ') || 'no version'} in Cargo.lock and the table of the bridge's surfaces was read at ${version}: read the table again from the scripts that the crates in the file list at the top of this file inject into a page, then change READ_AT`
        ]
  })
}

/** The bridge's package, and the scope that every module of it starts with. */
const PACKAGE_SCOPE = '@tauri-apps'

interface Surface {
  /** The name, or for a scheme the text that a URL of it starts with. */
  readonly name: string
  /** `name`: the token rule. `scheme`: a URL's start. `function`: the symbol rule. */
  readonly kind: 'name' | 'scheme' | 'function'
  /** The platforms the application builds for that it is on. */
  readonly platforms: string
  /** Where the injected script defines or replaces it, at the version in `READ_AT`. */
  readonly source: string
}

/** THE TABLE: every name that an injected script defines or replaces and that leads to the bridge. */
const SURFACES: readonly Surface[] = [
  { name: 'ipc', kind: 'name', platforms: 'macOS, iOS, Linux, Windows, Android', source: "wry 0.57.1 src/lib.rs:647; src/wkwebview/mod.rs:695, src/webkitgtk/mod.rs:352, src/webview2/mod.rs:967 (`window.ipc`); Android src/android/main_pipe.rs:307" },
  { name: 'postMessage', kind: 'name', platforms: 'all of them', source: 'wry 0.57.1 src/lib.rs:647; src/android/kotlin/Ipc.kt:12; src/webview2/mod.rs:967; src/wkwebview/mod.rs:695' },
  { name: 'chrome', kind: 'name', platforms: 'Windows (WebView2)', source: 'wry 0.57.1 src/webview2/mod.rs:967 (`window.chrome.webview`)' },
  { name: 'webview', kind: 'name', platforms: 'Windows (WebView2)', source: 'wry 0.57.1 src/webview2/mod.rs:967' },
  { name: 'webkit', kind: 'name', platforms: 'macOS, iOS, Linux', source: 'wry 0.57.1 src/wkwebview/mod.rs:695, src/webkitgtk/mod.rs:352 (`window.webkit.messageHandlers`)' },
  { name: 'messageHandlers', kind: 'name', platforms: 'macOS, iOS, Linux', source: 'wry 0.57.1 src/wkwebview/mod.rs:695, src/webkitgtk/mod.rs:352' },
  { name: 'isTauri', kind: 'name', platforms: 'all of them', source: "tauri 2.12.5 src/manager/webview.rs:170 (`Object.defineProperty(window, 'isTauri', …)`)" },
  { name: '__TAURI__', kind: 'name', platforms: 'all of them (off here)', source: 'tauri 2.12.5 scripts/bundle.global.js:1 (`window.__TAURI__=__TAURI_IIFE__`); tauri-utils 2.10.2 src/config.rs:3380' },
  { name: '__TAURI_IIFE__', kind: 'name', platforms: 'all of them (off here)', source: 'tauri 2.12.5 scripts/bundle.global.js:1 (`var __TAURI_IIFE__=…`, a global)' },
  { name: '__TAURI_INTERNALS__', kind: 'name', platforms: 'all of them', source: "tauri 2.12.5 src/manager/webview.rs:175; scripts/core.js:13-81, scripts/ipc.js:142, scripts/ipc-protocol.js:88, src/path/init.js:5" },
  { name: '__TAURI_EVENT_PLUGIN_INTERNALS__', kind: 'name', platforms: 'all of them', source: 'tauri 2.12.5 src/event/init.js:6' },
  { name: '__TAURI_ISOLATION_HOOK__', kind: 'name', platforms: 'all of them (not used here)', source: 'tauri-utils 2.10.2 src/pattern/isolation.js:115' },
  { name: 'print', kind: 'name', platforms: 'macOS, iOS', source: "tauri 2.12.5 src/webview/scripts/print.js:5 (`window.print = function () { … invoke('plugin:webview|print') }`), installed by src/webview/plugin.rs:199-201" },
  { name: 'data-tauri-drag-region', kind: 'name', platforms: 'all of them', source: 'tauri 2.12.5 src/window/scripts/drag.js:11 (`TAURI_DRAG_REGION_ATTR`), a DOM attribute that starts a native window drag' },
  { name: 'tauriDragRegion', kind: 'name', platforms: 'all of them', source: 'the same attribute through `dataset` (tauri 2.12.5 src/window/scripts/drag.js:11)' },
  { name: 'alert', kind: 'function', platforms: 'all of them', source: 'tauri-plugin-dialog 2.7.3 src/init-iife.js (`window.alert=function(i){n("plugin:dialog|message",…)}`)' },
  { name: 'confirm', kind: 'function', platforms: 'all of them', source: 'tauri-plugin-dialog 2.7.3 src/init-iife.js (`window.confirm=async function(i){…n("plugin:dialog|confirm",…)}`)' },
  { name: 'ipc://', kind: 'scheme', platforms: 'macOS, iOS, Linux', source: 'tauri 2.12.5 scripts/core.js:16-19, scripts/ipc-protocol.js:37; the policy names `ipc:` (tauri.conf.json:29)' },
  { name: 'http://ipc.localhost', kind: 'scheme', platforms: 'Windows, Android', source: 'tauri 2.12.5 scripts/core.js:16-19; the policy names it (tauri.conf.json:29)' },
  { name: 'https://ipc.localhost', kind: 'scheme', platforms: 'Windows, Android (https)', source: 'tauri 2.12.5 scripts/core.js:16-19 (`protocolScheme`)' }
]

/** The names, written out by hand once more, so that a row taken out of the table is seen. */
const NAMES = [
  'ipc',
  'postMessage',
  'chrome',
  'webview',
  'webkit',
  'messageHandlers',
  'isTauri',
  '__TAURI__',
  '__TAURI_IIFE__',
  '__TAURI_INTERNALS__',
  '__TAURI_EVENT_PLUGIN_INTERNALS__',
  '__TAURI_ISOLATION_HOOK__',
  'print',
  'data-tauri-drag-region',
  'tauriDragRegion'
] as const
const FUNCTIONS = ['alert', 'confirm'] as const
const SCHEMES = ['ipc://', 'http://ipc.localhost', 'https://ipc.localhost'] as const

const NAME_SET = new Set(SURFACES.filter((row) => row.kind === 'name').map((row) => row.name))
const FUNCTION_SET = new Set(SURFACES.filter((row) => row.kind === 'function').map((row) => row.name))
const SCHEME_LIST = SURFACES.filter((row) => row.kind === 'scheme').map((row) => row.name)

/** Whether a string is the bridge's package, one of its modules, or the start of a URL of its schemes. */
function namesTheBridge(text: string): boolean {
  const lower = text.toLowerCase()
  return (
    text === PACKAGE_SCOPE ||
    text.startsWith(`${PACKAGE_SCOPE}/`) ||
    SCHEME_LIST.some((scheme) => lower.startsWith(scheme))
  )
}

/** The companion's folder: the cases run from it (`vitest.config.ts` is there). */
const ROOT = `${ts.sys.getCurrentDirectory()}/`
/** The one module of the page that may name the bridge. */
const BOUNDARY = `${ROOT}src/host/tauri.ts`

/** The page's own compiler settings. */
function projectConfig(): ts.ParsedCommandLine {
  const read = ts.readConfigFile(`${ROOT}tsconfig.json`, (name) => ts.sys.readFile(name))
  return ts.parseJsonConfigFileContent(read.config, ts.sys, ROOT)
}

/** Whether a symbol is declared by the DOM library: the window's own function. */
function isDom(symbol: ts.Symbol | undefined): boolean {
  return (
    symbol?.declarations?.some((declaration) => /lib\.dom(\.[a-z.]+)?\.d\.ts$/.test(declaration.getSourceFile().fileName)) ??
    false
  )
}

/** What a module holds that names the bridge: its tokens, and what its `alert` and `confirm` resolve to. */
function reachesIn(source: ts.SourceFile, checker: ts.TypeChecker): string[] {
  const found: string[] = []
  const note = (node: ts.Node, what: string): void => {
    found.push(`${what} at line ${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`)
  }
  /** The property of the type that a destructuring takes apart, for the element's key. */
  const propertyOf = (element: ts.BindingElement): ts.Symbol | undefined => {
    const key = element.propertyName ?? element.name
    const name = ts.isComputedPropertyName(key)
      ? ts.isStringLiteralLike(key.expression)
        ? key.expression.text
        : undefined
      : ts.isIdentifier(key) || ts.isStringLiteralLike(key)
        ? key.text
        : undefined
    return name === undefined ? undefined : checker.getTypeAtLocation(element.parent).getProperty(name)
  }
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node)) {
      if (NAME_SET.has(node.text)) note(node, `the name ${node.text}`)
      else if (FUNCTION_SET.has(node.text)) {
        const element = node.parent
        const keyOfElement = ts.isBindingElement(element) && (element.propertyName === node || element.name === node)
        if (isDom(keyOfElement ? propertyOf(element) : checker.getSymbolAtLocation(node))) note(node, `the DOM's ${node.text}`)
      }
    } else if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (NAME_SET.has(node.text) || namesTheBridge(node.text)) note(node, `the string ${node.text}`)
      else if (FUNCTION_SET.has(node.text)) {
        const owner = node.parent
        const symbol = ts.isElementAccessExpression(owner) && owner.argumentExpression === node
          ? checker.getSymbolAtLocation(node)
          : ts.isBindingElement(owner) && owner.propertyName === node
            ? propertyOf(owner)
            : undefined
        if (isDom(symbol)) note(node, `the DOM's ${node.text}`)
      }
    } else if (ts.isTemplateExpression(node) && namesTheBridge(node.head.text)) {
      note(node, `the template ${node.head.text}…`)
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

/** The modules of `program` named in `paths` other than the port module that name the bridge, by path. */
function outside(program: ts.Program, paths: readonly string[]): Record<string, string[]> {
  const checker = program.getTypeChecker()
  return Object.fromEntries(
    paths
      .filter((path) => path !== BOUNDARY)
      .map((path) => [path, reachesIn(program.getSourceFile(path)!, checker)] as const)
      .filter(([, found]) => found.length > 0)
  )
}

/** A program over `texts` (by absolute path) with the page's compiler settings. */
function programOf(texts: Readonly<Record<string, string>>): ts.Program {
  const options = { ...projectConfig().options, noEmit: true }
  const host = ts.createCompilerHost(options)
  const original = host.getSourceFile.bind(host)
  host.getSourceFile = (name, ...rest) =>
    name in texts ? ts.createSourceFile(name, texts[name], ts.ScriptTarget.Latest, true) : original(name, ...rest)
  host.fileExists = (name) => name in texts || ts.sys.fileExists(name)
  host.readFile = (name) => texts[name] ?? ts.sys.readFile(name)
  return ts.createProgram(Object.keys(texts), options, host)
}

const files = import.meta.glob('../src/**/*.{ts,tsx,js,jsx,mjs,cjs}', {
  query: '?raw',
  import: 'default',
  eager: true
})

/** A second module, in the port module's own folder, so that a rule widened to the folder is seen. */
const SECOND = `${ROOT}src/host/second`

/** The plants, each a module of its own in one program made once. */
const plants: { readonly how: string; readonly path: string; readonly text: string }[] = []
const plant = (how: string, text: string, extension = 'ts'): void => {
  // Each plant is a module of its own, so that no two share a scope.
  plants.push({ how, path: `${SECOND}-${plants.length}.${extension}`, text: `${text}\nexport {}` })
}

for (const name of NAMES) {
  if (name.includes('-')) {
    plant(`${name}: a JSX attribute`, `export const view = <div ${name} />`, 'tsx')
    plant(`${name}: a string for setAttribute`, `export const set = (el: Element) => { el.setAttribute('${name}', '') }`)
    plant(`${name}: a key of an object`, `export const made = { '${name}': '' }`)
    plant(`${name}: a property by a bracket with a literal`, `export const reach = (el: never) => el['${name}']`)
    plant(`${name}: a key in a template with no substitution`, 'export const reach = (el: never) => el[`' + name + '`]')
  } else {
    plant(`${name}: a property by a dot`, `export const reach = window.${name}`)
    plant(`${name}: a property by a bracket with a literal`, `export const reach = window['${name}']`)
    plant(`${name}: a key in a template with no substitution`, 'export const reach = window[`' + name + '`]')
    plant(`${name}: a variable taken from the object and used later`, `const { ${name}: taken } = window as never\nexport const reach = () => taken`)
    plant(`${name}: a shorthand binding`, `const { ${name} } = window as never\nexport const reach = ${name}`)
  }
}
const REVIEWER = [
  "window['ipc']['postMessage'](message)",
  'const taken = window.ipc\ntaken.postMessage(message)',
  "window.chrome['webview'].postMessage(message)"
]
for (const line of REVIEWER) plant(`the reviewer's line: ${line}`, `declare const message: string\n${line}`)

const IMPORTS: readonly (readonly [string, string])[] = [
  ['a static import', "import { invoke } from '@tauri-apps/api/core'\nexport const ask = invoke"],
  ['a type import', "import type { InvokeArgs } from '@tauri-apps/api/core'\nexport type Args = InvokeArgs"],
  ['a side-effect import', "import '@tauri-apps/api/event'"],
  ['an import of a plugin', "import { open } from '@tauri-apps/plugin-dialog'\nexport const choose = open"],
  ['a re-export', "export { listen } from '@tauri-apps/api/event'"],
  ['a dynamic import with a literal', "export const core = () => import('@tauri-apps/api/core')"],
  ['a dynamic import with a template', 'export const core = () => import(`@tauri-apps/api/core`)'],
  ['a require', "const core = require('@tauri-apps/api/core')\nexport default core"],
  ['an import equals require', "import core = require('@tauri-apps/api/core')\nexport default core"],
  ['the package itself', "export const name = '@tauri-apps'"],
  ['a URL of the framework’s scheme', "export const ask = () => fetch('ipc://localhost/some_command')"],
  ['a URL of the Windows form', "export const ask = () => fetch('http://ipc.localhost/some_command')"],
  ['a URL with a substitution', 'export const ask = (cmd: string) => fetch(`ipc://localhost/${cmd}`)']
]
for (const [how, text] of IMPORTS) plant(how, text)

/** The symbol kind's plants: each of `alert` and `confirm` reached every way. */
const FUNCTION_PLANTS: readonly (readonly [string, string])[] = FUNCTIONS.flatMap((name) => [
  [`${name}: a bare call`, `${name}('sure?')`],
  ...(['window', 'globalThis', 'self', 'top'] as const).flatMap((receiver) => {
    const here = receiver === 'top' ? 'top!' : receiver
    return [
      [`${name}: a member of ${receiver} by a dot`, `${here}.${name}('sure?')`],
      [`${name}: a member of ${receiver} by a bracket with a literal`, `${here}['${name}']('sure?')`]
    ] as const
  }),
  [`${name}: a destructuring`, `const { ${name} } = window\n${name}('sure?')`],
  [`${name}: a renamed destructuring`, `const { ${name}: ask } = window\nask('sure?')`],
  [`${name}: an alias of the window`, `const w = window\nw.${name}('sure?')`],
  [`${name}: an alias by a bracket`, `const w = globalThis\nw['${name}']('sure?')`]
])
for (const [how, text] of FUNCTION_PLANTS) plant(how, text)

/** What passes: the page's own uses of the same words, and a module that names none of the bridge. */
const CONTROLS: readonly (readonly [string, string, string])[] = [
  ['the ARIA role string', 'export const view = <p role="alert">alert</p>', 'tsx'],
  ['a prop named confirm and its call', 'interface Props { confirm: () => void }\nexport function Panel({ confirm }: Props) { confirm() }\nexport const call = (props: Props) => { props.confirm() }', 'ts'],
  ['a question kind', "export const kind = 'confirm'\nexport const other = { kind: 'alert' }", 'ts'],
  ['a local function of that spelling', 'function alert(text: string) { return text }\nexport const said = alert("hi")', 'ts'],
  ['a method of an object of its own', 'const dialogs = { confirm(text: string) { return text }, alert(text: string) { return text } }\nexport const said = dialogs.alert("a") + dialogs.confirm("b")', 'ts'],
  [
    'a module that names none of the bridge, in comments and strings',
    [
      "import { tauriPort } from './host/tauri'",
      "import { Bar } from './components/chrome'",
      '// the browser chrome, the web view, an ipc of our own, window.webkit.messageHandlers, window.print',
      '/* __TAURI_INTERNALS__ and @tauri-apps/api */',
      "export const css = '-webkit-app-region: drag; --chrome-unit: 1px'",
      "export const note = 'ipc is a word, and so is webview, and print'",
      'export const view = <div className="bar">chrome</div>',
      'export const port = tauriPort()'
    ].join('\n'),
    'tsx'
  ]
]
for (const [how, text, extension] of CONTROLS) plant(`control: ${how}`, text, extension)

let plantProgram: ts.Program
let plantResults: Record<string, string[]>
let pageProgram: ts.Program
let pagePaths: string[]

beforeAll(() => {
  plantProgram = programOf(Object.fromEntries(plants.map((one) => [one.path, one.text])))
  plantResults = outside(plantProgram, plants.map((one) => one.path))
  const config = projectConfig()
  pagePaths = config.fileNames.filter((name) => name.startsWith(`${ROOT}src/`))
  pageProgram = ts.createProgram(pagePaths, config.options)
}, 120_000)

describe('the table of the bridge’s surfaces', () => {
  it('is the closed list, each row with its source', () => {
    expect(SURFACES.filter((row) => row.kind === 'name').map((row) => row.name)).toEqual(NAMES)
    expect(SURFACES.filter((row) => row.kind === 'function').map((row) => row.name)).toEqual(FUNCTIONS)
    expect(SURFACES.filter((row) => row.kind === 'scheme').map((row) => row.name)).toEqual(SCHEMES)
    for (const row of SURFACES) {
      expect(row.platforms.length, row.name).toBeGreaterThan(0)
      expect(row.source, row.name).toMatch(/(wry 0\.57\.1|tauri 2\.12\.5|tauri-utils 2\.10\.2|tauri-plugin-dialog 2\.7\.3)/)
    }
  })

  it('was read at the versions that Cargo.lock pins, or a person reads the scripts again', () => {
    expect(differences(lockText, READ_AT), 'the table is behind the framework').toEqual([])
  })

  it('tells a person what to do when a version differs', () => {
    const moved = lockText.replace(/(name = "tauri"\nversion = )"[^"]+"/, '$1"9.9.9"')
    const told = differences(moved, READ_AT)
    expect(told).toHaveLength(1)
    expect(told[0]).toContain('tauri is at 9.9.9 in Cargo.lock')
    expect(told[0]).toContain('read the table again from the scripts')
    expect(differences(lockText.replace(/name = "wry"\nversion/, 'name = "wryx"\nversion'), READ_AT)[0]).toContain(
      'wry is at no version'
    )
  })
})

describe('the native bridge is named in the port module alone', () => {
  it('holds in the page’s sources: every module is walked, and only the port module names the bridge', () => {
    expect(pagePaths.length).toBeGreaterThan(100)
    expect(pagePaths.length).toBe(Object.keys(files).length)
    expect(pagePaths).toContain(BOUNDARY)
    expect(outside(pageProgram, pagePaths)).toEqual({})
  })

  it('reads the port module as one that names the bridge, and lets it pass only by its exemption', () => {
    const named = reachesIn(pageProgram.getSourceFile(BOUNDARY)!, pageProgram.getTypeChecker())
    expect(named.some((found) => found.startsWith('the string @tauri-apps/api/core'))).toBe(true)
    expect(named.some((found) => found.startsWith('the string @tauri-apps/api/event'))).toBe(true)
    expect(outside(pageProgram, [BOUNDARY])).toEqual({})
  })

  it('makes its programs once: one for the plants and one for the page, from the page’s own settings', () => {
    expect(plantProgram.getSourceFiles().length).toBeGreaterThan(plants.length)
    expect(pageProgram.getSourceFiles().length).toBeGreaterThan(pagePaths.length)
  })

  it.each(plants.filter((one) => !one.how.startsWith('control:')).map((one) => [one.how, one] as const))(
    'fails on a plant: %s',
    (_how, one) => {
      expect(plantResults[one.path], one.text).toBeDefined()
    }
  )

  it.each(plants.filter((one) => one.how.startsWith('control:')).map((one) => [one.how, one] as const))(
    'passes: %s',
    (_how, one) => {
      expect(plantResults[one.path], `${one.text} -> ${(plantResults[one.path] ?? []).join(', ')}`).toBeUndefined()
    }
  )
})
