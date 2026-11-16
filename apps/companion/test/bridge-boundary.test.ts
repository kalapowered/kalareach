/**
 * The native bridge is named in the port module alone.
 *
 * THE REASONING. The boundary's promise is that on the page the ACTION of a failure does not exist
 * past one module. For that, no other module may be able to call an APPLICATION command or to
 * receive its failure. The names that reach the bridge itself can do both, so they are in the table
 * below. The functions that an injected script REPLACES (`print`, `alert`, `confirm`) and the drag
 * region's attribute lead to FIXED commands of the framework or of a plugin: by the scripts' own
 * lines (below) they cannot invoke an application command, and cannot return an application failure
 * with its action. The scan does not need them, and they are not rows.
 *
 * THE CLAIM. No module of the page other than `src/host/tauri.ts` holds, as an identifier, a
 * property name or a whole string literal (a plain string or a template with no substitution), a
 * name through which an application command can be invoked or its failure received (the table: the
 * bridge's own objects and their platform forms, the framework's globals), and none holds a string,
 * or the head of a template, that is the bridge's package or starts with its scope or with one of its
 * URL schemes. The scan reads the TOKENS of each module, parsed by the project's own TypeScript
 * compiler, so the form of the access (a dot, a bracket with a literal, a template key, a
 * destructuring, a variable taken from the object, an import of any kind, a re-export, `require`)
 * cannot hide a name that is written out; a comment and the text of an element are not read. A
 * template WITH a substitution gets the package and address checks and NO check of a surface's name
 * (`window[`ipc${''}`]` passes).
 *
 * WHAT IT CANNOT SEE. A name that the program puts together at run time (`'__TAU' + 'RI__'`; a key
 * from a constant is a name that is not written out), a template with a substitution that makes a
 * name, and code that is made from a string, which `eslint.config.js` (`no-restricted-syntax`
 * against `new Function` and `eval(`) and the content policy (`src-tauri/tauri.conf.json`,
 * `security.csp`: `script-src 'self'`, no `unsafe-eval`) forbid. A reference through an `any`-typed
 * receiver is also outside what the scan reads when the name is not written out; the page's lint
 * forbids `any` (`tseslint.configs.recommendedTypeChecked`: `no-explicit-any`,
 * `no-unsafe-member-access`, `no-unsafe-call`) unless a module disables the rule with a comment.
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
 * - `src/webview/scripts/zoom-hotkey.js:12,30` and `toggle-devtools.js:14,29`: keyboard and wheel listeners; they define
 *   no name and are reached by a gesture. NONE.
 * tauri-utils 2.10.2: `src/pattern/isolation.js:115,129`: reads `window.__TAURI_ISOLATION_HOOK__` (set by an isolation
 *   application, which this one is not), listens for `message`. ROW `__TAURI_ISOLATION_HOOK__`.
 * wry 0.57.1 (the web view library; its initialisation scripts are in Rust): `src/webkitgtk/mod.rs:352`,
 *   `src/wkwebview/mod.rs:695`, `src/webview2/mod.rs:967`: `window.ipc` with `postMessage`, over
 *   `window.webkit.messageHandlers['ipc']` (macOS, iOS, Linux) or `window.chrome.webview` (Windows);
 *   Android `src/android/main_pipe.rs:307`: the interface `ipc` (`Ipc.kt:12`, `postMessage`). ROWS `ipc`, `postMessage`,
 *   `chrome`, `webview`, `webkit`, `messageHandlers`. wry has no other `window` definition (searched `window.`,
 *   `defineProperty`, `addEventListener`); tauri-runtime-wry 2.12.3 has no script.
 * tauri-plugin-opener 2.5.5, `src/init-iife.js`: one `click` listener that opens an `<a>` of http, https, mailto or tel
 *   with `plugin:opener|open_url`; defines no name, reached by a link and not by a name (the page opens links through
 *   its port's `openExternal`). NONE.
 * tauri-plugin-clipboard-manager 2.3.3: no initialisation script (`api-iife.js` is the guest API for `__TAURI__`). NONE.
 *
 * THESE LEAD TO A FIXED COMMAND AND CANNOT CARRY AN APPLICATION FAILURE (not rows; see `FIXED`). Each script's body was
 * read for a way to reach an application command or to pass a caller's own command name: there is none; the command is
 * a literal of the script, and what a caller supplies is a payload (a message text) or nothing. The one line of each
 * script that shows the fixed command, at the version in `READ_AT` (the version guard carries that these lines still
 * stand: the page's cases read no file of the cargo registry):
 * - `print`: tauri 2.12.5 `src/webview/scripts/print.js:6` (installed on macOS and iOS by `src/webview/plugin.rs:199-201`):
 *   `return window.__TAURI_INTERNALS__.invoke('plugin:webview|print')`
 * - `alert`: tauri-plugin-dialog 2.7.3 `src/init-iife.js:1`:
 *   `window.alert=function(i){n("plugin:dialog|message",{message:i.toString()})}`
 * - `confirm`: tauri-plugin-dialog 2.7.3 `src/init-iife.js:1`:
 *   `window.confirm=async function(i){return await n("plugin:dialog|confirm",{message:i.toString()})}`
 *   (`prompt`, `open` and `close` are not replaced by any injected script.)
 * - the attribute `data-tauri-drag-region` (and its `dataset` form `tauriDragRegion`): tauri 2.12.5
 *   `src/window/scripts/drag.js:103`: `const cmd = e.detail === 2 ? 'internal_toggle_maximize' : 'start_dragging'`, used at
 *   `drag.js:104` as `invoke('plugin:window|' + cmd)`; `drag.js:123-125` calls `'plugin:window|internal_toggle_maximize'`.
 */

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

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
  /** `name`: the token rule. `scheme`: a URL's start. */
  readonly kind: 'name' | 'scheme'
  /** The platforms the application builds for that it is on. */
  readonly platforms: string
  /** Where the injected script defines it, at the version in `READ_AT`. */
  readonly source: string
}

/** THE TABLE: every name that an injected script defines and through which an application command can be reached. */
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
  { name: 'ipc://', kind: 'scheme', platforms: 'macOS, iOS, Linux', source: 'tauri 2.12.5 scripts/core.js:16-19, scripts/ipc-protocol.js:37; the policy names `ipc:` (tauri.conf.json:29)' },
  { name: 'http://ipc.localhost', kind: 'scheme', platforms: 'Windows, Android', source: 'tauri 2.12.5 scripts/core.js:16-19; the policy names it (tauri.conf.json:29)' },
  { name: 'https://ipc.localhost', kind: 'scheme', platforms: 'Windows, Android (https)', source: 'tauri 2.12.5 scripts/core.js:16-19 (`protocolScheme`)' }
]

/**
 * What leads to a FIXED command and is therefore not a row (see the header): the name, the script and the one
 * line that shows the command. They are data here so that no row of the table can be one of them by mistake.
 */
const FIXED: readonly { readonly name: string; readonly script: string; readonly line: string; readonly commands: readonly string[] }[] = [
  { name: 'print', script: 'tauri 2.12.5 src/webview/scripts/print.js:6', line: "return window.__TAURI_INTERNALS__.invoke('plugin:webview|print')", commands: ['plugin:webview|print'] },
  { name: 'alert', script: 'tauri-plugin-dialog 2.7.3 src/init-iife.js:1', line: 'window.alert=function(i){n("plugin:dialog|message",{message:i.toString()})}', commands: ['plugin:dialog|message'] },
  { name: 'confirm', script: 'tauri-plugin-dialog 2.7.3 src/init-iife.js:1', line: 'window.confirm=async function(i){return await n("plugin:dialog|confirm",{message:i.toString()})}', commands: ['plugin:dialog|confirm'] },
  { name: 'data-tauri-drag-region', script: 'tauri 2.12.5 src/window/scripts/drag.js:103', line: "const cmd = e.detail === 2 ? 'internal_toggle_maximize' : 'start_dragging'", commands: ['internal_toggle_maximize', 'start_dragging'] },
  { name: 'tauriDragRegion', script: 'tauri 2.12.5 src/window/scripts/drag.js:103', line: "const cmd = e.detail === 2 ? 'internal_toggle_maximize' : 'start_dragging'", commands: ['internal_toggle_maximize', 'start_dragging'] }
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
  '__TAURI_ISOLATION_HOOK__'
] as const
const SCHEMES = ['ipc://', 'http://ipc.localhost', 'https://ipc.localhost'] as const

const NAME_SET = new Set(SURFACES.filter((row) => row.kind === 'name').map((row) => row.name))
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

/** The one module of the page that may name the bridge. */
const BOUNDARY = '../src/host/tauri.ts'

/** What a module holds that names the bridge: its tokens, parsed by the compiler, not its text. */
function reachesIn(path: string, text: string): string[] {
  const kind = /\.[jt]sx$/.test(path)
    ? ts.ScriptKind.TSX
    : /\.(js|mjs|cjs)$/.test(path)
      ? ts.ScriptKind.JS
      : ts.ScriptKind.TS
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind)
  const found: string[] = []
  const note = (node: ts.Node, what: string): void => {
    found.push(`${what} at line ${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`)
  }
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && NAME_SET.has(node.text)) note(node, `the name ${node.text}`)
    else if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (NAME_SET.has(node.text) || namesTheBridge(node.text)) note(node, `the string ${node.text}`)
    } else if (ts.isTemplateExpression(node) && namesTheBridge(node.head.text)) {
      note(node, `the template ${node.head.text}…`)
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

/** The modules other than the port module that name the bridge, by path. */
function outside(sources: Readonly<Record<string, string>>): Record<string, string[]> {
  return Object.fromEntries(
    Object.entries(sources)
      .filter(([path]) => path !== BOUNDARY)
      .map(([path, text]) => [path, reachesIn(path, text)] as const)
      .filter(([, found]) => found.length > 0)
  )
}

const files = import.meta.glob('../src/**/*.{ts,tsx,js,jsx,mjs,cjs}', {
  query: '?raw',
  import: 'default',
  eager: true
})

/** A second module, in the port module's own folder, so that a rule widened to the folder is seen. */
const SECOND = '../src/host/second'

describe('the table of the bridge’s surfaces', () => {
  it('is the closed list, each row with its source', () => {
    expect(SURFACES.filter((row) => row.kind === 'name').map((row) => row.name)).toEqual(NAMES)
    expect(SURFACES.filter((row) => row.kind === 'scheme').map((row) => row.name)).toEqual(SCHEMES)
    for (const row of SURFACES) {
      expect(row.platforms.length, row.name).toBeGreaterThan(0)
      expect(row.source, row.name).toMatch(/(wry 0\.57\.1|tauri 2\.12\.5|tauri-utils 2\.10\.2)/)
    }
  })

  it('holds no function that a script replaces and no drag attribute: they lead to a fixed command', () => {
    for (const fixed of FIXED) {
      expect(NAME_SET.has(fixed.name), fixed.name).toBe(false)
      for (const command of fixed.commands) expect(fixed.line, fixed.name).toContain(command)
      expect(fixed.script, fixed.name).toMatch(/(tauri 2\.12\.5|tauri-plugin-dialog 2\.7\.3)/)
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
  it('holds in the page’s sources: every module is read, and only the port module names the bridge', () => {
    expect(Object.keys(files).length).toBeGreaterThan(100)
    expect(files[BOUNDARY]).toBeDefined()
    expect(outside(files)).toEqual({})
  })

  it('reads the port module as one that names the bridge, and lets it pass only by its exemption', () => {
    const named = reachesIn(BOUNDARY, files[BOUNDARY])
    expect(named.some((found) => found.startsWith('the string @tauri-apps/api/core'))).toBe(true)
    expect(named.some((found) => found.startsWith('the string @tauri-apps/api/event'))).toBe(true)
    expect(outside({ [BOUNDARY]: files[BOUNDARY] })).toEqual({})
  })

  it('passes a module that names none of it, whatever words it uses in comments and strings', () => {
    const text = [
      "import { tauriPort } from './host/tauri'",
      "import { Bar } from './components/chrome'",
      '// the browser chrome, the web view, an ipc of our own, window.webkit.messageHandlers',
      '/* __TAURI_INTERNALS__ and @tauri-apps/api */',
      "export const css = '-webkit-app-region: drag; --chrome-unit: 1px'",
      "export const note = 'ipc is a word, and so is webview'",
      'export const view = <div className="bar">chrome</div>',
      'export const port = tauriPort()'
    ].join('\n')
    expect(outside({ [`${SECOND}.tsx`]: text })).toEqual({})
  })

  it('does not claim the functions that lead to a fixed command: a call of each passes', () => {
    const text = [
      "window.print()",
      "window.alert('sure?')",
      "confirm('sure?')",
      "export const view = <p role=\"alert\" data-note=\"confirm\">x</p>"
    ].join('\n')
    expect(outside({ [`${SECOND}.tsx`]: text })).toEqual({})
  })

  const surfaces = NAMES.flatMap((name) => [
    [`${name}: a property by a dot`, `export const reach = window.${name}`],
    [`${name}: a property by a bracket with a literal`, `export const reach = window['${name}']`],
    [`${name}: a key in a template with no substitution`, 'export const reach = window[`' + name + '`]'],
    [`${name}: a variable taken from the object and used later`, `const { ${name}: taken } = window as never\nexport const reach = () => taken`],
    [`${name}: a shorthand binding`, `const { ${name} } = window as never\nexport const reach = ${name}`]
  ])

  it.each(surfaces)('fails on a plant: %s', (_how, plant) => {
    expect(Object.keys(outside({ [`${SECOND}.ts`]: plant })), plant).toEqual([`${SECOND}.ts`])
  })

  it.each([
    ["window['ipc']['postMessage'](message)"],
    ['const taken = window.ipc\ntaken.postMessage(message)'],
    ["window.chrome['webview'].postMessage(message)"]
  ])('fails on a line that the round 5 scan passed: %s', (plant) => {
    expect(Object.keys(outside({ [`${SECOND}.ts`]: `declare const message: string\n${plant}` })), plant).toEqual([`${SECOND}.ts`])
  })

  it.each([
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
  ])('fails on an import or a reach of the package or its schemes from a second module: %s', (_how, plant) => {
    expect(Object.keys(outside({ [`${SECOND}.ts`]: plant })), plant).toEqual([`${SECOND}.ts`])
  })
})
