/**
 * The native bridge is named in the port module alone.
 *
 * THE CLAIM. No module of the page other than `src/host/tauri.ts` holds, as an identifier, a
 * property name or a whole string literal (a plain string, a template with no substitution, or the
 * head of a template), any name that the bridge's libraries put on the web view's `window` for a
 * platform the application builds for (the table below, each row with its source), and none holds a
 * string that is the bridge's package or starts with its scope or with one of its URL schemes. It
 * reads the TOKENS of each module, parsed by the project's own TypeScript compiler, so the form of
 * the access (a dot, a bracket with a literal, a template key, a destructuring, a variable taken
 * from the object, an import of any kind, a re-export, `require`) cannot hide a name that is written
 * out; a comment and the text of an element are not tokens of that kind and are not read.
 *
 * WHAT IT CANNOT SEE. A name that the program puts together at run time (`'__TAU' + 'RI__'`), and
 * code that is made from a string. The second is forbidden elsewhere: `eslint.config.js` has
 * `no-restricted-syntax` rules against `new Function` and `eval(`, and the content policy of the
 * application (`src-tauri/tauri.conf.json`, `security.csp`: `script-src 'self'`, no `unsafe-eval`)
 * stops the web view from making code out of a string at run time in any spelling. The first has no
 * other defence than this rule not claiming it.
 */

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

/** The one module of the page that may name the bridge. */
const BOUNDARY = '../src/host/tauri.ts'

/** The bridge's package, and the scope that every module of it starts with. */
const PACKAGE_SCOPE = '@tauri-apps'

interface Surface {
  /** The name, or for a scheme the text that a URL of it starts with. */
  readonly name: string
  readonly kind: 'name' | 'scheme'
  /** The platforms the application builds for that it is on. */
  readonly platforms: string
  /** Where the bridge library's own source defines it, at the version `Cargo.lock` pins. */
  readonly source: string
}

/**
 * THE TABLE OF THE BRIDGE'S SURFACES: a closed list. Versions are those of `Cargo.lock`: wry 0.57.1
 * (the web view library the desktop framework uses), tauri 2.12.5, tauri-utils 2.10.2. A name that
 * a module of the page may need for another purpose is not in it; the sources were searched for
 * what each platform puts on `window` (`Object.defineProperty(window, …)`, the web view's own
 * message handler, the Android interface) and for the framework's own globals.
 */
const SURFACES: readonly Surface[] = [
  {
    name: 'ipc',
    kind: 'name',
    platforms: 'macOS, iOS, Linux, Windows, Android',
    source:
      "wry 0.57.1 src/lib.rs:647 (documented: `window.ipc.postMessage`); src/wkwebview/mod.rs:695, src/webkitgtk/mod.rs:352, src/webview2/mod.rs:967 (`Object.defineProperty(window, 'ipc', …)`); Android: src/android/main_pipe.rs:307 (`addJavascriptInterface(…, \"ipc\")`)"
  },
  {
    name: 'postMessage',
    kind: 'name',
    platforms: 'all of them',
    source:
      'wry 0.57.1 src/lib.rs:647; src/android/kotlin/Ipc.kt:12 (`fun postMessage`); src/webview2/mod.rs:967 (`window.chrome.webview.postMessage`); src/wkwebview/mod.rs:695 (`messageHandlers.ipc.postMessage`)'
  },
  {
    name: 'chrome',
    kind: 'name',
    platforms: 'Windows (WebView2)',
    source: 'wry 0.57.1 src/webview2/mod.rs:967 (`window.chrome.webview.postMessage(s)`)'
  },
  {
    name: 'webview',
    kind: 'name',
    platforms: 'Windows (WebView2)',
    source: 'wry 0.57.1 src/webview2/mod.rs:967 (`window.chrome.webview.postMessage(s)`)'
  },
  {
    name: 'webkit',
    kind: 'name',
    platforms: 'macOS, iOS (WKWebView), Linux (WebKitGTK)',
    source:
      "wry 0.57.1 src/wkwebview/mod.rs:695 and src/webkitgtk/mod.rs:352 (`window.webkit.messageHandlers…`)"
  },
  {
    name: 'messageHandlers',
    kind: 'name',
    platforms: 'macOS, iOS (WKWebView), Linux (WebKitGTK)',
    source:
      "wry 0.57.1 src/wkwebview/mod.rs:695 and src/webkitgtk/mod.rs:352 (`window.webkit.messageHandlers['ipc']`)"
  },
  {
    name: 'isTauri',
    kind: 'name',
    platforms: 'all of them',
    source: "tauri 2.12.5 src/manager/webview.rs:170 (`Object.defineProperty(window, 'isTauri', …)`)"
  },
  {
    name: '__TAURI__',
    kind: 'name',
    platforms: 'all of them (off here: `withGlobalTauri` is false, `tauri.conf.json:13`)',
    source:
      'tauri-utils 2.10.2 src/config.rs:3380 (`withGlobalTauri`: the API on `window.__TAURI__`); tauri 2.12.5 scripts/bundle.global.js (`window.__TAURI__=__TAURI_IIFE__`)'
  },
  {
    name: '__TAURI_INTERNALS__',
    kind: 'name',
    platforms: 'all of them',
    source:
      "tauri 2.12.5 src/manager/webview.rs:175 (`Object.defineProperty(window, '__TAURI_INTERNALS__', …)`); scripts/core.js, scripts/ipc.js, scripts/ipc-protocol.js (its `invoke`, `ipc`, `postMessage`, `convertFileSrc`)"
  },
  {
    name: '__TAURI_EVENT_PLUGIN_INTERNALS__',
    kind: 'name',
    platforms: 'all of them',
    source: "tauri 2.12.5 src/event/init.js:6 (`Object.defineProperty(window, '__TAURI_EVENT_PLUGIN_INTERNALS__', …)`)"
  },
  {
    name: '__TAURI_ISOLATION_HOOK__',
    kind: 'name',
    platforms: 'all of them (the isolation pattern; not used here)',
    source: 'tauri-utils 2.10.2 src/pattern/isolation.js:115 (`window.__TAURI_ISOLATION_HOOK__`)'
  },
  {
    name: 'ipc://',
    kind: 'scheme',
    platforms: 'macOS, iOS, Linux',
    source:
      "tauri 2.12.5 scripts/core.js:16-19 (`convertFileSrc`: `${protocol}://localhost/…`), scripts/ipc-protocol.js:37 (protocol 'ipc'); the policy's `connect-src` names `ipc:` (`tauri.conf.json:29`)"
  },
  {
    name: 'http://ipc.localhost',
    kind: 'scheme',
    platforms: 'Windows, Android',
    source:
      "tauri 2.12.5 scripts/core.js:16-19 (`${protocolScheme}://${protocol}.localhost/…`); the policy's `connect-src` names it (`tauri.conf.json:29`)"
  },
  {
    name: 'https://ipc.localhost',
    kind: 'scheme',
    platforms: 'Windows, Android (when the web view serves https)',
    source: 'tauri 2.12.5 scripts/core.js:16-19 (the same line, `protocolScheme` is `https`)'
  }
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
      if (NAME_SET.has(node.text)) note(node, `the string ${node.text}`)
      else if (namesTheBridge(node.text)) note(node, `the string ${node.text}`)
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
const SECOND = '../src/host/second.ts'

describe('the table of the bridge’s surfaces', () => {
  it('is the closed list, each row with its source', () => {
    expect(SURFACES.filter((row) => row.kind === 'name').map((row) => row.name)).toEqual(NAMES)
    expect(SURFACES.filter((row) => row.kind === 'scheme').map((row) => row.name)).toEqual(SCHEMES)
    for (const row of SURFACES) {
      expect(row.platforms.length, row.name).toBeGreaterThan(0)
      expect(row.source, row.name).toMatch(/(wry 0\.57\.1|tauri 2\.12\.5|tauri-utils 2\.10\.2)/)
    }
  })
})

describe('the native bridge is named in the port module alone', () => {
  it('holds in the page’s sources: every module is read, and only the port module names the bridge', () => {
    expect(Object.keys(files).length).toBeGreaterThan(100)
    expect(files[BOUNDARY]).toBeDefined()
    expect(outside(files)).toEqual({})
  })

  it('reads the port module as one that names the bridge, and lets it pass only by its exemption', () => {
    const text = files[BOUNDARY]
    const named = reachesIn(BOUNDARY, text)
    expect(named.some((found) => found.startsWith('the string @tauri-apps/api/core'))).toBe(true)
    expect(named.some((found) => found.startsWith('the string @tauri-apps/api/event'))).toBe(true)
    expect(outside({ [BOUNDARY]: text })).toEqual({})
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
    expect(outside({ '../src/host/other.tsx': text })).toEqual({})
  })

  const surfaces = NAMES.flatMap((name) => [
    [`${name}: a property by a dot`, `export const reach = window.${name}`],
    [`${name}: a property by a bracket with a literal`, `export const reach = window['${name}']`],
    [`${name}: a key in a template with no substitution`, 'export const reach = window[`' + name + '`]'],
    [`${name}: a variable taken from the object and used later`, `const { ${name}: taken } = window as never\nexport const reach = () => taken`],
    [`${name}: a shorthand binding`, `const { ${name} } = window as never\nexport const reach = ${name}`]
  ])

  it.each(surfaces)('fails on a plant: %s', (_how, plant) => {
    expect(Object.keys(outside({ [SECOND]: plant })), plant).toEqual([SECOND])
  })

  it.each([
    ["window['ipc']['postMessage'](message)"],
    ['const taken = window.ipc\ntaken.postMessage(message)'],
    ["window.chrome['webview'].postMessage(message)"]
  ])('fails on a line that the round 5 scan passed: %s', (plant) => {
    expect(Object.keys(outside({ [SECOND]: `declare const message: string\n${plant}` })), plant).toEqual([SECOND])
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
    expect(Object.keys(outside({ [SECOND]: plant })), plant).toEqual([SECOND])
  })
})
