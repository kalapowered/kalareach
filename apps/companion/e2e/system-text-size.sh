#!/bin/bash
# Holds, on the iOS Simulator, that the page follows the person's text size and follows a change
# made while it is open.
#
# The harness bundle is served, and opened in the simulator's own browser inside a frame of a small
# wrapper page that reads the page's text size and sends it back to this script. The simulator's
# Dynamic Type setting is then set to each size in turn, with the page left open, and the script
# waits until the page reports the size that setting calls for. It waits on that condition and on no
# delay: the page reaching the size is what it is waiting for, and a limit exists only so that a run
# that never gets there stops and says what it was waiting for.
#
# It must run inside the device lease, which also stops what it boots:
#
#   pnpm -C apps/companion build:harness
#   bash <lease script> <label> apps/companion/e2e/system-text-size.sh
#
# Environment: KR_IOS_DEVICE names the simulator (default "iPhone 17 Pro"); KR_TEXT_SIZE_SHOTS is
# where its screenshots go (default /tmp); KR_HARNESS_DIST names another built harness to hold to
# the same sizes, which is how a build that does not follow them is shown to fail. The script
# refuses a simulator that was already running, whose settings are not its to change. Exit status:
# 0 when every size held, 1 when one did not, 3 when there is no simulator to run on.
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dist=${KR_HARNESS_DIST:-$here/dist-harness}
[ -f "$dist/harness.html" ] || { echo "no built harness at $dist: run pnpm -C apps/companion build:harness"; exit 3; }
# The checks themselves are Node, read from the rest of this file.
exec node --input-type=module - "$dist" <<'JS'
import { execFileSync } from 'node:child_process'
import { createReadStream, existsSync, statSync } from 'node:fs'
import { createServer } from 'node:http'
import { extname, join, normalize } from 'node:path'

const root = process.argv[2]
const device = process.env.KR_IOS_DEVICE ?? 'iPhone 17 Pro'
const shots = process.env.KR_TEXT_SIZE_SHOTS ?? '/tmp'
const LINE = 'Find why the reconnect test is flaky.'

/**
 * The size of the system's body text at each Dynamic Type setting, in points. The page's root is
 * 16px at the default setting, which is 17 points, and the page keeps that ratio at every size.
 */
const SIZES = [
  ['large', 17],
  ['accessibility-extra-extra-extra-large', 53],
  ['extra-small', 14],
  ['accessibility-medium', 28],
  ['large', 17]
]
const ROOT_AT_THE_DEFAULT = 16
const BODY_AT_THE_DEFAULT = 17

const wrapper = `<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1">
<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100%}</style>
<iframe id="page" src="/harness.html?surface=ios&session=8a7b6c50-22bb-4c3d-8e4f-000000000101"></iframe>
<script>
const frame = document.getElementById('page')
const send = () => {
  const doc = frame.contentDocument
  if (!doc || !doc.documentElement) return
  const line = [...doc.querySelectorAll('p, span, div')].find((e) => e.children.length === 0 && e.textContent === ${JSON.stringify(LINE)})
  const view = frame.contentWindow
  const body = {
    root: parseFloat(view.getComputedStyle(doc.documentElement).fontSize),
    scale: doc.documentElement.style.getPropertyValue('--text-scale'),
    line: line ? line.getBoundingClientRect().height : 0,
    wide: doc.documentElement.scrollWidth,
    screen: view.innerWidth
  }
  fetch('/report', { method: 'POST', body: JSON.stringify(body) })
}
setInterval(send, 400)
</script>`

const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff': 'font/woff', '.woff2': 'font/woff2' }
let latest = null
const server = createServer((request, response) => {
  const path = new URL(request.url ?? '/', 'http://localhost').pathname
  if (path === '/report') {
    let text = ''
    request.on('data', (chunk) => (text += chunk))
    request.on('end', () => {
      latest = JSON.parse(text)
      response.end('ok')
    })
    return
  }
  if (path === '/wrapper.html') {
    response.setHeader('content-type', 'text/html')
    response.end(wrapper)
    return
  }
  const file = join(root, normalize(path).replace(/^(\.\.[/\\])+/, ''))
  if (!file.startsWith(root) || !existsSync(file) || !statSync(file).isFile()) {
    response.statusCode = 404
    response.end('not found')
    return
  }
  response.setHeader('content-type', types[extname(file)] ?? 'application/octet-stream')
  createReadStream(file).pipe(response)
})
await new Promise((resolve) => server.listen(0, resolve))
const port = server.address().port

const simctl = (...args) =>
  execFileSync('xcrun', ['simctl', ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    // A command that is never answered stops the run, which says which one it was.
    timeout: 300_000
  })
const find = JSON.parse(simctl('list', 'devices', 'available', '-j'))
const found = Object.values(find.devices)
  .flat()
  .find((candidate) => candidate.name === device)
if (found === undefined) {
  console.log(`no iOS simulator named ${device}`)
  server.close()
  process.exit(3)
}
if (found.state === 'Booted') {
  console.log(`${device} is already running: its text size is not this script's to change`)
  server.close()
  process.exit(3)
}

const waitFor = async (what, ready, limitMs = 120_000) => {
  const started = Date.now()
  while (!ready()) {
    if (Date.now() - started > limitMs) throw new Error(`gave up waiting for ${what}`)
    await new Promise((resolve) => setTimeout(resolve, 200))
  }
}

let failures = 0
/** The text size the simulator had when it started, which is put back whatever happens. */
let before = null
const check = (condition, message) => {
  console.log(`${condition ? 'PASS' : 'FAIL'}: ${message}`)
  if (!condition) failures += 1
}

try {
  simctl('boot', found.udid)
  simctl('bootstatus', found.udid, '-b')
  before = simctl('ui', found.udid, 'content_size').trim()
  simctl('ui', found.udid, 'content_size', 'large')
  simctl('launch', found.udid, 'com.apple.mobilesafari')
  simctl('openurl', found.udid, `http://localhost:${port}/wrapper.html`)
  await waitFor('the page to report its size', () => latest !== null && latest.line > 0)

  let atDefault = null
  for (const [category, body] of SIZES) {
    const expected = (ROOT_AT_THE_DEFAULT * body) / BODY_AT_THE_DEFAULT
    simctl('ui', found.udid, 'content_size', category)
    // The page, still open, is what is asked: nothing here reloads it.
    await waitFor(
      `the root text to reach ${expected.toFixed(2)}px at ${category}`,
      () => latest !== null && Math.abs(latest.root - expected) < 0.05 && latest.line > 0
    ).catch((failure) => {
      console.log(`FAIL: ${failure.message}; the page said ${JSON.stringify(latest)}`)
      failures += 1
    })
    const seen = latest
    check(
      seen !== null && Math.abs(seen.root - expected) < 0.05,
      `${category}: the root text is ${seen?.root}px, as the system's ${body}-point body text asks (${expected.toFixed(2)}px)`
    )
    if (category === 'large' && atDefault === null) atDefault = seen
    if (seen !== null && atDefault !== null && body > BODY_AT_THE_DEFAULT) {
      check(
        seen.line > atDefault.line * 1.3,
        `${category}: a line of the conversation is ${seen.line.toFixed(1)}px tall, against ${atDefault.line.toFixed(1)}px at the default size`
      )
    }
    check(seen !== null && seen.wide <= seen.screen, `${category}: the page is no wider than the screen (${seen?.wide} of ${seen?.screen})`)
    simctl('io', found.udid, 'screenshot', join(shots, `kr-text-size-${category}-${body}.png`))
  }
} catch (failure) {
  console.log(`FAIL: ${failure.message}`)
  failures += 1
} finally {
  try {
    if (before !== null && before !== '') simctl('ui', found.udid, 'content_size', before)
  } catch {
    // The simulator may already be gone.
  }
  simctl('shutdown', found.udid)
  server.close()
}
console.log(failures === 0 ? 'every size held' : `${failures} did not hold`)
process.exit(failures === 0 ? 0 : 1)
JS
