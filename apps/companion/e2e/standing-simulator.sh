#!/bin/bash
# Holds, on the iOS Simulator, that a session screen whose opening the host ended says so inside the
# screen at the default text size and at the largest, with its buttons a finger tall.
#
# The harness bundle is served and opened in the simulator's own browser inside a frame of a wrapper
# page. The wrapper makes the scripted host end the share the screen runs under, and reports what the
# page shows of it: the banner's words, where its edges are, how tall its buttons are, what the
# status region says. The simulator's Dynamic Type setting is set to each size in turn, with the page
# left open, and the script waits until the page reports the size that setting calls for. It waits on
# those conditions and on no delay; a limit exists only so that a run that never gets there stops and
# says what it was waiting for.
#
# It must run inside the device lease, which also stops what it boots:
#
#   pnpm -C apps/companion build:harness
#   bash <lease script> <label> apps/companion/e2e/standing-simulator.sh
#
# Environment: KR_IOS_DEVICE names the simulator (default "iPhone 17 Pro"); KR_STANDING_SHOTS is where
# its screenshots go (default /tmp); KR_HARNESS_DIST names another built harness. The script refuses a
# simulator that was already running, whose settings are not its to change. Exit status: 0 when every
# size held, 1 when one did not, 3 when there is no simulator to run on.
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dist=${KR_HARNESS_DIST:-$here/dist-harness}
[ -f "$dist/harness.html" ] || { echo "no built harness at $dist: run pnpm -C apps/companion build:harness"; exit 3; }
exec node --input-type=module - "$dist" <<'JS'
import { execFileSync } from 'node:child_process'
import { createReadStream, existsSync, statSync } from 'node:fs'
import { createServer } from 'node:http'
import { extname, join, normalize } from 'node:path'

const root = process.argv[2]
const device = process.env.KR_IOS_DEVICE ?? 'iPhone 17 Pro'
const shots = process.env.KR_STANDING_SHOTS ?? '/tmp'
const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The system's body text at each Dynamic Type setting, in points; the page's root is 16px at 17. */
const SIZES = [
  ['large', 17],
  ['accessibility-extra-extra-extra-large', 53]
]
const FINGER = 44

const wrapper = `<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1">
<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100%}</style>
<iframe id="page" src="/harness.html?surface=ios&session=${SESSION}"></iframe>
<script>
const frame = document.getElementById('page')
let ended = false
const send = () => {
  const view = frame.contentWindow
  const doc = frame.contentDocument
  const host = view && view.krTestHost
  if (!doc || !doc.documentElement || !host) return
  if (!ended && host.standings.tokenOf(${JSON.stringify(SESSION)})) {
    ended = true
    host.standings.say(${JSON.stringify(SESSION)}, { state: 'ended', reason: 'revoked' })
  }
  const banner = doc.querySelector('[data-testid="standing-banner"]')
  const edge = banner ? banner.getBoundingClientRect() : null
  const body = {
    root: parseFloat(view.getComputedStyle(doc.documentElement).fontSize),
    banner: banner ? banner.textContent : null,
    shown: banner ? banner.getAttribute('data-shown') : null,
    left: edge ? edge.left : 0,
    right: edge ? edge.right : 0,
    buttons: banner ? [...banner.querySelectorAll('button')].map((each) => each.getBoundingClientRect().height) : [],
    status: (doc.querySelector('[data-testid="standing-status"]') || {}).textContent || '',
    send: (() => { const b = [...doc.querySelectorAll('button')].find((each) => each.textContent === 'Send'); return b ? b.disabled : null })(),
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
  execFileSync('xcrun', ['simctl', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 300_000 })
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
let before = null
const check = (condition, message) => {
  console.log(`${condition ? 'PASS' : 'FAIL'}: ${message}`)
  if (!condition) failures += 1
}

let restored = false
function restore() {
  if (restored) return
  restored = true
  try {
    if (before !== null && before !== '') simctl('ui', found.udid, 'content_size', before)
  } catch (failure) {
    console.log(`FAIL: the text size ${before} was not put back (${failure.message}): xcrun simctl ui ${found.udid} content_size ${before}`)
    failures += 1
  }
  try {
    simctl('shutdown', found.udid)
  } catch {
    // It may already be shut down.
  }
  server.close()
}
for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
  process.on(signal, () => {
    restore()
    process.exit(code)
  })
}

try {
  simctl('boot', found.udid)
  simctl('bootstatus', found.udid, '-b')
  before = simctl('ui', found.udid, 'content_size').trim()
  simctl('ui', found.udid, 'content_size', 'large')
  simctl('launch', found.udid, 'com.apple.mobilesafari')
  simctl('openurl', found.udid, `http://localhost:${port}/wrapper.html`)
  await waitFor('the page to say the share ended', () => latest !== null && latest.banner !== null && latest.shown === 'true')

  for (const [category, body] of SIZES) {
    const expected = (16 * body) / 17
    simctl('ui', found.udid, 'content_size', category)
    await waitFor(
      `the root text to reach ${expected.toFixed(2)}px at ${category}`,
      () => latest !== null && Math.abs(latest.root - expected) < 0.05 && latest.banner !== null
    ).catch((failure) => {
      console.log(`FAIL: ${failure.message}; the page said ${JSON.stringify(latest)}`)
      failures += 1
    })
    const seen = latest
    check(seen !== null && (seen.banner ?? '').includes('This share ended'), `${category}: the banner says the share ended`)
    check(seen !== null && seen.status.includes('This share ended'), `${category}: the status region says it once`)
    check(seen !== null && seen.send === true, `${category}: Send is turned off`)
    check(seen !== null && seen.left >= 0 && seen.right <= seen.screen + 0.5, `${category}: the banner is inside the screen (${seen?.left}..${seen?.right} of ${seen?.screen})`)
    check(seen !== null && seen.wide <= seen.screen, `${category}: the page is no wider than the screen (${seen?.wide} of ${seen?.screen})`)
    check(
      seen !== null && seen.buttons.length > 0 && seen.buttons.every((height) => height + 0.5 >= FINGER),
      `${category}: the banner's buttons are ${seen?.buttons.map((height) => height.toFixed(1)).join(', ')}px tall, at least ${FINGER}`
    )
    simctl('io', found.udid, 'screenshot', join(shots, `kr-standing-ios-${category}-${body}.png`))
  }
} catch (failure) {
  console.log(`FAIL: ${failure.message}`)
  failures += 1
} finally {
  restore()
}
console.log(failures === 0 ? 'every size held' : `${failures} did not hold`)
process.exit(failures === 0 ? 0 : 1)
JS
