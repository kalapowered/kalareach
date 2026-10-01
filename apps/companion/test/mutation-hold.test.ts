/**
 * The scripted host can hold a send, as a host does that has the request and has not answered it.
 *
 * Reconnection and recovery are about exactly that moment: a prompt has left the device and no
 * receipt has come back. The hold keeps the host's side effect and the page's wait apart, so a test
 * can lose and regain contact while one action has no confirmed outcome.
 */

import { describe, expect, it } from 'vitest'

import { fakeHost } from '../src/host/fake'
import { answeredState } from '../src/model/receipts'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** What a page sends to put one prompt into the session's agent. */
async function submit(host: ReturnType<typeof fakeHost>, text: string) {
  const agents = await host.port.sessionAgents(SESSION_MAIN)
  const live = agents.instances.instances.find((each) => each.ended_at === null)
  if (live === undefined) throw new Error('the scripted session has no agent')
  const facts = await host.port.agentCapabilities({
    subject: { session_id: SESSION_MAIN, application_instance_id: live.application_instance_id }
  })
  return host.port.composerSubmit({
    target: {
      subject: { session_id: SESSION_MAIN, application_instance_id: live.application_instance_id },
      binding_revision: facts.binding.binding_revision
    },
    draft_id: null,
    text
  })
}

describe('a send the scripted host holds (KR-ACC-012)', () => {
  it('counts a send the moment the host has it, and answers it when released', async () => {
    const host = fakeHost()
    const held = host.controls.holdMutation()
    let answered = false
    const pending = submit(host, 'run it').then((outcome) => {
      answered = true
      return outcome
    })

    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(host.controls.submissions).toBe(1)
    expect(held.count).toBe(1)
    expect(answered).toBe(false)

    held.release()
    const outcome = await pending
    expect(answered).toBe(true)
    expect(answeredState(outcome)).toBe('applied')
    expect(host.controls.submissions).toBe(1)
  })

  it('answers a send at once when nothing is held, and counts it', async () => {
    const host = fakeHost()
    const outcome = await submit(host, 'run it')
    expect(answeredState(outcome)).toBe('applied')
    expect(host.controls.submissions).toBe(1)
  })

  it('holds nothing after a release', async () => {
    const host = fakeHost()
    const held = host.controls.holdMutation()
    const first = submit(host, 'one')
    await new Promise((resolve) => setTimeout(resolve, 50))
    held.release()
    await first
    const second = await submit(host, 'two')
    expect(answeredState(second)).toBe('applied')
    expect(host.controls.submissions).toBe(2)
    expect(held.count).toBe(1)
  })

  it('refuses a send it cannot reach, and counts only what it received', async () => {
    const host = fakeHost()
    host.controls.setConnected(false)
    await expect(submit(host, 'lost')).rejects.toBeDefined()
    expect(host.controls.submissions).toBe(0)
  })
})
