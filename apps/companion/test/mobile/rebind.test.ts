/**
 * What the host says about the conversation a draft was written for, read when contact is back.
 *
 * The rebind decides three outcomes by comparing a draft's target with what the host reports now,
 * so what is reported has to be right: a session that has gone, a conversation that moved, and
 * above all a read that failed, which says nothing and so changes nothing.
 */

import { describe, expect, it } from 'vitest'

import { fakeHost } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { connectionLost, edit, startDraft, type Draft } from '../../src/model/drafts'
import { liveInstance } from '../../src/model/agent'
import { attachmentFor, observeTargets } from '../../src/mobile/model/rebind'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const GONE = '8a7b6c50-22bb-4c3d-8e4f-0000000009ff'

/** The conversation a session's agent is in now, as the host reports it. */
async function conversationOf(
  { port, controls }: ReturnType<typeof fakeHost>,
  sessionId: string
): Promise<{ instance: string; binding: string }> {
  const live = liveInstance((await port.sessionAgents(sessionId)).instances.instances)
  if (live === null) throw new Error('the scripted session has no agent')
  return {
    instance: live.application_instance_id,
    binding: controls.records.agentOf(sessionId).binding.binding_revision
  }
}

function detached(draftId: string, sessionId: string, instance: string | null, revision: string | null): Draft {
  return connectionLost(
    edit(
      startDraft(draftId, { sessionId, applicationInstanceId: instance, agentBindingRevision: revision }, 0),
      'written earlier',
      1
    )
  )
}

describe('reading where each detached draft now stands (KR-ACC-012)', () => {
  it('reports the live conversation of a session that is there', async () => {
    const host = fakeHost()
    const { port } = host
    const now = await conversationOf(host, SESSION_MAIN)
    const seen = await observeTargets(port, [detached('d-1', SESSION_MAIN, now.instance, now.binding)])
    expect(seen).toHaveLength(1)
    expect(seen[0]?.draftId).toBe('d-1')
    expect(seen[0]?.attachmentId).toBe(attachmentFor(SESSION_MAIN))
    expect(seen[0]?.target).toEqual({
      sessionId: SESSION_MAIN,
      applicationInstanceId: now.instance,
      agentBindingRevision: now.binding
    })
  })

  it('reports a conversation that moved as the conversation it moved to', async () => {
    const host = fakeHost()
    const { port, controls } = host
    const before = await conversationOf(host, SESSION_MAIN)
    controls.records.moveBinding(SESSION_MAIN)
    const after = await conversationOf(host, SESSION_MAIN)
    expect(after.binding).not.toBe(before.binding)
    const [seen] = await observeTargets(port, [
      detached('d-1', SESSION_MAIN, before.instance, before.binding)
    ])
    expect(seen?.target).toEqual({
      sessionId: SESSION_MAIN,
      applicationInstanceId: after.instance,
      agentBindingRevision: after.binding
    })
  })

  it('reports a session the host does not know as gone, and only that', async () => {
    const { port } = fakeHost()
    const [seen] = await observeTargets(port, [detached('d-1', GONE, 'app-1', '4')])
    expect(seen).toMatchObject({ draftId: 'd-1', target: null })
  })

  it('reports a session the host holds only as closed as gone, though its worker is not there to ask', async () => {
    const { port } = fakeHost()
    // What a controller answers for a closed session: its record, with the state closed. Its
    // worker has stopped, so the read of the agents is refused as for a session that never was.
    const closed: HostPort = {
      ...port,
      sessionRead: async (params) => {
        const read = await port.sessionRead(params)
        return { ...read, session: { ...read.session, state: 'closed' } }
      },
      sessionAgents: () =>
        Promise.reject({ code: 'UNKNOWN_SESSION', message: 'No worker holds that session.', user_action: 'none' })
    }
    const [seen] = await observeTargets(closed, [detached('d-1', SESSION_MAIN, 'app-1', '4')])
    expect(seen).toMatchObject({ draftId: 'd-1', target: null })
  })

  it('says nothing about a draft when the agents of its session cannot be read, or their binding', async () => {
    const { port } = fakeHost()
    const refused = { code: 'UNAVAILABLE', message: 'The host did not answer.', user_action: 'retry' }
    const noAgents: HostPort = { ...port, sessionAgents: () => Promise.reject(refused) }
    const noBinding: HostPort = { ...port, agentCapabilities: () => Promise.reject(refused) }
    const draft = detached('d-1', SESSION_MAIN, 'app-1', '4')
    expect(await observeTargets(noAgents, [draft])).toEqual([])
    expect(await observeTargets(noBinding, [draft])).toEqual([])
  })

  it('asks the host once about a session however many drafts wait on it', async () => {
    const { port } = fakeHost()
    const reads: string[] = []
    const counting: HostPort = {
      ...port,
      sessionRead: (params) => {
        reads.push((params as { session_id?: string }).session_id ?? '')
        return port.sessionRead(params)
      }
    }
    const seen = await observeTargets(counting, [
      detached('d-1', SESSION_MAIN, null, null),
      detached('d-2', SESSION_MAIN, null, null)
    ])
    expect(reads).toEqual([SESSION_MAIN])
    expect(seen.map((each) => each.draftId)).toEqual(['d-1', 'd-2'])
  })

  it('says nothing about a draft whose read failed for any other reason, so it stays detached', async () => {
    const { port } = fakeHost()
    const unreachable: HostPort = {
      ...port,
      sessionRead: (params) => {
        const asked = (params as { session_id?: string }).session_id
        return asked === SESSION_BUILD
          ? Promise.reject({ code: 'UNAVAILABLE', message: 'unreachable', user_action: 'retry' })
          : port.sessionRead(params)
      }
    }
    const seen = await observeTargets(unreachable, [
      detached('d-main', SESSION_MAIN, null, null),
      detached('d-build', SESSION_BUILD, 'app-1', '4')
    ])
    expect(seen.map((each) => each.draftId)).toEqual(['d-main'])
  })

  it('leaves a draft as it was written when the session has no agent running', async () => {
    const { port } = fakeHost()
    const noAgent: HostPort = {
      ...port,
      sessionAgents: async (sessionId) => {
        const read = await port.sessionAgents(sessionId)
        return { ...read, instances: { ...read.instances, instances: [] } }
      }
    }
    const draft = detached('d-1', SESSION_MAIN, 'app-1', '4')
    const [seen] = await observeTargets(noAgent, [draft])
    // Nothing the host reports contradicts the draft, so it binds where it was written for.
    expect(seen?.target).toEqual(draft.target)
  })

  it('reads only the drafts that are detached', async () => {
    const { port } = fakeHost()
    let reads = 0
    const counting: HostPort = {
      ...port,
      sessionRead: (params) => {
        reads += 1
        return port.sessionRead(params)
      }
    }
    const bound = startDraft('d-bound', { sessionId: SESSION_MAIN, applicationInstanceId: null, agentBindingRevision: null }, 0)
    expect(await observeTargets(counting, [bound])).toEqual([])
    expect(reads).toBe(0)
  })
})
