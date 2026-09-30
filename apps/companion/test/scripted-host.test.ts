/**
 * The scripted host answers and refuses the published methods as a real host does.
 *
 * A page that passes against it sends what a real host takes, so its refusals are the codes the
 * session's worker and the daemon answer with, in the order they check: a parameter map the method
 * does not take, an instance the session does not have, a suspended binding, a binding revision
 * that moved on, a turn that is not the one running, and a capability that is not usable now.
 */

import { describe, expect, it } from 'vitest'

import type { AgentMutationTarget, AgentSubject, GrantCreateParams } from '@kalareach/protocol'
import { base64UrlToBytes } from '@kalareach/protocol'

import { fakeHost } from '../src/host/fake'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const INSTANCE_MAIN = 'a1a1a1a1-0000-4000-8000-000000000001'
const INSTANCE_BUILD = 'a1a1a1a1-0000-4000-8000-000000000002'
const APPROVAL = 'b2b2b2b2-0000-4000-8000-000000000001'
const PHONE = 'd4d4d4d4-0000-4000-8000-000000000001'
const RETIRED_PHONE = 'd4d4d4d4-0000-4000-8000-000000000002'
const ENVIRONMENT = '3f1a2c40-11aa-4b2c-9d3e-000000000001'

const main: AgentSubject = { session_id: SESSION_MAIN, application_instance_id: INSTANCE_MAIN }
const build: AgentSubject = { session_id: SESSION_BUILD, application_instance_id: INSTANCE_BUILD }

function target(subject: AgentSubject, revision = '4'): AgentMutationTarget {
  return { subject, binding_revision: revision }
}

describe("the scripted host and the agent's methods", () => {
  it('refuses a parameter map the method does not take, before anything else', async () => {
    const { port } = fakeHost()
    await expect(
      port.agentSnapshot({ subject: main, from_node: null, limit: 10 } as never)
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' })
    await expect(
      port.composerSubmit({ target: target(main), draft_id: null, text: '' })
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' })
    await expect(
      port.composerSubmit({ target: target(main), draft_id: null, text: null })
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' })
  })

  it('refuses an instance the session does not have as a stale subject', async () => {
    const { port } = fakeHost()
    await expect(
      port.agentCapabilities({ subject: { ...main, application_instance_id: INSTANCE_BUILD } })
    ).rejects.toMatchObject({ code: 'STALE_SESSION' })
  })

  it('refuses a mutation prepared against a binding that has moved on', async () => {
    const { port, controls } = fakeHost()
    controls.records.moveBinding(SESSION_MAIN)
    await expect(
      port.composerSubmit({ target: target(main, '4'), draft_id: null, text: 'hello' })
    ).rejects.toMatchObject({ code: 'STALE_SESSION' })
    const moved = await port.composerSubmit({ target: target(main, '5'), draft_id: null, text: 'hello' })
    expect(moved.value?.binding_revision).toBe('5')
  })

  it('refuses every mutation while the binding is unverified, and says why', async () => {
    const { port, controls } = fakeHost()
    controls.records.suspend(SESSION_MAIN, 'The conversation changed outside this host.')
    await expect(
      port.composerSubmit({ target: target(main), draft_id: null, text: 'hello' })
    ).rejects.toMatchObject({
      code: 'DRAFT_CONFLICT',
      message: 'The conversation changed outside this host.'
    })
    const facts = await port.agentCapabilities({ subject: main })
    expect(facts.binding.rich_mutations_suspended).toBe(true)
  })

  it('checks suspension before the binding revision, and the turn before the capability', async () => {
    const { port, controls } = fakeHost()
    // Both a moved binding and a suspension: the suspension is what the worker answers.
    controls.records.moveBinding(SESSION_BUILD)
    controls.records.suspend(SESSION_BUILD, 'The conversation changed outside this host.')
    await expect(
      port.composerSubmit({ target: target(build, '4'), draft_id: null, text: 'hello' })
    ).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    // Both a turn that is not running and a capability the upstream lacks: the turn comes first.
    await expect(
      port.composerSteer({ target: target(main), turn_id: 'turn-1', text: 'stop' })
    ).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    controls.records.setCapability(SESSION_MAIN, 'agent.steer', 'incompatible')
    await expect(
      port.composerSteer({ target: target(main), turn_id: 'turn-1', text: 'stop' })
    ).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    await expect(
      port.composerSteer({ target: target(main), turn_id: 'turn-9', text: 'stop' })
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_CAPABILITY' })
  })

  it('reads a draft attachment the way native code does, contribution and all', async () => {
    const { port } = fakeHost()
    await expect(
      port.draftAddAttachment(
        {
          draft_id: 'draft-8a7b6c50-22bb-4c3d-8e4f-000000000101',
          transfer_id: '99999999-9999-4999-8999-999999999999',
          insertion_method: 'typed_submission'
        },
        { sessionId: SESSION_MAIN }
      )
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' })
  })

  it('refuses what the upstream does not offer, and a turn that is not the one running', async () => {
    const { port } = fakeHost()
    await expect(
      port.composerQueue({ target: target(build), draft_id: null, text: 'later' })
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_CAPABILITY' })
    await expect(
      port.composerSteer({ target: target(main), turn_id: 'turn-1', text: 'stop' })
    ).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
  })

  it('starts a turn on a prompt, ends it on a cancellation, and records what it did', async () => {
    const { port, controls } = fakeHost()
    await port.composerSubmit({ target: target(build), draft_id: null, text: 'Build it' })
    const running = controls.records.agentOf(SESSION_BUILD).binding.turn_id
    expect(running).not.toBeNull()
    await port.composerInterrupt({ target: target(build), turn_id: running ?? '' })
    const after = controls.records.agentOf(SESSION_BUILD)
    expect(after.binding.turn_id).toBeNull()
    expect(after.entries.map((entry) => entry.text)).toContain('Build it')
  })

  it('answers an approval once, and only with a decision the request offered', async () => {
    const { port } = fakeHost()
    const inspected = await port.approvalInspect({ subject: main, resource_id: APPROVAL })
    expect(inspected.decoding.projection.decisions.map((each) => each.option_id)).toEqual([
      'approved',
      'approved_for_session',
      'denied'
    ])
    // What the agent sent is kept as it arrived, beside what the decoder read.
    expect(new TextDecoder().decode(base64UrlToBytes(inspected.decoding.source_bytes))).toContain(
      '"method":"execCommandApproval"'
    )

    await expect(
      port.approvalRespond({ target: target(main), resource_id: APPROVAL, option_id: 'maybe' })
    ).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
    await expect(
      port.approvalRespond({
        target: target(main),
        resource_id: 'b2b2b2b2-0000-4000-8000-000000000009',
        option_id: 'approved'
      })
    ).rejects.toMatchObject({ code: 'STALE_SESSION' })
    // An answer is a mutation like any other: prepared at a binding that moved, or where the
    // approval capability is not usable now, it is refused.
    await expect(
      port.approvalRespond({ target: target(main, '3'), resource_id: APPROVAL, option_id: 'approved' })
    ).rejects.toMatchObject({ code: 'STALE_SESSION' })
    const answered = await port.approvalRespond({
      target: target(main),
      resource_id: APPROVAL,
      option_id: 'approved'
    })
    expect(answered.value?.state).toBe('resolved')
    await expect(
      port.approvalRespond({ target: target(main), resource_id: APPROVAL, option_id: 'denied' })
    ).rejects.toMatchObject({ code: 'QUESTION_RESOLVED' })
  })

  it('refuses an answer where the approval capability is not usable now', async () => {
    const { port, controls } = fakeHost()
    controls.records.setCapability(SESSION_MAIN, 'agent.approval', 'temporarily_unavailable')
    await expect(
      port.approvalRespond({ target: target(main), resource_id: APPROVAL, option_id: 'approved' })
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_CAPABILITY' })
  })

  it('continues a long history in parts, and counts only what each part withheld', async () => {
    const { port, controls } = fakeHost()
    for (let index = 0; index < 50; index += 1) {
      controls.records.appendEntry(SESSION_MAIN, 'message', `entry ${index}`)
    }
    controls.records.withhold(SESSION_MAIN, 2)
    const first = await port.agentSnapshot({ subject: main, from_node: null })
    expect(first.entries).toHaveLength(40)
    expect(first.withheld_entries).toBe('2')
    const from = first.continuation?.from_node ?? null
    expect(from).toBe('43')
    const rest = await port.agentSnapshot({ subject: main, from_node: from })
    expect(rest.entries).toHaveLength(13)
    expect(rest.continuation).toBeNull()
    expect(rest.withheld_entries).toBe('0')
  })

  it('pages retained output by cursor and byte bound, and says what it let go', async () => {
    const { port } = fakeHost()
    const early = await port.historyPage({ session_id: SESSION_MAIN, from_cursor: '0', max_bytes: '64' })
    expect(early.gap).toEqual({ from_cursor: '0', to_cursor: '2048', cause: 'retention' })
    expect(early.from_cursor).toBe('2048')
    expect(early.next_cursor).toBe('2112')
    expect(base64UrlToBytes(early.bytes)).toHaveLength(64)

    const next = await port.historyPage({
      session_id: SESSION_MAIN,
      from_cursor: early.next_cursor,
      max_bytes: '64'
    })
    expect(next.gap).toBeNull()
    expect(next.from_cursor).toBe('2112')
  })
})

describe('the scripted host and attention, review and sharing', () => {
  it('marks an item seen only at the revision the person saw', async () => {
    const { port, controls } = fakeHost()
    const failure = controls.records.attentionItem('attention.command_failed')
    const stale = await port.attentionAcknowledge({
      items: [{ key: failure.key, revision: String(Number(failure.revision) - 1) }]
    })
    expect(stale.value?.stale).toEqual([failure.key])
    const seen = await port.attentionAcknowledge({
      items: [{ key: failure.key, revision: failure.revision }]
    })
    expect(seen.value?.acknowledged).toEqual([failure.key])
    const inbox = await port.attentionRead({
      session_id: null,
      include_acknowledged: false,
      max_items: '200',
      after: null
    })
    expect(inbox.items.map((item) => item.key)).not.toContain(failure.key)
  })

  it('marks a change set reviewed up to a version it holds, and keeps newer work outstanding', async () => {
    const { port } = fakeHost()
    const change = {
      session_id: SESSION_MAIN,
      subject: {
        change_set: { session_id: SESSION_MAIN, change_set_id: 'c3c3c3c3-0000-4000-8000-000000000001' }
      }
    }
    await expect(port.reviewAcknowledge({ ...change, version: '3' })).rejects.toMatchObject({
      code: 'DRAFT_CONFLICT'
    })
    await expect(
      port.reviewAcknowledge({ ...change, session_id: SESSION_BUILD, version: '2' })
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' })
    const older = await port.reviewAcknowledge({ ...change, version: '1' })
    expect(older.value?.review).toMatchObject({ acknowledged_version: '1', outstanding: true })
    const current = await port.reviewAcknowledge({ ...change, version: '2' })
    expect(current.value?.review).toMatchObject({ acknowledged_version: '2', outstanding: false })
    // An older version read again is not a retreat.
    const again = await port.reviewAcknowledge({ ...change, version: '1' })
    expect(again.value?.review).toMatchObject({ acknowledged_version: '2', outstanding: false })
  })

  it('pages the inbox and review state, and refuses a page after something it does not hold', async () => {
    const { port } = fakeHost()
    const first = await port.attentionRead({
      session_id: null,
      include_acknowledged: false,
      max_items: '2',
      after: null
    })
    expect(first.items).toHaveLength(2)
    expect(first.more).toBe(true)
    const second = await port.attentionRead({
      session_id: null,
      include_acknowledged: false,
      max_items: '2',
      after: first.items[1]?.key ?? null
    })
    expect(second.items.map((item) => item.key)).not.toContain(first.items[0]?.key)
    await expect(
      port.attentionRead({
        session_id: null,
        include_acknowledged: false,
        max_items: '2',
        after: 'attention.pending_approval|~ffffffffffffffffffffffffffffffff'
      })
    ).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })

    const reviews = await port.reviewRead({
      session_id: null,
      subject: null,
      max_reviews: '1',
      after: null
    })
    expect(reviews.reviews).toHaveLength(1)
    expect(reviews.more).toBe(true)
    const rest = await port.reviewRead({
      session_id: null,
      subject: null,
      max_reviews: '1',
      after: reviews.reviews[0]?.subject ?? null
    })
    expect(rest.reviews).toHaveLength(1)
    expect(rest.more).toBe(false)
  })

  it('refuses a whole acknowledgement that names a revision an item has not reached', async () => {
    const { port, controls } = fakeHost()
    const failure = controls.records.attentionItem('attention.command_failed')
    await expect(
      port.attentionAcknowledge({
        items: [{ key: failure.key, revision: String(Number(failure.revision) + 1) }]
      })
    ).rejects.toMatchObject({ code: 'DRAFT_CONFLICT' })
  })

  describe('an invitation', () => {
    function invitation(over: Partial<GrantCreateParams> = {}): GrantCreateParams {
      return {
        session_id: SESSION_MAIN,
        recipient_device_id: PHONE,
        parent_grant_id: null,
        selection: {
          role: 'viewer',
          history_from_cursor_ms: null,
          include_live_screen: false,
          include_question_respond: true,
          named_questions: [],
          named_approvals: []
        },
        lifetime_ms: null,
        accepted_notices: ['agent_permissions'],
        owner_confirmation: null,
        ...over
      }
    }

    it('carries the consequences its selection compiles to, in the host’s own words', async () => {
      const { port } = fakeHost()
      const carried = await port.grantNotices(invitation().selection)
      expect(carried.actions).toEqual(['session.view', 'question.respond'])
      expect(carried.notices.map((each) => each.notice)).toEqual(['agent_permissions'])
      expect(carried.notices[0]?.sentence.length).toBeGreaterThan(0)
    })

    it('is refused when the consequences accepted are not the ones it carries', async () => {
      const { port } = fakeHost()
      await expect(port.grantCreate(invitation({ accepted_notices: [] }), {})).rejects.toMatchObject({
        code: 'PERMISSION_DENIED'
      })
    })

    it('is refused for a device the host does not hold, or one it retired', async () => {
      const { port } = fakeHost()
      await expect(
        port.grantCreate(invitation({ recipient_device_id: RETIRED_PHONE }), {})
      ).rejects.toMatchObject({ code: 'PERMISSION_DENIED' })
    })

    it('is used once and expires an hour after it is issued unless the issuer chose otherwise', async () => {
      const { port } = fakeHost()
      const issued = await port.grantCreate(invitation(), {})
      const preview = issued.value?.preview
      expect(preview?.single_use).toBe(true)
      const expiry = issued.value?.grant.expiry
      expect(typeof expiry === 'object' ? Number(expiry.at.expires_at_ms) : 0).toBeGreaterThan(0)
      const listed = await port.grantList({ session_id: SESSION_MAIN, include_resolved: false })
      expect(listed.grants.map((each) => each.state)).toEqual(['pending'])
    })
  })
})

describe("the scripted host and a retained artefact's deletion", () => {
  it("reads the request as the request's own type is read, and refuses the rest by name", async () => {
    const { port } = fakeHost()
    const refusals: [unknown, string][] = [
      [{}, 'missing field `object_id`'],
      [{ object_id: 3 }, '`object_id` is an identifier of 1 to 256 bytes'],
      [{ object_id: '' }, '`object_id` is an identifier of 1 to 256 bytes'],
      [{ object_id: 'obj-1\u0000' }, '`object_id` is an identifier of 1 to 256 bytes'],
      [{ object_id: 'obj-1', hold: true }, 'unknown field `hold`'],
      ['obj-1', '`` is a map'],
      [null, '`` is a map']
    ]
    for (const [params, problem] of refusals) {
      await expect(port.storageObjectDelete(params, {}), JSON.stringify(params)).rejects.toEqual({
        code: 'INVALID_ARGUMENT',
        message: `those are not this operation's parameters: ${problem}`,
        user_action: 'nothing'
      })
    }
    // Nothing was deleted by a request it refused.
    expect(JSON.stringify(await port.storageStatus({}))).toContain('obj-1')
  })

  it('deletes what a request of the right shape names, and refuses a copy held elsewhere as before', async () => {
    const { port } = fakeHost()
    await port.storageObjectDelete({ object_id: 'obj-1' }, {})
    expect(JSON.stringify(await port.storageStatus({}))).not.toContain('obj-1')
    await expect(port.storageObjectDelete({ object_id: 'obj-3' }, {})).rejects.toMatchObject({
      code: 'PERMISSION_DENIED'
    })
  })
})

describe('the scripted host and packages', () => {
  it('lists only the environment it owns', async () => {
    const { port } = fakeHost()
    const installed = await port.pluginList({ environment_id: ENVIRONMENT })
    expect(installed.plugins.map((plugin) => plugin.plugin_id)).toContain('openai.codex')
    await expect(
      port.catalogueList({ environment_id: '3f1a2c40-11aa-4b2c-9d3e-000000000999' })
    ).rejects.toMatchObject({ code: 'ENVIRONMENT_UNAVAILABLE' })
  })
})
