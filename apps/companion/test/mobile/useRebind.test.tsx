/**
 * What an answer about a draft's conversation may do once the page has moved on (KR-ACC-012).
 *
 * The shell asks the host where each detached draft stands and binds the drafts the answer clears.
 * An answer belongs to the question it was read for: one read before the application came back to
 * the front again, or before contact was lost, says nothing about the draft as it is now, and it
 * must be dropped even when the page has not yet rendered what changed. These drive the hook with
 * a lifecycle of their own, so that moment can be held still.
 */

import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'

import { AppProvider } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { connectionLost, edit, startDraft, type Draft } from '../../src/model/drafts'
import type { Lifecycle } from '../../src/mobile/useLifecycle'
import { useRebind } from '../../src/mobile/useRebind'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

afterEach(cleanup)

/** A draft a break detached, written for the conversation the scripted host is in. */
function detachedDraft(): Draft {
  return connectionLost(
    edit(
      startDraft(
        'd-1',
        { sessionId: SESSION_MAIN, applicationInstanceId: null, agentBindingRevision: null },
        0
      ),
      'written before the break',
      1
    )
  )
}

/** A lifecycle holding `draft`, whose resumptions the test declares by hand. */
function lifecycleOf(draft: Draft) {
  let resumptions = 0
  const setDrafts = vi.fn()
  const lifecycle = {
    state: { drafts: [draft], submissions: [] },
    resumed: 0,
    resumedNow: () => resumptions,
    setDrafts
  } as unknown as Lifecycle
  return {
    lifecycle,
    setDrafts,
    resume: () => {
      resumptions += 1
    }
  }
}

/** A port whose answer to the session read waits for `release`. */
function holdingTheSessionRead(): { port: HostPort; release: () => void } {
  const { port } = fakeHost()
  let release: () => void = () => undefined
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  return {
    release,
    port: {
      ...port,
      sessionRead: async (params) => {
        await gate
        return await port.sessionRead(params)
      }
    }
  }
}

const wrapperFor = (port: HostPort) =>
  function Wrapper({ children }: { readonly children: ReactNode }): ReactNode {
    return <AppProvider port={port}>{children}</AppProvider>
  }

/** Lets the answer's chain of reads run to its end, which takes the scripted host a few turns. */
async function untilAnswered(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => {
      setTimeout(resolve, 200)
    })
  })
}

describe('an answer about where a draft stands (KR-ACC-012)', () => {
  it('binds the draft it was read for when nothing came in between', async () => {
    const { port, release } = holdingTheSessionRead()
    const { lifecycle, setDrafts } = lifecycleOf(detachedDraft())
    renderHook(() => {
      useRebind(lifecycle, true)
    }, { wrapper: wrapperFor(port) })

    release()
    await untilAnswered()

    expect(setDrafts).toHaveBeenCalledTimes(1)
  })

  it('drops an answer read before the application came back again, though the page has not rendered that', async () => {
    const { port, release } = holdingTheSessionRead()
    const { lifecycle, setDrafts, resume } = lifecycleOf(detachedDraft())
    renderHook(() => {
      useRebind(lifecycle, true)
    }, { wrapper: wrapperFor(port) })

    // The application comes back to the front again; the page has rendered nothing yet.
    resume()
    release()
    await untilAnswered()

    expect(setDrafts).not.toHaveBeenCalled()
  })

  it('asks nothing while the host is out of contact', async () => {
    const { port, release } = holdingTheSessionRead()
    const { lifecycle, setDrafts } = lifecycleOf(detachedDraft())
    renderHook(() => {
      useRebind(lifecycle, false)
    }, { wrapper: wrapperFor(port) })

    release()
    await untilAnswered()

    expect(setDrafts).not.toHaveBeenCalled()
  })
})
