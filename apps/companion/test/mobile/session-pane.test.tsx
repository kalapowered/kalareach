/**
 * The pane a phone's session screen opens on (KR-REQ-12.25).
 *
 * A route into a session can name the pane, so an approval that is answered in the terminal opens
 * the session there; a route that names none opens the conversation.
 */

import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

import { AppProvider } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import { MobileSession } from '../../src/mobile/views/MobileSession'
import { useLifecycle } from '../../src/mobile/useLifecycle'
import type { ReactNode } from 'react'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

function OnSession({ initialPane }: { readonly initialPane?: 'semantic' | 'terminal' }): ReactNode {
  const lifecycle = useLifecycle(null)
  return (
    <MobileSession
      sessionId={SESSION_MAIN}
      surface="ios"
      lifecycle={lifecycle}
      connected={true}
      initialPane={initialPane}
      onBack={() => undefined}
    />
  )
}

const paneShown = () => document.querySelector('[data-pane]')?.getAttribute('data-pane') ?? null

describe('the pane the phone session screen opens on', () => {
  it('opens_on_the_terminal_when_the_route_names_it', async () => {
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <OnSession initialPane="terminal" />
      </AppProvider>
    )
    await waitFor(() => {
      expect(paneShown()).toBe('terminal')
    })
  })

  it('opens_on_the_conversation_when_the_route_names_none', async () => {
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <OnSession />
      </AppProvider>
    )
    await screen.findByTestId('mobile-conversation')
    expect(paneShown()).toBe('semantic')
  })
})
