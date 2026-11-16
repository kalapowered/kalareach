/**
 * What the Sync panel says when the sync service refuses for want of capacity (KR-REQ-17.48): the
 * whole text native code sent, with no line of the page's own after a text that carries its own
 * delay or list.
 */

import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AppProvider } from '../src/app/state'
import { SyncPanel } from '../src/components/SyncPanel'
import { fakeHost } from '../src/host/fake'
import { receivedFailure } from '../src/host/tauri'
import capacityRefusals from './fixtures/capacity-refusals.json'

describe('the Sync panel when the sync service has no capacity', () => {
  it.each(Object.entries(capacityRefusals.sync_panel))(
    'tells the whole text native code sent, with no line of the page after it: %s',
    async (_kind, sent) => {
      const { port } = fakeHost()
      vi.spyOn(port, 'syncServiceView').mockRejectedValue(
        receivedFailure({
          code: sent.code,
          message: sent.message,
          user_action: sent.user_action,
          retry: 'transient'
        })
      )
      render(
        <AppProvider port={port}>
          <SyncPanel port={port} account={null} surface="desktop" />
        </AppProvider>
      )
      await waitFor(() => {
        expect(screen.getByTestId('sync-problem').textContent).toBe(sent.page)
      })
    }
  )
})
