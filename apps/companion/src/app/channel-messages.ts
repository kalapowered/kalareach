/**
 * How a screen reaches the messages this device keeps apart: the shelf the window holds, read the
 * way React reads a store. The shelf itself is in `model/channel-messages.ts`, and one is made for
 * the window by the application's provider.
 */

import { useSyncExternalStore } from 'react'

import type { ChannelShelf, ShelfSnapshot } from '../model/channel-messages'
import { useApp } from './state'

/** What the shelf holds, and the page re-renders when it changes. */
export function useChannelMessages(): ShelfSnapshot {
  const { channelMessages } = useApp()
  return useSyncExternalStore(channelMessages.subscribe, channelMessages.snapshot)
}

/** The window's shelf, for a screen that keeps, reads or removes messages. */
export function useChannelShelf(): ChannelShelf {
  return useApp().channelMessages
}
