/**
 * The phone's settings, over a live session.
 *
 * Settings are not a destination. A person changing how the application looks has not left what
 * they were doing, so they open as a sheet over the session, which stays behind them, running and
 * keeping its draft. The sheet is the desktop's: it follows the finger, can be caught and thrown
 * away, and fades where the person asks for less motion.
 */

import type { ReactNode } from 'react'

import { Sheet, ThemeChooser } from '../../components/ui'

/** The settings sheet: shown while `open`, and asks to be closed by any of the ways a sheet closes. */
export function MobileSettings({
  open,
  onClose
}: {
  readonly open: boolean
  readonly onClose: () => void
}): ReactNode {
  return (
    <Sheet open={open} title="Settings" description="The session behind this keeps running." onClose={onClose}>
      <div className="settings-content">
        <h2>Appearance</h2>
        <p className="muted">Light, dark, or whatever this device is set to.</p>
        <ThemeChooser />
      </div>
    </Sheet>
  )
}
