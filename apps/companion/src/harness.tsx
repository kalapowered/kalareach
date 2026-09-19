/**
 * The test harness's entry.
 *
 * The same application, against a host that answers without a machine behind it. This entry is
 * built only when a test build asks for it, so the desktop bundle never carries it.
 */

// First, so the colour mode is on the document before anything paints.
import './theme-init'

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { App } from './App'
import { AppProvider } from './app/state'
import { fakeHost, type FakeHostControls } from './host/fake'
import './styles/tokens.css'
import './styles/base.css'
import './styles/components.css'
import './styles/views.css'

declare global {
  interface Window {
    /** What a browser test drives the host with. */
    krTestHost?: FakeHostControls
  }
}

const root = document.getElementById('root')
if (!root) throw new Error('The application has no root element.')

const { port, controls } = fakeHost()
window.krTestHost = controls

createRoot(root).render(
  <StrictMode>
    <AppProvider port={port}>
      <App />
    </AppProvider>
  </StrictMode>
)
