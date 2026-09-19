/**
 * The desktop application's entry.
 *
 * One entry, one port. There is no branch here that could reach a scripted host: the production
 * bundle contains the desktop port and nothing else.
 */

// First, so the colour mode is on the document before anything paints.
import './theme-init'

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { AppProvider } from './app/state'
import { tauriPort } from './host/tauri'
// The phone's shell. `Shell` picks it from the platform, so the desktop window renders exactly
// what it rendered before and iOS and Android render the mobile surfaces.
import { Shell, surfaceOf } from './mobile/entry'
import './styles/tokens.css'
import './styles/base.css'
import './styles/components.css'
import './styles/views.css'

const root = document.getElementById('root')
if (!root) throw new Error('The application has no root element.')

createRoot(root).render(
  <StrictMode>
    <AppProvider port={tauriPort()}>
      <Shell surface={surfaceOf()} />
    </AppProvider>
  </StrictMode>
)
