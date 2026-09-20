/**
 * Asserts the voice surface states across WebKit and Chromium engines.
 *
 * KR-REQ-15.09: managed content access disclosed in the provider choice.
 * KR-REQ-15.19: the provider and context scope shown before voice starts.
 * KR-REQ-15.36 & KR-ACC-014: muted or unavailable capture shown; unheard speech never authorises.
 * KR-REQ-15.17: local mute and closure survive broker failure.
 * KR-REQ-15.22: speech interruption stops playback only; cancellation uses typed turn request.
 */

import { chromium, webkit, type BrowserType } from '@playwright/test'

const baseUrl = 'http://localhost:4188'

async function assertEngine(browserType: BrowserType, name: string): Promise<void> {
  console.log(`[assert-voice-surface] Checking engine: ${name}`)
  const browser = await browserType.launch({ headless: true })
  const page = await browser.newPage()

  try {
    // 1. KR-REQ-15.19 & KR-REQ-15.09: Provider choice screen
    await page.goto(`${baseUrl}/harness.html?surface=desktop&tab=voice`)
    await page.waitForSelector('.kr-voice')

    // Model and broker
    const modelText = await page.textContent('.kr-voice__provider dd')
    if (!modelText?.includes('gpt-live-1')) {
      throw new Error(`Expected model gpt-live-1, got ${modelText}`)
    }

    // KR-REQ-15.09: Managed content access disclosure
    const content = await page.content()
    if (!content.includes('Audio travels directly between this device and the provider')) {
      throw new Error('Missing disclosure: Audio travels directly')
    }
    if (!content.includes('The provider and this service can process the speech and the context')) {
      throw new Error('Missing disclosure: process the speech')
    }
    if (!content.includes('is not a confirmation')) {
      throw new Error('Missing disclosure: confirmation refusal')
    }

    // KR-REQ-15.19: Context scope
    if (!content.includes('Building the release') || !content.includes('~/work/kalareach')) {
      throw new Error('Missing context scope items')
    }
    if (!content.includes('8,000 tokens this host allows')) {
      throw new Error('Missing token cap text')
    }
    if (!content.includes('file contents') || !content.includes('terminal scrollback')) {
      throw new Error('Missing withheld items')
    }

    // Refusal of start when over cap
    await page.goto(`${baseUrl}/harness.html?surface=desktop&tab=voice&over_cap=1`)
    await page.waitForSelector('.kr-voice')
    const startBtnDisabled = await page.isDisabled('button.kr-voice__start')
    if (!startBtnDisabled) {
      throw new Error('Expected start button to be disabled when over cap')
    }

    // 2. KR-REQ-15.36 & KR-ACC-014: Capture unavailable & refusal
    await page.goto(`${baseUrl}/harness.html?surface=desktop&tab=voice&state=unavailable`)
    await page.waitForSelector('.kr-voice')
    const statusText = await page.textContent('.kr-voice__capture')
    if (!statusText?.includes('No microphone available')) {
      throw new Error(`Expected 'No microphone available', got ${statusText}`)
    }
    const refusalText = await page.textContent('.kr-voice__refusal')
    if (!refusalText?.includes('Nothing spoken while the microphone was not carrying your voice can authorise an action')) {
      throw new Error(`Missing unheard speech refusal text, got: ${refusalText}`)
    }

    // 3. KR-REQ-15.36: Muted capture & refusal
    await page.goto(`${baseUrl}/harness.html?surface=desktop&tab=voice&state=muted`)
    await page.waitForSelector('.kr-voice')
    const mutedStatus = await page.textContent('.kr-voice__capture')
    if (!mutedStatus?.includes('Microphone muted')) {
      throw new Error(`Expected 'Microphone muted', got ${mutedStatus}`)
    }
    const mutedRefusal = await page.textContent('.kr-voice__refusal')
    if (!mutedRefusal?.includes('can authorise an action')) {
      throw new Error('Missing refusal warning when muted')
    }

    // 4. KR-REQ-15.17: Broker unreachable survival
    await page.goto(`${baseUrl}/harness.html?surface=desktop&tab=voice&state=capturing&broker=unreachable`)
    await page.waitForSelector('.kr-voice')
    const brokerWarning = await page.textContent('.kr-voice__refusal[role="status"]')
    if (!brokerWarning?.includes('The voice service is not answering')) {
      throw new Error('Missing broker unreachable warning')
    }

    // Local controls remain enabled
    const muteBtn = page.getByRole('button', { name: 'Mute microphone' })
    if (!(await muteBtn.isEnabled())) throw new Error('Mute button should be enabled')

    const stopVoiceBtn = page.getByRole('button', { name: 'Stop the voice' })
    if (!(await stopVoiceBtn.isEnabled())) throw new Error('Stop voice button should be enabled')

    const endBtn = page.getByRole('button', { name: 'End session' })
    if (!(await endBtn.isEnabled())) throw new Error('End session button should be enabled')

    // Task cancellation disabled when broker unreachable
    const cancelBtn = page.getByRole('button', { name: 'Cancel the current turn' })
    if (!(await cancelBtn.isDisabled())) throw new Error('Cancel turn button should be disabled when broker unreachable')

    // 5. KR-REQ-15.22: Interruption separation
    await page.goto(`${baseUrl}/harness.html?surface=desktop&tab=voice&state=capturing`)
    await page.waitForSelector('.kr-voice')
    const liveCancelBtn = page.getByRole('button', { name: 'Cancel the current turn' })
    await liveCancelBtn.click()
    const confirmCancelBtn = page.getByRole('button', { name: 'Cancel this turn' })
    if (!(await confirmCancelBtn.isVisible())) {
      throw new Error('Confirmation button for task cancellation not visible')
    }

    console.log(`[assert-voice-surface] All checks passed on ${name}`)
  } finally {
    await browser.close()
  }
}

async function main() {
  await assertEngine(chromium, 'Chromium')
  await assertEngine(webkit, 'WebKit')
  console.log('[assert-voice-surface] Voice surface verified successfully across engines.')
}

main().catch((err: unknown) => {
  console.error('[assert-voice-surface] FAILURE:', err)
  throw err
})
