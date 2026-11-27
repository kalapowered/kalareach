/**
 * Sentences that hold technical words: a model says them as pieces, plain text and words, and the page
 * draws each word as a technical word. Joined, the pieces are the sentence.
 */

import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Wording } from '../src/components/Wording'
import { describeAccount } from '../src/model/account'
import { describeCodeSent } from '../src/model/deletion'
import { describeRoute } from '../src/model/revocation'
import { costSentence } from '../src/setup/descriptions'
import { technical, wordingText } from '../src/model/wording'

function words(of: ReturnType<typeof describeAccount>): string[] {
  return of.flatMap((piece) => (typeof piece === 'string' ? [] : [piece.technical]))
}

describe('Wording', () => {
  it('draws each word as a technical word and keeps the text round it as it is', () => {
    const { container } = render(<p>{<Wording of={['Signed in as ', technical('sam@example.com'), '.']} />}</p>)
    const boxes = container.querySelectorAll('.technical-word')
    expect(boxes).toHaveLength(1)
    expect(boxes[0]?.textContent).toBe('sam@example.com')
    expect(container.querySelector('p')?.textContent).toBe('Signed in as sam@example.com.')
  })

  it('names the account as a word where the address is known, and as no word where it is not', () => {
    const known = describeAccount({ state: 'signed_in', email: 'sam@example.com' } as never)
    expect(words(known)).toEqual(['sam@example.com'])
    expect(wordingText(known)).toBe('Signed in as sam@example.com.')
    expect(words(describeAccount({ state: 'signed_in', email: null } as never))).toEqual([])
  })

  it('names the address a deletion code went to as a word, sent or maybe sent', () => {
    const preview = { address: 'sam@example.com', code_lifetime_minutes: 10 } as never
    expect(words(describeCodeSent(preview, true))).toEqual(['sam@example.com'])
    expect(words(describeCodeSent(preview, false))).toEqual(['sam@example.com'])
    expect(wordingText(describeCodeSent(preview, true))).toMatch(/^We sent an \d+-digit code to sam@example\.com\. It works for 10 minutes\.$/)
  })

  it('names the revocation feed as a word where the host gave one', () => {
    const host = { route: 'feed', feed: null } as never
    const said = describeRoute(host, 'reach.kala.to')
    expect(words(said)).toEqual(['reach.kala.to'])
    expect(wordingText(said)).toMatch(/^Reached through its feed at reach\.kala\.to\./)
    expect(words(describeRoute(host, null))).toEqual([])
  })

  it('names each source of a download as a word', () => {
    const none = costSentence({ asset_bytes: '1000', sources: [] } as never)
    expect(words(none)).toEqual([])
    const two = costSentence({ asset_bytes: '1000', sources: ['huggingface.co', 'cdn.example.org'] } as never)
    expect(words(two)).toEqual(['huggingface.co', 'cdn.example.org'])
    expect(wordingText(two)).toMatch(/ to download, from huggingface\.co and cdn\.example\.org\.$/)
  })
})
