/**
 * What the Markdown renderer will and will not put on the page.
 *
 * The interesting cases are all the same shape: a package or an agent prints something, and the
 * question is whether the interface turns it into a thing the person can be tricked into
 * activating.
 */

import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { openableScheme, renderMarkdown } from '../src/markdown/render'

function show(source: string, overrides: Partial<Parameters<typeof renderMarkdown>[1]> = {}) {
  const context = {
    openLink: vi.fn(),
    importImage: vi.fn(),
    importedImages: new Map<string, string>(),
    ...overrides
  }
  const view = render(<div data-testid="out">{renderMarkdown(source, context)}</div>)
  return { context, view }
}

describe('the Markdown renderer', () => {
  it('renders the ordinary things as elements', () => {
    show('# Heading\n\nSome **bold** and `code`.\n\n- one\n- two\n')
    expect(screen.getByRole('heading', { name: 'Heading' })).toBeInTheDocument()
    expect(screen.getByText('bold').tagName).toBe('STRONG')
    expect(screen.getByText('code').tagName).toBe('CODE')
    expect(screen.getAllByRole('listitem')).toHaveLength(2)
  })

  it('never turns raw HTML into markup', () => {
    show('<img src=x onerror="alert(1)">\n\nAfter.')
    expect(screen.queryByRole('img')).toBeNull()
    expect(screen.getByTestId('out').querySelector('img')).toBeNull()
    expect(screen.getByTestId('out').textContent).toContain('<img')
  })

  it('never turns an inline script tag into markup either', () => {
    show('Before <script>window.stolen = 1</script> after.')
    expect(screen.getByTestId('out').querySelector('script')).toBeNull()
    expect(screen.getByTestId('out').textContent).toContain('<script>')
  })

  it('renders an https link as a control that asks the backend to open it', async () => {
    const { context } = show('[the guide](https://docs.example.org/guide)')
    const link = screen.getByRole('button', { name: 'the guide' })
    expect(link.tagName).toBe('BUTTON')
    await userEvent.click(link)
    expect(context.openLink).toHaveBeenCalledWith('https://docs.example.org/guide')
  })

  it('does not make a script URL activatable at all', () => {
    show('[press me](javascript:alert(1))')
    expect(screen.queryByRole('button')).toBeNull()
    expect(screen.getByTestId('out').querySelector('a')).toBeNull()
    expect(screen.getByTestId('out').textContent).toContain('press me')
  })

  it('does not make a file URL activatable either', () => {
    show('[open it](file:///etc/passwd)')
    expect(screen.queryByRole('button')).toBeNull()
    expect(screen.getByTestId('out').textContent).toContain('file:///etc/passwd')
  })

  it('never emits an anchor element, so the page cannot navigate', () => {
    show('[a](https://example.org) and [b](https://example.org/b)')
    expect(screen.getByTestId('out').querySelectorAll('a')).toHaveLength(0)
  })

  it('does not fetch an image because an agent printed a URL', () => {
    const { context } = show('![a screenshot](https://example.org/a.png)')
    expect(screen.getByTestId('out').querySelector('img')).toBeNull()
    expect(context.importImage).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Load this image' })).toBeInTheDocument()
  })

  it('imports an image only when the person asks for that image', async () => {
    const { context } = show('![a screenshot](https://example.org/a.png)')
    await userEvent.click(screen.getByRole('button', { name: 'Load this image' }))
    expect(context.importImage).toHaveBeenCalledWith('https://example.org/a.png')
  })

  it('shows an image once it has been imported', () => {
    show('![a screenshot](https://example.org/a.png)', {
      importedImages: new Map([['https://example.org/a.png', 'blob:imported']])
    })
    const image = screen.getByRole('img', { name: 'a screenshot' })
    expect(image).toHaveAttribute('src', 'blob:imported')
  })

  it('offers no import for an image whose scheme is not one the application opens', () => {
    show('![x](data:image/png;base64,AAAA)')
    expect(screen.queryByRole('button', { name: 'Load this image' })).toBeNull()
  })

  it('bounds a very long source rather than rendering all of it', () => {
    show(`${'word '.repeat(80_000)}`)
    expect(screen.getByTestId('out').textContent.length).toBeLessThan(220_000)
  })

  it('agrees with the backend about which schemes are openable', () => {
    expect(openableScheme('https://example.org')).toBe(true)
    expect(openableScheme('mailto:a@example.org')).toBe(true)
    expect(openableScheme('http://example.org')).toBe(false)
    expect(openableScheme('JAVASCRIPT:alert(1)')).toBe(false)
    expect(openableScheme('kalareach-internal://run')).toBe(false)
  })
})
