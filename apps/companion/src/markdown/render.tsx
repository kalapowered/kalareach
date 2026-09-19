/**
 * Markdown, through an allowlist, as elements rather than markup.
 *
 * Section 13 disables raw HTML and script URLs in rendered Markdown. The usual way to do that is to
 * produce HTML and then sanitise it, which puts the whole of the interface's safety on one
 * stripping pass. This renderer never produces HTML at all: an established parser turns the source
 * into tokens, and this turns the tokens it allows into React elements. A token it does not allow
 * has no branch that could render it as markup, so there is nothing to strip.
 *
 * Links are the other half. A link in agent or terminal text is a string someone else wrote, so it
 * is rendered as a button rather than an anchor: activating it calls the backend, which checks the
 * scheme and hands it to the platform. The page never navigates.
 */

import { Fragment, type ReactNode } from 'react'
import { Lexer, type Token, type Tokens } from 'marked'

/** What the renderer needs from the application around it. */
export interface MarkdownContext {
  /** Opens a link, after the backend has checked its scheme. */
  openLink(url: string): void
  /**
   * Imports one remote image, because the person asked for that image.
   *
   * A renderer that fetched images itself would tell whoever printed the URL that the reader had
   * read it, so an image is a placeholder until this is called.
   */
  importImage(url: string): void
  /** The image bytes already imported, keyed by URL. */
  importedImages: ReadonlyMap<string, string>
}

/** How much Markdown one node may carry before it is truncated. */
export const MAX_SOURCE_LENGTH = 200_000

/** Renders Markdown source as elements. */
export function renderMarkdown(source: string, context: MarkdownContext): ReactNode {
  const bounded =
    source.length > MAX_SOURCE_LENGTH ? `${source.slice(0, MAX_SOURCE_LENGTH)}…` : source
  const tokens = Lexer.lex(bounded, { gfm: true, breaks: false })
  return <>{renderTokens(tokens, context, 'md')}</>
}

function renderTokens(tokens: readonly Token[], context: MarkdownContext, key: string): ReactNode[] {
  const out: ReactNode[] = []
  tokens.forEach((token, index) => {
    const node = renderToken(token, context, `${key}-${index}`)
    if (node !== null) out.push(node)
  })
  return out
}

function renderToken(token: Token, context: MarkdownContext, key: string): ReactNode {
  switch (token.type) {
    case 'space':
      return null

    case 'paragraph': {
      const paragraph = token as Tokens.Paragraph
      return <p key={key}>{renderTokens(paragraph.tokens ?? [], context, key)}</p>
    }

    case 'heading': {
      const heading = token as Tokens.Heading
      // Headings inside a conversation sit under the message's own heading, so they start at h4
      // rather than competing with the page. The depth still maps one to one.
      const level = Math.min(6, heading.depth + 3)
      const Tag = `h${level}` as 'h4' | 'h5' | 'h6'
      return <Tag key={key}>{renderTokens(heading.tokens ?? [], context, key)}</Tag>
    }

    case 'text': {
      const text = token as Tokens.Text
      if (text.tokens && text.tokens.length > 0) {
        return <Fragment key={key}>{renderTokens(text.tokens, context, key)}</Fragment>
      }
      return <Fragment key={key}>{text.text}</Fragment>
    }

    case 'escape':
      return <Fragment key={key}>{(token as Tokens.Escape).text}</Fragment>

    case 'strong': {
      const strong = token as Tokens.Strong
      return <strong key={key}>{renderTokens(strong.tokens ?? [], context, key)}</strong>
    }

    case 'em': {
      const em = token as Tokens.Em
      return <em key={key}>{renderTokens(em.tokens ?? [], context, key)}</em>
    }

    case 'del': {
      const del = token as Tokens.Del
      return <del key={key}>{renderTokens(del.tokens ?? [], context, key)}</del>
    }

    case 'codespan':
      return <code key={key}>{(token as Tokens.Codespan).text}</code>

    case 'code': {
      const code = token as Tokens.Code
      // The language is a label, never a class that some highlighter would evaluate.
      return (
        <pre key={key} className="code-block" data-language={code.lang ?? ''}>
          <code>{code.text}</code>
        </pre>
      )
    }

    case 'blockquote': {
      const quote = token as Tokens.Blockquote
      return <blockquote key={key}>{renderTokens(quote.tokens ?? [], context, key)}</blockquote>
    }

    case 'list': {
      const list = token as Tokens.List
      const items = list.items.map((item, index) => (
        <li key={`${key}-i${index}`}>{renderTokens(item.tokens ?? [], context, `${key}-i${index}`)}</li>
      ))
      return list.ordered ? (
        <ol key={key} start={typeof list.start === 'number' ? list.start : 1}>
          {items}
        </ol>
      ) : (
        <ul key={key}>{items}</ul>
      )
    }

    case 'table': {
      const table = token as Tokens.Table
      return (
        <table key={key} className="md-table">
          <thead>
            <tr>
              {table.header.map((cell, index) => (
                <th key={`${key}-h${index}`} style={alignOf(table.align[index])}>
                  {renderTokens(cell.tokens ?? [], context, `${key}-h${index}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {table.rows.map((row, rowIndex) => (
              <tr key={`${key}-r${rowIndex}`}>
                {row.map((cell, cellIndex) => (
                  <td key={`${key}-r${rowIndex}c${cellIndex}`} style={alignOf(table.align[cellIndex])}>
                    {renderTokens(cell.tokens ?? [], context, `${key}-r${rowIndex}c${cellIndex}`)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )
    }

    case 'hr':
      return <hr key={key} />

    case 'br':
      return <br key={key} />

    case 'link': {
      const link = token as Tokens.Link
      const label = renderTokens(link.tokens ?? [], context, key)
      if (!openableScheme(link.href)) {
        // A scheme the application will not open renders as the text it was, with the target
        // shown, so nothing is hidden and nothing is activatable.
        return (
          <span key={key} className="link-refused" title={link.href}>
            {label} <span className="faint">({displayTarget(link.href)})</span>
          </span>
        )
      }
      return (
        <button
          key={key}
          type="button"
          className="md-link"
          // A link opens on a completed click, never on pointer-down: activating a link is a
          // deliberate act and a press that slides off is a cancelled one.
          onClick={() => {
            context.openLink(link.href)
          }}
          title={link.href}
        >
          {label}
        </button>
      )
    }

    case 'image': {
      const image = token as Tokens.Image
      const imported = context.importedImages.get(image.href)
      if (imported) {
        return <img key={key} className="md-image" src={imported} alt={image.text} />
      }
      // Nothing is fetched because an agent printed a URL. The person is shown what it is and can
      // ask for it.
      return (
        <span key={key} className="md-image-placeholder">
          <span className="faint">Image not loaded: {displayTarget(image.href)}</span>
          {openableScheme(image.href) ? (
            <button
              type="button"
              className="text-link"
              onClick={() => {
                context.importImage(image.href)
              }}
            >
              Load this image
            </button>
          ) : null}
        </span>
      )
    }

    // Raw HTML in any form. The parser recognises it; this renderer has no branch that turns it
    // into markup, so it is shown as the text it is.
    case 'html':
      return (
        <code key={key} className="html-refused">
          {(token as Tokens.HTML).raw}
        </code>
      )

    default:
      // An unknown token renders its own source as text rather than disappearing, because content
      // that vanished would be worse than content that is plain.
      return <Fragment key={key}>{'raw' in token ? String(token.raw) : ''}</Fragment>
  }
}

/** The schemes a rendered link may carry. Everything else renders as text. */
const OPENABLE = ['https:', 'mailto:']

/** Whether a Markdown target is one the application would hand to the backend. */
export function openableScheme(href: string): boolean {
  const trimmed = href.trim().toLowerCase()
  return OPENABLE.some((scheme) => trimmed.startsWith(scheme))
}

/** What a refused target is shown as: short, and never activatable. */
function displayTarget(href: string): string {
  const flattened = href.replace(/\s+/g, ' ').trim()
  return flattened.length > 80 ? `${flattened.slice(0, 77)}…` : flattened
}

function alignOf(align: 'center' | 'left' | 'right' | null | undefined) {
  return align ? { textAlign: align } : undefined
}
