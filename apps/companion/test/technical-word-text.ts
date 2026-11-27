/**
 * A text matcher for a technical word. The word is drawn in boxes (a part of an option that cannot
 * end a line is one), so no one element holds all its characters as its own text; the box that holds
 * the whole word has them as its text content.
 */
export function technicalWordText(text: string): (content: string, element: Element | null) => boolean {
  return (_content, element) => element?.classList.contains('technical-word') === true && element.textContent === text
}
