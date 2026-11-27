/**
 * A text matcher for a technical word. The word is drawn in boxes (a part of an option that cannot
 * end a line is one), so no one element holds all its characters as its own text; the box that holds
 * the whole word has them as its text content.
 */
export function technicalWordText(text: string): (content: string, element: Element | null) => boolean {
  return (_content, element) => element?.classList.contains('technical-word') === true && element.textContent === text
}

/**
 * A text matcher for a sentence that holds a technical word. The word is a box of its own, so no one
 * element holds the sentence as its own text; the innermost element whose text content is the whole
 * sentence is the one that says it.
 */
export function sentenceText(text: string): (content: string, element: Element | null) => boolean {
  return (_content, element) =>
    element !== null &&
    element.textContent === text &&
    !Array.from(element.children).some((child) => child.textContent === text)
}
