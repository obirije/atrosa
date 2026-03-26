/**
 * Extract Python code from LLM output
 */

/**
 * Extract Python code from LLM output.
 *
 * Security: Only accepts code within proper ``` fences.
 * The previous fallback that accepted any text containing 'import' and
 * 'def detect' was removed — it allowed arbitrary text to be treated as
 * executable Python, which is an injection vector.
 */
export function extractCodeBlock(text: string): string | null {
  // Match ```python ... ``` or ``` ... ```
  const pattern = /```(?:python)?\s*\n([\s\S]*?)```/;
  const match = text.match(pattern);
  if (match) {
    return match[1].trim();
  }
  return null;
}
