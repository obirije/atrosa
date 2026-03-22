/**
 * Extract Python code from LLM output
 */

export function extractCodeBlock(text: string): string | null {
  // Match ```python ... ``` or ``` ... ```
  const pattern = /```(?:python)?\s*\n([\s\S]*?)```/;
  const match = text.match(pattern);
  if (match) {
    return match[1].trim();
  }
  // If no code block, check if the entire response looks like Python
  if (text.includes("import ") && text.includes("def detect")) {
    return text.trim();
  }
  return null;
}
