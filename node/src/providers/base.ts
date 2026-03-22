/**
 * ATROSA LLM Provider Abstraction — Base classes
 */

export class RateLimitError extends Error {
  constructor(message = "Rate limit exceeded") {
    super(message);
    this.name = "RateLimitError";
  }
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export abstract class LLMProvider {
  model: string;
  systemPrompt: string;
  messages: ChatMessage[] = [];

  constructor(model: string, systemPrompt: string) {
    this.model = model;
    this.systemPrompt = systemPrompt;
  }

  protected abstract callApi(): Promise<string>;

  async chat(userMessage: string): Promise<string> {
    this.messages.push({ role: "user", content: userMessage });

    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const text = await this.callApi();
        this.messages.push({ role: "assistant", content: text });
        return text;
      } catch (err) {
        if (err instanceof RateLimitError) {
          const wait = Math.pow(2, attempt) * 15;
          console.log(`  [rate limit] Waiting ${wait}s before retry ${attempt + 1}/5...`);
          await new Promise((r) => setTimeout(r, wait * 1000));
          if (attempt === 4) throw err;
        } else {
          throw err;
        }
      }
    }

    throw new Error("Unreachable");
  }
}
