/**
 * Anthropic (Claude) provider
 */

import Anthropic from "@anthropic-ai/sdk";
import { LLMProvider, RateLimitError } from "./base.js";

export class AnthropicProvider extends LLMProvider {
  private client: Anthropic;

  constructor(model: string, systemPrompt: string) {
    super(model, systemPrompt);
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error("ANTHROPIC_API_KEY environment variable is required");
    }
    this.client = new Anthropic({ apiKey });
  }

  protected async callApi(): Promise<string> {
    try {
      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 4096,
        system: this.systemPrompt,
        messages: this.messages.map((m) => ({
          role: m.role,
          content: m.content,
        })),
      });
      const block = response.content[0];
      if (block.type === "text") {
        return block.text;
      }
      throw new Error("Unexpected response content type");
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        (err.constructor.name === "RateLimitError" ||
          (err.message && err.message.includes("rate_limit")))
      ) {
        throw new RateLimitError();
      }
      throw err;
    }
  }
}
