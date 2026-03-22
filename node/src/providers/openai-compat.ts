/**
 * OpenAI-compatible provider (covers OpenAI, OpenRouter, Local)
 */

import OpenAI from "openai";
import { LLMProvider, RateLimitError } from "./base.js";

export class OpenAICompatibleProvider extends LLMProvider {
  protected client: OpenAI;

  constructor(
    model: string,
    systemPrompt: string,
    baseURL: string,
    apiKey: string,
  ) {
    super(model, systemPrompt);
    this.client = new OpenAI({ baseURL, apiKey });
  }

  protected async callApi(): Promise<string> {
    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system" as const, content: this.systemPrompt },
      ...this.messages.map((m) => ({
        role: m.role as "user" | "assistant",
        content: m.content,
      })),
    ];

    try {
      const response = await this.client.chat.completions.create({
        model: this.model,
        messages,
        max_tokens: 4096,
        temperature: 0.7,
      });
      return response.choices[0]?.message?.content ?? "";
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

export class OpenAIProvider extends OpenAICompatibleProvider {
  constructor(model: string, systemPrompt: string) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      throw new Error("OPENAI_API_KEY environment variable is required");
    }
    super(model, systemPrompt, "https://api.openai.com/v1", apiKey);
  }
}

export class OpenRouterProvider extends OpenAICompatibleProvider {
  constructor(model: string, systemPrompt: string) {
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
      throw new Error("OPENROUTER_API_KEY environment variable is required");
    }
    super(model, systemPrompt, "https://openrouter.ai/api/v1", apiKey);
  }
}

export class LocalProvider extends OpenAICompatibleProvider {
  constructor(
    model: string,
    systemPrompt: string,
    baseUrl?: string,
  ) {
    const url =
      baseUrl ||
      process.env.LOCAL_LLM_URL ||
      "http://localhost:11434/v1";
    const apiKey = process.env.LOCAL_LLM_KEY || "not-needed";
    super(model, systemPrompt, url, apiKey);
  }
}
