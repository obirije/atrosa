/**
 * Google Gemini provider
 */

import { GoogleGenerativeAI } from "@google/generative-ai";
import { LLMProvider, RateLimitError } from "./base.js";

export class GeminiProvider extends LLMProvider {
  private client: GoogleGenerativeAI;

  constructor(model: string, systemPrompt: string) {
    super(model, systemPrompt);
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY environment variable is required");
    }
    this.client = new GoogleGenerativeAI(apiKey);
  }

  protected async callApi(): Promise<string> {
    const genModel = this.client.getGenerativeModel({
      model: this.model,
      systemInstruction: this.systemPrompt,
    });

    const contents = this.messages.map((m) => ({
      role: m.role === "user" ? "user" : "model",
      parts: [{ text: m.content }],
    }));

    try {
      const result = await genModel.generateContent({
        contents,
        generationConfig: {
          maxOutputTokens: 4096,
          temperature: 0.7,
        },
      });
      const response = result.response;
      return response.text();
    } catch (err: unknown) {
      const errStr = String(err);
      if (errStr.includes("429") || errStr.includes("RESOURCE_EXHAUSTED")) {
        throw new RateLimitError();
      }
      throw err;
    }
  }
}
