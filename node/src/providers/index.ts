/**
 * Provider factory + default models
 */

import { LLMProvider } from "./base.js";
import { AnthropicProvider } from "./anthropic.js";
import {
  OpenAIProvider,
  OpenRouterProvider,
  LocalProvider,
} from "./openai-compat.js";
import { GeminiProvider } from "./gemini.js";

export { LLMProvider, RateLimitError } from "./base.js";

export const DEFAULT_MODELS: Record<string, string> = {
  anthropic: "claude-sonnet-4-20250514",
  openai: "gpt-4o",
  gemini: "gemini-2.5-flash",
  openrouter: "anthropic/claude-sonnet-4",
  local: "qwen2.5-coder:14b",
};

export const ENV_KEYS: Record<string, string | null> = {
  anthropic: "ANTHROPIC_API_KEY",
  openai: "OPENAI_API_KEY",
  gemini: "GEMINI_API_KEY",
  openrouter: "OPENROUTER_API_KEY",
  local: null,
};

export type ProviderName =
  | "anthropic"
  | "openai"
  | "gemini"
  | "openrouter"
  | "local";

export function createProvider(
  providerName: string,
  systemPrompt: string,
  model?: string,
  baseUrl?: string,
): LLMProvider {
  const resolvedModel = model || DEFAULT_MODELS[providerName];
  if (!resolvedModel) {
    throw new Error(`No default model for provider: ${providerName}`);
  }

  switch (providerName) {
    case "anthropic":
      return new AnthropicProvider(resolvedModel, systemPrompt);
    case "openai":
      return new OpenAIProvider(resolvedModel, systemPrompt);
    case "gemini":
      return new GeminiProvider(resolvedModel, systemPrompt);
    case "openrouter":
      return new OpenRouterProvider(resolvedModel, systemPrompt);
    case "local":
      return new LocalProvider(resolvedModel, systemPrompt, baseUrl);
    default:
      throw new Error(
        `Unknown provider: ${providerName}. Choose from: anthropic, openai, gemini, openrouter, local`,
      );
  }
}
