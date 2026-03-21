"""
ATROSA LLM Provider Abstraction
=================================
Unified interface for multiple LLM backends:
- Anthropic (Claude)
- OpenAI (GPT-4o, o1, etc.)
- Google Gemini
- OpenRouter (access to 100+ models)
- Local models (Ollama, LM Studio, vLLM — anything OpenAI-compatible)

All providers implement the same interface: maintain conversation history,
send messages, return text responses with rate-limit retry.
"""

import os
import sys
import time
from abc import ABC, abstractmethod
from typing import Optional


# ===========================
# BASE PROVIDER
# ===========================
class LLMProvider(ABC):
    """Base class for all LLM providers."""

    def __init__(self, model: str, system_prompt: str):
        self.model = model
        self.system_prompt = system_prompt
        self.messages: list[dict] = []

    @abstractmethod
    def _call_api(self) -> str:
        """Make the actual API call. Returns assistant text."""
        ...

    def chat(self, user_message: str) -> str:
        """Send a message and get a response. Handles retry."""
        self.messages.append({"role": "user", "content": user_message})

        for attempt in range(5):
            try:
                text = self._call_api()
                self.messages.append({"role": "assistant", "content": text})
                return text
            except RateLimitError:
                wait = 2 ** attempt * 15
                print(f"  [rate limit] Waiting {wait}s before retry {attempt+1}/5...")
                time.sleep(wait)
                if attempt == 4:
                    raise


class RateLimitError(Exception):
    """Raised when any provider hits a rate limit."""
    pass


# ===========================
# ANTHROPIC
# ===========================
class AnthropicProvider(LLMProvider):

    def __init__(self, model: str, system_prompt: str):
        super().__init__(model, system_prompt)
        import anthropic
        self._anthropic = anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is required")
        self.client = anthropic.Anthropic(api_key=api_key)

    def _call_api(self) -> str:
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.system_prompt,
                messages=self.messages,
            )
            return response.content[0].text
        except self._anthropic.RateLimitError:
            raise RateLimitError()


# ===========================
# OPENAI-COMPATIBLE (covers OpenAI, OpenRouter, Local)
# ===========================
class OpenAICompatibleProvider(LLMProvider):
    """
    Works with any OpenAI-compatible API:
    - OpenAI: https://api.openai.com/v1
    - OpenRouter: https://openrouter.ai/api/v1
    - Ollama: http://localhost:11434/v1
    - LM Studio: http://localhost:1234/v1
    - vLLM: http://localhost:8000/v1
    """

    def __init__(self, model: str, system_prompt: str, base_url: str, api_key: str):
        super().__init__(model, system_prompt)
        from openai import OpenAI
        self._openai_module = __import__("openai")
        self.client = OpenAI(base_url=base_url, api_key=api_key)

    def _call_api(self) -> str:
        messages = [{"role": "system", "content": self.system_prompt}] + self.messages
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=4096,
                temperature=0.7,
            )
            return response.choices[0].message.content
        except self._openai_module.RateLimitError:
            raise RateLimitError()


class OpenAIProvider(OpenAICompatibleProvider):

    def __init__(self, model: str, system_prompt: str):
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        super().__init__(
            model=model,
            system_prompt=system_prompt,
            base_url="https://api.openai.com/v1",
            api_key=api_key,
        )


class OpenRouterProvider(OpenAICompatibleProvider):

    def __init__(self, model: str, system_prompt: str):
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY environment variable is required")
        super().__init__(
            model=model,
            system_prompt=system_prompt,
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        )


class LocalProvider(OpenAICompatibleProvider):

    def __init__(self, model: str, system_prompt: str, base_url: Optional[str] = None):
        url = base_url or os.environ.get("LOCAL_LLM_URL", "http://localhost:11434/v1")
        super().__init__(
            model=model,
            system_prompt=system_prompt,
            base_url=url,
            api_key=os.environ.get("LOCAL_LLM_KEY", "not-needed"),
        )


# ===========================
# GOOGLE GEMINI
# ===========================
class GeminiProvider(LLMProvider):

    def __init__(self, model: str, system_prompt: str):
        super().__init__(model, system_prompt)
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is required")
        from google import genai
        self.client = genai.Client(api_key=api_key)

    def _call_api(self) -> str:
        from google.genai import types

        contents = []
        for msg in self.messages:
            role = "user" if msg["role"] == "user" else "model"
            contents.append(types.Content(role=role, parts=[types.Part(text=msg["content"])]))

        config = types.GenerateContentConfig(
            system_instruction=self.system_prompt,
            max_output_tokens=4096,
            temperature=0.7,
        )

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=contents,
                config=config,
            )
            return response.text
        except Exception as e:
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                raise RateLimitError()
            raise


# ===========================
# PROVIDER FACTORY
# ===========================

# Default models per provider
DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o",
    "gemini": "gemini-2.5-flash",
    "openrouter": "anthropic/claude-sonnet-4",
    "local": "qwen2.5-coder:14b",
}

# Env var names per provider
ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "local": None,
}


def create_provider(
    provider_name: str,
    system_prompt: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> LLMProvider:
    """Factory function to create the right provider."""

    model = model or DEFAULT_MODELS.get(provider_name)

    if provider_name == "anthropic":
        return AnthropicProvider(model=model, system_prompt=system_prompt)

    elif provider_name == "openai":
        return OpenAIProvider(model=model, system_prompt=system_prompt)

    elif provider_name == "gemini":
        return GeminiProvider(model=model, system_prompt=system_prompt)

    elif provider_name == "openrouter":
        return OpenRouterProvider(model=model, system_prompt=system_prompt)

    elif provider_name == "local":
        return LocalProvider(model=model, system_prompt=system_prompt, base_url=base_url)

    else:
        raise ValueError(
            f"Unknown provider: {provider_name}. "
            f"Choose from: anthropic, openai, gemini, openrouter, local"
        )
