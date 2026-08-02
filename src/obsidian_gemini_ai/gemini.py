from __future__ import annotations

import os
from typing import Protocol

DEFAULT_MODEL = "gemini-2.5-flash"


class TextGenerator(Protocol):
    def generate(self, prompt: str) -> str: ...


class GeminiClient:
    """Small wrapper around the Google Gen AI SDK.

    The SDK import is intentionally lazy so local-only commands such as
    `remember` and `search` work before optional dependencies are installed.
    """

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        from google import genai

        self.model = model or os.getenv("GEMINI_MODEL") or DEFAULT_MODEL
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError("Set GEMINI_API_KEY before using Gemini-powered commands.")
        self.client = genai.Client(api_key=self.api_key)

    def generate(self, prompt: str) -> str:
        response = self.client.models.generate_content(model=self.model, contents=prompt)
        return response.text or ""
