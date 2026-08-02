from __future__ import annotations

from pathlib import Path

from .gemini import GeminiClient, TextGenerator
from .learning import fetch_web_document
from .memory import ObsidianMemory


class AdvancedGeminiAI:
    def __init__(
        self,
        vault: Path | str = "memory_vault",
        model: str = "gemini-2.5-flash",
        generator: TextGenerator | None = None,
    ) -> None:
        self.memory = ObsidianMemory(vault)
        self.gemini = generator or GeminiClient(model=model)

    def ask(self, message: str, reflect: bool = False, deep: bool = False) -> str:
        context = self.memory.context_for(message)
        prompt = f"""You are an advanced AI assistant with permanent markdown memory.
Use relevant memories when useful, but do not invent facts.
Prefer explicit assumptions, concise plans, and actionable next steps.

Relevant memory:
{context}

User message:
{message}
"""
        answer = self.gemini.generate(prompt)
        if deep:
            answer = self._deepen_answer(message, context, answer)
        self.memory.remember(
            title=f"Conversation: {message[:60]}",
            body=f"## User\n{message}\n\n## Assistant\n{answer}",
            tags=["conversation", "deep-reasoning" if deep else "standard-reasoning"],
        )
        if reflect:
            self.reflect(message, answer)
        return answer

    def _deepen_answer(self, message: str, context: str, draft: str) -> str:
        critique_prompt = f"""Review this draft answer before it is shown to the user.
Find missing constraints, memory conflicts, unsafe assumptions, and opportunities to be more useful.
Return concise critique bullets.

Relevant memory:
{context}

User message:
{message}

Draft answer:
{draft}
"""
        critique = self.gemini.generate(critique_prompt)
        final_prompt = f"""Create the final answer using the draft and critique.
Preserve correct content, fix issues, and keep the response direct.

User message:
{message}

Draft answer:
{draft}

Critique:
{critique}
"""
        final = self.gemini.generate(final_prompt)
        return f"{final}\n\n---\nReflection critique used internally:\n{critique}"

    def reflect(self, message: str, answer: str) -> str:
        prompt = f"""Reflect on this interaction for long-term learning.
Extract durable preferences, facts, unresolved questions, and strategy improvements.
Return concise markdown bullets with tags and possible [[wiki links]].

User:
{message}

Assistant:
{answer}
"""
        reflection = self.gemini.generate(prompt)
        self.memory.remember("Reflection", reflection, tags=["reflection", "continual-learning"], folder="reflections")
        return reflection

    def learn_url(self, url: str) -> Path:
        doc = fetch_web_document(url)
        prompt = f"""Summarize this web document into durable notes for future retrieval.
Include source URL, key facts, caveats, useful tags, and possible [[wiki links]].

Title: {doc.title}
URL: {doc.url}

{doc.text}
"""
        summary = self.gemini.generate(prompt)
        return self.memory.remember(doc.title, f"Source: {doc.url}\n\n{summary}", tags=["online-learning"], folder="sources")

    def consolidate(self) -> str:
        corpus = self.memory.all_notes_text()
        prompt = f"""Consolidate this memory vault into a concise knowledge map.
Merge duplicates, identify stable user preferences, list open loops, propose named [[concept links]], and suggest next learning goals.

{corpus}
"""
        consolidation = self.gemini.generate(prompt)
        self.memory.remember("Continual learning consolidation", consolidation, tags=["consolidation", "continual-learning"], folder="reflections")
        self.memory.export_graph()
        return consolidation
