import tempfile
from pathlib import Path
from unittest import TestCase

from obsidian_gemini_ai.agent import AdvancedGeminiAI


class FakeGenerator:
    def __init__(self):
        self.prompts = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return f"response-{len(self.prompts)}"


class AgentTest(TestCase):
    def test_deep_answer_runs_draft_critique_and_final(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = FakeGenerator()
            agent = AdvancedGeminiAI(vault=Path(temp_dir) / "vault", generator=generator)

            answer = agent.ask("Build a plan", deep=True)

            self.assertEqual(len(generator.prompts), 3)
            self.assertIn("response-3", answer)
            self.assertIn("Reflection critique used internally", answer)
