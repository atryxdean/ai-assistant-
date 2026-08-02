from pathlib import Path
from unittest import TestCase

from obsidian_gemini_ai.gui import format_hit
from obsidian_gemini_ai.memory import MemoryHit


class GuiTest(TestCase):
    def test_format_hit_includes_score_title_and_path(self):
        hit = MemoryHit(path=Path("vault/notes/example.md"), title="Example", score=0.75, text="Body")

        formatted = format_hit(hit)

        self.assertIn("0.75", formatted)
        self.assertIn("Example", formatted)
        self.assertIn("vault/notes/example.md", formatted)
