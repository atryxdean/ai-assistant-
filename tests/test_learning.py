from unittest import TestCase

from obsidian_gemini_ai.learning import fetch_web_document


class LearningTest(TestCase):
    def test_rejects_relative_urls(self):
        with self.assertRaises(ValueError):
            fetch_web_document("/relative/path")
