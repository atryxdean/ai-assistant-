import tempfile
from pathlib import Path
from unittest import TestCase

from obsidian_gemini_ai.memory import ObsidianMemory, slugify


class MemoryTest(TestCase):
    def test_slugify_falls_back_to_memory(self):
        self.assertEqual(slugify("!!!"), "memory")

    def test_remember_and_search(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            memory = ObsidianMemory(Path(temp_dir) / "vault")
            path = memory.remember("Project preference", "The user likes durable markdown memory.", tags=["Preference"])

            self.assertTrue(path.exists())
            hits = memory.search("durable markdown")

            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].title, "Project preference")

    def test_rebuild_index_after_manual_edit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            memory = ObsidianMemory(Path(temp_dir) / "vault")
            manual = memory.notes / "manual.md"
            manual.write_text('---\n{"title": "Manual note", "created": "now", "tags": ["x"]}\n---\n\nalpha beta', encoding="utf-8")

            count = memory.rebuild_index()
            hits = memory.search("alpha")

            self.assertEqual(count, 1)
            self.assertEqual(hits[0].title, "Manual note")

    def test_invalid_folder_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            memory = ObsidianMemory(Path(temp_dir) / "vault")

            with self.assertRaises(ValueError):
                memory.remember("Bad", "Body", folder="../outside")

    def test_export_graph_uses_wiki_links(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            memory = ObsidianMemory(Path(temp_dir) / "vault")
            memory.remember("Alpha", "Links to [[Beta]]", tags=["graph"])
            memory.remember("Beta", "Target note", tags=["graph"])

            graph_path = memory.export_graph()
            graph_text = graph_path.read_text(encoding="utf-8")

            self.assertIn('"edges"', graph_text)
            self.assertIn('"type": "wiki-link"', graph_text)

    def test_context_includes_tags_and_scores(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            memory = ObsidianMemory(Path(temp_dir) / "vault")
            memory.remember("Advanced retrieval", "Uses weighted token search.", tags=["retrieval"])

            context = memory.context_for("weighted retrieval")

            self.assertIn("# Advanced retrieval", context)
            self.assertIn("Tags: retrieval", context)

    def test_list_and_delete_memory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            memory = ObsidianMemory(Path(temp_dir) / "vault")
            path = memory.remember("Delete me", "temporary body", tags=["temp"])
            relative_path = str(path.relative_to(memory.vault))

            self.assertEqual(len(memory.list_memories()), 1)
            self.assertTrue(memory.delete_memory(relative_path))
            self.assertFalse(path.exists())
            self.assertEqual(memory.list_memories(), [])

    def test_delete_rejects_unsafe_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            memory = ObsidianMemory(Path(temp_dir) / "vault")

            with self.assertRaises(ValueError):
                memory.delete_memory("../outside.md")
