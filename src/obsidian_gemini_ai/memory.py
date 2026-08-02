from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

WORD_RE = re.compile(r"[a-zA-Z0-9_]+")
WIKI_LINK_RE = re.compile(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slugify(text: str, limit: int = 72) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower()).strip("-")
    return (slug[:limit].strip("-") or "memory")


def tokenize(text: str) -> set[str]:
    return {token.lower() for token in WORD_RE.findall(text) if len(token) > 2}


def extract_wiki_links(text: str) -> list[str]:
    return sorted({match.strip() for match in WIKI_LINK_RE.findall(text) if match.strip()})


@dataclass(frozen=True)
class MemoryHit:
    path: Path
    title: str
    score: float
    text: str
    tags: tuple[str, ...] = ()
    created: str | None = None


class ObsidianMemory:
    """A markdown vault for permanent, inspectable assistant memory."""

    def __init__(self, vault: Path | str = "memory_vault") -> None:
        self.vault = Path(vault)
        self.notes = self.vault / "notes"
        self.reflections = self.vault / "reflections"
        self.sources = self.vault / "sources"
        self.index_path = self.vault / "index.json"
        self.graph_path = self.vault / "graph.json"
        for folder in (self.notes, self.reflections, self.sources):
            folder.mkdir(parents=True, exist_ok=True)
        if not self.index_path.exists():
            self._write_index([])

    def remember(self, title: str, body: str, tags: Iterable[str] = (), folder: str = "notes") -> Path:
        if folder not in {"notes", "reflections", "sources"}:
            raise ValueError(f"Unsupported memory folder: {folder}")
        created = utc_now()
        tag_list = sorted({tag.strip().lower().replace(" ", "-") for tag in tags if tag.strip()})
        target_dir = getattr(self, folder)
        path = target_dir / f"{created[:10]}-{slugify(title)}.md"
        counter = 1
        while path.exists():
            path = target_dir / f"{created[:10]}-{slugify(title)}-{counter}.md"
            counter += 1
        frontmatter = {
            "title": title,
            "created": created,
            "tags": tag_list,
            "links": extract_wiki_links(body),
        }
        path.write_text(f"---\n{json.dumps(frontmatter, indent=2)}\n---\n\n{body.strip()}\n", encoding="utf-8")
        index = self._read_index()
        index.append(self._index_item(path, title, created, tag_list, body))
        self._write_index(index)
        return path

    def search(self, query: str, limit: int = 6) -> list[MemoryHit]:
        query_tokens = tokenize(query)
        if not query_tokens:
            return []
        index = self._read_index()
        doc_count = max(len(index), 1)
        document_frequency = self._document_frequency(index)
        hits: list[MemoryHit] = []
        for item in index:
            tokens = set(item.get("tokens", []))
            overlap = query_tokens & tokens
            if not overlap:
                continue
            path = self.vault / item["path"]
            if path.exists():
                text = path.read_text(encoding="utf-8")
                score = sum(math.log((doc_count + 1) / (document_frequency[token] + 1)) + 1 for token in overlap)
                title_bonus = 0.5 * len(overlap & tokenize(item.get("title", "")))
                tag_bonus = 0.25 * len(overlap & tokenize(" ".join(item.get("tags", []))))
                normalized = (score + title_bonus + tag_bonus) / max(len(query_tokens), 1)
                hits.append(
                    MemoryHit(
                        path=path,
                        title=item.get("title", path.stem),
                        score=normalized,
                        text=text[:2400],
                        tags=tuple(item.get("tags", [])),
                        created=item.get("created"),
                    )
                )
        return sorted(hits, key=lambda hit: hit.score, reverse=True)[:limit]

    def context_for(self, query: str, limit: int = 6) -> str:
        hits = self.search(query, limit=limit)
        if not hits:
            return "No relevant memories found."
        return "\n\n".join(
            f"# {hit.title}\nScore: {hit.score:.2f}\nTags: {', '.join(hit.tags) or 'none'}\n{hit.text}" for hit in hits
        )

    def all_notes_text(self, limit_chars: int = 20000) -> str:
        chunks: list[str] = []
        total = 0
        for item in self._read_index():
            path = self.vault / item["path"]
            if path.exists():
                chunk = path.read_text(encoding="utf-8")
                chunks.append(chunk)
                total += len(chunk)
            if total >= limit_chars:
                break
        return "\n\n".join(chunks)[:limit_chars]

    def rebuild_index(self) -> int:
        index: list[dict] = []
        for folder in (self.notes, self.reflections, self.sources):
            for path in sorted(folder.glob("*.md")):
                text = path.read_text(encoding="utf-8")
                frontmatter, body = self._parse_frontmatter(text)
                title = str(frontmatter.get("title") or path.stem)
                index.append(
                    self._index_item(
                        path=path,
                        title=title,
                        created=frontmatter.get("created"),
                        tags=frontmatter.get("tags", []),
                        body=body,
                    )
                )
        self._write_index(index)
        return len(index)

    def export_graph(self) -> Path:
        index = self._read_index()
        nodes = [
            {
                "id": item["path"],
                "title": item.get("title", item["path"]),
                "tags": item.get("tags", []),
                "created": item.get("created"),
            }
            for item in index
        ]
        title_to_path = {item.get("title", "").lower(): item["path"] for item in index}
        edges: list[dict[str, str]] = []
        for item in index:
            for link in item.get("links", []):
                target = title_to_path.get(link.lower(), link)
                edges.append({"source": item["path"], "target": target, "type": "wiki-link"})
        self.graph_path.write_text(json.dumps({"nodes": nodes, "edges": edges}, indent=2), encoding="utf-8")
        return self.graph_path

    def _index_item(self, path: Path, title: str, created: str | None, tags: Iterable[str], body: str) -> dict:
        tag_list = sorted({str(tag).strip().lower().replace(" ", "-") for tag in tags if str(tag).strip()})
        return {
            "path": str(path.relative_to(self.vault)),
            "title": title,
            "created": created,
            "tags": tag_list,
            "links": extract_wiki_links(body),
            "tokens": sorted(tokenize(title + " " + " ".join(tag_list) + " " + body)),
        }

    @staticmethod
    def _document_frequency(index: list[dict]) -> dict[str, int]:
        frequency: dict[str, int] = {}
        for item in index:
            for token in set(item.get("tokens", [])):
                frequency[token] = frequency.get(token, 0) + 1
        return frequency

    def _read_index(self) -> list[dict]:
        try:
            return json.loads(self.index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Memory index is corrupt: {self.index_path}") from exc

    def _write_index(self, data: list[dict]) -> None:
        self.index_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def _parse_frontmatter(text: str) -> tuple[dict, str]:
        if not text.startswith("---"):
            return {}, text
        parts = text.split("---", 2)
        if len(parts) < 3:
            return {}, text
        frontmatter_text = parts[1].strip()
        body = parts[2].strip()
        if not frontmatter_text:
            return {}, body
        return json.loads(frontmatter_text), body
