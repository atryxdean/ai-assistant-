from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

MAX_DOCUMENT_CHARS = 30000


@dataclass(frozen=True)
class WebDocument:
    title: str
    url: str
    text: str


def fetch_web_document(url: str, timeout: int = 20) -> WebDocument:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("learn-url requires an absolute http(s) URL")

    import requests
    from bs4 import BeautifulSoup

    response = requests.get(url, timeout=timeout, headers={"User-Agent": "obsidian-gemini-ai/0.2"})
    response.raise_for_status()
    content_type = response.headers.get("content-type", "").lower()
    if "html" not in content_type and "text" not in content_type:
        raise ValueError(f"Unsupported content type for online learning: {content_type or 'unknown'}")

    soup = BeautifulSoup(response.text, "html.parser")
    for element in soup(["script", "style", "noscript", "svg"]):
        element.decompose()
    title = soup.title.string.strip() if soup.title and soup.title.string else url
    text = "\n".join(line.strip() for line in soup.get_text("\n").splitlines() if line.strip())
    return WebDocument(title=title, url=url, text=text[:MAX_DOCUMENT_CHARS])
