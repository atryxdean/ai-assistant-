# Obsidian Gemini AI

A local-first AI assistant that uses the Gemini API while keeping durable, inspectable memory in an Obsidian-compatible Markdown vault.

## Features

- **Permanent memory like Obsidian**: every conversation, reflection, source, and consolidation is saved as Markdown with JSON front matter.
- **Reflection mode**: optionally asks Gemini to extract durable lessons after a conversation.
- **Online learning**: ingests a URL, summarizes it with Gemini, and stores the source note.
- **Continual learning**: periodically consolidates the vault into a knowledge map without fine-tuning or silently mutating model weights.
- **Local retrieval**: searches memory notes with a lightweight token-overlap retriever before prompting Gemini.
- **Interactive chat**: run a persistent terminal chat loop with optional reflection on each turn.
- **Reindexing**: rebuild retrieval metadata after editing notes directly in Obsidian.
- **Desktop GUI**: use a Tkinter interface for chat, memory search, manual notes, URL learning, consolidation, and reindexing.
- **Deep reasoning mode**: optionally runs a draft, critique, and final-answer pass for harder requests.
- **Memory graph export**: extracts `[[wiki links]]` into `graph.json` for inspecting relationships across notes.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
export GEMINI_API_KEY="your-key"
# Optional: override the default model
export GEMINI_MODEL="gemini-2.5-flash"
```

## Usage

Ask a question and save the exchange:

```bash
obsidian-gemini-ai ask "What should we work on next?" --reflect --deep
```

Start an interactive chat session:

```bash
obsidian-gemini-ai chat --reflect
```

Add manual memory:

```bash
obsidian-gemini-ai remember "User preference" "Prefers concise plans before implementation." --tag preference
```

Search memory:

```bash
obsidian-gemini-ai search "concise plans"
```

Learn from a web page:

```bash
obsidian-gemini-ai learn-url "https://example.com/article"
```

Consolidate long-term memory:

```bash
obsidian-gemini-ai consolidate
```

Rebuild the local search index after editing Markdown files manually:

```bash
obsidian-gemini-ai reindex
```

Export an Obsidian-style memory graph from `[[wiki links]]`:

```bash
obsidian-gemini-ai graph
```

Launch the desktop GUI:

```bash
obsidian-gemini-ai-gui
# or
obsidian-gemini-ai gui
```

## GUI workflow

The GUI exposes the same local-first workflow as the CLI:

1. Choose a vault directory or keep `memory_vault/`.
2. Set a Gemini model, or keep the default.
3. Type into the input bar and choose **Ask**, **Search**, **Learn URL**, **Remember**, **Consolidate**, or **Reindex**.
4. Enable **Reflect** before asking if you want each Gemini answer followed by a durable reflection note.
5. Enable **Deep** when a prompt deserves a draft, self-critique, and final-answer pass.

Gemini-powered GUI actions require `GEMINI_API_KEY`; local memory actions such as search, remember, and reindex do not.

## Memory layout

The default `memory_vault/` directory contains:

- `notes/` for conversations and manual notes.
- `sources/` for online learning notes.
- `reflections/` for reflections and consolidations.
- `index.json` for local retrieval metadata.
- `graph.json` for exported note relationship data.

Open the vault folder in Obsidian to browse, link, tag, and edit memories directly. Use `[[wiki links]]` in notes or reflections to create graph edges.

## Safety and learning model

This project implements continual learning as retrieval, reflection, and memory consolidation. It does not fine-tune Gemini, alter Gemini weights, or bypass provider controls. Treat saved vault data as sensitive and keep API keys in environment variables, not in notes.
