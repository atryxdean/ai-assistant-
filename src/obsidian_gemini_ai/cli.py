from __future__ import annotations

import argparse

from .agent import AdvancedGeminiAI
from .gemini import DEFAULT_MODEL
from .memory import ObsidianMemory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Gemini AI with Obsidian-style permanent memory")
    parser.add_argument("--vault", default="memory_vault", help="Path to the markdown memory vault")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Gemini model name")
    sub = parser.add_subparsers(dest="command", required=True)

    ask = sub.add_parser("ask", help="Ask the assistant and store the exchange")
    ask.add_argument("message")
    ask.add_argument("--reflect", action="store_true", help="Run reflection mode after answering")
    ask.add_argument("--deep", action="store_true", help="Use draft, critique, and final-answer reasoning")

    chat = sub.add_parser("chat", help="Start an interactive memory-backed chat")
    chat.add_argument("--reflect", action="store_true", help="Reflect after every turn")
    chat.add_argument("--deep", action="store_true", help="Use deep reasoning for every turn")

    remember = sub.add_parser("remember", help="Add a manual memory note without calling Gemini")
    remember.add_argument("title")
    remember.add_argument("body")
    remember.add_argument("--tag", action="append", default=[])

    search = sub.add_parser("search", help="Search the memory vault")
    search.add_argument("query")

    sub.add_parser("list", help="List memories in the vault")

    delete = sub.add_parser("delete", help="Delete a memory by vault-relative path")
    delete.add_argument("path")

    learn = sub.add_parser("learn-url", help="Learn from a URL and store a source note")
    learn.add_argument("url")

    sub.add_parser("consolidate", help="Run continual-learning memory consolidation")
    sub.add_parser("reindex", help="Rebuild index.json from Markdown files")
    sub.add_parser("graph", help="Export an Obsidian memory graph.json")
    sub.add_parser("gui", help="Launch the desktop GUI")
    return parser


def run_chat(ai: AdvancedGeminiAI, reflect: bool, deep: bool = False) -> None:
    print("Memory chat started. Type /exit to quit, /consolidate to summarize memory.")
    while True:
        message = input("you> ").strip()
        if message in {"/exit", "/quit"}:
            return
        if message == "/consolidate":
            print(ai.consolidate())
            continue
        if not message:
            continue
        print(f"ai> {ai.ask(message, reflect=reflect, deep=deep)}")


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "remember":
        path = ObsidianMemory(args.vault).remember(args.title, args.body, tags=args.tag)
        print(path)
        return
    if args.command == "search":
        for hit in ObsidianMemory(args.vault).search(args.query):
            print(f"{hit.score:.2f}\t{hit.path}\t{hit.title}")
        return
    if args.command == "list":
        for item in ObsidianMemory(args.vault).list_memories():
            print(f"{item.get('created') or 'unknown'}\t{item.get('path')}\t{item.get('title')}")
        return
    if args.command == "delete":
        deleted = ObsidianMemory(args.vault).delete_memory(args.path)
        print("Deleted" if deleted else "Not found")
        return
    if args.command == "reindex":
        count = ObsidianMemory(args.vault).rebuild_index()
        print(f"Indexed {count} notes")
        return
    if args.command == "graph":
        path = ObsidianMemory(args.vault).export_graph()
        print(path)
        return
    if args.command == "gui":
        from .gui import main as gui_main

        gui_main()
        return

    ai = AdvancedGeminiAI(vault=args.vault, model=args.model)
    if args.command == "ask":
        print(ai.ask(args.message, reflect=args.reflect, deep=args.deep))
    elif args.command == "chat":
        run_chat(ai, reflect=args.reflect, deep=args.deep)
    elif args.command == "learn-url":
        print(ai.learn_url(args.url))
    elif args.command == "consolidate":
        print(ai.consolidate())


if __name__ == "__main__":
    main()
